"""Public regressions for offline source inventory, exact snapshots and handoff."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import engine, source_projection
from awa_ddd.__main__ import dispatch as entry_dispatch
from awa_ddd.store import EngineError, Project, canonical


BASE_URL = "http://fixture.invalid"
FORBIDDEN_PREVIEW_KINDS = (
    "operation",
    "obligation",
    "candidate",
    "run",
    "evidence",
    "decision",
    "finding",
    "plan",
)


class SourceInventoryPublicTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="awa-source-inventory-")
        self.addCleanup(self.temporary.cleanup)
        self.workspace = self.temporary.name
        self.request = patch.object(
            engine,
            "request",
            side_effect=AssertionError("source inventory must remain offline"),
        ).start()
        self.addCleanup(self.request.stop)
        entry_dispatch(
            self.workspace,
            "project.create",
            {
                "project_id": "source-project",
                "target": BASE_URL,
                "assessment_mode": "src",
            },
        )

    def invoke(self, action, **args):
        return entry_dispatch(
            self.workspace,
            action,
            {"project_id": "source-project", **args},
        )

    def rejects(self, action, code, **args):
        with self.assertRaises(EngineError) as raised:
            self.invoke(action, **args)
        self.assertEqual(code, raised.exception.code)
        return raised.exception

    def write_json(self, name, document):
        path = Path(self.workspace) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(document, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        return path

    def write_openapi(self, name, paths, *, servers=None, security=None):
        document = {
            "openapi": "3.0.3",
            "info": {"title": "Synthetic source inventory fixture", "version": "1"},
            "servers": servers or [{"url": BASE_URL}],
            "paths": paths,
        }
        if security is not None:
            document["security"] = security
        return self.write_json(name, document)

    def preview(self, path, *, format="openapi", base_url=BASE_URL, **args):
        return self.invoke(
            "surface.import",
            path=str(path),
            format=format,
            base_url=base_url,
            mode="preview",
            **args,
        )

    def apply_snapshot(self, snapshot_id, **args):
        return self.invoke(
            "surface.import",
            snapshot_id=snapshot_id,
            mode="apply",
            **args,
        )

    def source_page(self, **args):
        args.setdefault("limit", 100)
        return self.invoke("surface.sources", **args)

    def entity_rows(self, kind):
        with Project(self.workspace, "source-project") as project:
            rows = project.connection.execute(
                "SELECT id,document FROM entities WHERE kind=? ORDER BY id",
                (kind,),
            ).fetchall()
        return [(row["id"], json.loads(row["document"])) for row in rows]

    def entity_counts(self):
        with Project(self.workspace, "source-project") as project:
            rows = project.connection.execute(
                "SELECT kind,COUNT(*) AS total FROM entities GROUP BY kind"
            ).fetchall()
            events = project.connection.execute(
                "SELECT COUNT(*) AS total FROM events"
            ).fetchone()["total"]
        return {row["kind"]: row["total"] for row in rows}, events

    def update_entity_json(self, kind, identity, change):
        with Project(self.workspace, "source-project") as project:
            record = project.get(kind, identity)
            changed = change(deepcopy(record))
            project.connection.execute(
                "UPDATE entities SET document=? WHERE kind=? AND id=?",
                (canonical(changed), kind, identity),
            )
            project.connection.commit()

    def item_for_snapshot(self, snapshot_id):
        item = next(
            (
                row
                for _, row in self.entity_rows("discovery_item")
                if row["snapshot_id"] == snapshot_id
            ),
            None,
        )
        self.assertIsNotNone(item)
        return item

    def test_preview_stores_only_sources_and_hands_off_exact_snapshot(self):
        path = self.write_openapi(
            "preview.json",
            {
                "/users": {
                    "get": {
                        "operationId": "listUsers",
                        "parameters": [{"name": "query", "in": "query"}],
                    }
                }
            },
        )

        result = self.preview(path)

        self.assertEqual("preview", result["mode"])
        self.assertEqual(0, result["requests_sent"])
        self.assertEqual([], result["operation_ids"])
        self.assertEqual([], result["candidate_ids"])
        self.assertEqual(0, result["counts"]["created"])
        self.assertEqual(1, result["source_inventory"]["snapshot_total"])
        self.assertGreaterEqual(result["source_inventory"]["pending_import_total"], 1)

        counts, _ = self.entity_counts()
        self.assertEqual(
            {"discovery_item", "discovery_snapshot", "discovery_source"},
            set(counts),
        )
        for kind in FORBIDDEN_PREVIEW_KINDS:
            self.assertNotIn(kind, counts)

        audit = self.invoke("plan.audit")
        self.assertEqual("partial", audit["completion"]["status"])
        self.assertFalse(audit["continuation"]["can_claim_complete"])
        self.assertEqual("surface.sources", audit["continuation"]["next_action"])

        source = self.source_page(
            source_id=result["source_id"],
            snapshot_id=result["snapshot_id"],
        )
        self.assertEqual(result["source_id"], source["source_id"])
        self.assertEqual(result["snapshot_id"], source["snapshot_id"])
        self.assertTrue(source["items"])
        self.assertTrue(all(item["status"] == "pending_import" for item in source["items"]))
        self.request.assert_not_called()

    def test_saved_snapshot_apply_never_rereads_changed_or_missing_file(self):
        path = self.write_openapi(
            "snapshot.json",
            {"/before": {"get": {"operationId": "before"}}},
        )
        preview = self.preview(path)
        original = self.source_page(snapshot_id=preview["snapshot_id"])

        self.write_openapi(
            "snapshot.json",
            {"/after": {"get": {"operationId": "after"}}},
        )
        path.unlink()

        applied = self.apply_snapshot(preview["snapshot_id"])

        self.assertEqual(preview["source_id"], applied["source_id"])
        self.assertEqual(preview["snapshot_id"], applied["snapshot_id"])
        self.assertTrue(applied["snapshot_reused"])
        self.assertEqual(0, applied["requests_sent"])
        self.assertEqual(1, len(applied["operation_ids"]))
        self.assertFalse(path.exists())

        operation = self.invoke(
            "surface.inspect",
            operation_id=applied["operation_ids"][0],
        )["operation"]
        self.assertEqual(BASE_URL + "/before", operation["url"])
        reused = self.source_page(snapshot_id=preview["snapshot_id"])
        self.assertEqual(original["snapshot"]["sha256"], reused["snapshot"]["sha256"])
        self.request.assert_not_called()

    def test_snapshot_apply_rejects_mixed_bindings_and_malformed_fixture(self):
        path = self.write_openapi(
            "binding.json",
            {"/binding": {"get": {"operationId": "binding"}}},
        )
        preview = self.preview(path)
        snapshot_id = preview["snapshot_id"]

        for args in (
            {"path": str(path)},
            {"format": "openapi"},
            {"base_url": BASE_URL},
            {"mode": "preview"},
        ):
            self.rejects(
                "surface.import",
                "source_snapshot_binding",
                snapshot_id=snapshot_id,
                **args,
            )
        self.rejects(
            "surface.import",
            "source_import_mode",
            path=str(path),
            format="openapi",
            base_url=BASE_URL,
            mode="something-else",
        )

        malformed = Path(self.workspace) / "malformed.invalid"
        malformed.write_text('{"openapi":"3.0.3","paths":', encoding="utf-8")
        self.rejects(
            "surface.import",
            "invalid_input",
            path=str(malformed),
            format="openapi",
            base_url=BASE_URL,
            mode="preview",
        )
        self.assertEqual(1, self.source_page()["source_inventory"]["snapshot_total"])
        self.request.assert_not_called()

    def test_sources_pagination_and_status_filters_remain_exact(self):
        alpha = self.write_openapi(
            "alpha.json",
            {"/alpha": {"get": {"operationId": "alpha"}}},
        )
        beta = self.write_openapi(
            "beta.json",
            {
                "/beta/one": {"get": {"operationId": "betaOne"}},
                "/beta/two": {"get": {"operationId": "betaTwo"}},
            },
        )
        alpha_preview = self.preview(alpha)
        beta_preview = self.preview(beta)
        self.apply_snapshot(alpha_preview["snapshot_id"])

        first = self.invoke("surface.sources", offset=0, limit=1)
        self.assertEqual(2, first["total"])
        self.assertEqual(1, len(first["sources"]))
        self.assertEqual(1, first["next_offset"])

        registered = self.invoke("surface.sources", status="registered")
        self.assertEqual(1, registered["total"])
        self.assertEqual(alpha_preview["source_id"], registered["sources"][0]["source_id"])

        pending = self.invoke("surface.sources", status="pending_import")
        self.assertEqual(1, pending["total"])
        self.assertEqual(beta_preview["source_id"], pending["sources"][0]["source_id"])

        detail = self.source_page(
            source_id=beta_preview["source_id"],
            snapshot_id=beta_preview["snapshot_id"],
            status="pending_import",
            offset=1,
            limit=1,
        )
        self.assertEqual(2, detail["total"])
        self.assertEqual(1, len(detail["items"]))
        self.assertIsNone(detail["next_offset"])
        self.assertEqual("pending_import", detail["items"][0]["status"])
        self.request.assert_not_called()

    def test_projection_incremental_changes_rebuild_only_linked_items(self):
        path = self.write_openapi(
            "incremental-projection.json",
            {
                "/plain": {"get": {"operationId": "plain"}},
                "/trace": {"trace": {"operationId": "traceCandidate"}},
            },
        )
        preview = self.preview(path)
        applied = self.apply_snapshot(preview["snapshot_id"])
        self.assertEqual(1, len(applied["operation_ids"]))

        with Project(self.workspace, "source-project") as project:
            initial = source_projection.ensure(project, rebuild=True)
            rows = project.connection.execute(
                "SELECT id,operation_key,candidate_key "
                "FROM source_projection_items ORDER BY id"
            ).fetchall()
            self.assertEqual(2, len(rows))
            operation_row = next(row for row in rows if row["operation_key"])
            candidate_row = next(row for row in rows if row["candidate_key"])

            receipt = project.get(
                "discovery_ingest", operation_row["id"])
            receipt["fixture_revision"] = 1
            project.put("discovery_ingest", receipt)
            receipt_work = source_projection.ensure(project)
            self.assertEqual("incremental", receipt_work["work"]["mode"])
            self.assertEqual(1, receipt_work["work"]["items_rebuilt"])

            operation = project.get(
                "operation", operation_row["operation_key"])
            operation["fixture_revision"] = 1
            project.put("operation", operation)
            operation_work = source_projection.ensure(project)
            self.assertEqual("incremental", operation_work["work"]["mode"])
            self.assertEqual(1, operation_work["work"]["items_rebuilt"])

            candidate = project.get(
                "candidate", candidate_row["candidate_key"])
            candidate["fixture_revision"] = 1
            project.put("candidate", candidate)
            candidate_work = source_projection.ensure(project)
            self.assertEqual("incremental", candidate_work["work"]["mode"])
            self.assertEqual(1, candidate_work["work"]["items_rebuilt"])
            self.assertGreater(
                initial["summary"]["source_item_total"], 0)

        self.request.assert_not_called()

    def test_projection_container_and_item_changes_force_full_rebuild(self):
        path = self.write_openapi(
            "projection-rebuild.json",
            {"/plain": {"get": {"operationId": "plain"}}},
        )
        preview = self.preview(path)

        with Project(self.workspace, "source-project") as project:
            initial = source_projection.ensure(project, rebuild=True)
            item_total = initial["summary"]["source_item_total"]
            self.assertEqual(1, item_total)

            source = project.get(
                "discovery_source", preview["source_id"])
            source["fixture_revision"] = 1
            project.put("discovery_source", source)
            source_work = source_projection.ensure(project)
            self.assertEqual("rebuild", source_work["work"]["mode"])
            self.assertEqual(item_total, source_work["work"]["items_rebuilt"])

            snapshot = project.get(
                "discovery_snapshot", preview["snapshot_id"])
            snapshot["created_at"] = "fixture-revision"
            project.connection.execute(
                "UPDATE entities SET document=? "
                "WHERE kind='discovery_snapshot' AND id=?",
                (canonical(snapshot), preview["snapshot_id"]),
            )
            project.connection.commit()
            snapshot_work = source_projection.ensure(project)
            self.assertEqual("rebuild", snapshot_work["work"]["mode"])
            self.assertEqual(item_total, snapshot_work["work"]["items_rebuilt"])

            item_document = project.connection.execute(
                "SELECT document FROM entities WHERE kind='discovery_item' "
                "AND json_extract(document,'$.snapshot_id')=? ORDER BY id LIMIT 1",
                (preview["snapshot_id"],),
            ).fetchone()[0]
            item = json.loads(item_document)
            item["created_at"] = "fixture-revision"
            project.connection.execute(
                "UPDATE entities SET document=? "
                "WHERE kind='discovery_item' AND id=?",
                (canonical(item), item["id"]),
            )
            project.connection.commit()
            item_work = source_projection.ensure(project)
            self.assertEqual("rebuild", item_work["work"]["mode"])
            self.assertEqual(item_total, item_work["work"]["items_rebuilt"])

        self.request.assert_not_called()

    def test_sources_cursor_stales_after_new_facts_and_restart_is_exact(self):
        alpha = self.write_openapi(
            "cursor-alpha.json",
            {"/alpha": {"get": {"operationId": "alpha"}}},
        )
        beta = self.write_openapi(
            "cursor-beta.json",
            {"/beta": {"get": {"operationId": "beta"}}},
        )
        alpha_preview = self.preview(alpha)
        beta_preview = self.preview(beta)

        first = self.invoke("surface.sources", offset=0, limit=1)
        self.assertIsInstance(first["cursor"], str)
        self.assertEqual(1, first["next_offset"])

        gamma = self.write_openapi(
            "cursor-gamma.json",
            {"/gamma": {"get": {"operationId": "gamma"}}},
        )
        gamma_preview = self.preview(gamma)
        with self.assertRaises(EngineError) as stale:
            self.invoke(
                "surface.sources",
                cursor=first["cursor"],
                offset=first["next_offset"],
                limit=1,
            )
        self.assertEqual("cursor_stale", stale.exception.code)

        collected, offset, cursor = [], 0, None
        while True:
            args = {"offset": offset, "limit": 1}
            if cursor is not None:
                args["cursor"] = cursor
            page = self.invoke("surface.sources", **args)
            collected.extend(page["sources"])
            for source in page["sources"]:
                self.assertRegex(source["source_id"], r"^DS-[a-f0-9]{24,32}$")
                self.assertRegex(source["snapshot_id"], r"^DSS-[a-f0-9]{24,32}$")
                self.assertIsInstance(source["source_item_total"], int)
            offset, cursor = page["next_offset"], page["cursor"]
            if offset is None:
                self.assertIsNone(cursor)
                break
            self.assertIsInstance(cursor, str)

        expected = {
            alpha_preview["source_id"],
            beta_preview["source_id"],
            gamma_preview["source_id"],
        }
        observed = {row["source_id"] for row in collected}
        self.assertEqual(3, len(collected))
        self.assertEqual(expected, observed)
        self.request.assert_not_called()

    def test_route_denominator_deduplicates_content_type_variants(self):
        path = self.write_openapi(
            "variants.json",
            {
                "/shared": {
                    "get": {
                        "operationId": "shared",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"body": {"type": "string"}},
                                    }
                                },
                                "application/xml": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"body": {"type": "string"}},
                                    }
                                },
                            }
                        },
                    }
                }
            },
        )
        preview = self.preview(path)
        self.assertEqual(1, preview["source_inventory"]["known_route_total"])
        self.assertEqual(2, preview["source_inventory"]["pending_import_total"])

        applied = self.apply_snapshot(preview["snapshot_id"])
        self.assertEqual(2, len(applied["operation_ids"]))
        self.assertEqual(1, applied["source_inventory"]["known_route_total"])
        self.assertEqual(1, applied["source_inventory"]["registered_route_total"])
        self.assertEqual(0, applied["source_inventory"]["known_not_registered_total"])

        detail = self.source_page(snapshot_id=preview["snapshot_id"])
        self.assertEqual(2, detail["total"])
        self.assertTrue(all(item["status"] == "registered" for item in detail["items"]))
        self.request.assert_not_called()

    def test_unknown_source_claims_preserve_local_policy_inputs_and_schema(self):
        local = self.invoke(
            "surface.register",
            url=BASE_URL + "/preserved",
            method="GET",
            auth="restricted",
            allowed_roles=["admin"],
            ownership=True,
            inputs=[
                {
                    "name": "q",
                    "location": "query",
                    "selector": "q",
                    "consumer": "sql_database",
                    "test_families": ["sql_injection"],
                    "schema_type": "string",
                    "required": True,
                }
            ],
        )
        path = self.write_openapi(
            "preserved.json",
            {
                "/preserved": {
                    "get": {
                        "operationId": "preserved",
                        "parameters": [
                            {
                                "name": "q",
                                "in": "query",
                                "required": True,
                                "schema": {"type": "string"},
                            }
                        ],
                    }
                }
            },
        )
        preview = self.preview(path)
        applied = self.apply_snapshot(preview["snapshot_id"])

        self.assertIn(local["id"], applied["operation_ids"])
        inspected = self.invoke(
            "surface.inspect",
            operation_id=local["id"],
        )
        operation = inspected["operation"]
        self.assertEqual("restricted", operation["auth"])
        self.assertEqual(["admin"], operation["allowed_roles"])
        self.assertTrue(operation["ownership"])
        query = next(item for item in inspected["inputs"] if item["selector"] == "q")
        self.assertEqual("sql_database", query["consumer"])
        self.assertEqual(["sql_injection"], query["test_families"])
        self.assertEqual("string", query["schema_type"])
        self.assertTrue(query["required"])
        self.request.assert_not_called()

    def test_known_conflict_preserves_operation_and_records_exact_candidate(self):
        local = self.invoke(
            "surface.register",
            url=BASE_URL + "/conflict",
            method="GET",
            auth="public",
        )
        path = self.write_openapi(
            "conflict.json",
            {"/conflict": {"get": {"operationId": "conflict"}}},
            security=[{"bearerAuth": []}],
        )
        preview = self.preview(path)
        applied = self.apply_snapshot(preview["snapshot_id"])

        self.assertGreaterEqual(applied["counts"]["conflicts"], 1)
        self.assertGreaterEqual(applied["counts"]["candidate_created"], 1)
        self.assertTrue(applied["candidate_ids"])
        self.assertEqual([], applied["operation_ids"])

        operation = self.invoke(
            "surface.inspect",
            operation_id=local["id"],
        )["operation"]
        self.assertEqual("public", operation["auth"])

        page = self.source_page(snapshot_id=preview["snapshot_id"])
        conflict = next(item for item in page["items"] if item["status"] == "conflict")
        self.assertIn("auth", conflict["conflict_fields"])

        with Project(self.workspace, "source-project") as project:
            candidate = project.get("candidate", applied["candidate_ids"][0])
        self.assertEqual("operation_hint", candidate["kind"])
        self.assertIn("auth", candidate["conflict_fields"])
        self.request.assert_not_called()

    def test_file_change_creates_snapshot_and_old_pending_items_page_exactly(self):
        path = self.write_openapi(
            "changing.json",
            {
                "/old/one": {"get": {"operationId": "oldOne"}},
                "/old/two": {"get": {"operationId": "oldTwo"}},
                "/old/three": {"get": {"operationId": "oldThree"}},
            },
        )
        old = self.preview(path)
        self.write_openapi(
            "changing.json",
            {
                "/old/one": {"get": {"operationId": "oldOne"}},
                "/new/four": {"get": {"operationId": "newFour"}},
                "/new/five": {"get": {"operationId": "newFive"}},
            },
        )
        new = self.preview(path)

        self.assertEqual(old["source_id"], new["source_id"])
        self.assertNotEqual(old["snapshot_id"], new["snapshot_id"])
        self.assertEqual(2, new["source_inventory"]["snapshot_total"])
        self.assertEqual(6, new["source_inventory"]["source_item_total"])
        self.assertEqual(6, new["source_inventory"]["pending_import_total"])
        self.assertEqual(3, new["source_inventory"]["historical_pending_total"])

        old_page = self.source_page(
            source_id=old["source_id"],
            snapshot_id=old["snapshot_id"],
            offset=0,
            limit=3,
        )
        self.assertEqual(3, old_page["total"])
        self.assertTrue(all(item["pending_import"] for item in old_page["items"]))

        first = self.apply_snapshot(old["snapshot_id"], offset=0, limit=1)
        self.assertEqual(3, first["result_total"])
        self.assertEqual(1, len(first["results"]))
        self.assertEqual(1, first["next_offset"])
        self.assertEqual(1, len(first["operation_ids"]))
        self.assertEqual(1, len(self.entity_rows("operation")))

        second = self.apply_snapshot(old["snapshot_id"], offset=1, limit=2)
        self.assertEqual(3, second["result_total"])
        self.assertEqual(2, len(second["results"]))
        self.assertIsNone(second["next_offset"])
        self.assertEqual(2, len(second["operation_ids"]))
        self.assertEqual(3, len(self.entity_rows("operation")))
        self.request.assert_not_called()

    def test_apply_next_input_and_audit_checklist_follow_original_offsets(self):
        path = self.write_openapi(
            "paged-handoff.json",
            {
                "/paged/" + str(index): {
                    "get": {"operationId": "paged" + str(index)}
                }
                for index in range(5)
            },
        )
        preview = self.preview(path)

        first = self.apply_snapshot(preview["snapshot_id"], offset=0, limit=2)
        self.assertEqual("surface.import", first["next_action"])
        self.assertEqual(2, first["next_offset"])
        self.assertEqual(
            {
                "snapshot_id": preview["snapshot_id"],
                "mode": "apply",
                "offset": 2,
                "limit": 2,
            },
            first["next_input"],
        )
        self.assertEqual(2, len(first["operation_ids"]))
        self.assertEqual(3, first["source_inventory"]["pending_import_total"])

        def source_checklist():
            audit = self.invoke("plan.audit", limit=100)
            return next(
                row
                for row in audit["checklist"]
                if row["kind"] == "discovery_source"
                and row["snapshot_id"] == preview["snapshot_id"]
            )

        first_checklist = source_checklist()
        self.assertEqual("surface.import", first_checklist["action"])
        self.assertEqual(
            preview["snapshot_id"],
            first_checklist["input_template"]["snapshot_id"],
        )
        self.assertEqual("apply", first_checklist["input_template"]["mode"])
        self.assertEqual(2, first_checklist["input_template"]["offset"])

        # Applying a later original page must not make the checklist point past
        # the earliest still-pending item.
        last = self.apply_snapshot(preview["snapshot_id"], offset=4, limit=1)
        self.assertEqual(1, len(last["results"]))
        self.assertIsNone(last["next_offset"])
        self.assertEqual("surface.sources", last["next_action"])
        self.assertIsNone(last.get("next_input"))
        self.assertEqual(2, source_checklist()["input_template"]["offset"])

        remainder = self.invoke("surface.import", **first["next_input"])
        self.assertEqual(2, len(remainder["results"]))
        self.assertEqual(0, remainder["source_inventory"]["pending_import_total"])
        self.assertEqual("surface.sources", remainder["next_action"])
        self.assertEqual(5, len(self.entity_rows("operation")))
        self.request.assert_not_called()

    def test_repeated_apply_is_entity_event_and_cs_snapshot_idempotent(self):
        path = self.write_openapi(
            "idempotent.json",
            {
                "/idempotent/one": {"get": {"operationId": "idempotentOne"}},
                "/idempotent/two": {"get": {"operationId": "idempotentTwo"}},
            },
        )
        preview = self.preview(path)
        first = self.apply_snapshot(preview["snapshot_id"])
        first_counts = self.entity_counts()
        first_cs = self.invoke("plan.audit")["continuation"]["snapshot_id"]

        second = self.apply_snapshot(preview["snapshot_id"])
        second_counts = self.entity_counts()
        second_cs = self.invoke("plan.audit")["continuation"]["snapshot_id"]

        self.assertEqual(first["source_id"], second["source_id"])
        self.assertEqual(first["snapshot_id"], second["snapshot_id"])
        self.assertEqual(first_counts, second_counts)
        self.assertEqual(first_cs, second_cs)
        self.assertEqual(0, second["counts"]["created"])
        self.assertEqual(0, second["counts"]["candidate_created"])
        self.request.assert_not_called()

    def test_snapshot_and_item_put_are_immutable_and_missing_item_blocks_apply(self):
        path = self.write_openapi(
            "immutable.json",
            {
                "/immutable/one": {"get": {"operationId": "immutableOne"}},
                "/immutable/two": {"get": {"operationId": "immutableTwo"}},
            },
        )
        preview = self.preview(path)
        snapshots = self.entity_rows("discovery_snapshot")
        items = self.entity_rows("discovery_item")
        self.assertEqual(1, len(snapshots))
        self.assertGreaterEqual(len(items), 2)

        with Project(self.workspace, "source-project") as project:
            snapshot_before = project.get("discovery_snapshot", snapshots[0][0])
            changed_snapshot = deepcopy(snapshot_before)
            changed_snapshot["unexpected_revision"] = True
            with self.assertRaises(EngineError) as raised:
                project.put("discovery_snapshot", changed_snapshot)
            self.assertEqual("immutable_record", raised.exception.code)
            self.assertEqual(snapshot_before, project.get("discovery_snapshot", snapshots[0][0]))

            item_id, item_before = items[0]
            changed_item = deepcopy(item_before)
            changed_item["unexpected_revision"] = True
            with self.assertRaises(EngineError) as raised:
                project.put("discovery_item", changed_item)
            self.assertEqual("immutable_record", raised.exception.code)
            self.assertEqual(item_before, project.get("discovery_item", item_id))

            project.connection.execute(
                "DELETE FROM entities WHERE kind='discovery_item' AND id=?",
                (item_id,),
            )
            project.connection.commit()

        self.rejects(
            "surface.import",
            "source_snapshot_changed",
            snapshot_id=preview["snapshot_id"],
            mode="apply",
        )
        self.assertEqual([], self.entity_rows("operation"))

        audit = self.invoke("plan.audit")
        self.assertEqual("partial", audit["completion"]["status"])
        self.assertGreaterEqual(audit["completion"]["unimported_source_items"], 1)
        self.assertFalse(audit["continuation"]["can_claim_complete"])
        self.assertFalse(audit["continuation"]["can_finalize"])
        self.request.assert_not_called()

    def test_manifest_and_item_tampering_block_snapshot_and_path_apply(self):
        manifest_path = self.write_openapi(
            "manifest-tamper.json",
            {"/manifest": {"get": {"operationId": "manifest"}}},
        )
        item_path = self.write_openapi(
            "item-tamper.json",
            {"/item": {"get": {"operationId": "item"}}},
        )
        manifest = self.preview(manifest_path)
        item_source = self.preview(item_path)

        def corrupt_manifest(record):
            record["normalized_sha256"] = "0" * 64
            return record

        def corrupt_item_hint(record):
            record["hint"]["url"] = BASE_URL + "/tampered-hint"
            return record

        self.update_entity_json(
            "discovery_snapshot",
            manifest["snapshot_id"],
            corrupt_manifest,
        )
        tampered_item = self.item_for_snapshot(item_source["snapshot_id"])
        self.update_entity_json(
            "discovery_item",
            tampered_item["id"],
            corrupt_item_hint,
        )

        apply_errors = []
        for preview, path in (
            (manifest, manifest_path),
            (item_source, item_path),
        ):
            with self.subTest(snapshot_id=preview["snapshot_id"]):
                page = self.source_page(snapshot_id=preview["snapshot_id"])
                self.assertEqual("changed", page["snapshot_integrity"])
                self.assertGreaterEqual(page["missing_item_total"], 1)
                self.assertEqual([], page["items"])
                self.assertEqual(0, page["total"])
                with self.assertRaises(EngineError) as by_snapshot:
                    self.apply_snapshot(preview["snapshot_id"])
                with self.assertRaises(EngineError) as by_path:
                    self.invoke(
                        "surface.import",
                        path=str(path),
                        format="openapi",
                        base_url=BASE_URL,
                        mode="apply",
                    )
                apply_errors.extend((
                    by_snapshot.exception.code,
                    by_path.exception.code,
                ))

        self.assertEqual(["source_snapshot_changed"] * 4, apply_errors)

        self.assertEqual([], self.entity_rows("operation"))
        audit = self.invoke("plan.audit", limit=100)
        self.assertEqual("partial", audit["completion"]["status"])
        self.assertGreaterEqual(audit["completion"]["source_unresolved_total"], 2)
        self.assertFalse(audit["continuation"]["can_claim_complete"])
        self.assertEqual("surface.sources", audit["continuation"]["next_action"])
        source_rows = [
            row for row in audit["checklist"] if row["kind"] == "discovery_source"
        ]
        self.assertEqual(
            {manifest["source_id"], item_source["source_id"]},
            {row["discovery_source_id"] for row in source_rows},
        )
        self.request.assert_not_called()

    def test_invalid_and_out_of_scope_hints_are_offline_and_visible(self):
        hints = self.write_json(
            "hints.invalid",
            {
                "schema_version": 1,
                "source_kind": "validator_export",
                "entries": [
                    {
                        "url": "http://outside.invalid/rejected",
                        "method": "GET",
                        "type": "XSS",
                        "test_family": "xss",
                        "inputs": [{"name": "q", "location": "query"}],
                        "result": "hint",
                    },
                    {
                        "url": BASE_URL + "/invalid",
                        "method": "NOT A METHOD",
                        "type": "SQL注入",
                        "inputs": [{"name": "id", "location": "query"}],
                        "result": "hint",
                    },
                ],
            },
        )
        preview = self.preview(hints, format="assessment_hints")
        applied = self.apply_snapshot(preview["snapshot_id"])

        self.assertEqual(0, applied["requests_sent"])
        self.assertGreaterEqual(applied["counts"]["rejected"], 1)
        self.assertGreaterEqual(applied["source_inventory"]["rejected_total"], 1)
        self.assertEqual(1, len(applied["candidate_ids"]))
        self.assertEqual(4, len(applied["limitations"]))
        with Project(self.workspace, "source-project") as project:
            snapshot = project.get("discovery_snapshot", preview["snapshot_id"])
        codes = {row["code"] for row in snapshot["limitations"]}
        self.assertIn("invalid_assessment_hint", codes)
        self.assertIn("assessment_hints_are_not_independent_vulnerability_evidence", codes)

        page = self.source_page(
            snapshot_id=preview["snapshot_id"],
            status="rejected",
        )
        self.assertGreaterEqual(page["total"], 1)
        self.assertTrue(all(item["status"] == "rejected" for item in page["items"]))
        self.assertEqual([], self.entity_rows("operation"))
        self.request.assert_not_called()

    def test_missing_latest_and_damaged_source_are_readable_integrity_states(self):
        missing_path = self.write_openapi(
            "missing-latest.json",
            {"/missing-latest": {"get": {"operationId": "missingLatest"}}},
        )
        damaged_path = self.write_openapi(
            "damaged-source.json",
            {"/damaged-source": {"get": {"operationId": "damagedSource"}}},
        )
        missing = self.preview(missing_path)
        damaged = self.preview(damaged_path)

        with Project(self.workspace, "source-project") as project:
            project.connection.execute(
                "DELETE FROM entities WHERE kind='discovery_snapshot' AND id=?",
                (missing["snapshot_id"],),
            )
            project.connection.commit()

        def damage_source(record):
            record["path"] = str(Path(self.workspace) / "relocated-source.json")
            return record

        self.update_entity_json(
            "discovery_source",
            damaged["source_id"],
            damage_source,
        )

        listed = self.invoke("surface.sources", limit=100)
        self.assertEqual(2, listed["total"])
        rows = {row["source_id"]: row for row in listed["sources"]}
        self.assertEqual({"missing", "changed"}, {
            rows[missing["source_id"]]["snapshot_integrity"],
            rows[damaged["source_id"]]["snapshot_integrity"],
        })
        self.assertEqual(1, rows[missing["source_id"]]["missing_item_total"])
        self.assertEqual(1, rows[damaged["source_id"]]["missing_item_total"])
        self.assertIsNone(rows[missing["source_id"]].get("snapshot_id"))
        self.assertEqual(
            damaged["snapshot_id"],
            rows[damaged["source_id"]]["snapshot_id"],
        )

        missing_detail = self.source_page(source_id=missing["source_id"])
        self.assertEqual("missing", missing_detail["snapshot_integrity"])
        self.assertEqual(1, missing_detail["missing_item_total"])
        self.assertEqual([], missing_detail["items"])
        self.assertEqual(0, missing_detail["total"])
        self.assertIsNone(missing_detail.get("snapshot_id"))
        self.assertIsNone(missing_detail.get("snapshot"))

        damaged_detail = self.source_page(source_id=damaged["source_id"])
        self.assertEqual("changed", damaged_detail["snapshot_integrity"])
        self.assertEqual(1, damaged_detail["missing_item_total"])
        self.assertEqual([], damaged_detail["items"])
        self.assertEqual(0, damaged_detail["total"])
        self.assertEqual(damaged["snapshot_id"], damaged_detail["snapshot_id"])

        audit = self.invoke("plan.audit", limit=100)
        self.assertEqual("partial", audit["completion"]["status"])
        self.assertGreaterEqual(audit["completion"]["source_unresolved_total"], 2)
        self.assertFalse(audit["continuation"]["can_claim_complete"])
        self.assertEqual("surface.sources", audit["continuation"]["next_action"])
        checklist = {
            row["discovery_source_id"]: row
            for row in audit["checklist"]
            if row["kind"] == "discovery_source"
        }
        missing_row = checklist[missing["source_id"]]
        self.assertEqual(1, missing_row["missing_item_total"])
        self.assertEqual("surface.sources", missing_row["suggested_action"])
        self.assertEqual(
            {"source_id": missing["source_id"]},
            missing_row["input_template"],
        )
        damaged_row = checklist[damaged["source_id"]]
        self.assertEqual("surface.sources", damaged_row["suggested_action"])
        self.assertNotIn("mode", damaged_row["input_template"])
        self.assertEqual(
            damaged["source_id"],
            damaged_row["input_template"]["source_id"],
        )

        compact = self.invoke("plan.next", compact=True, limit=2)
        compact_missing = next(
            row
            for row in compact["review_followups"]
            if row["discovery_source_id"] == missing["source_id"]
        )
        self.assertEqual("surface.sources", compact_missing["suggested_action"])
        self.request.assert_not_called()

    def test_audit_checklist_and_compact_plan_keep_exact_snapshot_binding(self):
        path = self.write_openapi(
            "handoff.json",
            {
                "/handoff/one": {"get": {"operationId": "handoffOne"}},
                "/handoff/two": {"get": {"operationId": "handoffTwo"}},
            },
        )
        preview = self.preview(path)

        audit = self.invoke("plan.audit", limit=100)
        source_rows = [
            row for row in audit["checklist"] if row["kind"] == "discovery_source"
        ]
        self.assertEqual(1, len(source_rows))
        row = source_rows[0]
        self.assertEqual(preview["source_id"], row["discovery_source_id"])
        self.assertEqual(preview["snapshot_id"], row["snapshot_id"])
        self.assertEqual(
            {"snapshot_id": preview["snapshot_id"], "mode": "apply"},
            row["input_template"],
        )

        compact = self.invoke("plan.next", compact=True, limit=2)
        self.assertTrue(compact["compact"])
        self.assertEqual("surface.sources", compact["continuation"]["next_action"])
        self.assertEqual(
            audit["continuation"]["snapshot_id"],
            compact["continuation"]["snapshot_id"],
        )
        exact = self.source_page(
            source_id=preview["source_id"],
            snapshot_id=preview["snapshot_id"],
            offset=0,
            limit=1,
        )
        self.assertEqual(preview["snapshot_id"], exact["snapshot_id"])
        self.assertEqual(2, exact["total"])
        self.assertEqual(1, len(exact["items"]))
        self.assertEqual(1, exact["next_offset"])
        self.request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
