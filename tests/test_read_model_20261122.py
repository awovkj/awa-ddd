"""Query projections preserve strong semantics and bound warm hydration."""
from __future__ import annotations

from pathlib import Path
import unittest
from unittest.mock import patch

import test_continuation_20261030 as fixtures
from awa_ddd import completeness, engine, read_model, workflow
from awa_ddd.store import EngineError, canonical


class ReadModelTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ContinuationTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.project = self.fixture.project

    def test_projected_pages_agree_with_the_strong_evaluator(self):
        pairs = ((workflow._project_status_strong, workflow.project_status),
                 (workflow._next_work_strong, workflow.next_work),
                 (completeness._audit_strong, completeness.audit))
        for strong, projected in pairs:
            with self.subTest(query=projected.__name__):
                expected = strong(self.project, {"limit": 7})
                actual = projected(self.project, {"limit": 7})
                for key in expected:
                    self.assertEqual(expected[key], actual[key], key)

    def test_warm_pages_do_not_rebuild_hydrate_history_or_hash_artifacts(self):
        for index in range(35):
            engine.register_operation(self.project, {
                "url": "http://fixture.invalid/items/" + str(index),
                "method": "GET", "auth": "public"})
        engine.build_plan(self.project)
        self.fixture.capture()
        read_model.snapshot(self.project)
        self.project.metrics = {key: 0 for key in self.project.metrics}
        with patch.object(read_model, "_build", side_effect=AssertionError("warm rebuild")), \
                patch.object(self.project, "list", side_effect=AssertionError("history hydration")), \
                patch.object(self.project, "read_artifact", side_effect=AssertionError("artifact hash")), \
                patch.object(self.project, "read_material", side_effect=AssertionError("material hash")):
            status = workflow.project_status(self.project, {"limit": 7})
            work = workflow.next_work(self.project, {"limit": 7})
            audit = completeness.audit(self.project, {"limit": 7})
        self.assertTrue(all(row["projection_reused"] for row in (status, work, audit)))
        self.assertLessEqual(self.project.metrics["records_decoded"], 40)
        self.assertEqual(0, self.project.metrics["artifact_bytes_hashed"])
        self.assertEqual(0, self.project.metrics["material_bytes_hashed"])
        self.assertGreater(self.project.metrics["artifact_stats"], 0)
        self.assertEqual(7, len(work["work_items"]))
        self.assertEqual(7, len(audit["checklist"]))

    def test_database_and_config_changes_invalidate_the_projection(self):
        initial, _ = read_model.snapshot(self.project)
        operation = dict(self.fixture.operation, label="Changed fixture label")
        self.project.connection.execute("UPDATE entities SET document=? WHERE kind='operation' AND id=?",
                                        (canonical(operation), operation["id"]))
        changed, reused = read_model.snapshot(self.project)
        self.assertFalse(reused)
        self.assertGreater(changed["generation"], initial["generation"])
        generation = self.project.generation()
        self.project.set_config({**self.project.config, "exclude": [operation["url"]]})
        configured, reused = read_model.snapshot(self.project)
        self.assertFalse(reused)
        self.assertEqual(generation, self.project.generation())
        self.assertNotEqual(changed["config_sha256"], configured["config_sha256"])

    def test_session_expiry_invalidates_without_a_database_event(self):
        engine.add_actor(self.project, {"actor_id": "fixture-user", "subject": "fixture-user", "roles": []})
        session = engine.add_session(self.project, {"session_id": "fixture-session", "actor_id": "fixture-user",
                                                   "ttl_seconds": 120, "headers": {}})
        expiry = engine.stamp(session["expires_at"])
        initial, _ = read_model.snapshot(self.project)
        self.assertAlmostEqual(expiry.timestamp(), initial["valid_until"], places=3)
        generation = self.project.generation()
        with patch.object(read_model.time, "time", return_value=expiry.timestamp() + 1), \
                patch.object(read_model, "_build", wraps=read_model._build) as build:
            _, reused = read_model.snapshot(self.project)
        self.assertFalse(reused)
        self.assertEqual(1, build.call_count)
        self.assertEqual(generation, self.project.generation())

    def test_artifact_damage_and_restoration_refresh_an_incomplete_project(self):
        evidence = self.fixture.capture()
        self.fixture.baseline(evidence)
        original = completeness.audit(self.project, {})
        self.assertEqual(1, original["layers"]["assessed"]["valid_decisions"])
        generation = self.project.generation()
        path = self.project.base / evidence["artifact_path"]
        material = path.read_bytes()
        path.write_bytes(b"{}")
        damaged = completeness.audit(self.project, {})
        self.assertFalse(damaged["projection_reused"])
        self.assertEqual(0, damaged["layers"]["assessed"]["valid_decisions"])
        self.assertFalse(damaged["continuation"]["can_claim_complete"])
        path.write_bytes(material)
        restored = completeness.audit(self.project, {})
        self.assertFalse(restored["projection_reused"])
        self.assertEqual(1, restored["layers"]["assessed"]["valid_decisions"])
        self.assertEqual(generation, self.project.generation())

    def test_batched_metadata_stays_fresh_without_individual_file_stat_calls(self):
        observations = [self.fixture.capture() for _ in range(7)]
        initial, _ = read_model.snapshot(self.project)
        self.project.metrics = {key: 0 for key in self.project.metrics}
        with patch.object(Path, "stat", side_effect=AssertionError("individual artifact stat")), \
                patch.object(self.project, "list", side_effect=AssertionError("history hydration")), \
                patch.object(self.project, "read_artifact", side_effect=AssertionError("artifact hash")):
            current, reused = read_model.snapshot(self.project)
        self.assertTrue(reused)
        self.assertEqual(initial["material_fingerprint"], current["material_fingerprint"])
        self.assertEqual(7, self.project.metrics["artifact_stats"])
        self.assertEqual(1, self.project.metrics["artifact_directory_reads"])
        self.assertEqual(0, self.project.metrics["artifact_bytes_hashed"])

        path = self.project.base / observations[0]["artifact_path"]
        original = path.read_bytes()
        generation = self.project.generation()
        path.write_bytes(b"{}")
        damaged, reused = read_model.snapshot(self.project)
        self.assertFalse(reused)
        self.assertNotEqual(initial["material_fingerprint"], damaged["material_fingerprint"])
        path.write_bytes(original)
        _, reused = read_model.snapshot(self.project)
        self.assertFalse(reused)
        self.assertEqual(generation, self.project.generation())

    def test_locator_cache_invalidates_after_direct_sql_reference_change(self):
        observation = self.fixture.capture()
        read_model.snapshot(self.project)
        original = self.project.base / observation["artifact_path"]
        replacement = original.with_name("replacement-material.json")
        replacement.write_bytes(original.read_bytes())
        changed = dict(observation, artifact_path=replacement.relative_to(self.project.base).as_posix())
        self.project.connection.execute("UPDATE entities SET document=? WHERE kind='evidence' AND id=?",
                                        (canonical(changed), observation["id"]))
        updated, reused = read_model.snapshot(self.project)
        self.assertFalse(reused)
        replacement.write_bytes(b"{}")
        damaged, reused = read_model.snapshot(self.project)
        self.assertFalse(reused)
        self.assertNotEqual(updated["material_fingerprint"], damaged["material_fingerprint"])

    def test_exhausted_coverage_always_checks_actual_bytes(self):
        evidence = self.fixture.close_generic()
        read_model.snapshot(self.project)
        with patch.object(read_model, "_material_fingerprint", return_value=read_model._material_fingerprint(self.project)):
            (self.project.base / evidence["artifact_path"]).write_bytes(b"{}")
            result = completeness.audit(self.project, {})
        self.assertFalse(result["projection_reused"])
        self.assertNotEqual("complete", result["completion"]["status"])
        self.assertFalse(result["continuation"]["can_finalize"])

    def test_corrupt_projection_metadata_is_rebuilt_from_facts(self):
        read_model.snapshot(self.project)
        for document in ("not-json", "[]", '{"evaluated":{}}'):
            with self.subTest(document=document):
                self.project.connection.execute("UPDATE projection_store SET document=? WHERE name=?",
                                                (document, read_model.NAME))
                result = completeness.audit(self.project, {})
                self.assertFalse(result["projection_reused"])
                self.assertGreater(result["checklist_total"], 0)
                self.assertFalse(result["continuation"]["can_finalize"])

    def test_compare_detects_queue_damage_and_rebuild_repairs_it(self):
        read_model.snapshot(self.project)
        generation = self.project.generation()
        self.project.connection.execute("UPDATE ready_queue_items SET document=? WHERE queue=?",
                                        ('{"id":"damaged-row"}', read_model.NAME + "/work"))
        compared = read_model.maintain(self.project, {"mode": "compare"})
        self.assertFalse(compared["comparison"]["equal"])
        self.assertIn("work", compared["comparison"]["differences"])
        rebuilt = read_model.maintain(self.project, {"mode": "rebuild"})
        self.assertTrue(rebuilt["rebuilt"])
        self.assertTrue(read_model.maintain(self.project, {"mode": "compare"})["comparison"]["equal"])
        self.assertEqual(generation, self.project.generation())

    def test_descending_cursor_has_no_duplicates_and_binds_its_order(self):
        for index in range(9):
            self.project.put("run", {"id": "RUN-page-" + str(index), "status": "pending",
                                     "created_at": "2026-11-22T00:00:00+00:00"})
        first = self.project.list_page("run", limit=4, order_desc=True)
        second = self.project.list_page("run", limit=4, order_desc=True, cursor=first["cursor"])
        third = self.project.list_page("run", limit=4, order_desc=True, cursor=second["cursor"])
        identities = [row["id"] for page in (first, second, third) for row in page["items"]]
        self.assertEqual(sorted(identities, reverse=True), identities)
        self.assertEqual(9, len(set(identities)))
        with self.assertRaises(EngineError) as mismatch:
            self.project.list_page("run", limit=4, cursor=first["cursor"])
        self.assertEqual("cursor_stale", mismatch.exception.code)
        self.project.put("run", {"id": "RUN-new", "status": "pending"})
        with self.assertRaises(EngineError) as stale:
            self.project.list_page("run", limit=4, order_desc=True, cursor=first["cursor"])
        self.assertEqual("cursor_stale", stale.exception.code)

    def test_malformed_window_cursor_and_mode_have_contract_errors(self):
        for args in ({"limit": True}, {"offset": -1}, {"method_limit": []},
                     {"method_operation_offset": -1}, {"method_operation_offset": True},
                     {"method_operation_limit": 0}, {"method_operation_limit": 101},
                     {"method_operation_limit": []}):
            with self.subTest(args=args), self.assertRaises(EngineError) as caught:
                workflow.project_status(self.project, args)
            self.assertEqual("pagination", caught.exception.code)
        for cursor in ([], 1, "", "not-a-cursor"):
            with self.subTest(cursor=cursor), self.assertRaises(EngineError) as caught:
                self.project.list_page("run", cursor=cursor)
            self.assertEqual("cursor_invalid", caught.exception.code)
        for mode in ([], {}, True, None):
            with self.subTest(mode=mode), self.assertRaises(EngineError) as caught:
                read_model.maintain(self.project, {"mode": mode})
            self.assertEqual("projection_mode", caught.exception.code)

    def test_nested_method_memberships_page_without_decoding_the_complete_array(self):
        operations = [engine.register_operation(self.project, {
            "url": "http://fixture.invalid/bulk/item" + str(index).zfill(4),
            "method": "GET", "auth": "public"}) for index in range(23)]
        engine.build_plan(self.project)
        internal = engine._method_coverage(self.project)
        complete = next(row for row in internal if row["operations"] == sorted(item["id"] for item in operations))
        self.assertEqual(23, len(complete["operations"]))
        read_model.snapshot(self.project)
        offset, seen = 0, []
        while offset is not None:
            self.project.metrics = {key: 0 for key in self.project.metrics}
            with patch.object(read_model, "_build", side_effect=AssertionError("warm rebuild")), \
                    patch.object(read_model.json, "loads", wraps=read_model.json.loads) as decoded:
                result = workflow.project_status(self.project, {"method_operation_offset": offset,
                                                                "method_operation_limit": 4})
            page = next(row for row in result["method_coverage"] if row["operations_total"] == 23)
            self.assertEqual(complete["operations"][offset:offset + 4], page["operations"])
            self.assertEqual(offset, page["operation_offset"])
            self.assertEqual(4, page["operation_limit"])
            self.assertTrue(result["projection_reused"])
            self.assertLessEqual(self.project.metrics["method_operation_ids_returned"], 8)
            self.assertFalse(any('"operations":[' in call.args[0] for call in decoded.call_args_list))
            seen.extend(page["operations"])
            offset = page["operation_next_offset"]
        self.assertEqual(complete["operations"], seen)
        self.assertEqual(23, len(set(seen)))
        self.assertIn(complete, engine._method_coverage(self.project))

    def test_strong_and_projected_method_pages_agree_at_the_end_and_beyond(self):
        for index in range(7):
            engine.register_operation(self.project, {"url": "http://fixture.invalid/window/" + str(index),
                                                      "method": "GET", "auth": "public"})
        engine.build_plan(self.project)
        for offset in (0, 3, 7, 100):
            args = {"method_operation_offset": offset, "method_operation_limit": 3}
            expected = workflow._project_status_strong(self.project, args)
            actual = workflow.project_status(self.project, args)
            for key in ("method_coverage", "method_total", "method_offset", "method_next_offset",
                        "method_operation_offset", "method_operation_limit"):
                self.assertEqual(expected[key], actual[key], (key, offset))


if __name__ == "__main__":
    unittest.main()
