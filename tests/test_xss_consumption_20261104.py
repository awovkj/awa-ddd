"""Stored XSS closes its writing input only through original content and viewer controls."""
from __future__ import annotations

import base64
import hashlib
import json
import unittest
from unittest.mock import patch
from pathlib import Path

from awa_ddd import browser, completeness, engine
from awa_ddd.assessment import record_finding
from awa_ddd.__main__ import dispatch
from awa_ddd.reporting import build_report
from awa_ddd.store import EngineError, now
import test_analyst_binding_20261030 as fixtures


class StoredConsumptionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.AnalystBindingTests("test_reviewed_runtime_closes_only_its_typed_input_and_remains_analyst")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.project = self.fixture.project
        self.marker, self.payload = self.fixture.marker, self.fixture.payload

    def capture(self, operation, session, response, **extra):
        with patch.object(engine, "request", side_effect=lambda *args: fixtures.observation(*args, response=response)):
            return engine.capture(self.project, {"operation_id": operation["id"], "session_id": session["id"], **extra})

    def visit(self, read, viewer, session, *, normal, **extra):
        raw = self.project.read_artifact(read)
        body = base64.b64decode(raw["response"]["body_base64"], validate=True)
        url = self.fixture.base + "/user/home"
        network = [{"url": url, "method": "GET", "type": "document", "status": 200, "request_headers": session["headers"]},
                   {"url": raw["request"]["url"], "method": "GET", "type": "fetch", "status": 200,
                    "request_headers": session["headers"], "request_body_sha256": hashlib.sha256(b"").hexdigest(),
                    "response_body_sha256": hashlib.sha256(body).hexdigest(), "response_body_bytes": len(body),
                    "response_body_complete": True}]
        return self.fixture.visit(url, session=session, actor=viewer, network=network,
            dialogs=[] if normal else [{"type": "alert", "message": self.marker, "action_index": None, "document_url": url}],
            started_at=now(), completed_at=now(), **extra)

    def prepared(self, *, fill=None, normal_content="normal", read_content=None, read_resource="fixture-1", source_hint=None, reader_hint=None):
        writer, writer_session = self.fixture.actor("writer")
        viewer, viewer_session = self.fixture.actor("viewer")
        engine.update_project(self.project, {"allow_mutation": True})
        operation = engine.register_operation(self.project, {"url": self.fixture.base + "/api/product", "method": "POST",
            "auth": "authenticated", "content_type": "application/json", "inputs": [
                {"name": "name", "location": "body", "selector": "/name", "consumer": "html_render", "test_families": ["xss"]},
                {"name": "id", "location": "body", "selector": "/id"}]})
        resource = engine.add_resource(self.project, {"operation_id": operation["id"], "owner_actor_id": writer["id"],
            "external_id": "fixture-1", "request_binding": {"location": "body", "selector": "/id"}})
        reader = engine.register_operation(self.project, {"url": self.fixture.base + "/api/product/fixture-1",
            "method": "GET", "auth": "authenticated"})
        engine.build_plan(self.project)
        item = next(row for row in self.project.list("obligation") if row.get("kind") == "input_test"
                    and row["operation_id"] == operation["id"] and row.get("test_family") == "xss" and not row.get("superseded"))
        writers, reads, visits = [], [], []
        for index, content in enumerate((normal_content, self.payload)):
            writers.append(self.capture(operation, writer_session, {"ok": True}, resource_id=resource["id"],
                effect="test_resource_write", body={"id": "fixture-1", "name": content},
                **({"headers": {"X-Context": source_hint}} if source_hint is not None else {})))
            reads.append(self.capture(reader, viewer_session, {"data": {"id": read_resource,
                "name": read_content if index and read_content is not None else content}},
                **({"headers": {"X-Context": reader_hint}} if reader_hint is not None else {})))
            actions = [] if fill is None else [{"action": "fill", "selector": "#search", "ok": True, "value": fill,
                "value_sha256": hashlib.sha256(fill.encode("utf-8")).hexdigest()}]
            visits.append(self.visit(reads[-1], viewer, viewer_session, normal=not index, actions=actions))
        args = {"mode": "analyst", "title": "Controlled stored content executes for a different viewer", "category": "Stored XSS",
            "impact": "The precise writer-controlled fixture executes in the native viewer context", "remediation": "Encode the content sink",
            "reviewer": "fixture reviewer", "reason": "Reviewed writing input, fixture versions, API content and independent normal/attack visits",
            "obligation_id": item["id"], "evidence_ids": [row["id"] for row in [*writers, *reads]],
            "runtime_visit_id": visits[1]["id"], "consumer_url": visits[1]["url"], "runtime_marker": self.marker,
            "xss_consumption": {"type": "stored_api", "normal_read_evidence_id": reads[0]["id"],
                "attack_read_evidence_id": reads[1]["id"], "normal_runtime_visit_id": visits[0]["id"],
                "content_selector": "/data/name", "resource_selector": "/data/id",
                "write_success_selector": "/ok", "write_success_expected": True}}
        return operation, item, writers, reads, visits, writer_session, viewer_session, args

    def reject(self, args, code=None):
        self.fixture.reject_without_changes(args, code)

    def replacement(self, visit, **changes):
        raw = self.project.read_artifact(visit)
        raw.update(changes)
        viewer = self.project.get("actor", visit["actor_id"])
        session = self.project.get("session", visit["session_id"])
        return browser._record_observation(self.project, raw, self.project.id("PV"), "local_playwright", session=session, actor=viewer)

    def test_cross_principal_content_chain_closes_only_the_actual_source(self):
        operation, item, writers, reads, visits, _, viewer_session, args = self.prepared()
        with patch.object(engine, "request") as network:
            finding = record_finding(self.project, args)
            audit = completeness.audit(self.project, {})
        network.assert_not_called()
        self.assertEqual(self.project.get("obligation", item["id"])["status"], "evaluated")
        decision = self.project.get("decision", finding["decision_id"])
        self.assertEqual(decision["mode"], "analyst")
        self.assertEqual(decision["proof"]["binding_version"], 2)
        self.assertEqual(decision["proof"]["mechanism"], "stored_api_consumer")
        self.assertEqual(decision["proof"]["operation_id"], operation["id"])
        self.assertEqual(decision["proof"]["identity"]["actor_id"], "writer")
        self.assertEqual(decision["proof"]["viewer_identity"]["actor_id"], "viewer")
        self.assertEqual(decision["proof"]["viewer_identity"]["session_id"], viewer_session["id"])
        self.assertEqual(audit["security_coverage"]["evaluated"], 1)
        self.assertNotIn(self.payload, json.dumps(decision["proof"]))
        self.assertNotIn("Bearer", json.dumps(decision["proof"]))

    def test_equal_ordinary_consumer_fill_stays_unbound_as_an_independent_possible_source(self):
        *_, args = self.prepared(fill="ordinary lookup")
        self.reject(args, "xss_runtime_binding")

    def test_public_help_preparation_and_report_keep_the_source_and_viewer_references(self):
        operation, item, writers, reads, visits, _, _, args = self.prepared()
        with patch.object(engine, "request") as network:
            help_value = dispatch(self.project.workspace, "action.help", {"name": "finding.record"})
            prepared = dispatch(self.project.workspace, "assessment.prepare", {"project_id": self.project.project_id,
                "obligation_id": item["id"], "limit": 1})
            finding = dispatch(self.project.workspace, "finding.record", {"project_id": self.project.project_id, **args})
            report = build_report(self.project)
        network.assert_not_called()
        self.assertIn("stored_api", help_value["fields"]["xss_consumption"])
        self.assertEqual(prepared["items"][0]["runtime_binding_modes"], ["direct_document", "stored_api"])
        self.assertEqual(finding["evidence_ids"], args["evidence_ids"])
        summary = json.loads(Path(report["summary"]).read_text(encoding="utf-8"))
        current = next(row for row in summary["coverage"]["findings"] if row["id"] == finding["id"])
        proof = current["proof"]
        self.assertEqual(proof["mechanism"], "stored_api_consumer")
        self.assertEqual(proof["operation_id"], operation["id"])
        self.assertEqual(proof["normal_runtime_visit_id"], visits[0]["id"])
        self.assertEqual(proof["readback_evidence_ids"], [row["id"] for row in reads])
        self.assertEqual(proof["viewer_identity"]["actor_id"], "viewer")
        self.assertNotIn("Bearer fixture-", json.dumps(summary))

    def test_fill_cannot_introduce_the_runtime_marker(self):
        *_, args = self.prepared(fill="lookup " + self.marker)
        self.reject(args, "xss_runtime_binding")

    def test_encoded_consumer_script_or_plain_writer_flag_cannot_close_the_writer(self):
        encoded = base64.b64encode(self.payload.encode("utf-8")).decode("ascii")
        *_, args = self.prepared(fill=encoded)
        self.reject(args, "xss_runtime_binding")
        self.payload = "enabled " + self.marker
        *_, args = self.prepared(fill=encoded)
        self.reject(args, "xss_input_binding")

    def test_encoded_markers_in_fixed_writer_or_reader_context_are_not_source_proof(self):
        variants = [base64.b64encode(self.payload.encode("utf-8")).decode("ascii"),
                    "".join("%" + format(ord(character), "02X") for character in self.marker),
                    "".join("&#" + str(ord(character)) + ";" for character in self.marker),
                    "".join("\\u" + format(ord(character), "04x") for character in self.marker)]
        for value in variants:
            with self.subTest(context="writer", encoding=value[:8]):
                *_, args = self.prepared(source_hint=value)
                self.reject(args, "xss_input_binding")
        *_, args = self.prepared(reader_hint=variants[0])
        self.reject(args, "xss_input_binding")

    def test_wrong_readback_content_or_fixture_does_not_attribute_the_dialog(self):
        for changes in ({"read_content": "different " + self.marker}, {"read_resource": "other-fixture"}):
            with self.subTest(changes=changes):
                *_, args = self.prepared(**changes)
                self.reject(args, "xss_input_binding")

    def test_a_search_locator_cannot_be_substituted_for_the_writing_source(self):
        *_, args = self.prepared()
        search = self.fixture.operation("/search")
        engine.build_plan(self.project)
        item = next(row for row in self.project.list("obligation") if row.get("kind") == "input_test" and row["operation_id"] == search["id"])
        self.reject({**args, "obligation_id": item["id"]}, "xss_input_binding")

    def test_the_consumer_must_read_the_exact_captured_content_version(self):
        *_, visits, writer_session, viewer_session, args = self.prepared()
        for field, value in (("response_body_sha256", "0" * 64), ("response_body_complete", False),
                             ("response_body_bytes", 1), ("request_body_sha256", "1" * 64)):
            raw = self.project.read_artifact(visits[1])
            raw["network"][1][field] = value
            other = self.replacement(visits[1], network=raw["network"])
            with self.subTest(field=field):
                self.reject({**args, "runtime_visit_id": other["id"]}, "xss_runtime_binding")

    def test_a_normal_dialog_or_an_unrelated_attack_document_is_rejected(self):
        *_, visits, writer_session, viewer_session, args = self.prepared()
        wrong = self.replacement(visits[0], dialogs=[{"message": self.marker, "document_url": visits[0]["url"]}])
        self.reject({**args, "xss_consumption": {**args["xss_consumption"], "normal_runtime_visit_id": wrong["id"]}}, "xss_runtime_binding")
        wrong = self.replacement(visits[1], dialogs=[{"message": self.marker, "document_url": self.fixture.base + "/other"}])
        self.reject({**args, "runtime_visit_id": wrong["id"]}, "xss_runtime_binding")

    def test_api_and_document_credentials_must_match_the_verified_reader(self):
        *_, visits, writer_session, viewer_session, args = self.prepared()
        for index in (0, 1):
            raw = self.project.read_artifact(visits[1])
            raw["network"][index]["request_headers"] = writer_session["headers"]
            other = self.replacement(visits[1], network=raw["network"])
            self.reject({**args, "runtime_visit_id": other["id"]}, "xss_runtime_identity")

    def test_missing_digested_api_request_is_not_inferred_from_page_success(self):
        *_, visits, writer_session, viewer_session, args = self.prepared()
        raw = self.project.read_artifact(visits[1])
        other = self.replacement(visits[1], network=raw["network"][:1])
        self.reject({**args, "runtime_visit_id": other["id"]}, "xss_runtime_binding")

    def test_independent_readback_roles_and_success_assertions_are_required(self):
        *_, args = self.prepared()
        self.reject({**args, "evidence_ids": args["evidence_ids"][:2]}, "xss_input_binding")
        self.reject({**args, "evidence_ids": [args["evidence_ids"][1], args["evidence_ids"][0], *args["evidence_ids"][2:]]}, "xss_input_binding")
        self.reject({**args, "xss_consumption": {**args["xss_consumption"], "write_success_expected": False}}, "xss_input_binding")

    def test_unknown_or_malformed_consumption_fields_are_atomic_rejections(self):
        *_, args = self.prepared()
        for changes in ({"type": "direct_document"}, {"content_selector": "name"}, {"resource_selector": None}, {"extra": True}):
            with self.subTest(changes=changes):
                self.reject({**args, "xss_consumption": {**args["xss_consumption"], **changes}}, "xss_runtime_binding")
        self.reject({key: value for key, value in args.items() if key != "obligation_id"}, "analyst_obligation")

    def test_uncaptured_fill_or_changed_interaction_cannot_supply_a_source_proof(self):
        *_, visits, writer_session, viewer_session, args = self.prepared()
        for action in ({"action": "fill", "selector": "#search", "ok": True},
                       {"action": "click", "selector": "#different", "ok": True}):
            other = self.replacement(visits[1], actions=[action])
            self.reject({**args, "runtime_visit_id": other["id"]}, "xss_runtime_binding")

    def test_clipboard_or_typing_keys_cannot_introduce_an_uncaptured_consumer_source(self):
        *_, visits, writer_session, viewer_session, args = self.prepared()
        for key in ("Control+V", "Meta+V", "A"):
            other = self.replacement(visits[1], actions=[{"action": "press", "selector": "#search", "key": key, "ok": True}])
            self.reject({**args, "runtime_visit_id": other["id"]}, "xss_runtime_binding")

    def test_original_timestamps_and_actual_normal_then_attack_order_are_required(self):
        *_, visits, writer_session, viewer_session, args = self.prepared()
        for changes in ({"started_at": None, "completed_at": None},
                        {"started_at": "2000-01-01T00:00:00+00:00", "completed_at": "2000-01-01T00:00:01+00:00"}):
            other = self.replacement(visits[1], **changes)
            self.reject({**args, "runtime_visit_id": other["id"]}, "xss_runtime_binding")

    def test_imported_mcp_cannot_impersonate_a_verified_native_viewer(self):
        *_, visits, writer_session, viewer_session, args = self.prepared()
        raw = self.project.read_artifact(visits[1])
        imported = browser._record_observation(self.project, raw, self.project.id("PV"), "imported_mcp")
        self.reject({**args, "runtime_visit_id": imported["id"]}, "xss_runtime_identity")

    def test_changed_read_operation_or_normal_browser_artifact_reopens_the_source(self):
        operation, item, writers, reads, visits, _, _, args = self.prepared()
        finding = record_finding(self.project, args)
        reader = self.project.get("operation", reads[0]["operation_id"])
        self.project.put("operation", {**reader, "auth": "unknown"})
        evaluated = engine.evaluate_coverage(self.project)
        self.assertTrue(any(row["id"] == item["id"] for row in evaluated["gaps"]))
        self.assertFalse(next(row for row in evaluated["findings"] if row["id"] == finding["id"])["current"])
        self.project.put("operation", reader)
        self.assertFalse(any(row["id"] == item["id"] for row in engine.evaluate_coverage(self.project)["gaps"]))
        path = self.project.base / visits[0]["artifact_path"]
        path.write_text("{}", encoding="utf-8")
        evaluated = engine.evaluate_coverage(self.project)
        self.assertTrue(any(row["id"] == item["id"] for row in evaluated["gaps"]))
        self.assertFalse(next(row for row in evaluated["findings"] if row["id"] == finding["id"])["current"])


if __name__ == "__main__":
    unittest.main()
