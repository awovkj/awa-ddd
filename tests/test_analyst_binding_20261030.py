"""Offline controlled-input and runtime integrity tests for reviewed XSS closure."""
from __future__ import annotations

import base64
import json
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

from awa_ddd import browser, completeness, engine
from awa_ddd.assessment import evaluate, record_finding
from awa_ddd.store import EngineError, Project, now


def observation(url, method, headers, body, timeout, max_bytes, *, response=None):
    response_body = json.dumps(response or {"ok": True}).encode("utf-8")
    sent = (body if isinstance(body, bytes) else body.encode("utf-8") if isinstance(body, str)
            else json.dumps(body).encode("utf-8") if body is not None else b"")
    return {"request": {"url": url, "method": method, "headers": headers,
                        "body_base64": base64.b64encode(sent).decode("ascii")},
            "response": {"status": 200, "headers": [["content-type", "application/json"]],
                         "length": len(response_body), "body_base64": base64.b64encode(response_body).decode("ascii")},
            "started_at": now(), "completed_at": now(), "complete": True}


class AnalystBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-analyst-binding-")
        self.addCleanup(self.tmp.cleanup)
        self.base = "http://fixture.invalid"
        engine.create_project(self.tmp.name, {"project_id": "binding", "target": self.base})
        self.project = Project(self.tmp.name, "binding")
        self.addCleanup(self.project.close)
        self.marker = "AWA-XSS-0011223344556677"
        self.payload = "<img src=x onerror=alert('" + self.marker + "')>"

    def operation(self, path="/render", *, family="xss", auth="public", **extra):
        return engine.register_operation(self.project, {"url": self.base + path, "method": "GET", "auth": auth,
            "inputs": [{"name": "content", "location": "query", "consumer": "html_render",
                        "test_families": [family]}, {"name": "other", "location": "query"}], **extra})

    def capture(self, operation, value, *, other="fixed", response=None, **extra):
        url = operation["url"] + "?" + urlencode({"content": value, "other": other})
        with patch.object(engine, "request", side_effect=lambda *values: observation(*values, response=response)):
            return engine.capture(self.project, {"operation_id": operation["id"], "url": url, **extra})

    def actor(self, identity):
        actor = engine.add_actor(self.project, {"actor_id": identity, "subject": identity, "roles": ["user"]})
        session = engine.add_session(self.project, {"actor_id": identity,
            "headers": {"Authorization": "Bearer fixture-" + identity}})
        operation = engine.register_operation(self.project, {"url": self.base + "/whoami", "method": "GET", "auth": "authenticated"})
        with patch.object(engine, "request", side_effect=lambda *values: observation(*values, response={"subject": identity, "roles": ["user"]})):
            engine.verify_identity(self.project, {"operation_id": operation["id"], "session_id": session["id"],
                "subject_selector": "/subject", "roles_selector": "/roles"})
        return actor, self.project.get("session", session["id"])

    def visit(self, url, *, session=None, actor=None, headers=None, **overrides):
        raw = {"url": url, "finalUrl": url, "status": 200, "signals": {"forms": 1},
               "dialogs": [{"type": "alert", "message": self.marker, "action_index": None}],
               "network": [{"url": url, "method": "GET", "type": "document", "status": 200,
                            "request_headers": headers if headers is not None else session["headers"] if session else {}}],
               **overrides}
        return browser._record_observation(self.project, raw, self.project.id("PV"), "local_playwright",
                                           session=session, actor=actor)

    def prepared(self, *, family="xss", session=None, actor=None, method="GET"):
        operation = self.operation(family=family, auth="authenticated" if session else "public", method=method)
        engine.build_plan(self.project)
        captures = [self.capture(operation, value, **({"session_id": session["id"]} if session else {}))
                    for value in ("normal", self.payload)]
        item = next(item for item in self.project.list("obligation") if item.get("kind") == "input_test"
                    and item["operation_id"] == operation["id"] and not item.get("superseded"))
        url = self.project.read_artifact(captures[1])["request"]["url"]
        visit = self.visit(url, session=session, actor=actor)
        args = {"mode": "analyst", "title": "Controlled runtime fixture", "category": "XSS",
                "impact": "The fixture input executes in its consumer document", "remediation": "Encode the sink output",
                "reviewer": "fixture reviewer", "reason": "Reviewed isolated normal/attack controls and runtime dialog",
                "obligation_id": item["id"], "evidence_ids": [capture["id"] for capture in captures],
                "runtime_visit_id": visit["id"], "consumer_url": url, "runtime_marker": self.marker}
        return operation, item, captures, visit, args

    def reject_without_changes(self, args, code=None):
        before = [tuple(row) for row in self.project.connection.execute("SELECT * FROM entities ORDER BY kind,id")]
        events = self.project.connection.execute("SELECT count(*) FROM events").fetchone()[0]
        with self.assertRaises(EngineError) as caught:
            record_finding(self.project, args)
        if code:
            self.assertEqual(caught.exception.code, code)
        self.assertEqual(before, [tuple(row) for row in self.project.connection.execute("SELECT * FROM entities ORDER BY kind,id")])
        self.assertEqual(events, self.project.connection.execute("SELECT count(*) FROM events").fetchone()[0])

    def test_reviewed_runtime_closes_only_its_typed_input_and_remains_analyst(self):
        operation, item, captures, visit, args = self.prepared()
        with patch.object(engine, "request") as network:
            finding = record_finding(self.project, args)
            audit = completeness.audit(self.project, {})
        network.assert_not_called()
        current = self.project.get("obligation", item["id"])
        decision = self.project.get("decision", finding["decision_id"])
        self.assertEqual(current["status"], "evaluated")
        self.assertEqual(current["decision_id"], decision["id"])
        self.assertEqual(decision["mode"], "analyst")
        self.assertEqual(decision["oracle"], {"type": "analyst_runtime", "test_family": "xss"})
        self.assertEqual(decision["proof"]["attack_evidence_id"], captures[1]["id"])
        self.assertEqual(decision["proof"]["artifact_sha256"], visit["sha256"])
        self.assertEqual(audit["completion"]["unlinked_analyst_findings"], 0)
        self.assertEqual(audit["security_coverage"]["evaluated"], 1)
        self.assertEqual(self.project.get("obligation", next(row["id"] for row in self.project.list("obligation")
            if row.get("kind") == "input_review"))["status"], "open")
        with self.assertRaises(EngineError) as caught:
            self.project.put("decision", {**decision, "mode": "machine"})
        self.assertEqual(caught.exception.code, "immutable_record")

    def test_authenticated_runtime_requires_the_same_actual_credential_identity(self):
        actor, session = self.actor("alice")
        operation, item, captures, visit, args = self.prepared(session=session, actor=actor)
        finding = record_finding(self.project, args)
        decision = self.project.get("decision", finding["decision_id"])
        self.assertEqual(decision["proof"]["identity"], {"actor_id": "alice", "session_id": session["id"], "session_generation": 1})
        self.assertNotIn("Bearer", json.dumps(decision["proof"]))

    def test_stored_xss_write_uses_controlled_body_and_the_same_exact_fixture(self):
        actor, session = self.actor("alice")
        engine.update_project(self.project, {"allow_mutation": True})
        operation = engine.register_operation(self.project, {"url": self.base + "/store", "method": "POST",
            "auth": "authenticated", "content_type": "application/json", "inputs": [
                {"name": "content", "location": "body", "selector": "/content", "consumer": "html_render", "test_families": ["xss"]},
                {"name": "id", "location": "body", "selector": "/id"}]})
        resource = engine.add_resource(self.project, {"operation_id": operation["id"], "owner_actor_id": "alice",
            "external_id": "fixture-1", "request_binding": {"location": "body", "selector": "/id"}})
        engine.build_plan(self.project)
        captures = []
        for content in ("normal", self.payload):
            with patch.object(engine, "request", side_effect=observation):
                captures.append(engine.capture(self.project, {"operation_id": operation["id"], "session_id": session["id"],
                    "resource_id": resource["id"], "effect": "test_resource_write", "body": {"id": "fixture-1", "content": content}}))
        item = next(row for row in self.project.list("obligation") if row.get("kind") == "input_test"
                    and row["operation_id"] == operation["id"] and not row.get("superseded"))
        visit = self.visit(self.base + "/consumer?id=fixture-1", session=session, actor=actor)
        finding = record_finding(self.project, {"mode": "analyst", "title": "Stored fixture runtime", "category": "Stored XSS",
            "impact": "The controlled fixture executes on its read-only consumer page", "remediation": "Encode content",
            "reviewer": "fixture reviewer", "reason": "Reviewed exact fixture and runtime signal", "obligation_id": item["id"],
            "evidence_ids": [row["id"] for row in captures], "runtime_visit_id": visit["id"],
            "consumer_url": visit["url"], "runtime_marker": self.marker})
        self.assertEqual(finding["proof"]["resource_id"], resource["id"])
        self.assertEqual(self.project.get("obligation", item["id"])["status"], "evaluated")

    def test_machine_evaluate_cannot_use_the_reviewed_runtime_oracle_as_a_shortcut(self):
        operation, item, captures, visit, args = self.prepared()
        before = [tuple(row) for row in self.project.connection.execute("SELECT * FROM entities ORDER BY kind,id")]
        with self.assertRaises(EngineError) as caught:
            evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": args["evidence_ids"],
                "oracle": {"type": "analyst_runtime", "test_family": "xss"}})
        self.assertEqual(caught.exception.code, "unsupported_oracle")
        self.assertEqual(before, [tuple(row) for row in self.project.connection.execute("SELECT * FROM entities ORDER BY kind,id")])

    def test_wrong_family_and_generic_analyst_text_cannot_close_an_obligation(self):
        operation, item, captures, visit, args = self.prepared(family="generic")
        self.reject_without_changes(args, "analyst_obligation")
        self.reject_without_changes({**args, "category": "Information Disclosure"}, "analyst_obligation")

    def test_legacy_untyped_xss_cannot_be_promoted_to_typed_runtime_closure(self):
        operation, item, captures, visit, args = self.prepared()
        changed = self.project.get("operation", operation["id"])
        changed["inputs"][0].pop("test_families")
        self.project.put("operation", changed)
        engine.build_plan(self.project)
        legacy = next(row for row in self.project.list("obligation") if row.get("kind") == "input_test" and not row.get("superseded"))
        self.reject_without_changes({**args, "obligation_id": legacy["id"]}, "analyst_obligation")

    def test_changed_other_input_cannot_attribute_a_dialog_to_the_selected_input(self):
        operation, item, captures, visit, args = self.prepared()
        wrong = self.capture(operation, self.payload, other="changed")
        self.reject_without_changes({**args, "evidence_ids": [captures[0]["id"], wrong["id"]]}, "input_binding")

    def test_marker_in_another_input_or_absent_from_selected_attack_is_rejected(self):
        operation, item, captures, visit, args = self.prepared()
        wrong = self.capture(operation, "harmless", other=self.marker)
        self.reject_without_changes({**args, "evidence_ids": [captures[0]["id"], wrong["id"]]}, "input_binding")
        harmless = self.capture(operation, "harmless")
        self.reject_without_changes({**args, "evidence_ids": [captures[0]["id"], harmless["id"]]}, "xss_input_binding")

    def test_marker_in_normal_input_or_reversed_capture_order_is_rejected(self):
        operation, item, captures, visit, args = self.prepared()
        marked = self.capture(operation, "normal-" + self.marker)
        self.reject_without_changes({**args, "evidence_ids": [marked["id"], captures[1]["id"]]}, "xss_input_binding")
        self.reject_without_changes({**args, "evidence_ids": list(reversed(args["evidence_ids"]))}, "xss_input_binding")

    def test_distinct_independent_captures_and_exact_operation_are_required(self):
        operation, item, captures, visit, args = self.prepared()
        self.reject_without_changes({**args, "evidence_ids": [captures[1]["id"]]}, "xss_input_binding")
        self.reject_without_changes({**args, "evidence_ids": [captures[1]["id"], captures[1]["id"]]}, "independent_evidence")
        wrong = self.capture(self.operation("/other-render"), "normal")
        self.reject_without_changes({**args, "evidence_ids": [wrong["id"], captures[1]["id"]]}, "evidence_binding")

    def test_static_reflection_without_actual_dialog_does_not_close_xss(self):
        operation, item, captures, visit, args = self.prepared()
        without_dialog = self.visit(args["consumer_url"], dialogs=[], console=[{"message": self.marker}])
        self.reject_without_changes({**args, "runtime_visit_id": without_dialog["id"]}, "xss_runtime_required")

    def test_a_different_reflected_consumer_or_uncaptured_browser_fill_cannot_close_input(self):
        operation, item, captures, visit, args = self.prepared()
        other = self.visit(self.base + "/other-render?content=" + self.marker)
        self.reject_without_changes({**args, "runtime_visit_id": other["id"], "consumer_url": other["url"]}, "xss_runtime_binding")
        filled = self.visit(args["consumer_url"], actions=[{"type": "fill", "selector": "#unrelated", "ok": True,
            "finalUrl": args["consumer_url"]}])
        self.reject_without_changes({**args, "runtime_visit_id": filled["id"]}, "xss_runtime_binding")

    def test_get_browser_rendering_cannot_close_a_head_method_hypothesis(self):
        operation, item, captures, visit, args = self.prepared(method="HEAD")
        self.reject_without_changes(args, "xss_runtime_binding")

    def test_missing_consumer_header_snapshot_is_conservatively_unsupported(self):
        operation, item, captures, visit, args = self.prepared()
        no_headers = self.visit(args["consumer_url"], network=[{"url": args["consumer_url"], "method": "GET", "type": "document", "status": 200}])
        self.reject_without_changes({**args, "runtime_visit_id": no_headers["id"]}, "xss_runtime_identity")

    def test_runtime_actor_and_credentials_cannot_be_substituted(self):
        actor, session = self.actor("alice")
        operation, item, captures, visit, args = self.prepared(session=session, actor=actor)
        anonymous = self.visit(args["consumer_url"])
        self.reject_without_changes({**args, "runtime_visit_id": anonymous["id"]}, "xss_runtime_identity")
        wrong = self.visit(args["consumer_url"], session=session, actor=actor, headers={"authorization": "Bearer fixture-bob"})
        self.reject_without_changes({**args, "runtime_visit_id": wrong["id"]}, "xss_runtime_identity")

    def test_control_identity_cannot_change_between_normal_and_attack(self):
        actor, session = self.actor("alice")
        operation, item, captures, visit, args = self.prepared(session=session, actor=actor)
        other_actor, other_session = self.actor("bob")
        wrong = self.capture(operation, self.payload, session_id=other_session["id"])
        self.reject_without_changes({**args, "evidence_ids": [captures[0]["id"], wrong["id"]]}, "control_identity")

    def test_ambiguous_other_document_or_navigation_cannot_supply_consumer_dialog(self):
        operation, item, captures, visit, args = self.prepared()
        url = args["consumer_url"]
        wrong = self.visit(url, network=[{"url": url, "method": "GET", "type": "document", "status": 200, "request_headers": {}},
                                        {"url": self.base + "/another-page", "method": "GET", "type": "document", "status": 200, "request_headers": {}}])
        self.reject_without_changes({**args, "runtime_visit_id": wrong["id"]}, "xss_runtime_binding")
        navigation = self.visit(url, actions=[{"type": "click", "selector": "#other", "ok": True, "finalUrl": self.base + "/another-page"}])
        self.reject_without_changes({**args, "runtime_visit_id": navigation["id"]}, "xss_runtime_binding")

    def test_runtime_artifact_or_identity_tampering_reopens_the_evaluated_input(self):
        operation, item, captures, visit, args = self.prepared()
        finding = record_finding(self.project, args)
        changed = self.project.get("page_visit", visit["id"])
        changed["actor_id"] = "forged"
        self.project.put("page_visit", changed)
        evaluated = engine.evaluate_coverage(self.project)
        self.assertTrue(any(gap["id"] == item["id"] and gap["status"] == "open" for gap in evaluated["gaps"]))
        self.assertFalse(next(row for row in evaluated["findings"] if row["id"] == finding["id"])["current"])
        changed["actor_id"] = None
        self.project.put("page_visit", changed)
        artifact = self.project.base / visit["artifact_path"]
        raw = json.loads(artifact.read_text(encoding="utf-8"))
        raw["dialogs"] = []
        artifact.write_text(json.dumps(raw), encoding="utf-8")
        evaluated = engine.evaluate_coverage(self.project)
        self.assertTrue(any(gap["id"] == item["id"] and gap["status"] == "open" for gap in evaluated["gaps"]))

    def test_current_declared_input_changes_are_revalidated_without_manual_replan(self):
        operation, item, captures, visit, args = self.prepared()
        finding = record_finding(self.project, args)
        changed = self.project.get("operation", operation["id"])
        changed["inputs"][0]["test_families"] = ["generic"]
        self.project.put("operation", changed)
        evaluated = engine.evaluate_coverage(self.project)
        self.assertTrue(any(gap["id"] == item["id"] and gap["status"] == "open" for gap in evaluated["gaps"]))
        self.assertFalse(next(row for row in evaluated["findings"] if row["id"] == finding["id"])["current"])

    def test_legacy_unbound_finding_keeps_old_behavior_and_does_not_close_input(self):
        operation, item, captures, visit, args = self.prepared()
        legacy = {key: value for key, value in args.items() if key != "obligation_id"}
        legacy["evidence_ids"] = [captures[1]["id"]]
        finding = record_finding(self.project, legacy)
        self.assertNotIn("obligation_id", self.project.get("decision", finding["decision_id"]))
        self.assertEqual(self.project.get("obligation", item["id"])["status"], "open")
        self.assertEqual(completeness.audit(self.project, {})["completion"]["unlinked_analyst_findings"], 1)

    def test_sql_metadata_requirements_are_unchanged_and_runtime_cannot_bypass_them(self):
        operation, item, captures, visit, args = self.prepared()
        self.reject_without_changes({key: value for key, value in {**args, "category": "SQL Injection"}.items()
            if key != "obligation_id"}, "sql_metadata_required")
        self.reject_without_changes({**args, "category": "SQL Injection"}, "analyst_obligation")


if __name__ == "__main__":
    unittest.main()
