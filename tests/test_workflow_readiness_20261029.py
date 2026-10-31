"""Offline regressions for current surface status and adapter/session readiness."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import engine, workflow
from awa_ddd.assessment import evaluate
from awa_ddd.store import Project, now


def observation(url, method, headers, body, timeout, max_bytes, *, response=None):
    response = {"ok": True} if response is None else response
    raw = json.dumps(response, ensure_ascii=False).encode("utf-8")
    sent = body if isinstance(body, bytes) else body.encode("utf-8") if isinstance(body, str) else b""
    return {"request": {"url": url, "method": method, "headers": headers,
                        "body_base64": base64.b64encode(sent).decode("ascii")},
            "response": {"status": 200, "headers": [["content-type", "application/json"]],
                         "length": len(raw), "body_base64": base64.b64encode(raw).decode("ascii")},
            "started_at": now(), "completed_at": now(), "complete": True}


class WorkflowReadinessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-readiness-")
        self.addCleanup(self.tmp.cleanup)
        self.base = "http://fixture.invalid"
        self.other = "http://other.invalid"
        engine.create_project(self.tmp.name, {"project_id": "readiness", "target": self.base,
            "scope": [self.base, self.other, "http://fixture.invalid:8080", "https://fixture.invalid"]})
        self.project = Project(self.tmp.name, "readiness")
        self.addCleanup(self.project.close)

    def operation(self, path="/items", **extra):
        return engine.register_operation(self.project, {"url": self.base + path,
            "method": "GET", "auth": "public", **extra})

    def session(self, subject="alice", *, origin=None, roles=(), verify_roles=False):
        origin = self.base if origin is None else origin
        engine.add_actor(self.project, {"actor_id": subject, "subject": subject, "roles": list(roles)})
        session = engine.add_session(self.project, {"actor_id": subject,
            "headers": {"Cookie": "fixture-principal=" + subject}})
        identity = engine.register_operation(self.project, {"url": origin + "/whoami",
            "method": "GET", "auth": "authenticated"})
        args = {"operation_id": identity["id"], "session_id": session["id"], "subject_selector": "/subject"}
        if verify_roles or roles:
            args["roles_selector"] = "/roles"
        with patch.object(engine, "request", side_effect=lambda *args: observation(*args,
                response={"subject": subject, "roles": list(roles)})):
            engine.verify_identity(self.project, args)
        return self.project.get("session", session["id"])

    def captured(self, operation, **args):
        with patch.object(engine, "request", side_effect=observation):
            return engine.capture(self.project, {"operation_id": operation["id"], **args})

    def obligation(self, operation, kind, actor=None):
        engine.build_plan(self.project)
        return next(item for item in self.project.list("obligation")
            if item["operation_id"] == operation["id"] and item["kind"] == kind
            and item.get("actor_id") == actor and not item.get("superseded"))

    def work_row(self, operation, kind, actor=None):
        engine.build_plan(self.project)
        offset = 0
        with patch.object(engine, "request") as network:
            while True:
                result = workflow.next_work(self.project, {"include_blocked": True, "limit": 25, "offset": offset})
                row = next((item for item in result["work_items"] if item["operation_id"] == operation["id"]
                            and item["obligation_kind"] == kind and item.get("actor_id") == actor), None)
                if row is not None:
                    network.assert_not_called()
                    return row
                if result["next_offset"] is None:
                    self.fail("No matching work item")
                offset = result["next_offset"]

    def inspected_obligation(self, operation, obligation):
        with patch.object(engine, "request") as network:
            view = workflow.inspect_surface(self.project, {"operation_id": operation["id"]})
        network.assert_not_called()
        return next(item for item in view["obligations"] if item["id"] == obligation["id"])

    def record_baseline(self, operation, session=None):
        args = {"session_id": session["id"]} if session else {}
        evidence = self.captured(operation, **args)
        obligation = self.obligation(operation, "baseline", session["actor_id"] if session else None)
        evaluate(self.project, {"obligation_id": obligation["id"], "evidence_ids": [evidence["id"]],
            "oracle": {"type": "baseline", "selector": "/ok", "expected": True}})
        return obligation, evidence

    def test_surface_inspect_reopens_a_baseline_after_actor_security_change(self):
        session = self.session()
        operation = self.operation("/protected", auth="authenticated")
        obligation, _ = self.record_baseline(operation, session)
        engine.add_actor(self.project, {"actor_id": "alice", "subject": "alice", "roles": ["user"]})
        engine.build_plan(self.project)
        original = self.project.get("obligation", obligation["id"])
        self.assertEqual(original["status"], "evaluated")
        rows_before = self.project.connection.execute("SELECT count(*) FROM events").fetchone()[0]
        inspected = self.inspected_obligation(operation, obligation)
        gap = next(item for item in engine.evaluate_coverage(self.project)["gaps"] if item["id"] == obligation["id"])
        for field in ("status", "gap_id", "reason_code", "next_action"):
            self.assertEqual(inspected[field], gap[field])
        self.assertEqual(inspected["status"], "open")
        self.assertEqual(self.project.get("obligation", obligation["id"]), original)
        self.assertEqual(self.project.connection.execute("SELECT count(*) FROM events").fetchone()[0], rows_before)

    def test_surface_inspect_reopens_ownership_after_fixture_binding_change(self):
        alice, bob = self.session(), self.session("bob")
        operation = self.operation("/owned", auth="authenticated", ownership=True,
            inputs=[{"name": "id", "location": "query", "consumer": "resource_reference"}])
        resource = engine.add_resource(self.project, {"operation_id": operation["id"],
            "owner_actor_id": "alice", "external_id": "7", "request_binding": {"location": "query", "selector": "id"}})
        args = {"url": self.base + "/owned?id=7", "resource_id": resource["id"]}
        baseline = self.captured(operation, session_id=alice["id"], **args)
        variant = self.captured(operation, session_id=bob["id"], **args)
        obligation = self.obligation(operation, "ownership", "bob")
        evaluate(self.project, {"obligation_id": obligation["id"], "evidence_ids": [baseline["id"], variant["id"]],
            "oracle": {"type": "authorization", "selector": "/ok"}})
        engine.add_resource(self.project, {"resource_id": resource["id"], "operation_id": operation["id"],
            "owner_actor_id": "alice", "external_id": "8", "request_binding": {"location": "query", "selector": "id"}})
        inspected = self.inspected_obligation(operation, obligation)
        self.assertEqual(inspected["status"], "open")
        self.assertEqual(inspected["reason_code"], "evidence_invalid")
        self.assertEqual(inspected["next_action"], "repair_evidence")

    def test_surface_inspect_reopens_not_applicable_after_evidence_damage(self):
        operation = self.operation()
        evidence = self.captured(operation)
        obligation = self.obligation(operation, "baseline")
        engine.disposition(self.project, {"obligation_id": obligation["id"], "status": "not_applicable",
            "reason": "Explicit fixture business fact", "basis": "business_fact", "evidence_ids": [evidence["id"]]})
        (self.project.base / Path(evidence["artifact_path"])).write_bytes(b"changed fixture artifact")
        inspected = self.inspected_obligation(operation, obligation)
        self.assertEqual(inspected["status"], "open")
        self.assertEqual(inspected["reason_code"], "exclusion_evidence_invalid")
        self.assertEqual(inspected["next_action"], "repair_evidence")

    def test_surface_inspect_keeps_current_evaluated_baselines(self):
        operation = self.operation()
        obligation, _ = self.record_baseline(operation)
        inspected = self.inspected_obligation(operation, obligation)
        self.assertEqual(inspected["status"], "evaluated")
        self.assertNotIn("reason_code", inspected)

    def test_surface_inspect_preserves_operator_block_reason(self):
        operation = self.operation()
        obligation = self.obligation(operation, "baseline")
        engine.disposition(self.project, {"obligation_id": obligation["id"], "status": "blocked",
            "reason": "Fixture account unavailable"})
        inspected = self.inspected_obligation(operation, obligation)
        self.assertEqual(inspected["status"], "blocked")
        self.assertEqual(inspected["reason_code"], "blocked_precondition")
        self.assertEqual(inspected["operator_reason"], "Fixture account unavailable")

    def test_authenticated_query_sql_recommends_only_sqlmap(self):
        session = self.session()
        operation = self.operation("/search", auth="authenticated",
            inputs=[{"name": "q", "location": "query", "consumer": "sql_like"}])
        row = self.work_row(operation, "input_test")
        self.assertEqual(row["queue_status"], "ready")
        self.assertEqual(row["recommended_tools"], ["tool.sqlmap"])
        self.assertEqual(row["input_template"]["session_id"], session["id"])
        self.assertNotIn("analyst_write_side_business_proof", row["proof_channels"])

    def test_public_query_sql_never_inherits_a_live_session(self):
        self.session(origin=self.other)
        operation = self.operation("/search", inputs=[{"name": "q", "location": "query", "consumer": "sql"}])
        row = self.work_row(operation, "input_test")
        self.assertEqual(row["queue_status"], "ready")
        self.assertEqual(row["recommended_tools"], ["tool.yakit_replay", "tool.sqlmap"])
        self.assertNotIn("session_id", row["input_template"])
        self.assertEqual(row["missing_prerequisites"], [])

    def test_get_sql_in_nonquery_locations_has_no_url_only_adapter(self):
        for location in ("body", "header", "cookie", "path", "graphql"):
            with self.subTest(location=location):
                operation = self.operation("/" + location,
                    inputs=[{"name": "q", "location": location, "consumer": "sql"}])
                self.assertEqual(self.work_row(operation, "input_test")["recommended_tools"], [])

    def test_graphql_sql_query_is_not_a_supported_http_adapter(self):
        operation = self.operation("/graphql", protocol="graphql", operation_name="FixtureQuery",
            inputs=[{"name": "q", "location": "query", "consumer": "sql"}])
        self.assertEqual(self.work_row(operation, "input_test")["recommended_tools"], [])

    def test_non_get_sql_has_no_get_adapter_and_only_writes_offer_behaviour_proof(self):
        for method in ("HEAD", "OPTIONS", "POST"):
            with self.subTest(method=method):
                operation = self.operation("/" + method.lower(), method=method,
                    inputs=[{"name": "q", "location": "query", "consumer": "sql"}])
                row = self.work_row(operation, "input_test")
                self.assertEqual(row["recommended_tools"], [])
                self.assertEqual("analyst_write_side_business_proof" in row["proof_channels"], method == "POST")

    def test_unknown_access_policy_does_not_recommend_an_external_execution(self):
        self.session()
        operation = self.operation("/unknown", auth="unknown",
            inputs=[{"name": "q", "location": "query", "consumer": "sql"}])
        row = self.work_row(operation, "input_test")
        self.assertEqual(row["queue_status"], "blocked")
        self.assertEqual(row["recommended_tools"], [])
        self.assertIn("declared_access_policy", row["missing_prerequisites"])

    def test_input_work_is_blocked_when_identity_was_verified_at_another_origin(self):
        self.session(origin=self.other)
        operation = self.operation("/protected", auth="authenticated",
            inputs=[{"name": "q", "location": "query", "consumer": "sql"}])
        row = self.work_row(operation, "input_test")
        self.assertEqual(row["queue_status"], "blocked")
        self.assertIn("verified_session_for_target_origin", row["missing_prerequisites"])
        self.assertEqual(row["recommended_tools"], [])
        self.assertNotIn("session_id", row["input_template"])

    def test_anonymous_access_work_requires_an_allowed_baseline_at_the_target_origin(self):
        self.session(origin=self.other)
        operation = self.operation("/protected", auth="authenticated")
        row = self.work_row(operation, "access")
        self.assertEqual(row["queue_status"], "blocked")
        self.assertIn("verified_allowed_baseline", row["missing_prerequisites"])
        self.assertIn("verified_session_for_target_origin", row["missing_prerequisites"])

    def test_variant_actor_work_is_blocked_when_only_its_session_is_foreign(self):
        self.session("admin", roles=["admin"])
        self.session(origin=self.other, verify_roles=True)
        operation = self.operation("/admin", auth="restricted", allowed_roles=["admin"])
        row = self.work_row(operation, "access", "alice")
        self.assertEqual(row["queue_status"], "blocked")
        self.assertIn("verified_session_for_target_origin", row["missing_prerequisites"])
        self.assertNotIn("session_id", row["input_template"])

    def test_foreign_owner_baseline_cannot_make_ownership_ready(self):
        self.session(origin=self.other)
        self.session("bob")
        operation = self.operation("/owned", auth="authenticated", ownership=True,
            inputs=[{"name": "id", "location": "query", "consumer": "resource_reference"}])
        engine.add_resource(self.project, {"operation_id": operation["id"], "owner_actor_id": "alice",
            "external_id": "7", "request_binding": {"location": "query", "selector": "id"}})
        row = self.work_row(operation, "ownership", "bob")
        self.assertEqual(row["queue_status"], "blocked")
        self.assertIn("live_verified_owner_baseline", row["missing_prerequisites"])
        self.assertIn("verified_session_for_target_origin", row["missing_prerequisites"])

    def test_a_foreign_session_does_not_hide_a_matching_session_for_the_same_actor(self):
        foreign = self.session(origin=self.other)
        matching = self.session()
        operation = self.operation("/protected", auth="authenticated",
            inputs=[{"name": "q", "location": "query", "consumer": "sql"}])
        row = self.work_row(operation, "input_test")
        self.assertEqual(row["queue_status"], "ready")
        self.assertEqual(row["input_template"]["session_id"], matching["id"])
        self.assertNotEqual(row["input_template"]["session_id"], foreign["id"])

    def test_scheme_and_port_are_part_of_the_session_origin(self):
        for origin in ("http://fixture.invalid:8080", "https://fixture.invalid"):
            with self.subTest(origin=origin):
                self.session(origin=origin)
                operation = self.operation("/protected", auth="authenticated")
                row = self.work_row(operation, "baseline", "alice")
                self.assertEqual(row["queue_status"], "blocked")
                self.assertIn("verified_session_for_target_origin", row["missing_prerequisites"])

    def test_expired_matching_session_does_not_require_recollecting_a_valid_baseline(self):
        session = self.session()
        operation = self.operation("/protected", auth="authenticated")
        evidence = self.captured(operation, session_id=session["id"])
        session["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        self.project.put("session", session)
        row = self.work_row(operation, "baseline", "alice")
        self.assertEqual(row["queue_status"], "ready")
        self.assertEqual(row["suggested_action"], "assessment.evaluate")
        self.assertEqual(row["input_template"]["evidence_ids"], [evidence["id"]])
        self.assertEqual(row["missing_prerequisites"], [])


if __name__ == "__main__":
    unittest.main()
