"""Unknown policy is a local prerequisite, not a project-wide projection failure."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import engine, workflow
from awa_ddd.__main__ import dispatch
from awa_ddd.assessment import _authorized, evaluate
from awa_ddd.store import EngineError, Project, now


def observed(url, method, headers, body, timeout, max_bytes, *, response=None):
    response = {"ok": True, "value": "fixture"} if response is None else response
    raw = json.dumps(response).encode("utf-8")
    sent = body if isinstance(body, bytes) else body.encode("utf-8") if isinstance(body, str) else b""
    return {"request": {"url": url, "method": method, "headers": headers,
                        "body_base64": base64.b64encode(sent).decode("ascii")},
            "response": {"status": 200, "headers": [["content-type", "application/json"]],
                         "length": len(raw), "body_base64": base64.b64encode(raw).decode("ascii")},
            "started_at": now(), "completed_at": now(), "complete": True}


class UnknownPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-unknown-policy-")
        self.addCleanup(self.tmp.cleanup)
        self.base = "http://fixture.invalid"
        self.project_id = "unknown-policy"
        engine.create_project(self.tmp.name, {"project_id": self.project_id, "target": self.base})
        self.project = Project(self.tmp.name, self.project_id)
        self.addCleanup(self.project.close)

    def operation(self, path="/unknown", **extra):
        return engine.register_operation(self.project, {"url": self.base + path, "method": "GET",
            "auth": "unknown", **extra})

    def session(self, subject, *, roles=()):
        engine.add_actor(self.project, {"actor_id": subject, "subject": subject, "roles": list(roles)})
        session = engine.add_session(self.project, {"actor_id": subject,
            "headers": {"Cookie": "fixture-subject=" + subject}})
        identity = self.operation("/whoami", auth="authenticated")
        args = {"operation_id": identity["id"], "session_id": session["id"], "subject_selector": "/subject"}
        if roles:
            args["roles_selector"] = "/roles"
        with patch.object(engine, "request", side_effect=lambda *args: observed(*args,
                response={"subject": subject, "roles": list(roles)})):
            engine.verify_identity(self.project, args)
        return self.project.get("session", session["id"])

    def captured(self, operation, **args):
        with patch.object(engine, "request", side_effect=observed):
            return engine.capture(self.project, {"operation_id": operation["id"], **args})

    def invoke(self, action, **args):
        return dispatch(self.tmp.name, action, {"project_id": self.project_id, **args})

    def no_unknown_authorization(self, project, operation, actor_id):
        self.assertNotEqual(operation["auth"], "unknown", "Projection inferred an unknown access policy")
        return _authorized(project, operation, actor_id)

    def work_items(self, operation):
        evaluated = engine.evaluate_coverage(self.project)
        return [row for row in workflow.queue_inventory(self.project, evaluated)
                if row["operation_id"] == operation["id"]]

    def populated_unknown(self, *, inputs=None, ownership=False):
        roles = ("user",) if ownership else ()
        alice, bob = self.session("alice", roles=roles), self.session("bob", roles=roles)
        operation = self.operation(inputs=inputs or [], ownership=ownership)
        args = {}
        if ownership:
            resource = engine.add_resource(self.project, {"operation_id": operation["id"],
                "owner_actor_id": "alice", "external_id": "7",
                "request_binding": {"location": "query", "selector": "id"}})
            args = {"url": self.base + "/unknown?id=7", "resource_id": resource["id"]}
        captures = [self.captured(operation, session_id=session["id"], **args) for session in (alice, bob)]
        return operation, captures

    def test_two_principal_observations_do_not_poison_readonly_project_views(self):
        operation, captures = self.populated_unknown()
        with patch("awa_ddd.assessment._authorized", side_effect=self.no_unknown_authorization), \
                patch.object(engine, "request") as network:
            engine.build_plan(self.project)
            before = {kind: self.project.list(kind) for kind in ("actor", "session", "operation", "obligation", "evidence", "run", "decision")}
            for action in ("project.status", "plan.next", "plan.audit", "plan.list", "report.coverage", "surface.list"):
                with self.subTest(action=action):
                    result = self.invoke(action)
                    self.assertIsInstance(result, dict)
                    if "continuation" in result:
                        self.assertTrue(result["continuation"]["continue_required"])
            self.assertEqual(self.invoke("surface.inspect", operation_id=operation["id"])["operation"]["auth"], "unknown")
            for evidence in captures:
                inspected = self.invoke("evidence.inspect", evidence_id=evidence["id"])
                self.assertEqual(inspected["integrity"], "valid")
                self.assertEqual(inspected["lineage"], "current")
            self.assertEqual(before, {kind: self.project.list(kind) for kind in before})
            network.assert_not_called()

    def test_existing_unknown_observations_do_not_block_administrative_mutations(self):
        operation, _ = self.populated_unknown(inputs=[{"name": "q", "location": "query"}])
        with patch("awa_ddd.assessment._authorized", side_effect=self.no_unknown_authorization), \
                patch.object(engine, "request") as network:
            actor = self.invoke("identity.actor", actor_id="charlie", subject="charlie", roles=[])
            self.assertEqual(actor["id"], "charlie")
            registered = self.invoke("surface.register", url=self.base + "/next", method="GET", auth="public")
            self.assertEqual(registered["auth"], "public")
            batch = self.invoke("surface.batch", operations=[
                {"url": self.base + "/third", "method": "GET", "auth": "public"},
                {"url": self.base + "/unknown-next", "method": "GET", "auth": "unknown"}])
            self.assertEqual((batch["accepted"], batch["rejected"]), (2, 0))
            declared = self.invoke("surface.declare_consumer", operation_id=operation["id"],
                input_location="query", input_selector="q", consumer="sql_like")
            self.assertEqual(declared["input"]["consumer"], "sql_like")
            self.assertEqual(self.project.get("operation", operation["id"])["auth"], "unknown")
            rows = self.work_items(operation)
            self.assertTrue(any(row["obligation_kind"] == "auth_review" for row in rows))
            self.assertTrue(self.invoke("project.status")["continuation"]["continue_required"])
            network.assert_not_called()

    def test_unknown_access_review_is_bound_to_the_same_actor_without_authorizing_it(self):
        operation, captures = self.populated_unknown()
        with patch("awa_ddd.assessment._authorized", side_effect=self.no_unknown_authorization):
            engine.build_plan(self.project)
            rows = self.work_items(operation)
        by_actor = {row.get("actor_id"): row for row in rows if row["obligation_kind"] == "access"}
        for evidence in captures:
            row = by_actor[evidence["actor_id"]]
            self.assertEqual(row["queue_status"], "review")
            self.assertTrue(row["execution_blocked"])
            self.assertIn("declared_access_policy", row["missing_prerequisites"])
            self.assertIn("verified_allowed_baseline", row["missing_prerequisites"])
            self.assertEqual(row["evidence_ids"], [evidence["id"]])
            self.assertEqual(row["input_template"], {"evidence_id": evidence["id"]})
            self.assertEqual(row["assessment_followup_action"], "surface.register")
        self.assertEqual(by_actor[None]["queue_status"], "blocked")

    def test_unknown_input_observations_remain_offline_review_not_sql_execution(self):
        operation, captures = self.populated_unknown(inputs=[{"name": "q", "location": "query", "consumer": "sql_like"}])
        with patch("awa_ddd.assessment._authorized", side_effect=self.no_unknown_authorization):
            engine.build_plan(self.project)
            row = next(row for row in self.work_items(operation) if row["obligation_kind"] == "input_test")
        self.assertEqual(row["queue_status"], "review")
        self.assertTrue(row["execution_blocked"])
        self.assertIn("declared_access_policy", row["missing_prerequisites"])
        self.assertIn("live_verified_allowed_session", row["missing_prerequisites"])
        self.assertEqual(row["suggested_action"], "evidence.inspect")
        self.assertEqual(row["assessment_followup_action"], "surface.register")
        self.assertEqual(row["recommended_tools"], [])
        self.assertEqual(set(row["evidence_ids"]), {item["id"] for item in captures})
        self.assertNotIn("session_id", row["input_template"])
        self.assertFalse(row["browser_testing"]["invoke_now"])

    def test_unknown_ownership_keeps_precise_evidence_and_fixture_prerequisites(self):
        operation, captures = self.populated_unknown(ownership=True,
            inputs=[{"name": "id", "location": "query", "consumer": "resource_reference"}])
        with patch("awa_ddd.assessment._authorized", side_effect=self.no_unknown_authorization):
            engine.build_plan(self.project)
            row = next(row for row in self.work_items(operation) if row["obligation_kind"] == "ownership")
            self.invoke("identity.resource", operation_id=operation["id"], owner_actor_id="alice", external_id="8",
                request_binding={"location": "query", "selector": "id"})
        self.assertEqual(row["queue_status"], "review")
        self.assertIn("declared_access_policy", row["missing_prerequisites"])
        self.assertTrue(row["execution_blocked"])
        matching = next(item for item in captures if item["actor_id"] == row["actor_id"])
        self.assertEqual(row["input_template"], {"evidence_id": matching["id"]})

    def test_unknown_access_positive_oracle_still_requires_declared_policy(self):
        operation, captures = self.populated_unknown()
        engine.build_plan(self.project)
        obligation = next(item for item in self.project.list("obligation")
            if item["operation_id"] == operation["id"] and item["kind"] == "access" and item.get("actor_id") == "bob")
        with self.assertRaises(EngineError) as caught:
            evaluate(self.project, {"obligation_id": obligation["id"], "evidence_ids": [item["id"] for item in captures],
                "oracle": {"type": "authorization", "selector": "/ok"}})
        self.assertEqual(caught.exception.code, "access_policy")
        self.assertEqual(self.project.get("obligation", obligation["id"])["status"], "open")
        self.assertEqual(self.project.list("decision"), [])

    def test_legacy_unknown_baseline_success_is_not_an_authorization_shortcut(self):
        operation, captures = self.populated_unknown()
        session = next(item for item in self.project.list("session") if item["actor_id"] == "alice")
        gap = {"id": "OB-legacy-baseline", "gap_id": "G-legacy-baseline", "operation_id": operation["id"],
               "obligation_kind": "baseline", "actor_id": "alice", "status": "open", "reason_code": "not_started"}
        with patch("awa_ddd.assessment._authorized", side_effect=self.no_unknown_authorization):
            row = workflow._work_item(self.project, gap, {operation["id"]: operation},
                {"alice": session}, {operation["id"]: captures})
        self.assertEqual(row["queue_status"], "review")
        self.assertTrue(row["execution_blocked"])
        self.assertIn("declared_access_policy", row["missing_prerequisites"])
        self.assertEqual(row["assessment_followup_action"], "surface.register")
        self.assertEqual(row["suggested_action"], "evidence.inspect")

    def test_unknown_evidence_review_does_not_relax_scope_or_identity_execution_gates(self):
        operation, _ = self.populated_unknown()
        engine.build_plan(self.project)
        engine.add_actor(self.project, {"actor_id": "unverified", "subject": "unverified", "roles": []})
        session = engine.add_session(self.project, {"actor_id": "unverified", "headers": {"Cookie": "fixture=unverified"}})
        with patch.object(engine, "request") as network:
            with self.assertRaises(EngineError) as caught:
                engine.capture(self.project, {"operation_id": operation["id"], "session_id": session["id"]})
            self.assertEqual(caught.exception.code, "identity_unverified")
            with self.assertRaises(EngineError) as caught:
                engine.capture(self.project, {"operation_id": operation["id"], "url": "http://outside.invalid/unknown"})
            self.assertEqual(caught.exception.code, "out_of_scope")
            network.assert_not_called()

    def test_known_policy_keeps_the_previous_offline_allowed_baseline_fallback(self):
        alice, bob = self.session("alice"), self.session("bob")
        operation = self.operation(auth="restricted", allowed_roles=["admin"],
            inputs=[{"name": "q", "location": "query", "consumer": "sql_like"}])
        # The known-policy input fallback can still inspect a permitted historical actor.
        engine.add_actor(self.project, {"actor_id": "alice", "subject": "alice", "roles": ["admin"]})
        identity = self.project.get("operation", self.operation("/whoami", auth="authenticated")["id"])
        with patch.object(engine, "request", side_effect=lambda *args: observed(*args,
                response={"subject": "alice", "roles": ["admin"]})):
            engine.verify_identity(self.project, {"operation_id": identity["id"], "session_id": alice["id"],
                "subject_selector": "/subject", "roles_selector": "/roles"})
        evidence = self.captured(operation, session_id=alice["id"])
        alice = self.project.get("session", alice["id"])
        alice["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        self.project.put("session", alice)
        engine.build_plan(self.project)
        rows = self.work_items(operation)
        row = next(row for row in rows if row["obligation_kind"] == "input_test")
        self.assertEqual(row["queue_status"], "review")
        self.assertEqual(row["input_template"], {"evidence_id": evidence["id"]})
        self.assertEqual(row["assessment_followup_action"], "assessment.evaluate")
        self.assertIn("live_verified_allowed_session", row["missing_prerequisites"])
        self.assertNotIn("declared_access_policy", row["missing_prerequisites"])
        variant = next(row for row in rows if row["obligation_kind"] == "access" and row.get("actor_id") == bob["actor_id"])
        self.assertEqual(variant["queue_status"], "review")
        self.assertEqual(variant["input_template"], {"evidence_id": evidence["id"]})


if __name__ == "__main__":
    unittest.main()
