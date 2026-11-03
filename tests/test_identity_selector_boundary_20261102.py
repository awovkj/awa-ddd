"""Identity fields cannot reuse one scalar as subject, tenant and role membership."""
from __future__ import annotations

import base64
import json
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import engine
from awa_ddd.assessment import evaluate
from awa_ddd.store import EngineError, Project, now


def observation(url, method, headers, body, timeout, max_bytes, *, profile=None):
    raw = json.dumps({"subject": "member", "tenant": "member", "role": "member", "roles": ["member"]}
                     if profile is None else profile).encode("utf-8")
    return {"request": {"url": url, "method": method, "headers": headers, "body_base64": ""},
            "response": {"status": 200, "headers": [["content-type", "application/json"]],
                         "length": len(raw), "body_base64": base64.b64encode(raw).decode("ascii")},
            "started_at": now(), "completed_at": now(), "complete": True}


class IdentitySelectorBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="awa-identity-selectors-")
        self.addCleanup(temporary.cleanup)
        engine.create_project(temporary.name, {"project_id": "identity", "target": "http://fixture.invalid"})
        self.project = Project(temporary.name, "identity")
        self.addCleanup(self.project.close)
        engine.add_actor(self.project, {"actor_id": "fixture-actor", "subject": "member", "tenant_id": "member", "roles": ["member"]})
        self.session = engine.add_session(self.project, {"actor_id": "fixture-actor", "headers": {"Cookie": "fixture-session=member"}})
        self.operation = engine.register_operation(self.project, {"url": "http://fixture.invalid/whoami", "method": "GET", "auth": "authenticated"})
        self.args = {"operation_id": self.operation["id"], "session_id": self.session["id"],
                     "subject_selector": "/subject", "tenant_selector": "/tenant", "roles_selector": "/roles"}

    def rejected_offline(self, overrides, code):
        events = self.project.connection.execute("SELECT count(*) FROM events").fetchone()[0]
        with patch.object(engine, "request") as network, self.assertRaises(EngineError) as raised:
            engine.verify_identity(self.project, {**self.args, **overrides})
        network.assert_not_called()
        self.assertEqual(code, raised.exception.code)
        self.assertEqual([], self.project.list("run"))
        self.assertEqual([], self.project.list("evidence"))
        self.assertEqual(events, self.project.connection.execute("SELECT count(*) FROM events").fetchone()[0])
        self.assertIsNone(self.project.get("session", self.session["id"])["verified_at"])

    def test_subject_and_roles_cannot_select_the_same_account_identifier(self):
        self.rejected_offline({"roles_selector": "/subject"}, "identity_selector_boundary")

    def test_subject_and_tenant_cannot_select_the_same_account_identifier(self):
        self.rejected_offline({"tenant_selector": "/subject"}, "identity_selector_boundary")

    def test_tenant_and_roles_cannot_reuse_one_scalar_field(self):
        self.rejected_offline({"roles_selector": "/tenant"}, "identity_selector_boundary")

    def test_pointer_grammar_is_checked_before_any_target_request(self):
        for field, value in (("subject_selector", "subject"), ("roles_selector", ["/roles"]),
                             ("tenant_selector", 1), ("roles_selector", "/bad~escape"), ("roles_selector", "")):
            with self.subTest(field=field, value=value):
                self.rejected_offline({field: value}, "identity_assertion")

    def test_valid_distinct_fields_preserve_identity_and_expose_semantic_limits(self):
        with patch.object(engine, "request", side_effect=observation):
            result = engine.verify_identity(self.project, self.args)
        self.assertIsNotNone(result["session"]["verified_at"])
        self.assertIn("arbitrary field semantics", result["identity_assertion_limitation"])
        self.assertIn("another account", result["identity_assertion_limitation"].lower())
        self.assertEqual(result["evidence_id"], engine.verify_current_evidence(self.project, result["evidence_id"])[0]["id"])

    def test_automatic_role_pointer_is_also_checked_against_subject(self):
        args = {**self.args, "subject_selector": "/role", "roles_selector": None}
        with patch.object(engine, "request", side_effect=lambda *args: observation(*args,
                profile={"subject": "member", "tenant": "member", "role": "member"})) as network, self.assertRaises(EngineError) as raised:
            engine.verify_identity(self.project, args)
        self.assertEqual(1, network.call_count)
        self.assertEqual("identity_selector_boundary", raised.exception.code)
        self.assertEqual(1, len(self.project.list("evidence")))
        self.assertIsNone(self.project.get("session", self.session["id"])["verified_at"])

    def test_automatic_tenant_pointer_is_also_checked_against_subject(self):
        args = {**self.args, "subject_selector": "/tenant", "tenant_selector": None}
        with patch.object(engine, "request", side_effect=observation) as network, self.assertRaises(EngineError) as raised:
            engine.verify_identity(self.project, args)
        self.assertEqual(1, network.call_count)
        self.assertEqual("identity_selector_boundary", raised.exception.code)
        self.assertEqual(1, len(self.project.list("evidence")))
        self.assertIsNone(self.project.get("session", self.session["id"])["verified_at"])

    def test_legacy_mixed_assertion_is_revalidated_without_rewriting_history(self):
        with patch.object(engine, "request", side_effect=observation):
            result = engine.verify_identity(self.project, self.args)
        engine.build_plan(self.project)
        obligation = next(item for item in self.project.list("obligation") if item["kind"] == "baseline"
                          and item.get("actor_id") == "fixture-actor")
        decision = evaluate(self.project, {"obligation_id": obligation["id"], "evidence_ids": [result["evidence_id"]],
            "oracle": {"type": "baseline", "selector": "/subject", "expected": "member"}})
        session = self.project.get("session", self.session["id"])
        session["verification_assertion"]["roles_selector"] = "/subject"
        self.project.put("session", session)
        with self.assertRaises(EngineError) as raised:
            engine.verify_current_evidence(self.project, result["evidence_id"])
        self.assertEqual("identity_selector_boundary", raised.exception.code)
        evaluated = engine.evaluate_coverage(self.project)
        self.assertIn(obligation["id"], {gap["id"] for gap in evaluated["gaps"]})
        self.assertEqual("evaluated", self.project.get("obligation", obligation["id"])["status"])
        self.assertEqual(decision, self.project.get("decision", decision["id"]))


if __name__ == "__main__":
    unittest.main()
