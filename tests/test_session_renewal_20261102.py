"""Expired sessions offer manual renewal only when their captured context is current."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import engine, publication, workflow
from awa_ddd.__main__ import dispatch
from awa_ddd.store import EngineError, Project, now


def observation(url, method, headers, body, timeout, max_bytes, *, profile):
    raw = json.dumps(profile).encode("utf-8")
    return {"request": {"url": url, "method": method, "headers": headers, "body_base64": ""},
            "response": {"status": 200, "headers": [["content-type", "application/json"]],
                         "length": len(raw), "body_base64": base64.b64encode(raw).decode("ascii")},
            "started_at": now(), "completed_at": now(), "complete": True}


class SessionRenewalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="awa-renewal-")
        self.addCleanup(temporary.cleanup)
        self.base, self.other = "http://fixture.invalid", "http://other.invalid"
        engine.create_project(temporary.name, {"project_id": "renewal", "target": self.base,
            "scope": [self.base, self.other]})
        self.project = Project(temporary.name, "renewal")
        self.addCleanup(self.project.close)

    def session(self, *, origin=None, roles=("member",), role_assertion=True):
        engine.add_actor(self.project, {"actor_id": "fixture-actor", "subject": "fixture-subject",
            "tenant_id": "fixture-tenant", "roles": list(roles)})
        session = engine.add_session(self.project, {"actor_id": "fixture-actor",
            "headers": {"Cookie": "fixture-principal=fixture-subject"}})
        identity = engine.register_operation(self.project, {"url": (origin or self.base) + "/whoami",
            "method": "GET", "auth": "authenticated"})
        profile = {"subject": "fixture-subject", "tenant": "fixture-tenant", "roles": list(roles)}
        args = {"session_id": session["id"], "operation_id": identity["id"],
                "subject_selector": "/subject", "tenant_selector": "/tenant"}
        if role_assertion:
            args["roles_selector"] = "/roles"
        with patch.object(engine, "request", side_effect=lambda *args: observation(*args, profile=profile)):
            engine.verify_identity(self.project, args)
        return self.project.get("session", session["id"])

    def operation(self, *, auth="restricted", url=None, **extra):
        operation = engine.register_operation(self.project, {"url": url or self.base + "/items", "method": "GET",
            "auth": auth, "allowed_roles": ["member"] if auth == "restricted" else [],
            "inputs": [{"name": "q", "location": "query", "consumer": "business_input", "test_families": ["generic"]}],
            **extra})
        engine.build_plan(self.project)
        return operation

    def expire(self, session):
        session = self.project.get("session", session["id"])
        session["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
        self.project.put("session", session)
        return session

    def row(self, operation, *, kind="input_test", actor_id=None):
        with patch.object(engine, "request") as network:
            result = workflow.next_work(self.project, {"include_blocked": True, "limit": 25})
        network.assert_not_called()
        return next(item for item in result["work_items"] if item["operation_id"] == operation["id"]
                    and item["obligation_kind"] == kind and item.get("actor_id") == actor_id)

    def assert_no_renewal(self, row):
        self.assertEqual("blocked", row["queue_status"])
        self.assertEqual([], row.get("session_renewal_candidates", []))
        self.assertFalse(any(item.get("input_template", {}).get("renew") is True
                             for item in row["preparation_actions"]))

    def rpc_session(self, secret, *, origin=None, roles=("member",), role_assertion=True):
        def call(action, **args):
            return dispatch(self.project.workspace, action, {"project_id": "renewal", **args})

        actor = call("identity.actor", subject="root", roles=list(roles))
        session = call("identity.session", actor_id=actor["id"], headers={"X-API-Key": secret})
        identity = call("surface.register", url=(origin or self.base) + "/whoami", method="GET", auth="authenticated")
        args = {"operation_id": identity["id"], "session_id": session["id"], "subject_selector": "/subject"}
        if role_assertion:
            args["roles_selector"] = "/roles"
        with patch.object(engine, "request", side_effect=lambda *args: observation(*args,
                profile={"subject": "root", "roles": list(roles)})):
            call("identity.verify", **args)
        return self.project.get("session", session["id"])

    def rpc_row(self, operation, actor_id, kind="baseline"):
        with patch.object(engine, "request") as network:
            result = dispatch(self.project.workspace, "plan.next", {"project_id": "renewal",
                "include_blocked": True, "limit": 25})
        network.assert_not_called()
        return next(item for item in result["work_items"] if item["operation_id"] == operation["id"]
                    and item["obligation_kind"] == kind and item.get("actor_id") == actor_id)

    def test_expired_current_session_remains_blocked_until_explicit_manual_renewal(self):
        session = self.session()
        operation = self.operation()
        expired = self.expire(session)
        events = self.project.connection.execute("SELECT count(*) FROM events").fetchone()[0]
        evidence = self.project.list("evidence")
        row = self.row(operation)
        self.assertEqual("blocked", row["queue_status"])
        candidate = row["session_renewal_candidates"][0]
        template = {"session_id": session["id"], "renew": True}
        self.assertEqual(template, candidate["input_template"])
        self.assertFalse(candidate["automatic_execution_allowed"])
        self.assertFalse(candidate["renewal_is_login"])
        preparation = next(item for item in row["preparation_actions"]
                           if item["prerequisite"] == "live_verified_allowed_session")
        self.assertEqual(template, preparation["input_template"])
        self.assertNotIn("headers", preparation["input_template"])
        self.assertFalse(preparation["automatic_execution_allowed"])
        self.assertEqual(expired, self.project.get("session", session["id"]))
        self.assertEqual(evidence, self.project.list("evidence"))
        self.assertEqual(events, self.project.connection.execute("SELECT count(*) FROM events").fetchone()[0])
        with patch.object(engine, "request") as network, self.assertRaises(EngineError) as raised:
            engine.capture(self.project, {"operation_id": operation["id"], "session_id": session["id"]})
        network.assert_not_called()
        self.assertEqual("session_expired", raised.exception.code)
        engine.add_session(self.project, template)
        renewed = self.project.get("session", session["id"])
        for key in ("generation", "headers", "verified_at", "verification_evidence_id", "credential_signature"):
            self.assertEqual(expired[key], renewed[key])
        row = self.row(operation)
        self.assertEqual("ready", row["queue_status"])
        self.assertEqual(session["id"], row["input_template"]["session_id"])
        self.assertNotIn("session_renewal_candidates", row)

    def test_expired_session_from_a_different_origin_is_not_a_renewal_candidate(self):
        session = self.session(origin=self.other)
        operation = self.operation()
        self.expire(session)
        self.assert_no_renewal(self.row(operation))

    def test_subject_only_session_does_not_unlock_a_restricted_role_comparison(self):
        session = self.session(roles=(), role_assertion=False)
        operation = self.operation()
        self.expire(session)
        self.assert_no_renewal(self.row(operation, kind="access", actor_id="fixture-actor"))
        self.assert_no_renewal(self.row(operation))

    def test_subject_only_session_can_renew_an_authenticated_nonrole_context(self):
        session = self.session(roles=(), role_assertion=False)
        operation = self.operation(auth="authenticated")
        self.expire(session)
        row = self.row(operation)
        self.assertEqual("blocked", row["queue_status"])
        self.assertEqual(session["id"], row["session_renewal_candidates"][0]["session_id"])

    def test_legacy_missing_role_assertion_is_not_a_role_complete_renewal(self):
        session = self.session()
        operation = self.operation()
        session["verification_assertion"]["roles_selector"] = None
        self.project.put("session", session)
        self.expire(session)
        self.assert_no_renewal(self.row(operation))

    def test_actor_security_change_does_not_offer_renewal_as_reverification(self):
        session = self.session()
        operation = self.operation()
        engine.add_actor(self.project, {"actor_id": "fixture-actor", "roles": ["different-role"]})
        self.expire(session)
        self.assert_no_renewal(self.row(operation))

    def test_changed_credential_bytes_do_not_offer_renewal(self):
        session = self.session()
        operation = self.operation()
        session["headers"]["cookie"] = "fixture-principal=different-subject"
        self.project.put("session", session)
        self.expire(session)
        self.assert_no_renewal(self.row(operation))

    def test_rotated_unverified_generation_does_not_offer_renewal(self):
        session = self.session()
        operation = self.operation()
        changed = engine.add_session(self.project, {"session_id": session["id"], "actor_id": "fixture-actor",
            "headers": {"Cookie": "fixture-principal=fixture-subject"}})
        self.expire(changed)
        self.assert_no_renewal(self.row(operation))

    def test_damaged_identity_evidence_does_not_offer_renewal(self):
        session = self.session()
        operation = self.operation()
        evidence = self.project.get("evidence", session["verification_evidence_id"])
        path = self.project.base / evidence["artifact_path"]
        path.write_bytes(path.read_bytes() + b" ")
        self.expire(session)
        self.assert_no_renewal(self.row(operation))

    def test_outside_scope_operation_is_not_unblocked_by_a_renewal_hint(self):
        session = self.session()
        operation = self.operation()
        config = self.project.config
        config["exclude"] = [operation["url"]]
        self.project.set_config(config)
        self.expire(session)
        row = self.row(operation)
        self.assertIn("authorized_operation_scope", row["missing_prerequisites"])
        self.assert_no_renewal(row)

    def test_rpc_renewal_controls_survive_short_credential_collisions(self):
        for secret in ("true", "root", "false", "1"):
            with self.subTest(secret=secret):
                session = self.rpc_session(secret)
                operation = self.operation()
                self.expire(session)
                row = self.rpc_row(operation, session["actor_id"])
                self.assertEqual("blocked", row["queue_status"])
                candidate = row["session_renewal_candidates"][0]
                self.assertEqual(session["id"], candidate["session_id"])
                self.assertEqual(session["actor_id"], candidate["actor_id"])
                self.assertEqual(1, candidate["generation"])
                self.assertIs(candidate["input_template"]["renew"], True)
                self.assertIs(candidate["automatic_execution_allowed"], False)
                self.assertIs(candidate["renewal_is_login"], False)
                preparation = next(item for item in row["preparation_actions"]
                                   if item["prerequisite"] == "live_verified_session_for_actor")
                self.assertEqual({"session_id": session["id"], "renew": True}, preparation["input_template"])
                self.assertIs(preparation["automatic_execution_allowed"], False)
                self.assertNotIn(json.dumps(secret), json.dumps(row))
                with patch.object(engine, "request") as network:
                    dispatch(self.project.workspace, "identity.session", {"project_id": "renewal", **preparation["input_template"]})
                network.assert_not_called()
                self.assertEqual(session["generation"], self.project.get("session", session["id"])["generation"])

    def test_rpc_credential_collision_does_not_add_a_foreign_origin_renewal(self):
        session = self.rpc_session("true", origin=self.other)
        operation = self.operation()
        self.expire(session)
        self.assert_no_renewal(self.rpc_row(operation, session["actor_id"]))

    def test_rpc_missing_role_proof_does_not_add_a_restricted_renewal(self):
        session = self.rpc_session("root", roles=(), role_assertion=False)
        operation = self.operation()
        self.expire(session)
        self.assert_no_renewal(self.rpc_row(operation, session["actor_id"], "access"))

    def test_renewal_schema_does_not_restore_untrusted_text_as_controls(self):
        self.rpc_session("root")
        with patch.object(engine, "request") as network:
            public = publication.publish(self.project, "plan.next", {"work_items": [{
                "session_renewal_candidates": [{"session_id": "root", "actor_id": "root", "generation": "root",
                    "action": "root", "input_template": {"session_id": "root", "renew": "root", "unregistered": "root"},
                    "automatic_execution_allowed": "root", "renewal_is_login": "root", "unregistered": "root"}]}]})
        network.assert_not_called()
        self.assertNotIn('"root"', json.dumps(public))
        self.assertIsNot(public["work_items"][0]["session_renewal_candidates"][0]["input_template"]["renew"], True)


if __name__ == "__main__":
    unittest.main()
