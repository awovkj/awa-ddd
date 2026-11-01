"""Actor self-state cannot hide a resource selector in a header or cookie."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import engine
from awa_ddd.scenario import preflight, run_scenario
from awa_ddd.store import EngineError, Project, now


def observation(url, method, headers, body, timeout, max_bytes):
    raw = json.dumps({"subject": "alice", "roles": ["user"], "value": "fixture"}).encode("utf-8")
    encoded = body if isinstance(body, bytes) else body.encode("utf-8") if isinstance(body, str) else b""
    return {"request": {"url": url, "method": method, "headers": headers,
            "body_base64": base64.b64encode(encoded).decode("ascii")},
        "response": {"status": 200, "headers": [], "length": len(raw),
            "body_base64": base64.b64encode(raw).decode("ascii")},
        "complete": True, "started_at": now(), "completed_at": now()}


class ActorWriteBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="awa-actor-header-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.base = "http://actor.fixture.invalid"
        engine.create_project(self.root, {"project_id": "actor-header", "target": self.base, "allow_mutation": True})
        self.project = Project(self.root, "actor-header")
        self.addCleanup(self.project.close)
        self.identity = engine.register_operation(self.project, {"url": self.base + "/identity", "method": "GET",
            "auth": "authenticated"})
        engine.add_actor(self.project, {"actor_id": "alice", "subject": "alice", "roles": ["user"]})
        self.session = self.verified_session({"Cookie": "synthetic-session=alice"})
        self.operation = engine.register_operation(self.project, {"url": self.base + "/self-state", "method": "POST",
            "auth": "authenticated", "state_scope": "actor"})

    def verified_session(self, headers, credential_names=None):
        args = {"actor_id": "alice", "headers": headers}
        if credential_names is not None:
            args["credential_header_names"] = credential_names
        session = engine.add_session(self.project, args)
        with patch.object(engine, "request", side_effect=observation):
            engine.verify_identity(self.project, {"operation_id": self.identity["id"], "session_id": session["id"],
                "subject_selector": "/subject", "roles_selector": "/roles"})
        return session

    def args(self, **extra):
        return {"operation_id": self.operation["id"], "session_id": self.session["id"],
            "effect": "test_resource_write", **extra}

    def rejects(self, args, code="operation_effect"):
        before = self.project.list("run")
        with patch.object(engine, "request") as network:
            for action in (engine.preflight_capture, engine.capture):
                with self.subTest(action=action.__name__), self.assertRaises(EngineError) as caught:
                    action(self.project, args)
                self.assertEqual(code, caught.exception.code)
        network.assert_not_called()
        self.assertEqual(before, self.project.list("run"))

    def test_header_and_cookie_input_declarations_cannot_use_actor_self_state(self):
        before = self.project.list("operation")
        for location in ("header", "cookie"):
            with self.subTest(location=location), self.assertRaises(EngineError) as caught:
                engine.register_operation(self.project, {"url": self.base + "/self-" + location,
                    "method": "POST", "auth": "authenticated", "state_scope": "actor",
                    "inputs": [{"name": "x-resource-id", "location": location, "consumer": "resource_reference"}]})
            self.assertEqual("state_scope", caught.exception.code)
        self.assertEqual(before, self.project.list("operation"))

    def test_undeclared_business_header_cannot_hide_a_foreign_resource(self):
        for name in ("x-resource-id", "X-Owner-Id", "x-user-id", "x-tenant-id"):
            with self.subTest(name=name):
                self.rejects(self.args(headers={name: "foreign-fixture-resource"}))

    def test_unclassified_session_business_header_is_not_an_identity_binding(self):
        session = self.verified_session({"Cookie": "synthetic-session=alice", "x-resource-id": "foreign-fixture-resource"})
        self.rejects(self.args(session_id=session["id"]))

    def test_management_headers_and_verified_cookie_preserve_valid_self_state(self):
        headers = {"Accept": "application/json", "Accept-Language": "en", "Content-Type": "text/plain",
            "Cache-Control": "no-cache", "Pragma": "no-cache", "User-Agent": "awa-local-fixture"}
        with patch.object(engine, "request", side_effect=observation) as network:
            evidence = engine.capture(self.project, self.args(headers=headers))
        network.assert_called_once()
        self.assertIsNone(evidence["resource_id"])
        self.assertEqual(evidence, engine.verify_current_evidence(self.project, evidence["id"])[0])

    def test_classified_verified_custom_credentials_do_not_become_business_headers(self):
        session = self.verified_session({"x-custom-auth": "synthetic-credential"}, ["x-custom-auth"])
        with patch.object(engine, "request", side_effect=observation) as network:
            evidence = engine.capture(self.project, self.args(session_id=session["id"]))
        network.assert_called_once()
        self.assertIsNone(evidence["resource_id"])
        self.assertEqual(evidence, engine.verify_current_evidence(self.project, evidence["id"])[0])

    def test_legacy_fixture_free_business_header_write_stays_private_but_not_current(self):
        with patch.object(engine, "_actor_bound_write", return_value=True), \
                patch.object(engine, "request", side_effect=observation):
            evidence = engine.capture(self.project, self.args(headers={"x-resource-id": "foreign-fixture-resource"}))
        original = self.project.read_artifact(evidence)
        with self.assertRaises(EngineError) as caught:
            engine.verify_current_evidence(self.project, evidence["id"])
        self.assertEqual("resource_unbound", caught.exception.code)
        self.assertEqual(original, self.project.read_artifact(evidence))

    def test_legacy_declared_header_input_is_blocked_before_dispatch(self):
        legacy = self.project.get("operation", self.operation["id"])
        legacy["inputs"] = [{"name": "x-resource-id", "selector": "x-resource-id", "location": "header",
            "consumer": "resource_reference"}]
        self.project.put("operation", legacy)
        self.rejects(self.args(headers={"x-resource-id": "foreign-fixture-resource"}))

    def test_scenario_and_preflight_use_the_same_business_header_boundary(self):
        scenario = {"scenario": {"steps": [{"id": "one", **self.args(headers={"x-resource-id": "foreign-fixture-resource"})}]}}
        before = self.project.list("run")
        with patch.object(engine, "request") as network:
            result = preflight(self.project, scenario)
            self.assertFalse(result["static_valid"])
            with self.assertRaises(EngineError) as caught:
                run_scenario(self.project, scenario)
        self.assertEqual("scenario_preflight", caught.exception.code)
        network.assert_not_called()
        self.assertEqual(before, self.project.list("run"))

    def test_model_cannot_supply_executor_headers_even_with_the_correct_host(self):
        self.rejects(self.args(headers={"Host": "actor.fixture.invalid"}), "headers")

    def test_managed_private_framing_remains_eligible_only_with_exact_executor_values(self):
        session = self.project.get("session", self.session["id"])
        actual = {**session["headers"], "host": "actor.fixture.invalid", "content-length": "0",
            "accept-encoding": "identity", "connection": "close"}
        self.assertTrue(engine._actor_bound_write(self.operation, session, headers=actual))
        for name, value in (("host", "foreign.invalid"), ("content-length", "5"), ("accept-encoding", "gzip"),
                            ("connection", "keep-alive")):
            with self.subTest(name=name):
                self.assertFalse(engine._actor_bound_write(self.operation, session, headers={**actual, name: value}))


if __name__ == "__main__":
    unittest.main()
