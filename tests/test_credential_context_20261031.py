"""Private credential integrity never publishes a low-entropy password oracle."""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import engine
from awa_ddd.__main__ import dispatch
from awa_ddd.reporting import public_integrity_metadata
from awa_ddd.store import EngineError, Project, now


def observation(url, method, headers, body, timeout, max_bytes):
    raw = b'{"subject":"alice","roles":["user"],"value":"fixture"}'
    return {"request": {"url": url, "method": method, "headers": headers, "body_base64": ""},
        "response": {"status": 200, "headers": [], "length": len(raw),
            "body_base64": base64.b64encode(raw).decode("ascii")},
        "complete": True, "started_at": now(), "completed_at": now()}


class CredentialContextTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="awa-private-credential-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.base = "http://credential.fixture.invalid"
        engine.create_project(self.root, {"project_id": "credential", "target": self.base})
        self.project = Project(self.root, "credential")
        self.addCleanup(self.project.close)
        engine.add_actor(self.project, {"actor_id": "alice", "subject": "alice", "roles": ["user"]})
        self.operation = engine.register_operation(self.project, {"url": self.base + "/profile",
            "method": "GET", "auth": "authenticated"})
        self.credential = "000012"

    def session(self, **extra):
        return engine.add_session(self.project, {"actor_id": "alice", "headers": {"X-OTP": self.credential},
            "credential_header_names": ["X-OTP"], **extra})

    def verify(self, session):
        with patch.object(engine, "request", side_effect=observation):
            return engine.verify_identity(self.project, {"operation_id": self.operation["id"],
                "session_id": session["id"], "subject_selector": "/subject", "roles_selector": "/roles"})

    def test_new_generations_have_unpublished_random_credential_context(self):
        first = self.session()
        second = self.session()
        records = [self.project.get("session", item["id"]) for item in (first, second)]
        for public, private in zip((first, second), records):
            self.assertNotIn("headers", public)
            self.assertNotIn("credential_nonce", public)
            self.assertNotIn("credential_signature", public)
            self.assertRegex(private["credential_nonce"], r"^[a-f0-9]{64}$")
            unsalted = engine.credential_signature({"headers": private["headers"],
                "credential_header_names": private["credential_header_names"]})
            self.assertNotEqual(unsalted, private["credential_signature"])
        self.assertNotEqual(records[0]["credential_nonce"], records[1]["credential_nonce"])
        self.assertNotEqual(records[0]["credential_signature"], records[1]["credential_signature"])

    def test_nonce_never_enters_target_headers_and_matching_snapshots_verify(self):
        session = self.session()
        verified = self.verify(session)
        private = self.project.get("session", session["id"])
        evidence, artifact = engine.verify_current_evidence(self.project, verified["evidence_id"])
        self.assertEqual({"x-otp": self.credential}, artifact["request"]["headers"])
        self.assertNotIn(private["credential_nonce"], json.dumps(artifact))
        self.assertEqual(private["credential_signature"], evidence["credential_signature"])
        self.assertNotIn("credential_nonce", json.dumps(verified))
        self.assertNotIn("credential_signature", json.dumps(verified))

    def test_renewal_preserves_salt_signature_generation_and_existing_evidence(self):
        session = self.session()
        verified = self.verify(session)
        before = copy.deepcopy(self.project.get("session", session["id"]))
        with patch.object(engine, "request") as network:
            public = engine.add_session(self.project, {"session_id": session["id"], "renew": True})
            engine.verify_current_evidence(self.project, verified["evidence_id"])
        network.assert_not_called()
        after = self.project.get("session", session["id"])
        for key in ("credential_nonce", "credential_signature", "generation", "headers", "verification_evidence_id"):
            self.assertEqual(before[key], after[key])
        self.assertNotIn("credential_nonce", public)

    def test_new_session_generation_changes_context_without_overwriting_old_evidence(self):
        session = self.session()
        verified = self.verify(session)
        before = self.project.get("session", session["id"])
        old = self.project.get("evidence", verified["evidence_id"])
        self.session(session_id=session["id"])
        current = self.project.get("session", session["id"])
        self.assertNotEqual(before["credential_nonce"], current["credential_nonce"])
        self.assertEqual(before["generation"] + 1, current["generation"])
        with self.assertRaises(EngineError) as caught:
            engine.verify_current_evidence(self.project, old["id"])
        self.assertEqual("session_changed", caught.exception.code)
        self.assertEqual(old, self.project.get("evidence", old["id"]))

    def test_missing_changed_or_malformed_salt_does_not_relabel_existing_evidence(self):
        session = self.session()
        verified = self.verify(session)
        original = self.project.get("session", session["id"])
        for value in (None, "changed", "b" * 64):
            candidate = copy.deepcopy(original)
            if value is None:
                candidate.pop("credential_nonce")
            else:
                candidate["credential_nonce"] = value
            self.project.put("session", candidate)
            with self.subTest(value=value), self.assertRaises(EngineError) as caught:
                engine.verify_current_evidence(self.project, verified["evidence_id"])
            self.assertEqual("credential_changed", caught.exception.code)
        self.project.put("session", original)

    def test_legacy_unsalted_sessions_keep_verifiable_private_lineage_without_publishing_hashes(self):
        session = self.session()
        legacy = self.project.get("session", session["id"])
        legacy.pop("credential_nonce")
        legacy["credential_signature"] = engine.credential_signature(legacy)
        self.project.put("session", legacy)
        verified = self.verify(session)
        engine.verify_current_evidence(self.project, verified["evidence_id"])
        self.assertNotIn("credential_signature", verified["session"])
        renewed = engine.add_session(self.project, {"session_id": session["id"], "renew": True})
        self.assertNotIn("credential_signature", renewed)
        self.assertNotIn("credential_nonce", self.project.get("session", session["id"]))

    def test_caller_cannot_choose_the_private_context_or_change_it_by_renewal(self):
        before = self.project.list("session")
        for field in ("credential_nonce", "credential_signature"):
            with self.subTest(field=field), self.assertRaises(EngineError) as caught:
                self.session(**{field: "a" * 64})
            self.assertEqual("credential_context", caught.exception.code)
        self.assertEqual(before, self.project.list("session"))
        session = self.session()
        with self.assertRaises(EngineError):
            engine.add_session(self.project, {"session_id": session["id"], "renew": True, "credential_nonce": "b" * 64})

    def test_public_digest_projection_removes_only_private_context_not_ordinary_integrity_controls(self):
        original = {"credential_signature": "private", "credentialNonce": "private", "nested": [
            {"redaction_context_sha256": "private", "sha256": "a" * 64, "count": 12, "status": 200}], "id": "E-fixture"}
        public = public_integrity_metadata(original)
        self.assertEqual({"nested": [{"sha256": "a" * 64, "count": 12, "status": 200}], "id": "E-fixture"}, public)
        self.assertEqual("private", original["credential_signature"])

    def test_actual_dispatch_does_not_publish_capture_or_run_credential_hashes(self):
        session = self.session()
        self.verify(session)
        with patch.object(engine, "request", side_effect=observation):
            evidence = dispatch(self.root, "http.capture", {"project_id": "credential", "operation_id": self.operation["id"],
                "session_id": session["id"]})
        run = dispatch(self.root, "run.inspect", {"project_id": "credential", "run_id": evidence["run_id"]})
        self.assertNotIn("credential_signature", json.dumps(evidence))
        self.assertNotIn("credential_nonce", json.dumps(run))
        self.assertNotIn("credential_signature", json.dumps(run))
        self.assertIn("credential_signature", self.project.get("evidence", evidence["id"]))


if __name__ == "__main__":
    unittest.main()
