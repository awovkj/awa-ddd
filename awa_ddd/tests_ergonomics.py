"""Regression for the tool-call ergonomics pass (offline; no network)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

PACKAGE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(PACKAGE)


def call(workspace, action, args):
    process = subprocess.run(
        [sys.executable, "-m", "awa_ddd", "--workspace", workspace],
        input=json.dumps({"action": action, "args": args}),
        text=True, capture_output=True, cwd=PACKAGE,
        env={**os.environ, "PYTHONPATH": PACKAGE})
    try:
        return json.loads(process.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "error": {"code": "unparseable", "raw": process.stdout[:400]}}


class ToolCallErgonomics(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.workspace = self.tmp.name
        created = call(self.workspace, "project.create", {
            "project_id": "erg", "target": "http://example.test/",
            "scope": ["http://example.test/"]})
        self.assertTrue(created["ok"], created)

    def tearDown(self):
        self.tmp.cleanup()

    def test_invalid_auth_lists_the_supported_values(self):
        result = call(self.workspace, "surface.register", {
            "project_id": "erg", "url": "http://example.test/api/x",
            "method": "GET", "auth": "session"})
        self.assertFalse(result["ok"])
        message = result["error"]["message"]
        for value in ("public", "authenticated", "restricted", "unknown"):
            self.assertIn(value, message)

    def test_non_boolean_ownership_is_rejected_not_coerced(self):
        result = call(self.workspace, "surface.register", {
            "project_id": "erg", "url": "http://example.test/api/y",
            "method": "GET", "auth": "public", "ownership": "none"})
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "ownership")

    def test_boolean_ownership_is_still_accepted(self):
        result = call(self.workspace, "surface.register", {
            "project_id": "erg", "url": "http://example.test/api/z",
            "method": "GET", "auth": "public", "ownership": True})
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["data"]["ownership"])

    def test_allow_mutation_can_be_enabled_without_recreating(self):
        updated = call(self.workspace, "project.update", {
            "project_id": "erg", "allow_mutation": True})
        self.assertTrue(updated["ok"], updated)
        self.assertTrue(updated["data"]["changed"])
        self.assertTrue(updated["data"]["config"]["allow_mutation"])
        again = call(self.workspace, "project.update", {
            "project_id": "erg", "allow_mutation": True})
        self.assertTrue(again["ok"])
        self.assertFalse(again["data"]["changed"])

    def test_actor_roles_can_be_corrected_in_place(self):
        first = call(self.workspace, "identity.actor", {
            "project_id": "erg", "actor_id": "u1", "label": "u1", "roles": ["user"]})
        self.assertTrue(first["ok"], first)
        second = call(self.workspace, "identity.actor", {
            "project_id": "erg", "actor_id": "u1", "label": "u1", "roles": []})
        self.assertTrue(second["ok"], second)
        self.assertEqual(second["data"]["roles"], [])

    def test_roles_selector_requirement_explains_the_workaround(self):
        call(self.workspace, "identity.actor", {
            "project_id": "erg", "actor_id": "r1", "label": "r1",
            "roles": ["admin"], "subject": "admin"})
        result = call(self.workspace, "identity.verify", {
            "project_id": "erg", "session_id": "missing", "operation_id": "O-x",
            "subject_selector": "/user"})
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
