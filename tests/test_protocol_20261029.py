"""Validate the complete JSON request before any project mutation."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from awa_ddd.__main__ import dispatch
from awa_ddd.contracts import CONTRACTS
from awa_ddd.store import EngineError


ROOT = Path(__file__).resolve().parents[1]


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-protocol-")
        self.addCleanup(self.tmp.cleanup)

    def invoke(self, request, *, environment=None):
        raw = request if isinstance(request, bytes) else json.dumps(request).encode("utf-8")
        completed = subprocess.run([sys.executable, "-B", "-m", "awa_ddd", "--workspace", self.tmp.name],
                                   input=raw, capture_output=True, cwd=ROOT, timeout=15, env=environment)
        result = json.loads(completed.stdout.decode("utf-8", errors="strict"))
        self.assertEqual(completed.stderr, b"")
        return completed, result

    def test_surrogates_in_any_value_or_key_fail_before_project_creation(self):
        for value in ({"unused": "\ud800"}, {"\udfff": "value"}, {"nested": ["\udc00"]}):
            with self.subTest(value=ascii(value)):
                completed, result = self.invoke({"action": "project.create", "args": {
                    "project_id": "invalid", "target": "http://fixture.invalid", **value}})
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(result["error"]["code"], "invalid_input")
                self.assertFalse((Path(self.tmp.name) / "projects").exists())

    def test_direct_dispatch_rejects_nonfinite_values_and_non_json_shapes(self):
        circular = []
        circular.append(circular)
        values = [float("inf"), float("nan"), {1: "not a JSON key"}, b"bytes", circular, ("tuple",)]
        for value in values:
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(EngineError) as raised:
                    dispatch(self.tmp.name, "project.create", {
                        "project_id": "invalid", "target": "http://fixture.invalid", "unused": value})
                self.assertEqual(raised.exception.code, "invalid_input")
                self.assertFalse((Path(self.tmp.name) / "projects").exists())

    def test_large_exponent_is_rejected_before_creating_a_project(self):
        completed, result = self.invoke(b'{"action":"project.create","args":{"project_id":"invalid",'
                                        b'"target":"http://fixture.invalid","unused":1e309}}')
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(result["error"]["code"], "invalid_input")
        self.assertFalse((Path(self.tmp.name) / "projects").exists())

    def test_duplicate_protocol_keys_are_not_silently_selected(self):
        for raw in (b'{"action":"action.help","action":"project.list","args":{}}',
                    b'{"action":"project.create","args":{"project_id":"a","project_id":"b",'
                    b'"target":"http://fixture.invalid"}}'):
            completed, result = self.invoke(raw)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(result["error"]["code"], "invalid_input")
        self.assertFalse((Path(self.tmp.name) / "projects").exists())

    def test_nesting_and_item_budgets_apply_to_direct_dispatch(self):
        deep = "leaf"
        for _ in range(65):
            deep = [deep]
        for value in (deep, [None] * 100001):
            with self.assertRaises(EngineError) as raised:
                dispatch(self.tmp.name, "action.help", {"unused": value})
            self.assertEqual(raised.exception.code, "invalid_input")

    def test_native_cli_owns_utf8_even_with_an_ascii_environment(self):
        environment = {**os.environ, "PYTHONIOENCODING": "ascii", "PYTHONUTF8": "0"}
        completed, result = self.invoke({"action": "project.create", "args": {
            "project_id": "unicode", "target": "http://fixture.invalid"}}, environment=environment)
        self.assertEqual(completed.returncode, 0, result)
        label = "\u4e2d\u6587\U0001f680"
        completed, result = self.invoke({"action": "identity.actor", "args": {
            "project_id": "unicode", "actor_id": "alice", "subject": "alice", "label": label}},
            environment=environment)
        self.assertEqual(completed.returncode, 0, result)
        self.assertEqual(result["data"]["label"], label)
        self.assertIn(label.encode("utf-8"), completed.stdout)

    def test_valid_utf8_bom_and_json_emoji_pair_are_preserved(self):
        completed, result = self.invoke(b'\xef\xbb\xbf{"action":"action.help","args":{'
                                        b'"unused":"\\ud83d\\ude80"}}')
        self.assertEqual(completed.returncode, 0, result)
        self.assertEqual(result["data"]["action_count"], len(CONTRACTS))


if __name__ == "__main__":
    unittest.main()
