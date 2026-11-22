"""Runtime/browser/external-tool hardening regressions; all fixtures are local."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import queue
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from awa_ddd import engine, external, runtime, transport, tscanplus
from awa_ddd.store import EngineError, Project
from test_tscanplus_20261030 import FakeClient, catalog, mcp_result


class TrustedExecutableTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="awa-trusted-tool-")
        self.addCleanup(self.temporary.cleanup)
        self.executable = Path(self.temporary.name) / "sqlmap.py"
        self.executable.write_text("# trusted fixture\n", encoding="utf-8")
        self.other = Path(self.temporary.name) / "other" / "sqlmap.py"
        self.other.parent.mkdir()
        self.other.write_text("# same name, different file\n", encoding="utf-8")

    def configure(self, path, digest=""):
        return patch.dict("os.environ", {external.TRUSTED_SQLMAP_ENV: json.dumps({
            "path": str(path), "sha256": digest})}, clear=True)

    def test_only_exact_admin_path_and_digest_are_accepted(self):
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(EngineError) as missing:
                external._executable(str(self.executable), "sqlmap_path")
        self.assertEqual("admin_not_configured", missing.exception.details["reason_code"])

        digest = hashlib.sha256(self.executable.read_bytes()).hexdigest()
        with self.configure(self.executable.resolve(), digest):
            self.assertEqual(self.executable.resolve(), external._executable(
                str(self.executable), "sqlmap_path"))
            with self.assertRaises(EngineError) as other:
                external._executable(str(self.other), "sqlmap_path")
            self.assertEqual("untrusted_path", other.exception.details["reason_code"])
            self.executable.write_text("# changed after administration\n", encoding="utf-8")
            with self.assertRaises(EngineError) as changed:
                external._executable(str(self.executable), "sqlmap_path")
            self.assertEqual("sha256_mismatch", changed.exception.details["reason_code"])


class YakBoundedReaderTests(unittest.TestCase):
    def client(self):
        client = object.__new__(external.MCPClient)
        client.queue = queue.Queue()
        client.noise = []
        client._bytes = 0
        client._reader_error = False
        client._lock = threading.Lock()
        class Process:
            def poll(self):
                return 0
        client.process = Process()
        return client

    def test_unterminated_json_line_is_delivered_without_waiting_for_newline(self):
        client = self.client()
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}).encode("utf-8")
        client._read(io.BytesIO(payload), True)
        self.assertEqual(1, client.queue.get_nowait()["id"])
        self.assertIsNone(client.queue.get_nowait())

    def test_unterminated_oversized_line_fails_before_unbounded_accumulation(self):
        client = self.client()
        with patch.object(external, "MAX_MCP_LINE_BYTES", 16):
            client._read(io.BytesIO(b"x" * 17), True)
        error = client.queue.get_nowait()
        self.assertIsInstance(error, EngineError)
        self.assertEqual("tool_output_budget", error.code)
        self.assertIsNone(client.queue.get_nowait())

    def test_binary_mcp_transport_writes_utf8_bytes(self):
        client = self.client()
        client.deadline = time.monotonic() + 1
        client.sequence = 0
        client.exchanges = []
        writes = []
        class Input:
            def write(self, value):
                self.value = value
                writes.append(value)
            def flush(self):
                pass
        client.process.stdin = Input()
        client.queue.put({"jsonrpc": "2.0", "id": 1, "result": {"ready": True}})
        self.assertEqual({"ready": True}, client.call("initialize"))
        self.assertEqual(1, len(writes))
        self.assertIsInstance(writes[0], bytes)
        self.assertEqual("initialize", json.loads(writes[0])["method"])


class TransportDeadlineTests(unittest.TestCase):
    def test_total_deadline_covers_a_peer_that_never_starts_the_status_line(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def peer():
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(1)
                try:
                    connection.recv(4096)
                except OSError:
                    pass
                time.sleep(0.8)
            listener.close()

        thread = threading.Thread(target=peer, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(listener.close)
        started = time.monotonic()
        artifact = transport.request("http://127.0.0.1:%d/" % port, timeout=0.15)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 0.75)
        self.assertFalse(artifact["complete"])
        self.assertIsNone(artifact["response"]["status"])
        self.assertEqual("TimeoutError", artifact["error"])


class TscanTerminalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="awa-tscan-terminal-")
        self.addCleanup(self.temporary.cleanup)
        self.base = "http://fixture.invalid"
        engine.create_project(self.temporary.name, {"project_id": "terminal", "target": self.base,
                                                    "allow_mutation": True})
        self.project = Project(self.temporary.name, "terminal")
        self.addCleanup(self.project.close)
        FakeClient.clients, FakeClient.calls, FakeClient.tools, FakeClient.handler = [], [], catalog(), None
        patched = patch.object(tscanplus, "StreamableHTTPClient", FakeClient)
        patched.start()
        self.addCleanup(patched.stop)
        tscanplus.probe(self.project, {"adapter": "tscanplus"})
        self.actor = engine.add_actor(self.project, {"actor_id": "owner", "roles": []})
        self.operation = engine.register_operation(self.project, {
            "url": self.base + "/store", "method": "POST", "auth": "public",
            "content_type": "application/json"})
        self.resource = engine.add_resource(self.project, {
            "operation_id": self.operation["id"], "owner_actor_id": self.actor["id"],
            "external_id": "fixture-1", "request_binding": {"location": "body", "selector": "/id"}})
        self.args = {"operation_id": self.operation["id"], "resource_id": self.resource["id"],
                     "effect": "test_resource_write", "body": {"id": "fixture-1"}}

    def test_empty_success_data_retains_unknown_write_and_lease(self):
        FakeClient.handler = lambda name, values: mcp_result({})
        with self.assertRaises(EngineError) as caught:
            tscanplus.request_run(self.project, self.args)
        self.assertEqual("tscanplus_result", caught.exception.code)
        run = self.project.get("run", caught.exception.details["run_id"])
        self.assertEqual("failed", run["status"])
        self.assertIsNone(run["target_traffic_sent"])
        self.assertTrue(run["effect_unknown"])
        self.assertTrue(run["remote_state_unknown"])
        self.assertFalse(run["lease_released"])
        self.assertFalse(run.get("lease_reconciled", False))
        self.assertIsNotNone(self.project.connection.execute(
            "SELECT 1 FROM execution_leases WHERE name=?", ("tscanplus:" + run["id"],)).fetchone())

        FakeClient.handler = lambda name, values: mcp_result({"status_code": 204, "truncated": False})
        result = tscanplus.request_run(self.project, self.args)
        self.assertEqual("succeeded", result["status"])
        self.assertTrue(result["target_traffic_sent"])
        self.assertFalse(result["effect_unknown"])
        self.assertTrue(result["lease_reconciled"])


class EnvironmentTests(unittest.TestCase):
    def test_subprocess_environment_drops_interpreter_and_proxy_injection(self):
        source = {"NODE_OPTIONS": "--require evil", "PYTHONPATH": "/tmp/evil",
                  "HTTPS_PROXY": "http://proxy.invalid", "PATH": os.environ.get("PATH", ""),
                  "AWA_DDD_REQUEST_NONCE": "a" * 64}
        with patch.dict("os.environ", source, clear=True):
            cleaned = runtime.clean_environment()
        self.assertEqual("a" * 64, cleaned["AWA_DDD_REQUEST_NONCE"])
        self.assertEqual(source["PATH"], cleaned["PATH"])
        for key in ("NODE_OPTIONS", "PYTHONPATH", "HTTPS_PROXY"):
            self.assertNotIn(key, cleaned)


if __name__ == "__main__":
    unittest.main()
