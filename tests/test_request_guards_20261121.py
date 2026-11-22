"""Private browser/sqlmap guards reject unsanctioned transport without egress."""
from __future__ import annotations

import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

from awa_ddd import engine, execution_coordinator as coordinator
from awa_ddd import ipc
from awa_ddd.store import Project
import v2_fixtures as fx


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _environment():
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(PROJECT_ROOT)
    environment.pop("AWA_DDD_REQUEST_NONCE", None)
    environment.pop("AWA_DDD_IPC_REQUEST_HASH", None)
    return environment


def _run_module(module, argument, *, environment=None):
    return subprocess.run(
        [sys.executable, "-X", "utf8", "-B", "-m", module, str(argument)],
        cwd=PROJECT_ROOT,
        env=environment or _environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )


class _CountingHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        with self.server.count_lock:
            self.server.request_count += 1
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        return


class GuardFixture(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _CountingHandler)
        self.server.request_count = 0
        self.server.count_lock = threading.Lock()
        self.server_thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.server_thread.start()
        self.addCleanup(self.server_thread.join, 5)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        target = "http://127.0.0.1:" + str(self.server.server_address[1]) + "/"
        self.temporary, self.root = fx.workspace(target, allow_mutation=True)
        self.addCleanup(self.temporary.cleanup)
        self.project = fx.project(self.root)
        self.addCleanup(self.project.close)
        self.operation = fx.register(self.project, target, "GET", "public")
        self.target = target
        self.artifacts = Path(self.root) / "guard-fixtures"
        self.artifacts.mkdir()

    def browser_lease(self):
        run = {
            "id": "RUN-browser-guard",
            "kind": "browser",
            "status": "running",
            "target_origin": self.target.rstrip("/"),
            "allow_write": True,
        }
        self.project.put("run", run)
        return coordinator.claim(self.project, "browser.visit:" + run["id"])

    def browser_decision(self, *, method="GET", url=None, operation=None, resource=None,
                         body=b"", content_type=None, bind_reads=True,
                         max_requests=1, max_writes=0, occurrence=1,
                         lease=None):
        lease = lease or self.browser_lease()
        spec = {
            "workspace": str(self.project.workspace),
            "project_id": self.project.project_id,
            "run_id": "RUN-browser-guard",
            "target": self.target,
            "operation": operation,
            "resource": resource,
            "bind_reads": bind_reads,
            "lease": lease,
            "budget_name": "browser-request-slots:RUN-browser-guard",
            "max_requests": max_requests,
            "max_writes": max_writes,
            "occurrence": occurrence,
            "request": {
                "url": url or self.target,
                "method": method,
                "request_body_sha256": hashlib.sha256(body).hexdigest(),
                "request_body_base64": base64.b64encode(body).decode("ascii"),
                "content_type": content_type,
                "resource_type": "document",
                "action_index": None,
            },
        }
        path = self.artifacts / ("browser-request-" + str(occurrence) + ".json")
        path.write_text(json.dumps(spec), encoding="utf-8")
        completed = _run_module("awa_ddd.request_guard", path)
        return completed, json.loads(completed.stdout.strip().splitlines()[-1])

    def sqlmap_run(self, source, *, method="GET", url=None, operation=None,
                   max_requests=1, max_writes=0, effect="read_only",
                   run_id="RUN-sqlmap-guard"):
        run_artifacts = self.artifacts / run_id
        run_artifacts.mkdir()
        script = run_artifacts / "sqlmap-fixture.py"
        script.write_text(source, encoding="utf-8")
        stdout = run_artifacts / "stdout.log"
        stderr = run_artifacts / "stderr.log"
        summary = run_artifacts / "guard-summary.json"
        lease = coordinator.claim(self.project, "tool.sqlmap:" + run_id)
        spec = {
            "workspace": str(self.project.workspace),
            "project_id": self.project.project_id,
            "run_id": run_id,
            "action": "tool.sqlmap",
            "target_url": self.target,
            "operation": operation or self.operation,
            "lease": lease,
            "budget_name": "request-slots:sqlmap:" + run_id,
            "max_requests": max_requests,
            "max_writes": max_writes,
            "effect": effect,
            "executable": str(script.resolve()),
            "argv": [url or self.target, "2"],
            "stdout_path": str(stdout),
            "stderr_path": str(stderr),
            "summary_path": str(summary),
        }
        spec_path = run_artifacts / "sqlmap-guard.json"
        spec_path.write_text(json.dumps(spec), encoding="utf-8")
        completed = _run_module("awa_ddd.sqlmap_guard", spec_path)
        guarded = json.loads(summary.read_text(encoding="utf-8"))
        return completed, guarded, stdout, stderr


class BrowserRequestGuardTests(GuardFixture):
    def test_one_request_slot_allows_one_dispatch_and_denies_the_second(self):
        lease = self.browser_lease()
        first, first_decision = self.browser_decision(lease=lease, occurrence=1)
        second, second_decision = self.browser_decision(lease=lease, occurrence=2)
        self.assertEqual(0, first.returncode, first.stderr)
        self.assertTrue(first_decision["ok"])
        self.assertEqual(2, second.returncode)
        self.assertEqual("execution_budget_exhausted", second_decision["reason"])
        dispatches = [
            row for row in self.project.list("execution_dispatch")
            if row.get("budget_name") == "browser-request-slots:RUN-browser-guard"
        ]
        self.assertEqual(["request_slots"], [row["budget_unit"] for row in dispatches])
        self.assertEqual([1], [row["requests"] for row in dispatches])

    def test_write_without_operation_is_rejected_even_before_budget_dispatch(self):
        lease = self.browser_lease()
        completed, decision = self.browser_decision(
            lease=lease, method="POST", max_requests=1, max_writes=0)
        self.assertEqual(2, completed.returncode)
        self.assertEqual("resource_binding", decision["reason"])
        self.assertEqual(
            [], [
                row for row in self.project.list("execution_dispatch")
                if row.get("budget_name") == "browser-request-slots:RUN-browser-guard"
            ])

    def test_scope_and_operation_binding_denials_precede_dispatch(self):
        lease = self.browser_lease()
        outside, outside_decision = self.browser_decision(
            lease=lease, url="http://outside.invalid/", occurrence=1)
        self.assertEqual(2, outside.returncode)
        self.assertEqual("out_of_scope", outside_decision["reason"])

        mismatch, mismatch_decision = self.browser_decision(
            lease=lease, method="POST", operation=self.operation, occurrence=2,
            max_requests=1, max_writes=1)
        self.assertEqual(2, mismatch.returncode)
        self.assertEqual("operation_binding", mismatch_decision["reason"])
        self.assertEqual(
            [], [
                row for row in self.project.list("execution_dispatch")
                if row.get("budget_name") == "browser-request-slots:RUN-browser-guard"
            ])

    def test_exact_operation_and_query_fixture_allow_one_write(self):
        operation = fx.register(self.project, self.target + "store", "POST", "public")
        actor = engine.add_actor(self.project, {"actor_id": "fixture-owner", "roles": []})
        resource = engine.add_resource(self.project, {
            "operation_id": operation["id"], "owner_actor_id": actor["id"],
            "external_id": "fixture-1", "request_binding": {"location": "query", "selector": "id"}})
        lease = self.browser_lease()
        run = self.project.get("run", "RUN-browser-guard")
        run.update(effect="test_resource_write", operation_id=operation["id"],
                   operation_signature=engine.operation_signature(operation), resource_id=resource["id"],
                   resource_signature=engine.resource_signature(resource))
        self.project.put("run", run)
        completed, decision = self.browser_decision(
            method="POST", url=self.target + "store?id=fixture-1", operation=operation,
            resource=resource, max_requests=1, max_writes=1, lease=lease)
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertTrue(decision["ok"])
        other, other_decision = self.browser_decision(
            method="POST", url=self.target + "store?id=other", operation=operation,
            resource=resource, max_requests=2, max_writes=1, occurrence=2, lease=lease)
        self.assertEqual(2, other.returncode)
        self.assertEqual("resource_mismatch", other_decision["reason"])


class SqlmapRequestGuardTests(GuardFixture):
    def _two_request_source(self, request_expression):
        return (
            "import urllib.request\n"
            "import sys\n"
            "target, attempts = sys.argv[1], int(sys.argv[2])\n"
            "for _index in range(attempts):\n"
            "    try:\n"
            + "".join("        " + line + "\n" for line in request_expression.splitlines())
            + "    except BaseException:\n"
            "        pass\n"
        )

    def test_budget_consumes_before_transport_and_denies_the_second_request(self):
        source = self._two_request_source(
            "with urllib.request.urlopen(target) as response:\n"
            "    response.read()")
        completed, guarded, _, _ = self.sqlmap_run(source)
        self.assertEqual(1, completed.returncode, (completed.stderr, guarded))
        self.assertEqual(1, self.server.request_count)
        self.assertEqual(1, guarded["requests_attempted"])
        self.assertEqual(1, guarded["guarded_requests"])
        self.assertEqual("execution_budget_exhausted", guarded["denied_requests"][0]["reason"])
        self.assertFalse(guarded["complete"])
        dispatches = [
            row for row in self.project.list("execution_dispatch")
            if row.get("budget_name") == "request-slots:sqlmap:RUN-sqlmap-guard"
        ]
        self.assertEqual(["request_slots"], [row["budget_unit"] for row in dispatches])
        self.assertEqual(1, len(dispatches))

    def test_wrong_method_and_out_of_scope_are_denied_before_connection(self):
        wrong_method = self._two_request_source(
            "with urllib.request.urlopen(urllib.request.Request(target, method='POST')) as response:\n"
            "    response.read()")
        completed, guarded, _, _ = self.sqlmap_run(wrong_method, method="GET")
        self.assertEqual(1, completed.returncode, (completed.stderr, guarded))
        self.assertEqual(0, self.server.request_count)
        self.assertEqual("operation_binding", guarded["denied_requests"][0]["reason"])

        outside = self._two_request_source(
            "with urllib.request.urlopen(target) as response:\n"
            "    response.read()")
        outside_url = "http://127.0.0.1:" + str(self.server.server_address[1] + 1) + "/"
        completed, guarded, stdout, _ = self.sqlmap_run(
            outside, url=outside_url, run_id="RUN-sqlmap-outside")
        self.assertEqual(
            1, completed.returncode,
            (completed.stderr, guarded, stdout.read_text(encoding="utf-8")))
        self.assertEqual(0, self.server.request_count)
        self.assertEqual("out_of_scope", guarded["denied_requests"][0]["reason"])

    def test_socket_or_dns_bypass_is_detected_and_makes_the_run_untrusted(self):
        source = (
            "import socket\n"
            "import sys\n"
            "try:\n"
            "    socket.getaddrinfo('outside.invalid', 443)\n"
            "except BaseException:\n"
            "    pass\n"
        )
        completed, guarded, _, _ = self.sqlmap_run(source)
        self.assertEqual(1, completed.returncode)
        self.assertGreaterEqual(guarded["unguarded_socket_attempts"], 1)
        self.assertFalse(guarded["complete"])

    def test_private_sqlmap_stderr_stays_out_of_the_bridge_channel(self):
        source = (
            "import sys\n"
            "sys.stderr.write('PRIVATE-SQLMAP-DIAGNOSTIC\\n')\n"
            "sys.stderr.flush()\n"
        )
        completed, guarded, _, stderr = self.sqlmap_run(source)
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertTrue(guarded["complete"])
        self.assertEqual("", completed.stderr)
        self.assertIn("PRIVATE-SQLMAP-DIAGNOSTIC", stderr.read_text(encoding="utf-8"))


class CrossProcessIpcTests(unittest.TestCase):
    def test_parent_and_child_receipts_share_nonce_request_hash_and_sequence(self):
        nonce = hashlib.sha256(b"cross-process-ipc-fixture").hexdigest()
        lock_path, sequence_path = ipc._sequence_files(nonce)
        self.addCleanup(lambda: lock_path.unlink(missing_ok=True))
        self.addCleanup(lambda: sequence_path.unlink(missing_ok=True))
        child = (
            "from awa_ddd import ipc\n"
            "ipc.emit_dispatch('browser.visit', 'RUN-provider-child', '"
            + "e" * 64 + "')\n"
        )
        parent = (
            "import os, subprocess, sys\n"
            "from awa_ddd import ipc\n"
            "ipc.emit('startup')\n"
            "ipc.accepted(b'{\"fixture\":true}', 'browser.visit')\n"
            "ipc.emit_dispatch('browser.visit', 'RUN-provider', '"
            + "d" * 64 + "')\n"
            "subprocess.run([sys.executable, '-X', 'utf8', '-B', '-c', "
            + repr(child) + "], check=True)\n"
        )
        environment = _environment()
        environment["AWA_DDD_REQUEST_NONCE"] = nonce
        completed = subprocess.run(
            [sys.executable, "-X", "utf8", "-B", "-c", parent],
            cwd=PROJECT_ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            timeout=30,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        rows = [json.loads(line) for line in completed.stderr.splitlines() if line.strip()]
        self.assertEqual([1, 2, 3, 4], [row["seq"] for row in rows])
        self.assertEqual(["startup", "accepted", "dispatch", "dispatch"],
                         [row["phase"] for row in rows])
        accepted_hash = hashlib.sha256(b'{"fixture":true}').hexdigest()
        self.assertEqual([accepted_hash], sorted({row["request_hash"] for row in rows[1:]}))
        self.assertEqual(["d" * 64, "e" * 64],
                         sorted(row["dispatch_hash"] for row in rows[2:]))


if __name__ == "__main__":
    unittest.main()
