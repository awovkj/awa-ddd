"""Target dispatch fencing for external adapters and the local browser."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import v2_fixtures as fx
from awa_ddd import browser, external
from awa_ddd import execution_coordinator as coordinator
from awa_ddd.store import EngineError


class ExternalDispatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary, self.root = fx.workspace(
            "http://audit.invalid", allow_mutation=True)
        self.addCleanup(self.temporary.cleanup)
        self.project = fx.project(self.root)
        self.addCleanup(self.project.close)
        self.executable = Path(self.root) / "sqlmap.py"
        self.executable.write_text("# fixture\n", encoding="utf-8")
        trusted = patch.dict("os.environ", {external.TRUSTED_SQLMAP_ENV: json.dumps({
            "path": str(self.executable.resolve()), "sha256": ""})})
        trusted.start()
        self.addCleanup(trusted.stop)
        self.operation = fx.register(
            self.project, "http://audit.invalid/items", "GET", "public",
            [{"name": "sort", "location": "query", "selector": "sort",
              "consumer": "sql_order_by"}])
        self.args = {
            "sqlmap_path": str(self.executable),
            "operation_id": self.operation["id"],
            "url": self.operation["url"] + "?sort=price",
            "parameter": "sort",
            "effect": "read_only",
        }

    def _sqlmap_process(self, *, traffic, stdout="", exit_code=0):
        def start(command, **options):
            spec_path = Path(command[-1])
            spec = json.loads(spec_path.read_text(encoding="utf-8"))
            Path(spec["stdout_path"]).write_text(stdout, encoding="utf-8")
            Path(spec["stderr_path"]).write_text("", encoding="utf-8")
            Path(spec["argv"][spec["argv"].index("-t") + 1]).write_text(
                traffic, encoding="utf-8")
            request_hash = hashlib.sha256(b"fixture-request").hexdigest()
            coordinator.dispatch(
                self.project, spec["lease"], action="tool.sqlmap",
                run_id=spec["run_id"], request_hash=request_hash,
                budget=spec["budget_name"], max_requests=spec["max_requests"],
                max_writes=spec["max_writes"], effect="read_only",
                requests=1, writes=0, budget_unit="request_slots",
                emit_ipc=False)
            Path(spec["summary_path"]).write_text(json.dumps({
                "schema": "awa-sqlmap-guard/v1", "complete": True,
                "requests_attempted": 1, "writes_attempted": 0,
                "guarded_requests": 1, "denied_requests": [],
                "unguarded_socket_attempts": 0, "transport": "fixture",
                "exit_code": exit_code,
            }), encoding="utf-8")

            class Process:
                returncode = exit_code

                def poll(self):
                    return self.returncode

            return Process()
        return start

    def _leases(self):
        return self.project.connection.execute(
            "SELECT name,dispatched FROM execution_leases").fetchall()

    def test_parameter_failure_happens_before_run_lease_or_dispatch(self):
        with patch.object(external, "_configured_executable",
                          return_value=self.executable):
            with self.assertRaises(EngineError) as caught:
                external.sqlmap_run(
                    self.project, {**self.args, "parameter": "not-registered"})
        self.assertEqual("tool_input", caught.exception.code)
        self.assertEqual([], self.project.list("run"))
        self.assertEqual([], self.project.list("execution_dispatch"))
        self.assertEqual([], self._leases())

    def test_success_emits_ipc_before_spawn_and_releases_after_artifact(self):
        events = []

        def emit(action, run_id, request_hash):
            self.assertEqual("tool.sqlmap", action)
            self.assertEqual(1, len(self.project.list("execution_dispatch")))
            events.append(("ipc", run_id, request_hash))

        def start(command, **options):
            events.append(("popen", None, None))
            return self._sqlmap_process(
                stdout="current database: 'audit_db'\ncurrent user: 'auditor'\n",
                traffic=("HTTP request [#1]:\nGET /items?sort=price HTTP/1.1\n\n"
                         "HTTP response [#1]:\nHTTP/1.1 200 OK\n\n"))(command, **options)

        release = coordinator.release

        def checked_release(project, lease, **kwargs):
            run = project.get("run", lease["name"].split(":", 1)[1])
            self.assertTrue(run["artifact_path"].endswith(".json"))
            self.assertEqual(64, len(run["sha256"]))
            events.append(("release", run["id"], kwargs.get("reconciled")))
            return release(project, lease, **kwargs)

        with patch("awa_ddd.ipc.emit_dispatch", side_effect=emit), \
                patch.object(external.subprocess, "Popen", side_effect=start), \
                patch("awa_ddd.execution_coordinator.release",
                      side_effect=checked_release):
            result = external.sqlmap_run(self.project, self.args)
        self.assertEqual(["ipc", "popen", "release"],
                         [event[0] for event in events])
        self.assertEqual("succeeded", result["status"])
        self.assertTrue(result["lease_reconciled"])
        self.assertEqual([], self._leases())

    def test_timeout_retains_dispatched_lease_and_blocks_automatic_reclaim(self):
        start = self._sqlmap_process(
            stdout="[INFO] partial\n", traffic="HTTP request [#1]:\n", exit_code=None)

        def stop(process):
            process.returncode = -9

        with patch.object(external.subprocess, "Popen", side_effect=start), \
                patch.object(external, "_kill", side_effect=stop), \
                patch.object(external.time, "monotonic", side_effect=[0, 6]):
            result = external.sqlmap_run(
                self.project, {**self.args, "timeout": 5})
        self.assertEqual("failed", result["status"])
        self.assertEqual(2, len(self.project.list("execution_dispatch")))
        self.assertEqual(1, self._leases()[0]["dispatched"])
        with self.assertRaises(EngineError) as caught:
            coordinator.claim(
                self.project, "tool.sqlmap:" + result["run_id"],
                owner="replacement", ttl=60)
        self.assertEqual("execution_lease_busy", caught.exception.code)
        self.assertEqual(
            0, caught.exception.details["requests_replayed"])


class YakitDispatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary, self.root = fx.workspace("http://audit.invalid")
        self.addCleanup(self.temporary.cleanup)
        self.project = fx.project(self.root)
        self.addCleanup(self.project.close)
        self.operation = fx.register(
            self.project, "http://audit.invalid/items", "GET", "public")
        self.args = {
            "yak_path": str(Path(self.root) / "yak.exe"),
            "operation_id": self.operation["id"],
            "url": self.operation["url"],
            "effect": "read_only",
        }

    class Client:
        def __init__(self, *args, **kwargs):
            self.exchanges = []
            self.noise = []
            self.calls = []
            self.project = kwargs.get("project")

        def initialize(self):
            self.calls.append("initialize")
            return {"serverInfo": {"name": "fixture"}}

        def list_tools(self):
            self.calls.append("tools/list")
            return [{
                "name": "http_fuzzer",
                "inputSchema": {
                    "properties": {
                        "requestRaw": {"type": "string"},
                        "noFollowRedirect": {"type": "boolean"},
                        "fuzzTagMode": {"type": "string"},
                    },
                    "required": ["requestRaw"],
                },
            }]

        def call_tool(self, name, arguments):
            self.calls.append("tools/call")
            return {"content": [{
                "type": "text",
                "text": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            }]}

        def close(self):
            self.calls.append("close")

    def test_only_tools_call_consumes_target_budget_and_success_is_released(self):
        project = self.project
        checks = {}

        class ObservedClient(YakitDispatchTests.Client):
            def initialize(self):
                checks["initialize"] = project.connection.execute(
                    "SELECT requests_used FROM execution_budget").fetchall()
                return super().initialize()

            def list_tools(self):
                checks["tools/list"] = project.connection.execute(
                    "SELECT requests_used FROM execution_budget").fetchall()
                return super().list_tools()

            def call_tool(self, name, arguments):
                checks["tools/call"] = project.connection.execute(
                    "SELECT requests_used FROM execution_budget").fetchall()
                return super().call_tool(name, arguments)

        with patch.object(external, "_configured_executable",
                          return_value=Path(self.args["yak_path"])), \
                patch.object(external, "MCPClient", ObservedClient):
            result = external.yakit_replay(project, self.args)
        self.assertEqual([], checks["initialize"])
        self.assertEqual([], checks["tools/list"])
        self.assertEqual(
            1, checks["tools/call"][0]["requests_used"])
        self.assertEqual("succeeded", result["status"])
        self.assertTrue(result["lease_reconciled"])
        self.assertEqual([], project.connection.execute(
            "SELECT name FROM execution_leases").fetchall())


class BrowserDispatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary, self.root = fx.workspace("http://audit.invalid")
        self.addCleanup(self.temporary.cleanup)
        self.project = fx.project(self.root)
        self.addCleanup(self.project.close)

    def _process(self, url):
        raw = {
            "url": url,
            "finalUrl": url,
            "status": 200,
            "signals": {"hasApp": True, "forms": 0, "inputs": 0},
            "network": [{"url": url, "method": "GET", "status": 200}],
            "actions": [],
            "blocked_requests": [],
            "requests_attempted": 1, "writes_attempted": 0,
            "request_budget": 100, "write_budget": 0,
        }
        return subprocess.CompletedProcess(
            [], 0, stdout=json.dumps(raw) + "\n", stderr="")

    def test_successful_visit_dispatches_then_releases_after_page_artifact(self):
        url = "http://audit.invalid/ui"

        def run(command, **options):
            spec = json.loads(Path(command[-1]).read_text(encoding="utf-8"))
            self.assertIs(spec["allowWrite"], False)
            self.assertEqual(0, spec["maxWrites"])
            self.assertIs(spec["ignoreHTTPSErrors"], False)
            self.assertIsNone(spec["guardContext"]["operation"])
            run_id = self.project.list("run")[0]["id"]
            lease = dict(self.project.connection.execute(
                "SELECT * FROM execution_leases").fetchone())
            coordinator.dispatch(
                self.project, lease, action="browser.visit", run_id=run_id,
                request_hash=hashlib.sha256(b"browser-fixture").hexdigest(),
                budget="browser-request-slots:" + run_id,
                max_requests=100, max_writes=0, effect="read_only",
                requests=1, writes=0, budget_unit="request_slots",
                emit_ipc=False)
            return self._process(url)

        self.project.set_config({**self.project.config, "allow_mutation": True})
        with patch.object(browser, "_browser_identity",
                          return_value=({}, {}, None, [], None, None)), \
                patch.object(browser, "probe", return_value={
                    "available": True, "node": "node",
                    "module_root": str(self.root), "executable_path": "chrome"}), \
                patch.object(browser.subprocess, "run", side_effect=run):
            result = browser.visit(
                self.project, {"url": url, "headless": True})
        self.assertEqual("succeeded", result["run_status"])
        self.assertTrue(result["lease_reconciled"])
        self.assertEqual(2, len(self.project.list("execution_dispatch")))
        self.assertEqual([], self.project.connection.execute(
            "SELECT name FROM execution_leases").fetchall())
        visit = self.project.get("page_visit", result["id"])
        self.assertTrue((self.project.base / visit["artifact_path"]).is_file())

    def test_timeout_retains_the_dispatched_lease(self):
        url = "http://audit.invalid/ui"
        with patch.object(browser, "_browser_identity",
                          return_value=({}, {}, None, [], None, None)), \
                patch.object(browser, "probe", return_value={
                    "available": True, "node": "node",
                    "module_root": str(self.root), "executable_path": "chrome"}), \
                patch.object(browser.subprocess, "run",
                             side_effect=subprocess.TimeoutExpired(["node"], 1)):
            with self.assertRaises(EngineError) as caught:
                browser.visit(self.project, {"url": url, "headless": True})
        self.assertEqual("browser_timeout", caught.exception.code)
        self.assertEqual(1, len(self.project.list("execution_dispatch")))
        lease = self.project.connection.execute(
            "SELECT name,dispatched FROM execution_leases").fetchone()
        self.assertEqual(1, lease["dispatched"])
        run = self.project.get("run", caught.exception.details["run_id"])
        self.assertEqual("interrupted", run["status"])
        with self.assertRaises(EngineError) as busy:
            coordinator.claim(
                self.project, lease["name"], owner="replacement", ttl=60)
        self.assertEqual("execution_lease_busy", busy.exception.code)


if __name__ == "__main__":
    unittest.main()
