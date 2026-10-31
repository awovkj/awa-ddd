"""Offline request-file SQL profiles, immutable bindings and partial tool clues."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import engine, external
from awa_ddd.assessment import evaluate
from awa_ddd.store import EngineError, Project, now


def observed(url, method, headers, body, timeout, max_bytes, response=None):
    raw = json.dumps(response if response is not None else {"items": ["normal"]}).encode("utf-8")
    return {"request": {"url": url, "method": method, "headers": headers,
                        "body_base64": base64.b64encode(external._request_bytes(body)).decode("ascii")},
            "response": {"status": 200, "headers": [["content-type", "application/json"]],
                         "body_base64": base64.b64encode(raw).decode("ascii"), "length": len(raw)},
            "complete": True, "started_at": now(), "completed_at": now()}


class PostSqlmapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-sqlmap-post-")
        self.addCleanup(self.tmp.cleanup)
        self.base = "http://fixture.invalid"
        engine.create_project(self.tmp.name, {"project_id": "post", "target": self.base,
                                              "allow_mutation": True})
        self.project = Project(self.tmp.name, "post")
        self.addCleanup(self.project.close)
        self.executable = Path(self.tmp.name) / "sqlmap.py"
        self.executable.write_text("# Mock fixture, never executed.\n", encoding="utf-8")
        identity = engine.register_operation(self.project, {"url": self.base + "/whoami", "method": "GET", "auth": "authenticated"})
        self.actor = engine.add_actor(self.project, {"subject": "alice", "roles": ["user"]})
        self.session = engine.add_session(self.project, {"actor_id": self.actor["id"],
            "headers": {"Authorization": "Bearer SYNTHETIC_ORIGINAL_CREDENTIAL", "X-Business": "fixed"}})
        with patch.object(engine, "request", side_effect=lambda *args: observed(*args, response={"id": "alice", "roles": ["user"]})):
            engine.verify_identity(self.project, {"operation_id": identity["id"], "session_id": self.session["id"],
                                                   "subject_selector": "/id", "roles_selector": "/roles"})
        self.operation = engine.register_operation(self.project, {"url": self.base + "/items/{id}", "method": "POST",
            "auth": "authenticated", "content_type": "application/json", "inputs": [
                {"name": "id", "location": "path", "consumer": "resource"},
                {"name": "q", "location": "body", "selector": "/q", "consumer": "sql_filter"}]})
        self.resource = engine.add_resource(self.project, {"operation_id": self.operation["id"],
            "owner_actor_id": self.actor["id"], "external_id": "lab-1",
            "request_binding": {"location": "path", "selector": "id"}})
        self.args = {"operation_id": self.operation["id"], "url": self.base + "/items/lab-1",
            "session_id": self.session["id"], "resource_id": self.resource["id"], "parameter": "/q",
            "input_location": "body", "effect": "test_resource_write", "sqlmap_path": str(self.executable),
            "body": {"q": "price", "fixed": "unchanged"}, "headers": {"X-Experiment": "same"}}
        self.commands = []

    def process(self, text="identified the following injection point(s)\ncurrent database: 'lab_db'\n", exit_code=0):
        def start(command, **options):
            self.commands.append((list(command), options))
            options["stdout"].write(text.encode("utf-8"))
            Path(command[command.index("-t") + 1]).write_text(
                "HTTP request [#1]:\nPOST /items/lab-1 HTTP/1.1\n\nHTTP response [#1]:\nHTTP/1.1 200 OK\n\n", encoding="utf-8")

            class Process:
                returncode = exit_code

                def poll(self):
                    return self.returncode

            return Process()
        return start

    def tool(self, **changes):
        with patch.object(external.subprocess, "Popen", side_effect=self.process()):
            return external.sqlmap_run(self.project, {**self.args, **changes})

    def controls(self, **changes):
        result = []
        for value in ("price", "price,(SELECT DATABASE())", "price,(SELECT DATABASE())+1"):
            args = {**self.args, "body": {"q": value, "fixed": "unchanged"}, **changes}
            with patch.object(engine, "request", side_effect=observed):
                evidence = engine.capture(self.project, args)
            result.append(evidence["id"])
        return result

    def confirm(self, tool, ids):
        engine.build_plan(self.project)
        item = next(item for item in self.project.list("obligation") if item["operation_id"] == self.operation["id"]
                    and item["kind"] == "input_test" and item.get("input_selector") == "/q" and not item.get("superseded"))
        return evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": ids,
            "oracle": {"type": "sql_metadata", "metadata_type": "database", "expected_value": "lab_db",
                       "baseline_selector": "/items", "baseline_expected": ["normal"], "tool_run_id": tool["run_id"]}})

    def test_post_uses_exact_private_request_file_and_fixed_metadata_argv(self):
        result = self.tool()
        command, options = self.commands[0]
        self.assertFalse(options["shell"])
        self.assertIn("-r", command)
        self.assertNotIn("-u", command)
        self.assertEqual(command[command.index("-p") + 1], "q")
        packet = Path(command[command.index("-r") + 1]).read_bytes()
        self.assertTrue(packet.startswith(b"POST /items/lab-1 HTTP/1.1\r\nHost: fixture.invalid\r\n"))
        self.assertEqual(packet.split(b"\r\n\r\n", 1)[1], b'{"q":"price","fixed":"unchanged"}')
        self.assertIn(b"x-experiment: same", packet)
        self.assertIn("--ignore-proxy", command)
        self.assertIn("--current-db", command)
        self.assertIn("--current-user", command)
        self.assertFalse(any(argument.startswith(("--dump", "--os-", "--sql-shell")) for argument in command))
        inspected = external.inspect(self.project, {"run_id": result["run_id"]})
        self.assertEqual(inspected["lineage_version"], 2)
        self.assertEqual(inspected["lineage"], "current")
        self.assertEqual(inspected["resource_id"], self.resource["id"])
        self.assertEqual(self.confirm(result, self.controls())["outcome"], "confirmed")

    def test_post_requires_permission_effect_and_disposable_fixture_before_spawn(self):
        for changes in ({"effect": "read_only"}, {"resource_id": None}, {"url": self.base + "/items/other"}):
            with self.subTest(changes=changes), patch.object(external.subprocess, "Popen") as process:
                with self.assertRaises(EngineError):
                    external.sqlmap_run(self.project, {**self.args, **changes})
                process.assert_not_called()
        engine.update_project(self.project, {"allow_mutation": False})
        with patch.object(external.subprocess, "Popen") as process:
            with self.assertRaises(EngineError):
                external.sqlmap_run(self.project, self.args)
            process.assert_not_called()

    def test_ambiguous_json_leaf_query_collision_and_structured_values_are_rejected(self):
        for changes in ({"body": {"q": "price", "nested": {"q": "other"}}},
                        {"body": {"q": ["price"]}}, {"body": {"q": None}},
                        {"url": self.base + "/items/lab-1?q=other"},
                        {"body_base64": base64.b64encode(b'{"q":"price","q":"other"}').decode(), "body": None}):
            with self.subTest(changes=changes), patch.object(external.subprocess, "Popen") as process:
                with self.assertRaises(EngineError):
                    external.sqlmap_run(self.project, {**self.args, **changes})
                process.assert_not_called()

    def test_original_request_file_tampering_invalidates_byte_integrity(self):
        result = self.tool()
        command = self.commands[0][0]
        Path(command[command.index("-r") + 1]).write_bytes(b"tampered")
        inspected = external.inspect(self.project, {"run_id": result["run_id"]})
        self.assertEqual(inspected["integrity"], "invalid")
        self.assertFalse(inspected["usable_for_confirmation"])

    def test_mutable_parameter_or_dbms_cannot_rewrite_recorded_execution_profile(self):
        for field, replacement in (("tool_parameter", "other"), ("dbms", "MySQL"), ("profile", {"techniques": "T"})):
            with self.subTest(field=field):
                result = self.tool()
                run = self.project.get("run", result["run_id"])
                run[field] = replacement
                self.project.put("run", run)
                inspected = external.inspect(self.project, {"run_id": result["run_id"]})
                self.assertEqual(inspected["integrity"], "invalid")
                self.assertEqual(inspected["lineage_reason_code"], "tool_profile_changed")
                self.assertFalse(inspected["usable_for_confirmation"])

    def test_fixture_and_other_business_headers_cannot_relabel_tool_proof(self):
        result = self.tool()
        with self.assertRaises(EngineError) as changed_header:
            self.confirm(result, self.controls(headers={"X-Experiment": "different"}))
        self.assertEqual(changed_header.exception.code, "tool_context_changed")
        engine.add_resource(self.project, {"resource_id": self.resource["id"], "operation_id": self.operation["id"],
            "owner_actor_id": self.actor["id"], "external_id": "lab-2", "request_binding": {"location": "path", "selector": "id"}})
        inspected = external.inspect(self.project, {"run_id": result["run_id"]})
        self.assertEqual(inspected["lineage_reason_code"], "resource_changed")

    def test_original_credentials_remain_redacted_after_rotation_with_request_file_profile(self):
        with patch.object(external.subprocess, "Popen", side_effect=self.process(
                "server repeated SYNTHETIC_ORIGINAL_CREDENTIAL\ncurrent database: 'lab_db'\n")):
            result = external.sqlmap_run(self.project, self.args)
        engine.add_session(self.project, {"session_id": self.session["id"], "actor_id": self.actor["id"],
            "headers": {"Authorization": "Bearer SYNTHETIC_ROTATED_CREDENTIAL"}})
        page = external.read_artifact(self.project, {"run_id": result["run_id"], "name": "stdout"})
        self.assertNotIn("SYNTHETIC_ORIGINAL_CREDENTIAL", page["content"])

    def test_partial_injection_signal_is_retained_without_confirming_a_finding(self):
        def stop(process):
            process.returncode = -9
        with patch.object(external.subprocess, "Popen", side_effect=self.process(
                "identified the following injection point(s)\n", exit_code=None)), \
                patch.object(external, "_kill", side_effect=stop), \
                patch.object(external.time, "monotonic", side_effect=[0, 6]):
            result = external.sqlmap_run(self.project, {**self.args, "timeout": 5})
        self.assertEqual(result["diagnostic"], "timeout")
        self.assertEqual(len(result["candidate_ids"]), 1)
        candidate = self.project.get("candidate", result["candidate_ids"][0])
        self.assertEqual(candidate["kind"], "tool_signal")
        self.assertEqual(candidate["status"], "unverified")
        self.assertFalse(external.inspect(self.project, {"run_id": result["run_id"]})["usable_for_confirmation"])
        self.assertEqual(self.project.list("finding"), [])


if __name__ == "__main__":
    unittest.main()
