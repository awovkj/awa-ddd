"""Mocked TscanPlus profiles and provenance; no scanner/database calls are made."""
from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import engine, tscanplus
from awa_ddd.mcp_http import MCPHTTPError
from awa_ddd.store import EngineError, Project, now


def catalog():
    return [{"name": "http_request", "inputSchema": {"type": "object", "required": ["url"],
                "properties": {key: {"type": value} for key, value in tscanplus.HTTP_SCHEMA.items()}}},
            {"name": "query_results", "inputSchema": {"type": "object", "required": [],
                "properties": {key: {"type": value} for key, value in tscanplus.QUERY_SCHEMA.items()}}},
            {"name": "url_scan", "inputSchema": {"type": "object", "properties": {}}}]


def mcp_result(data, success=True):
    return {"content": [{"type": "text", "text": json.dumps({"success": success, "message": "fixture only", "data": data})}]}


class FakeClient:
    clients, calls, tools, handler = [], [], catalog(), None

    def __init__(self, endpoint, timeout=30, max_bytes=None):
        self.endpoint, self.timeout, self.max_bytes = endpoint, timeout, max_bytes
        self.exchanges, self.last_tool_result = [], None
        self.clients.append(self)

    def initialize(self):
        self.exchanges.append({"direction": "request", "message": {"method": "initialize"}})
        return {"protocolVersion": "2025-03-26", "serverInfo": {"name": "fixture", "version": "1"}, "capabilities": {"tools": {}}}

    def list_tools(self):
        self.exchanges.append({"direction": "request", "message": {"method": "tools/list"}})
        return deepcopy(self.tools)

    def call_tool(self, name, arguments):
        copied = deepcopy(arguments)
        self.calls.append((name, copied))
        self.exchanges.append({"direction": "request", "message": {"method": "tools/call", "params": copied}})
        if self.handler is None:
            if name == "http_request":
                result = mcp_result({"status_code": 200, "body": "synthetic response", "truncated": False})
            else:
                result = mcp_result({"project": arguments["project"], "results": {arguments["table"]: []}, "counts": {arguments["table"]: 0}})
        else:
            result = type(self).handler(name, copied)
        self.last_tool_result = deepcopy(result)
        self.exchanges.append({"direction": "response", "message": {"result": result}})
        return result

    def close(self):
        pass


def observation(url, method, headers, body, timeout, max_bytes, response=None):
    raw = json.dumps(response or {"ok": True}).encode("utf-8")
    sent = body if isinstance(body, bytes) else body.encode("utf-8") if isinstance(body, str) else json.dumps(body).encode("utf-8") if body is not None else b""
    return {"request": {"url": url, "method": method, "headers": headers, "body_base64": base64.b64encode(sent).decode("ascii")},
            "response": {"status": 200, "headers": [["content-type", "application/json"]], "length": len(raw), "body_base64": base64.b64encode(raw).decode("ascii")},
            "started_at": now(), "completed_at": now(), "complete": True}


class TscanPlusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-tscanplus-")
        self.addCleanup(self.tmp.cleanup)
        self.base = "http://fixture.invalid"
        engine.create_project(self.tmp.name, {"project_id": "tscan", "target": self.base, "allow_mutation": True})
        self.project = Project(self.tmp.name, "tscan")
        self.addCleanup(self.project.close)
        FakeClient.clients, FakeClient.calls, FakeClient.tools, FakeClient.handler = [], [], catalog(), None
        patcher = patch.object(tscanplus, "StreamableHTTPClient", FakeClient)
        patcher.start()
        self.addCleanup(patcher.stop)

    def probe(self, **extra):
        return tscanplus.probe(self.project, {"adapter": "tscanplus", **extra})

    def operation(self, path="/items", method="GET", **extra):
        return engine.register_operation(self.project, {"url": self.base + path, "method": method, "auth": "public", **extra})

    def actor(self, identity="alice"):
        actor = engine.add_actor(self.project, {"actor_id": identity, "subject": identity, "roles": ["user"]})
        session = engine.add_session(self.project, {"actor_id": identity,
            "headers": {"Authorization": "Bearer synthetic-private-auth", "Cookie": "sid=synthetic-private-cookie"}})
        op = self.operation("/whoami", auth="authenticated")
        with patch.object(engine, "request", side_effect=lambda *args: observation(*args, response={"subject": identity, "roles": ["user"]})):
            engine.verify_identity(self.project, {"operation_id": op["id"], "session_id": session["id"], "subject_selector": "/subject", "roles_selector": "/roles"})
        return actor, self.project.get("session", session["id"])

    def query_rows(self, rows, count=None, project=None):
        def handler(name, values):
            return mcp_result({"project": project or values["project"], "results": {values["table"]: deepcopy(rows)},
                               "counts": {values["table"]: len(rows) if count is None else count}})
        FakeClient.handler = handler

    def assert_code(self, code, operation):
        with self.assertRaises(EngineError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_probe_is_metadata_only_and_persists_immutable_catalog_refs(self):
        result = self.probe()
        state = self.project.config["external_tools"]["tscanplus"]
        self.assertTrue(result["available"])
        self.assertEqual(FakeClient.calls, [])
        self.assertEqual(state["mcp_url"], "http://127.0.0.1:8088/mcp")
        self.assertTrue(state["scanner_project"].startswith("MCP-awa-"))
        self.assertLessEqual(len(state["scanner_project"]), 30)
        doc = self.project.read_artifact(self.project.get("run", result["run_id"]))
        self.assertEqual(doc["tools"], catalog())
        self.assertEqual(state["catalog"]["sha256"], result["sha256"])
        self.assertEqual(FakeClient.clients[0].max_bytes, 2 * 1024 * 1024)
        self.assertFalse(result["usable_for_confirmation"])

    def test_explicit_namespace_is_not_default_and_unsupported_probe_fields_fail_early(self):
        self.assert_code("tscanplus_project", lambda: self.probe(scanner_project="MCP"))
        self.assert_code("tscanplus_arguments", lambda: self.probe(sqlmap_path="unused"))
        self.assertEqual(FakeClient.clients, [])
        self.probe(scanner_project="owned-lab")
        self.assertEqual(self.project.config["external_tools"]["tscanplus"]["scanner_project"], "MCP-owned-lab")

    def test_http_get_and_head_use_only_fixed_single_request_profile(self):
        self.probe()
        for method in ("GET", "HEAD"):
            operation = self.operation("/" + method.lower(), method)
            result = tscanplus.request_run(self.project, {"operation_id": operation["id"]})
            name, values = FakeClient.calls[-1]
            self.assertEqual(name, "http_request")
            self.assertEqual(values["method"], method)
            self.assertIs(values["follow_redirect"], False)
            self.assertIs(values["path_as_is"], True)
            self.assertEqual(values["cookie"], "")
            self.assertEqual(values["body"], "")
            self.assertEqual(values["max_bytes"], 8192)
            self.assertEqual(json.loads(values["headers"]), {})
            self.assertEqual(result["selected_tool"], "http_request")
            self.assertTrue(result["target_traffic_sent"])
            self.assertFalse(result["usable_for_confirmation"])
        self.assertEqual(self.project.list("evidence"), [])
        self.assertEqual(self.project.list("decision"), [])

    def test_verified_session_cookie_stays_inside_headers_not_ambient_cookie(self):
        self.probe()
        actor, session = self.actor()
        op = self.operation(auth="authenticated")
        result = tscanplus.request_run(self.project, {"operation_id": op["id"], "session_id": session["id"]})
        values = FakeClient.calls[-1][1]
        self.assertEqual(json.loads(values["headers"]), session["headers"])
        self.assertEqual(values["cookie"], "")
        self.assertNotIn("synthetic-private", json.dumps(result))
        self.assertEqual(tscanplus.inspect(self.project, {"run_id": result["run_id"]})["lineage"], "current")

    def test_post_fixture_and_exact_utf8_body_are_required(self):
        self.probe()
        actor, session = self.actor()
        op = self.operation("/store", "POST", auth="authenticated", content_type="application/json")
        fixture = engine.add_resource(self.project, {"operation_id": op["id"], "owner_actor_id": actor["id"], "external_id": "fixture-1",
            "request_binding": {"location": "body", "selector": "/id"}})
        body = {"id": "fixture-1", "text": "\u6d4b\u8bd5\nvalue"}
        result = tscanplus.request_run(self.project, {"operation_id": op["id"], "session_id": session["id"],
            "resource_id": fixture["id"], "effect": "test_resource_write", "body": body})
        self.assertEqual(FakeClient.calls[-1][1]["body"].encode("utf-8"), json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        self.assertEqual(result["resource_id"], fixture["id"])
        self.assertEqual(tscanplus.inspect(self.project, {"run_id": result["run_id"]})["integrity"], "valid")
        before = len(FakeClient.calls)
        self.assert_code("resource_mismatch", lambda: tscanplus.request_run(self.project, {"operation_id": op["id"], "session_id": session["id"],
            "resource_id": fixture["id"], "effect": "test_resource_write", "body": {"id": "other"}}))
        self.assertEqual(len(FakeClient.calls), before)

    def test_actor_scoped_write_without_fixture_is_not_a_tscan_post_profile(self):
        self.probe()
        actor, session = self.actor()
        op = self.operation("/self-action", "POST", auth="authenticated", state_scope="actor")
        self.assert_code("tscanplus_fixture", lambda: tscanplus.request_run(self.project, {"operation_id": op["id"], "session_id": session["id"], "effect": "test_resource_write"}))
        self.assertEqual(FakeClient.calls, [])

    def test_scope_credentials_and_extra_mcp_fields_are_rejected_before_dispatch(self):
        self.probe()
        op = self.operation()
        self.assert_code("out_of_scope", lambda: tscanplus.request_run(self.project, {"operation_id": op["id"], "url": "http://outside.invalid/items"}))
        self.assert_code("credential_override", lambda: tscanplus.request_run(self.project, {"operation_id": op["id"], "headers": {"Authorization": "Bearer fake"}}))
        for extra in ({"method": "GET"}, {"tool_name": "url_scan"}, {"keyword": "x"}, {"offset": 0}, {"poc_check": True}):
            self.assert_code("tscanplus_arguments", lambda extra=extra: tscanplus.request_run(self.project, {"operation_id": op["id"], **extra}))
        self.assertEqual(FakeClient.calls, [])

    def test_live_schema_drift_blocks_before_any_target_tool(self):
        self.probe()
        op = self.operation()
        FakeClient.tools[0]["inputSchema"]["properties"]["headers"]["type"] = "object"
        error = self.assert_code("mcp_schema", lambda: tscanplus.request_run(self.project, {"operation_id": op["id"]}))
        run = self.project.get("run", error.details["run_id"])
        self.assertFalse(run["dispatch_attempted"])
        self.assertFalse(run["remote_may_continue"])
        self.assertEqual(FakeClient.calls, [])
        self.assertTrue(run["artifact_path"])

    def test_unsupported_byte_encoding_and_escaped_mcp_argument_budget_fail_without_dispatch(self):
        self.probe()
        actor = engine.add_actor(self.project, {"actor_id": "fixture-owner", "roles": []})
        op = self.operation("/store", "POST")
        fixture = engine.add_resource(self.project, {"operation_id": op["id"], "owner_actor_id": actor["id"], "external_id": "fixture-1",
            "request_binding": {"location": "query", "selector": "id"}})
        args = {"operation_id": op["id"], "resource_id": fixture["id"], "url": op["url"] + "?id=fixture-1", "effect": "test_resource_write"}
        self.assert_code("tscanplus_body", lambda: tscanplus.request_run(self.project, {**args, "body_base64": base64.b64encode(b'\xff').decode()}))
        self.assert_code("tscanplus_argument_budget", lambda: tscanplus.request_run(self.project, {**args, "body": "\x00" * 200000}))
        self.assertEqual(FakeClient.calls, [])

    def test_query_is_read_only_namespace_bound_and_imports_only_safe_unverified_clues(self):
        self.probe()
        rows = [{"URL": self.base + "/items?token=private-query", "Title": "Leak opaque-match-secret", "Category": "SQL signal",
                 "Pass": "opaque-pass-secret", "Match": "opaque-match-secret", "AccessKey": "opaque-access-secret", "SecretKey": "opaque-secret-key"}]
        self.query_rows(rows)
        result = tscanplus.query_results(self.project, {})
        name, values = FakeClient.calls[-1]
        self.assertEqual(name, "query_results")
        self.assertNotEqual(values["project"], "MCP")
        self.assertEqual(set(values), {"table", "project", "result_limit"})
        self.assertTrue(result["results_complete"])
        candidate = self.project.get("candidate", result["candidate_ids"][0])
        self.assertEqual(candidate["status"], "unverified")
        self.assertEqual(candidate["url"], self.base + "/items")
        self.assertNotIn("opaque-", json.dumps(candidate))
        self.assertEqual(candidate["source"]["sha256"], result["sha256"])
        self.assertNotEqual(candidate["row_digest"], candidate["source"]["sha256"])
        self.assertEqual(self.project.list("evidence"), [])
        self.assertEqual(self.project.list("finding"), [])

    def test_repeated_query_counts_changes_and_dismissal_do_not_clone_candidate(self):
        self.probe()
        rows = [{"URL": self.base + "/items", "Name": "fixture row", "InstanceID": "owned-instance"}]
        self.query_rows(rows)
        first = tscanplus.query_results(self.project, {})
        candidate = self.project.get("candidate", first["candidate_ids"][0])
        candidate.update(status="dismissed", reason="fixture disposition")
        self.project.put("candidate", candidate)
        self.query_rows(rows, count=5)
        second = tscanplus.query_results(self.project, {})
        self.assertEqual(first["candidate_ids"], second["candidate_ids"])
        self.assertEqual(second["new_candidates"], 0)
        self.assertEqual(second["duplicate_candidates"], 1)
        self.assertFalse(second["results_complete"])
        self.assertTrue(second["unretrieved_results"])
        self.assertEqual(len(self.project.list("candidate")), 1)
        self.assertEqual(self.project.get("candidate", candidate["id"]), candidate)

    def test_duplicate_rows_in_a_single_page_make_one_clue(self):
        self.probe()
        row = {"URL": self.base + "/items", "Name": "one row"}
        self.query_rows([row, row])
        result = tscanplus.query_results(self.project, {})
        self.assertEqual(result["new_candidates"], 1)
        self.assertEqual(result["duplicate_candidates"], 1)
        self.assertEqual(len(result["candidate_ids"]), 1)

    def test_query_filters_cannot_be_guessed_and_namespace_mismatch_is_blocked(self):
        self.probe()
        for extra in ({"offset": 0}, {"keyword": "x"}, {"finger": "x"}, {"port": "80"}, {"method": "GET"}, {"tool_name": "url_scan"}):
            self.assert_code("tscanplus_arguments", lambda extra=extra: tscanplus.query_results(self.project, extra))
        self.assert_code("tscanplus_namespace", lambda: tscanplus.query_results(self.project, {"scanner_project": "other"}))
        self.assertEqual(FakeClient.calls, [])
        self.query_rows([], project="MCP-other")
        error = self.assert_code("tscanplus_namespace", lambda: tscanplus.query_results(self.project, {}))
        run = self.project.get("run", error.details["run_id"])
        self.assertEqual(run["parser_status"], "blocked")
        self.assertFalse(run["results_complete"])

    def test_absent_namespace_or_unrecognized_result_is_not_a_security_negative(self):
        self.probe()
        FakeClient.handler = lambda name, values: mcp_result({"results": {values["table"]: []}, "counts": {values["table"]: 0}})
        result = tscanplus.query_results(self.project, {})
        self.assertFalse(result["results_complete"])
        self.assertEqual(result["parser_status"], "namespace_echo_missing")
        FakeClient.handler = lambda name, values: mcp_result({"rows": []})
        self.assert_code("tscanplus_result", lambda: tscanplus.query_results(self.project, {}))

    def test_out_of_scope_and_non_url_assets_are_not_auto_registered(self):
        self.probe()
        self.query_rows([{"URL": "http://outside.invalid/items"}, {"Host": "outside.invalid", "Port": 80}, {"URL": self.base + "/items"}])
        result = tscanplus.query_results(self.project, {})
        self.assertEqual(result["out_of_scope_rows"], 1)
        self.assertEqual(result["unmapped_rows"], 1)
        self.assertEqual(result["new_candidates"], 1)
        self.assertEqual(self.project.list("operation"), [])

    def test_remote_failure_after_dispatch_persists_unknown_state_and_never_replays(self):
        self.probe()
        op = self.operation()
        def failure(name, values):
            raise MCPHTTPError("mcp_timeout", "fixed private diagnostic")
        FakeClient.handler = failure
        args = {"operation_id": op["id"], "idempotency_key": "owned-key"}
        error = self.assert_code("mcp_timeout", lambda: tscanplus.request_run(self.project, args))
        run = self.project.get("run", error.details["run_id"])
        self.assertTrue(run["remote_may_continue"])
        self.assertFalse(run["remote_stopped_verified"])
        count = len(FakeClient.calls)
        self.assert_code("run_uncertain", lambda: tscanplus.request_run(self.project, args))
        self.assertEqual(len(FakeClient.calls), count)
        self.assertEqual(tscanplus.inspect(self.project, {"run_id": run["id"]})["integrity"], "valid")

    def test_idempotency_is_domain_separated_and_checks_exact_prior_request(self):
        self.probe()
        op = self.operation()
        native_id = engine.stable("RUN", "owned-key")
        self.project.put("run", {"id": native_id, "kind": "http", "status": "failed", "started_at": now()})
        args = {"operation_id": op["id"], "idempotency_key": "owned-key"}
        first = tscanplus.request_run(self.project, args)
        self.assertNotEqual(first["run_id"], native_id)
        second = tscanplus.request_run(self.project, args)
        self.assertTrue(second["idempotent_reuse"])
        self.assertEqual(len(FakeClient.calls), 1)
        self.assert_code("idempotency_conflict", lambda: tscanplus.request_run(self.project, {**args, "url": op["url"] + "?q=different"}))
        self.assertEqual(len(FakeClient.calls), 1)

    def test_expired_session_cached_execution_is_read_only_and_does_not_resend(self):
        self.probe()
        actor, session = self.actor()
        op = self.operation(auth="authenticated")
        args = {"operation_id": op["id"], "session_id": session["id"], "idempotency_key": "cached-session"}
        first = tscanplus.request_run(self.project, args)
        stored = self.project.get("session", session["id"])
        stored["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        self.project.put("session", stored)
        cached = tscanplus.request_run(self.project, args)
        self.assertEqual(cached["run_id"], first["run_id"])
        self.assertEqual(len(FakeClient.calls), 1)

    def test_artifact_view_redacts_entire_result_before_pagination_and_seeds_reports(self):
        self.probe()
        self.query_rows([{"URL": self.base + "/items", "Name": "opaque-match-secret", "Pass": "opaque-pass-secret", "Match": "opaque-match-secret",
                         "AccessKey": "opaque-access-secret", "SecretKey": "opaque-secret-key", "Headers": {"X-Auth": "opaque-header-secret"}}])
        result = tscanplus.query_results(self.project, {})
        chunks, offset = [], 0
        while True:
            view = tscanplus.read_artifact(self.project, {"run_id": result["run_id"], "name": "result", "offset": offset, "limit": 17})
            chunks.append(view["content"])
            if view["next_offset"] is None:
                break
            offset = view["next_offset"]
        content = "".join(chunks)
        for value in ("opaque-pass-secret", "opaque-match-secret", "opaque-access-secret", "opaque-secret-key", "opaque-header-secret"):
            self.assertNotIn(value, content)
            self.assertIn(value, tscanplus.report_context(self.project)["secret_values"])
        self.assert_code("tool_artifact_unavailable", lambda: tscanplus.read_artifact(self.project, {"run_id": result["run_id"], "name": "stdout"}))

    def test_tampered_artifacts_are_not_read_or_learned_as_report_context(self):
        self.probe()
        self.query_rows([{"URL": self.base + "/items", "Pass": "opaque-pass-secret"}])
        result = tscanplus.query_results(self.project, {})
        run = self.project.get("run", result["run_id"])
        (self.project.base / run["artifact_path"]).write_text('{"forged":"opaque-pass-secret"}', encoding="utf-8")
        self.assert_code("evidence_changed", lambda: tscanplus.read_artifact(self.project, {"run_id": result["run_id"]}))
        self.assertNotIn("opaque-pass-secret", tscanplus.report_context(self.project)["secret_values"])


if __name__ == "__main__":
    unittest.main()
