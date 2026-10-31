"""Offline TscanPlus 3.5.4 contracts; these fixtures never contact a scanner."""
from __future__ import annotations

from copy import deepcopy
import json
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import quote

from awa_ddd import candidates, engine, tscanplus
from awa_ddd.store import EngineError, Project


def catalog():
    profiles = {"http_request": tscanplus.HTTP_SCHEMA, "query_results": tscanplus.QUERY_SCHEMA,
                "project_summary": {"project": "string"}, "route_candidates": {"project": "string"}}
    return [
        {"name": name, "inputSchema": {"type": "object", "properties": {
            key: {"type": value} for key, value in fields.items()
        }, "required": ["url"] if name == "http_request" else []}}
        for name, fields in profiles.items()
    ] + [{"name": "poc_scan", "inputSchema": {"type": "object", "properties": {}}}]


def mcp_result(data):
    return {"content": [{"type": "text", "text": json.dumps({
        "success": True, "message": "offline fixture only", "data": data
    })}]}


class FakeClient:
    clients, calls, tools, handler = [], [], [], None

    def __init__(self, endpoint, timeout=30, max_bytes=None):
        self.endpoint, self.timeout, self.max_bytes = endpoint, timeout, max_bytes
        self.exchanges, self.last_tool_result = [], None
        self.clients.append(self)

    def initialize(self):
        self.exchanges.append({"direction": "request", "message": {"method": "initialize"}})
        return {"protocolVersion": "2025-03-26", "serverInfo": {"name": "fixture", "version": "3.5.4"},
                "capabilities": {"tools": {}}}

    def list_tools(self):
        self.exchanges.append({"direction": "request", "message": {"method": "tools/list"}})
        return deepcopy(self.tools)

    def call_tool(self, name, arguments):
        copied = deepcopy(arguments)
        self.calls.append((name, copied))
        self.exchanges.append({"direction": "request", "message": {"method": "tools/call", "params": copied}})
        if type(self).handler is None:
            raise AssertionError("No fixture response was explicitly selected")
        result = type(self).handler(name, copied)
        self.last_tool_result = deepcopy(result)
        self.exchanges.append({"direction": "response", "message": {"result": result}})
        return result

    def close(self):
        pass


class TscanPlusUpgradeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="awa-tscan-contract-")
        self.addCleanup(temporary.cleanup)
        self.base = "http://fixture.invalid"
        engine.create_project(temporary.name, {"project_id": "upgrade", "target": self.base,
            "exclude": [self.base + "/excluded"]})
        self.project = Project(temporary.name, "upgrade")
        self.addCleanup(self.project.close)
        FakeClient.clients, FakeClient.calls, FakeClient.tools, FakeClient.handler = [], [], catalog(), None
        patcher = patch.object(tscanplus, "StreamableHTTPClient", FakeClient)
        patcher.start()
        self.addCleanup(patcher.stop)

    def probe(self, **arguments):
        return tscanplus.probe(self.project, {"adapter": "tscanplus", **arguments})

    def reply(self, rows, *, style="flat", omit_project=False, omit_instance=False, **changes):
        def handler(name, values):
            self.assertEqual(name, "query_results")
            if style == "flat":
                data = {"results": deepcopy(rows), "table": values["table"], "total": len(rows),
                        "matched": len(rows), "result_limit": values["result_limit"]}
            else:
                data = {"results": {values["table"]: deepcopy(rows)}, "counts": {values["table"]: len(rows)}}
            if not omit_project:
                data["project"] = values["project"]
            if "instance_id" in values and not omit_instance:
                data["instance_id"] = values["instance_id"]
            data.update(deepcopy(changes))
            return mcp_result(data)
        FakeClient.handler = handler

    def assert_code(self, code, call):
        with self.assertRaises(EngineError) as caught:
            call()
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def assert_failed_run(self, code, arguments):
        return self.assert_failed_action(code, tscanplus.query_results, arguments)

    def assert_failed_action(self, code, action, arguments):
        error = self.assert_code(code, lambda: action(self.project, arguments))
        run = self.project.get("run", error.details["run_id"])
        self.assertEqual(run["status"], "failed")
        self.assertTrue(run["artifact_path"])
        self.assertFalse(run.get("results_complete", False))
        self.assertEqual(tscanplus.inspect(self.project, {"run_id": run["id"]})["integrity"], "valid")
        self.assertEqual(self.project.list("candidate"), [])
        return run

    def summary_reply(self, *, omit_project=False, **changes):
        def handler(name, values):
            self.assertEqual(name, "project_summary")
            data = {"counts": {table: 0 for table in tscanplus.TABLES}, "has_assets": False}
            if not omit_project:
                data["project"] = values["project"]
            data.update(deepcopy(changes))
            return mcp_result(data)
        FakeClient.handler = handler

    def routes_reply(self, rows, *, omit_project=False, **changes):
        def handler(name, values):
            self.assertEqual(name, "route_candidates")
            data = {"candidates": deepcopy(rows), "counts": {"urlscan": len(rows)}, "assets": [],
                    "has_assets": bool(rows)}
            if not omit_project:
                data["project"] = values["project"]
            data.update(deepcopy(changes))
            return mcp_result(data)
        FakeClient.handler = handler

    def test_probe_does_not_read_database_and_uses_server_compatible_namespace(self):
        result = self.probe()
        self.assertTrue(result["available"])
        self.assertLessEqual(len(result["scanner_project"]), 20)
        self.assertNotEqual(result["scanner_project"], "MCP")
        self.assertEqual(FakeClient.calls, [])
        self.assertEqual(self.project.list("candidate"), [])
        self.assertEqual(self.project.list("operation"), [])

    def test_namespace_exceeding_actual_server_limit_fails_before_connection(self):
        self.assert_code("tscanplus_project", lambda: self.probe(scanner_project="x" * 17))
        self.assertEqual(FakeClient.clients, [])
        self.assertTrue(self.probe(scanner_project="x" * 16)["available"])

    def test_legacy_long_namespace_artifact_remains_inspectable_but_cannot_start_new_work(self):
        namespace = "MCP-awa-" + "0" * 16
        original_namespace = tscanplus._namespace
        with patch.object(tscanplus, "_namespace", side_effect=lambda value, max_length=30:
                          original_namespace(value, max_length=30)):
            legacy = self.probe(scanner_project=namespace)
        before = len(FakeClient.clients)
        self.reply([])
        operation = engine.register_operation(self.project, {"url": self.base + "/read", "method": "GET", "auth": "public"})
        for action, arguments in ((tscanplus.query_results, {}), (tscanplus.project_summary, {}),
                                  (tscanplus.route_candidates, {}),
                                  (tscanplus.request_run, {"operation_id": operation["id"]})):
            with self.subTest(action=action.__name__):
                self.assert_code("tscanplus_project", lambda: action(self.project, arguments))
                self.assertEqual(len(FakeClient.clients), before)
                self.assertEqual(FakeClient.calls, [])
        self.assertEqual(self.project.config["external_tools"]["tscanplus"]["scanner_project"], namespace)
        self.assertEqual(tscanplus.inspect(self.project, {"run_id": legacy["run_id"]})["integrity"], "valid")
        self.probe(scanner_project="owned-lab")
        result = tscanplus.query_results(self.project, {})
        self.assertEqual(result["scanner_project"], "MCP-owned-lab")
        self.assertEqual([name for name, _ in FakeClient.calls], ["query_results"])

    def test_real_354_flat_query_shape_is_supported(self):
        self.probe()
        self.reply([])
        result = tscanplus.query_results(self.project, {"table": "urlscan", "result_limit": 1})
        self.assertEqual(FakeClient.calls, [("query_results", {
            "table": "urlscan", "project": result["scanner_project"], "result_limit": 1
        })])
        self.assertEqual(result["reported_count"], 0)
        self.assertEqual(result["returned_rows"], 0)
        self.assertTrue(result["results_complete"])
        self.assertFalse(result["usable_for_confirmation"])
        self.assertEqual(self.project.list("evidence"), [])
        self.assertEqual(self.project.list("finding"), [])

    def test_legacy_table_keyed_shape_remains_supported(self):
        self.probe()
        self.reply([{"target": self.base + "/item"}], style="legacy")
        result = tscanplus.query_results(self.project, {})
        self.assertTrue(result["results_complete"])
        self.assertEqual(result["new_candidates"], 1)
        self.assertEqual(self.project.get("candidate", result["candidate_ids"][0])["url"], self.base + "/item")

    def test_flat_query_uses_total_conservatively_when_matched_rows_are_limited(self):
        self.probe()
        self.reply([{"target": self.base + "/one"}, {"target": self.base + "/two"}], total=5, matched=2)
        result = tscanplus.query_results(self.project, {"instance_id": "mcp-owned"})
        self.assertEqual(result["reported_count"], 5)
        self.assertEqual(result["reported_matched"], 2)
        self.assertEqual(result["returned_rows"], 2)
        self.assertFalse(result["results_complete"])
        self.assertTrue(result["unretrieved_results"])

    def test_wrong_table_echo_is_rejected_and_saved_without_candidate_import(self):
        self.probe()
        self.reply([{"target": self.base + "/item"}], table="poccheck")
        self.assert_failed_run("tscanplus_result", {})

    def test_non_integer_or_inconsistent_flat_counts_are_rejected_and_saved(self):
        self.probe()
        for change in ({"total": "1"}, {"total": True}, {"matched": 1.0},
                       {"total": 0}, {"matched": 0}, {"total": 1, "matched": 2}):
            with self.subTest(change=change):
                self.reply([{"target": self.base + "/item"}], **change)
                self.assert_failed_run("tscanplus_result", {})

    def test_invalid_flat_result_collection_or_missing_count_is_not_empty_success(self):
        self.probe()
        for change in ({"results": ["not a row"]}, {"results": None}, {"matched": None}, {"total": None}):
            with self.subTest(change=change):
                self.reply([], **change)
                self.assert_failed_run("tscanplus_result", {})

    def test_flat_limit_echo_disagreement_is_not_silently_accepted(self):
        self.probe()
        self.reply([], result_limit=2)
        self.assert_failed_run("tscanplus_result", {"result_limit": 1})

    def test_instance_filter_without_any_source_echo_is_partial_and_not_row_attribution(self):
        self.probe()
        for style in ("flat", "legacy"):
            with self.subTest(style=style):
                self.reply([{"target": self.base + "/" + style}], style=style, omit_instance=True)
                result = tscanplus.query_results(self.project, {"instance_id": "requested-instance"})
                self.assertFalse(result["results_complete"])
                candidate = self.project.get("candidate", result["candidate_ids"][0])
                self.assertIsNone(candidate.get("instance_id"))
                self.assertIs(candidate["instance_verified"], False)
                self.assertFalse(result["usable_for_confirmation"])

    def test_verified_top_level_instance_echo_binds_rows_without_instance_fields(self):
        self.probe()
        self.reply([{"target": self.base + "/item"}])
        result = tscanplus.query_results(self.project, {"instance_id": "requested-instance"})
        self.assertTrue(result["results_complete"])
        candidate = self.project.get("candidate", result["candidate_ids"][0])
        self.assertEqual(candidate["instance_id"], "requested-instance")
        self.assertIs(candidate["instance_verified"], True)

    def test_conflicting_top_level_instance_echo_is_rejected_and_saved(self):
        self.probe()
        self.reply([{"target": self.base + "/item"}], instance_id="other-instance")
        self.assert_failed_run("tscanplus_namespace", {"instance_id": "requested-instance"})

    def test_conflicting_row_and_top_level_instance_echoes_are_rejected_and_saved(self):
        self.probe()
        self.reply([{"target": self.base + "/item", "InstanceID": "other-instance"}])
        self.assert_failed_run("tscanplus_namespace", {"instance_id": "requested-instance"})

    def test_missing_project_echo_is_partial_in_both_supported_shapes(self):
        self.probe()
        for style in ("flat", "legacy"):
            with self.subTest(style=style):
                self.reply([], style=style, omit_project=True)
                result = tscanplus.query_results(self.project, {})
                self.assertFalse(result["results_complete"])

    def test_explicit_truncation_or_incomplete_claim_wins_over_equal_counts(self):
        self.probe()
        for change in ({"truncated": True}, {"results_complete": False}):
            with self.subTest(change=change):
                self.reply([{"target": self.base + "/item"}], **change)
                result = tscanplus.query_results(self.project, {})
                self.assertFalse(result["results_complete"])

    def test_candidate_url_paths_do_not_publicly_expose_scanner_secret_values(self):
        self.probe()
        secret = "opaque-private-path-secret"
        self.reply([{"target": self.base + "/" + secret, "SecretKey": secret, "Title": "ordinary clue"}])
        result = tscanplus.query_results(self.project, {})
        self.assertEqual(result["new_candidates"], 1)
        candidate = candidates.inspect_candidate(self.project, {"candidate_id": result["candidate_ids"][0]})
        self.assertEqual(candidate["candidate"]["url"], "[private URL omitted]")
        self.assertIs(candidate["candidate"]["url_redacted"], True)
        listing = candidates.list_candidates(self.project, {})
        artifact = tscanplus.read_artifact(self.project, {"run_id": result["run_id"], "name": "result", "limit": 8000})
        for public in (result, candidate, listing, artifact):
            self.assertNotIn(secret, json.dumps(public))
        self.assertIn(secret, tscanplus.report_context(self.project)["secret_values"])

    def test_percent_encoded_scanner_secret_in_url_path_is_also_private(self):
        self.probe()
        secret = "opaque-private-path-secret"
        encoded = "".join("%%%02X" % ord(character) for character in secret)
        self.reply([{"target": self.base + "/" + encoded, "SecretKey": secret}])
        result = tscanplus.query_results(self.project, {})
        candidate = self.project.get("candidate", result["candidate_ids"][0])
        self.assertEqual(candidate["url"], "[private URL omitted]")
        self.assertIs(candidate["url_redacted"], True)
        self.assertNotIn(encoded, json.dumps(candidate))
        artifact = tscanplus.read_artifact(self.project, {"run_id": result["run_id"], "name": "result", "limit": 8000})
        self.assertNotIn(encoded, artifact["content"])
        self.assertNotIn(secret, artifact["content"])

    def test_private_url_placeholder_cannot_be_linked_or_used_as_request_target(self):
        self.probe()
        secret = "opaque-private-locator-key"
        self.reply([{"target": self.base + "/" + secret, "SecretKey": secret}])
        result = tscanplus.query_results(self.project, {})
        candidate = self.project.get("candidate", result["candidate_ids"][0])
        operation = engine.register_operation(self.project, {"url": self.base + "/read", "method": "GET", "auth": "public"})
        self.assert_code("candidate_scope", lambda: candidates.link_candidate(self.project, {
            "candidate_id": candidate["id"], "operation_id": operation["id"]
        }))
        with self.assertRaises(EngineError):
            tscanplus.request_run(self.project, {"operation_id": operation["id"], "url": candidate["url"]})
        self.assertEqual([name for name, _ in FakeClient.calls], ["query_results"])
        self.assertEqual(self.project.get("candidate", candidate["id"])["status"], "unverified")
        self.assertEqual(self.project.list("evidence"), [])

    def test_source_locators_and_digests_bind_exact_private_rows_in_both_shapes(self):
        self.probe()
        for style in ("flat", "legacy"):
            with self.subTest(style=style):
                row = {"target": self.base + "/" + style, "Title": "source fixture"}
                self.reply([row], style=style)
                result = tscanplus.query_results(self.project, {})
                candidate = self.project.get("candidate", result["candidate_ids"][0])
                source = candidate["source"]
                self.assertEqual(source["artifact_path"], result["artifact_path"])
                self.assertEqual(source["sha256"], result["sha256"])
                self.assertEqual(source["mcp_url"], result["mcp_url"])
                self.assertEqual(source["trust"], "untrusted_tool_output")
                expected = "parsed_result.data.results[0]" if style == "flat" else "parsed_result.data.results.urlscan[0]"
                self.assertEqual(source["locator"], expected)
                self.assertEqual(candidate["row_digest"], tscanplus._hash(row))
                document = self.project.read_artifact(self.project.get("run", result["run_id"]))
                saved = document["parsed_result"]["data"]["results"]
                self.assertEqual(saved[0] if style == "flat" else saved["urlscan"][0], row)

    def test_mixed_case_url_schemes_do_not_leak_encoded_secret_paths_in_artifacts(self):
        self.probe()
        secret = "opaque-mixedcase-path-secret"
        encoded = "".join("%%%02X" % ord(character) for character in secret)
        for scheme in ("HTTP", "HtTp"):
            with self.subTest(scheme=scheme):
                self.reply([{"target": scheme + "://fixture.invalid/" + encoded, "SecretKey": secret}])
                result = tscanplus.query_results(self.project, {})
                candidate = self.project.get("candidate", result["candidate_ids"][0])
                self.assertEqual(candidate["url"], "[private URL omitted]")
                self.assertTrue(candidate["url_redacted"])
                artifact = tscanplus.read_artifact(self.project, {"run_id": result["run_id"], "name": "result", "limit": 8000})
                self.assertNotIn(encoded, artifact["content"])
                self.assertNotIn(secret, artifact["content"])

    def test_four_layer_percent_encoding_fails_closed_for_candidate_and_artifact(self):
        self.probe()
        secret = "opaque-deep-path-secret"
        encoded = "".join("%%%02X" % ord(character) for character in secret)
        for _ in range(3):
            encoded = encoded.replace("%", "%25")
        self.reply([{"target": self.base + "/" + encoded, "SecretKey": secret}])
        result = tscanplus.query_results(self.project, {})
        candidate = self.project.get("candidate", result["candidate_ids"][0])
        self.assertEqual(candidate["url"], "[private URL omitted]")
        self.assertTrue(candidate["url_redacted"])
        self.assertNotIn(encoded, json.dumps(candidate))
        artifact = tscanplus.read_artifact(self.project, {"run_id": result["run_id"], "name": "result", "limit": 8000})
        self.assertNotIn(encoded, artifact["content"])
        self.assertNotIn(secret, artifact["content"])

    def test_literal_percent_triplets_in_secret_values_remain_private_at_every_decode_stage(self):
        self.probe()
        for secret in ("opaque%41private-key", "opaque%2Fprivate-key", "opaque%FFprivate-key"):
            with self.subTest(secret=secret):
                encoded = quote(secret, safe="")
                self.reply([{"target": self.base + "/" + encoded, "SecretKey": secret}])
                result = tscanplus.query_results(self.project, {})
                candidate = self.project.get("candidate", result["candidate_ids"][0])
                self.assertEqual(candidate["url"], "[private URL omitted]")
                self.assertTrue(candidate["url_redacted"])
                self.assertNotIn(encoded, json.dumps(candidate))
                artifact = tscanplus.read_artifact(self.project, {"run_id": result["run_id"], "name": "result", "limit": 8000})
                self.assertNotIn(encoded, artifact["content"])
                self.assertNotIn(secret, artifact["content"])

    def test_independent_endpoints_cannot_share_candidate_identity(self):
        self.probe(scanner_project="owned-lab")
        self.reply([{"target": self.base + "/item", "Title": "same immutable row"}])
        first = tscanplus.query_results(self.project, {})
        self.probe(mcp_url="http://127.0.0.1:8089/mcp", scanner_project="owned-lab")
        second = tscanplus.query_results(self.project, {})
        self.assertNotEqual(first["candidate_ids"], second["candidate_ids"])
        self.assertEqual(second["new_candidates"], 1)
        self.assertEqual(second["duplicate_candidates"], 0)
        self.assertEqual(len(self.project.list("candidate")), 2)
        first_candidate = self.project.get("candidate", first["candidate_ids"][0])
        second_candidate = self.project.get("candidate", second["candidate_ids"][0])
        self.assertEqual(first_candidate["mcp_url"], "http://127.0.0.1:8088/mcp")
        self.assertEqual(second_candidate["mcp_url"], "http://127.0.0.1:8089/mcp")

    def test_limit_alias_translates_to_result_limit_without_arbitrary_forwarding(self):
        self.probe()
        self.reply([])
        for arguments in ({"limit": 1}, {"result_limit": 1}, {"limit": 1, "result_limit": 1}):
            with self.subTest(arguments=arguments):
                tscanplus.query_results(self.project, arguments)
                values = FakeClient.calls[-1][1]
                self.assertEqual(values["result_limit"], 1)
                self.assertNotIn("limit", values)
                self.assertNotIn("offset", values)

    def test_conflicting_or_non_integer_limit_aliases_fail_before_dispatch(self):
        self.probe()
        self.reply([])
        for arguments in ({"limit": 1, "result_limit": 2}, {"limit": True}, {"limit": "1"},
                          {"limit": 1.0}, {"result_limit": True}, {"limit": 0}, {"limit": 101}):
            with self.subTest(arguments=arguments):
                with self.assertRaises(EngineError):
                    tscanplus.query_results(self.project, arguments)
                self.assertEqual(FakeClient.calls, [])

    def test_query_endpoint_override_must_match_saved_probe_exactly(self):
        self.probe()
        self.reply([])
        self.assert_code("tscanplus_configuration", lambda: tscanplus.query_results(
            self.project, {"mcp_url": "http://127.0.0.1:8089/mcp"}))
        self.assertEqual(FakeClient.calls, [])
        result = tscanplus.query_results(self.project, {"mcp_url": "http://127.0.0.1:8088/mcp"})
        self.assertTrue(result["results_complete"])
        self.assertNotIn("mcp_url", FakeClient.calls[-1][1])

    def test_remote_finding_table_and_unhashable_table_remain_blocked_before_dispatch(self):
        self.probe()
        self.reply([])
        for table in ("finding", ["urlscan"], {"name": "urlscan"}, None):
            with self.subTest(table=table):
                with self.assertRaises(EngineError):
                    tscanplus.query_results(self.project, {"table": table})
                self.assertEqual(FakeClient.calls, [])

    def test_summary_is_fixed_read_only_metadata_and_never_evidence(self):
        self.probe()
        counts = {table: 0 for table in tscanplus.TABLES}
        counts["urlscan"] = 3
        self.summary_reply(counts=counts, has_assets=True)
        result = tscanplus.project_summary(self.project, {})
        self.assertEqual(FakeClient.calls, [("project_summary", {"project": result["scanner_project"]})])
        self.assertEqual(result["counts"], counts)
        self.assertIs(result["has_assets"], True)
        self.assertIs(result["namespace_verified"], True)
        self.assertIs(result["results_complete"], True)
        self.assertFalse(result["usable_for_confirmation"])
        self.assertEqual(self.project.list("operation"), [])
        self.assertEqual(self.project.list("candidate"), [])
        self.assertEqual(self.project.list("evidence"), [])
        self.assertEqual(self.project.list("finding"), [])

    def test_summary_does_not_publish_remote_prompts_assets_or_suggested_actions(self):
        self.probe()
        marker = "REMOTE-CONTROL-INSTRUCTION-PRIVATE"
        self.summary_reply(surface=[marker], high_risk=[marker], candidates=[{"tool": "poc_scan", "target": marker}],
                           hint=marker, prompt=marker)
        result = tscanplus.project_summary(self.project, {})
        self.assertNotIn(marker, json.dumps(result))
        for field in ("surface", "high_risk", "candidates", "hint", "prompt"):
            self.assertNotIn(field, result)
        self.assertEqual([name for name, _ in FakeClient.calls], ["project_summary"])

    def test_summary_missing_namespace_is_partial_and_blocks_completion(self):
        self.probe()
        self.summary_reply(omit_project=True)
        result = tscanplus.project_summary(self.project, {})
        self.assertFalse(result["namespace_verified"])
        self.assertFalse(result["results_complete"])
        completion = engine.evaluate_coverage(self.project)["completion"]
        self.assertGreaterEqual(completion["failed_partial_tools"], 1)

    def test_summary_wrong_namespace_is_rejected_and_saved(self):
        self.probe()
        self.summary_reply(project="MCP-other")
        self.assert_failed_action("tscanplus_namespace", tscanplus.project_summary, {})

    def test_summary_rejects_missing_or_invalid_counters_and_non_boolean_assets(self):
        self.probe()
        for change in ({"counts": {"urlscan": 0}},
                       {"counts": {table: True for table in tscanplus.TABLES}},
                       {"counts": {table: -1 for table in tscanplus.TABLES}},
                       {"has_assets": 0}):
            with self.subTest(change=change):
                self.summary_reply(**change)
                self.assert_failed_action("tscanplus_result", tscanplus.project_summary, {})

    def test_summary_fixed_controls_do_not_forward_arbitrary_parameters(self):
        self.probe()
        self.summary_reply()
        for arguments in ({"fresh_project": True}, {"tool_name": "poc_scan"}, {"limit": 5},
                          {"mcp_url": "http://127.0.0.1:8089/mcp"}, {"scanner_project": "other"}):
            with self.subTest(arguments=arguments):
                with self.assertRaises(EngineError):
                    tscanplus.project_summary(self.project, arguments)
                self.assertEqual(FakeClient.calls, [])

    def test_summary_schema_drift_fails_before_any_remote_tool_dispatch(self):
        self.probe()
        self.summary_reply()
        summary = next(tool for tool in FakeClient.tools if tool["name"] == "project_summary")
        summary["inputSchema"]["properties"]["project"]["type"] = "object"
        run = self.assert_failed_action("mcp_schema", tscanplus.project_summary, {})
        self.assertFalse(run["dispatch_attempted"])
        self.assertEqual(FakeClient.calls, [])

    def test_routes_create_only_safe_unverified_clues_and_never_execute_suggestions(self):
        self.probe()
        marker = "REMOTE-ARGUMENT-INSTRUCTION-PRIVATE"
        self.routes_reply([
            {"tool": "http_request", "target": self.base + "/read?token=private-query",
             "arguments": {"method": "DELETE", "follow_redirect": True, "prompt": marker}},
            {"tool": "poc_scan", "target": self.base + "/poc", "prompt": marker},
            {"tool": "js_scan", "arguments": {"urls": self.base + "/app.js", "command": marker}},
            {"tool": "pwd_crack", "target": "fixture.invalid:22"},
            {"tool": "shell_exec", "target": self.base + "/untrusted-tool"},
        ], prompt=marker, empty_hint=marker)
        result = tscanplus.route_candidates(self.project, {})
        self.assertEqual([name for name, _ in FakeClient.calls], ["route_candidates"])
        self.assertEqual(result["new_candidates"], 3)
        self.assertEqual(self.project.list("operation"), [])
        self.assertEqual(self.project.list("evidence"), [])
        self.assertEqual(self.project.list("finding"), [])
        rows = [self.project.get("candidate", identity) for identity in result["candidate_ids"]]
        self.assertEqual({row["suggested_tool"] for row in rows}, {"http_request", "poc_scan", "js_scan"})
        for row in rows:
            self.assertEqual(row["status"], "unverified")
            self.assertEqual(row["mcp_url"], "http://127.0.0.1:8088/mcp")
            self.assertFalse(row["execution_supported"])
            self.assertTrue(row["requires_review"])
            self.assertNotIn("arguments", row)
            self.assertNotIn(marker, json.dumps(row))
        self.assertNotIn(marker, json.dumps(result))
        self.assertIn(self.base + "/read", {row["url"] for row in rows})
        self.assertFalse(result["usable_for_confirmation"])

    def test_route_execution_support_is_limited_to_body_free_public_get_and_head_hints(self):
        self.probe()
        secret = "opaque-route-secret-key"
        self.routes_reply([
            {"tool": "http_request", "target": self.base + "/get"},
            {"tool": "http_request", "target": self.base + "/head", "arguments": {"method": "HEAD"}},
            {"tool": "http_request", "target": self.base + "/body",
             "arguments": {"method": "GET", "body": "opaque-request-body-content"}},
            {"tool": "http_request", "target": self.base + "/" + secret, "arguments": {"method": "GET", "SecretKey": secret}},
        ])
        result = tscanplus.route_candidates(self.project, {})
        rows = {row["url"]: row for row in self.project.list("candidate")}
        self.assertTrue(rows[self.base + "/get"]["execution_supported"])
        self.assertTrue(rows[self.base + "/head"]["execution_supported"])
        self.assertFalse(rows[self.base + "/body"]["execution_supported"])
        self.assertFalse(rows["[private URL omitted]"]["execution_supported"])
        self.assertTrue(all(row["requires_review"] for row in rows.values()))
        self.assertEqual([name for name, _ in FakeClient.calls], ["route_candidates"])
        self.assertFalse(result["usable_for_confirmation"])
        self.assertEqual(self.project.list("operation"), [])

    def test_route_top_level_bodies_and_conflicting_nested_methods_are_not_supported(self):
        self.probe()
        self.routes_reply([
            {"tool": "http_request", "target": self.base + "/top-body", "body": "opaque-top-body"},
            {"tool": "http_request", "target": self.base + "/top-base64", "body_base64": "b3BhcXVlLWJvZHk="},
            {"tool": "http_request", "target": self.base + "/args-file", "args": {"body_file": "C:/never-read/body.bin"}},
            {"tool": "http_request", "target": self.base + "/different-methods",
             "arguments": {"method": "GET"}, "args": {"method": "DELETE"}},
            {"tool": "http_request", "target": self.base + "/mixed-read-methods", "method": "GET", "args": {"method": "HEAD"}},
        ])
        result = tscanplus.route_candidates(self.project, {})
        self.assertEqual(result["new_candidates"], 5)
        self.assertTrue(all(not row["execution_supported"] for row in self.project.list("candidate")))
        self.assertEqual([name for name, _ in FakeClient.calls], ["route_candidates"])
        self.assertEqual(self.project.list("operation"), [])

    def test_routes_outside_scope_excluded_and_relative_urls_never_expand_operations(self):
        self.probe()
        self.routes_reply([
            {"tool": "http_request", "target": "http://outside.invalid/item"},
            {"tool": "http_request", "target": self.base + "/excluded/item"},
            {"tool": "http_request", "target": "/relative"},
            {"tool": "http_request", "target": self.base + "/owned"},
        ])
        result = tscanplus.route_candidates(self.project, {})
        self.assertEqual(result["new_candidates"], 1)
        self.assertEqual(result["out_of_scope_rows"], 2)
        self.assertEqual(self.project.list("operation"), [])
        self.assertEqual(self.project.get("candidate", result["candidate_ids"][0])["url"], self.base + "/owned")

    def test_route_limit_is_local_only_and_omitted_candidates_remain_partial(self):
        self.probe()
        self.routes_reply([{"tool": "http_request", "target": self.base + "/" + str(index)} for index in range(3)])
        result = tscanplus.route_candidates(self.project, {"limit": 1})
        self.assertEqual(FakeClient.calls[-1], ("route_candidates", {"project": result["scanner_project"]}))
        self.assertEqual(result["reported_count"], 3)
        self.assertEqual(result["returned_rows"], 3)
        self.assertEqual(result["processed_rows"], 1)
        self.assertEqual(result["omitted_candidates"], 2)
        self.assertTrue(result["unretrieved_results"])
        self.assertFalse(result["results_complete"])
        self.assertEqual(result["new_candidates"], 1)

    def test_empty_routes_without_explicit_remote_completeness_cannot_close_assessment(self):
        self.probe()
        self.routes_reply([])
        result = tscanplus.route_candidates(self.project, {})
        self.assertFalse(result["results_complete"])
        self.assertEqual(result["reported_count"], 0)
        self.assertEqual(self.project.list("candidate"), [])
        completion = engine.evaluate_coverage(self.project)["completion"]
        self.assertGreaterEqual(completion["failed_partial_tools"], 1)

    def test_routes_missing_namespace_echo_are_partial_even_with_remote_complete_claim(self):
        self.probe()
        self.routes_reply([{"tool": "http_request", "target": self.base + "/owned"}],
                          omit_project=True, results_complete=True)
        result = tscanplus.route_candidates(self.project, {})
        self.assertFalse(result["namespace_verified"])
        self.assertFalse(result["results_complete"])
        candidate = self.project.get("candidate", result["candidate_ids"][0])
        self.assertFalse(candidate["namespace_verified"])
        self.assertEqual(candidate["status"], "unverified")

    def test_routes_wrong_namespace_is_rejected_before_import_and_saved(self):
        self.probe()
        self.routes_reply([{"tool": "poc_scan", "target": self.base + "/owned"}], project="MCP-other")
        self.assert_failed_action("tscanplus_namespace", tscanplus.route_candidates, {})

    def test_route_candidates_are_deduplicated_without_resetting_prior_disposition(self):
        self.probe()
        row = {"tool": "poc_scan", "target": self.base + "/owned"}
        self.routes_reply([row, row])
        first = tscanplus.route_candidates(self.project, {})
        self.assertEqual(first["new_candidates"], 1)
        self.assertEqual(len(first["candidate_ids"]), 1)
        candidate = self.project.get("candidate", first["candidate_ids"][0])
        candidate.update(status="dismissed", reason="offline fixture disposition")
        self.project.put("candidate", candidate)
        self.routes_reply([row])
        second = tscanplus.route_candidates(self.project, {})
        self.assertEqual(second["candidate_ids"], first["candidate_ids"])
        self.assertEqual(second["new_candidates"], 0)
        self.assertEqual(self.project.get("candidate", candidate["id"]), candidate)

    def test_routes_do_not_publish_secret_url_path_or_argument_values(self):
        self.probe()
        secret = "opaque-route-secret-key"
        self.routes_reply([{"tool": "http_request", "target": self.base + "/" + secret,
                            "arguments": {"SecretKey": secret, "headers": {"X-Secret": secret}}}])
        result = tscanplus.route_candidates(self.project, {})
        candidate = self.project.get("candidate", result["candidate_ids"][0])
        self.assertEqual(candidate["url"], "[private URL omitted]")
        self.assertTrue(candidate["url_redacted"])
        self.assertNotIn(secret, json.dumps(result))
        self.assertNotIn(secret, json.dumps(candidate))

    def test_routes_reject_malformed_collections_and_invalid_counts_without_import(self):
        self.probe()
        for change in ({"candidates": {}}, {"candidates": ["not a route"]},
                       {"counts": {"urlscan": -1}}, {"counts": {"urlscan": True}}):
            with self.subTest(change=change):
                self.routes_reply([], **change)
                self.assert_failed_action("tscanplus_result", tscanplus.route_candidates, {})

    def test_routes_block_arbitrary_tool_parameters_and_invalid_local_limits(self):
        self.probe()
        self.routes_reply([])
        for arguments in ({"limit": True}, {"limit": 1.0}, {"limit": "1"}, {"limit": 0},
                          {"limit": 101}, {"fresh_project": True}, {"tool_name": "poc_scan"},
                          {"mcp_url": "http://127.0.0.1:8089/mcp"}, {"scanner_project": "other"}):
            with self.subTest(arguments=arguments):
                with self.assertRaises(EngineError):
                    tscanplus.route_candidates(self.project, arguments)
                self.assertEqual(FakeClient.calls, [])

    def test_request_any_true_truncation_alias_overrides_false_aliases(self):
        self.probe()
        operation = engine.register_operation(self.project, {"url": self.base + "/read", "method": "GET", "auth": "public"})
        for flags in ({"response_truncated": False, "body_truncated": True},
                      {"response_truncated": False, "results_truncated": True},
                      {"truncated": False, "has_more": True}):
            with self.subTest(flags=flags):
                FakeClient.handler = lambda name, values: mcp_result({"status_code": 200, **flags})
                result = tscanplus.request_run(self.project, {"operation_id": operation["id"]})
                self.assertIs(result["response_truncated"], True)
                self.assertIs(result["results_complete"], False)
                self.assertFalse(result["usable_for_confirmation"])
                self.assertGreaterEqual(engine.evaluate_coverage(self.project)["completion"]["failed_partial_tools"], 1)
        self.assertTrue(all(name == "http_request" for name, _ in FakeClient.calls))
        self.assertEqual(self.project.list("evidence"), [])

    def test_request_explicit_incomplete_claim_overrides_false_or_absent_truncation(self):
        self.probe()
        operation = engine.register_operation(self.project, {"url": self.base + "/read", "method": "GET", "auth": "public"})
        for flags in ({"response_truncated": False, "results_complete": False}, {"results_complete": False}):
            with self.subTest(flags=flags):
                FakeClient.handler = lambda name, values: mcp_result({"status_code": 200, **flags})
                result = tscanplus.request_run(self.project, {"operation_id": operation["id"]})
                self.assertIs(result["response_truncated"], flags.get("response_truncated"))
                self.assertIs(result["results_complete"], False)
                self.assertFalse(result["usable_for_confirmation"])
                self.assertGreaterEqual(engine.evaluate_coverage(self.project)["completion"]["failed_partial_tools"], 1)
        self.assertTrue(all(name == "http_request" for name, _ in FakeClient.calls))
        self.assertEqual(self.project.list("evidence"), [])

    def test_request_without_truncation_disclosure_keeps_completeness_unknown(self):
        self.probe()
        operation = engine.register_operation(self.project, {"url": self.base + "/read", "method": "GET", "auth": "public"})
        for flags in ({}, {"results_complete": True}):
            with self.subTest(flags=flags):
                FakeClient.handler = lambda name, values: mcp_result({"status_code": 200, **flags})
                result = tscanplus.request_run(self.project, {"operation_id": operation["id"]})
                self.assertIsNone(result["response_truncated"])
                self.assertIsNone(result["results_complete"])
                self.assertFalse(result["usable_for_confirmation"])
                self.assertEqual(engine.evaluate_coverage(self.project)["completion"]["failed_partial_tools"], 0)
        self.assertTrue(all(name == "http_request" for name, _ in FakeClient.calls))
        self.assertEqual(self.project.list("evidence"), [])

    def assert_remote_review_remains_blocked(self, result):
        from awa_ddd import completeness, continuation

        audit = completeness.audit(self.project, {"limit": 100})
        row = next(item for item in audit["checklist"]
                   if item["kind"] == "failed_partial_tool" and item.get("run_id") == result["run_id"])
        arguments = {"checklist_id": row["id"], "status": "reviewed", "reviewer": "offline-fixture-reviewer",
                     "reason": "Inspecting local artifacts cannot establish missing remote result completeness."}
        self.assertEqual(audit["completion"]["failed_partial_tools"], 1)
        self.assert_code("remote_execution_unverified", lambda: continuation.review(self.project, arguments))
        self.assertEqual(self.project.list("closure_review"), [])
        blocked = continuation.review(self.project, {**arguments, "status": "blocked"})
        self.assertEqual(blocked["review"]["status"], "blocked")
        self.assertEqual(blocked["completion"]["failed_partial_tools"], 1)
        current = completeness.audit(self.project, {"limit": 100})
        self.assertEqual(current["completion"]["failed_partial_tools"], 1)
        retained = next(item for item in current["checklist"] if item["id"] == row["id"])
        self.assertEqual(retained["status"], "blocked")
        self.assert_code("remote_execution_unverified", lambda: continuation.review(self.project, arguments))
        self.assertEqual(len(self.project.list("closure_review")), 1)
        self.assertEqual(self.project.list("evidence"), [])

    def test_summary_missing_echo_cannot_be_administratively_reviewed_away(self):
        self.probe()
        self.summary_reply(omit_project=True)
        result = tscanplus.project_summary(self.project, {})
        self.assertFalse(result["results_complete"])
        self.assert_remote_review_remains_blocked(result)
        self.assertEqual([name for name, _ in FakeClient.calls], ["project_summary"])

    def test_routes_without_remote_completeness_cannot_be_administratively_reviewed_away(self):
        self.probe()
        self.routes_reply([])
        result = tscanplus.route_candidates(self.project, {})
        self.assertFalse(result["results_complete"])
        self.assert_remote_review_remains_blocked(result)
        self.assertEqual([name for name, _ in FakeClient.calls], ["route_candidates"])

    def test_dispatched_http_explicit_incomplete_result_cannot_be_administratively_reviewed_away(self):
        self.probe()
        operation = engine.register_operation(self.project, {"url": self.base + "/read", "method": "GET", "auth": "public"})
        FakeClient.handler = lambda name, values: mcp_result({"status_code": 200, "response_truncated": False,
                                                             "results_complete": False})
        result = tscanplus.request_run(self.project, {"operation_id": operation["id"]})
        self.assertTrue(result["dispatch_attempted"])
        self.assertFalse(result["results_complete"])
        self.assert_remote_review_remains_blocked(result)
        self.assertEqual([name for name, _ in FakeClient.calls], ["http_request"])

    def test_valid_legacy_reviewed_receipts_cannot_hide_incomplete_remote_sources(self):
        from awa_ddd import completeness, continuation
        from awa_ddd.store import now

        for profile in ("summary", "routes", "http"):
            with self.subTest(profile=profile):
                identity = "legacy-" + profile
                engine.create_project(self.project.workspace, {"project_id": identity, "target": self.base})
                with Project(self.project.workspace, identity) as project:
                    tscanplus.probe(project, {"adapter": "tscanplus"})
                    if profile == "summary":
                        self.summary_reply(omit_project=True)
                        result = tscanplus.project_summary(project, {})
                    elif profile == "routes":
                        self.routes_reply([])
                        result = tscanplus.route_candidates(project, {})
                    else:
                        operation = engine.register_operation(project, {"url": self.base + "/read", "method": "GET", "auth": "public"})
                        FakeClient.handler = lambda name, values: mcp_result({"status_code": 200,
                            "response_truncated": False, "results_complete": False})
                        result = tscanplus.request_run(project, {"operation_id": operation["id"]})
                    row = next(item for item in completeness.audit(project, {"limit": 100})["checklist"]
                               if item["kind"] == "failed_partial_tool" and item.get("run_id") == result["run_id"])
                    blocked = continuation.review(project, {"checklist_id": row["id"], "status": "blocked",
                        "reviewer": "offline-fixture-reviewer", "reason": "The remote result remains incomplete."})["review"]
                    # Public review responses redact signatures; retain the original stored receipt.
                    blocked = project.get("closure_review", blocked["id"])
                    legacy = {**blocked, "id": project.id("CR"), "status": "reviewed", "created_at": now()}
                    project.put("closure_review", legacy, create_only=True)
                    self.assertTrue(continuation._review_valid(project, legacy, project.get("run", result["run_id"])))
                    evaluated = engine.evaluate_coverage(project)
                    inventory = completeness._inventory(project, evaluated)
                    self.assertEqual(evaluated["completion"]["failed_partial_tools"], 1)
                    self.assertEqual(len(inventory["partial_tools"]), 1)
                    self.assertFalse(any(item["id"] == legacy["id"] for item in inventory["reviewed_admin"]))
                    self.assertEqual(completeness.audit(project, {})["administrative_reviews"], 0)
                    self.assertEqual(project.get("closure_review", blocked["id"]), blocked)
                    self.assertEqual(project.get("closure_review", legacy["id"]), legacy)
                    self.assertEqual(len(project.list("closure_review")), 2)
                    self.assertEqual(project.list("evidence"), [])


if __name__ == "__main__":
    unittest.main()
