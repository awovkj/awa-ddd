"""Offline tool-proof lineage and private artifact regressions."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

from awa_ddd import engine, external
from awa_ddd.assessment import evaluate, record_finding
from awa_ddd.store import EngineError, Project, now


def observed(url, method, headers, body, timeout, max_bytes, *, response=None):
    raw = json.dumps(response if response is not None else {"items": ["business-baseline"]}).encode("utf-8")
    sent = body if isinstance(body, bytes) else body.encode("utf-8") if isinstance(body, str) else json.dumps(body).encode("utf-8") if body is not None else b""
    return {"request": {"url": url, "method": method, "headers": headers,
                        "body_base64": base64.b64encode(sent).decode("ascii")},
            "response": {"status": 200, "headers": [["content-type", "application/json"]],
                         "length": len(raw), "body_base64": base64.b64encode(raw).decode("ascii")},
            "complete": True, "started_at": now(), "completed_at": now()}


class ToolLineageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-tool-lineage-")
        self.addCleanup(self.tmp.cleanup)
        self.base = "http://fixture.invalid"
        engine.create_project(self.tmp.name, {"project_id": "lineage", "target": self.base})
        self.project = Project(self.tmp.name, "lineage")
        self.addCleanup(self.project.close)
        self.executable = Path(self.tmp.name) / "sqlmap.py"
        self.executable.write_text("# A local mock fixture; never executed.\n", encoding="utf-8")
        self.operation = engine.register_operation(self.project, {
            "url": self.base + "/items", "method": "GET", "auth": "public",
            "inputs": [{"name": "sort", "location": "query", "consumer": "sql_order_by"}],
        })
        self.identity = engine.register_operation(self.project, {
            "url": self.base + "/whoami", "method": "GET", "auth": "authenticated"})

    def session(self, subject="alice", roles=None):
        roles = ["user"] if roles is None else roles
        engine.add_actor(self.project, {"actor_id": "actor", "subject": subject, "roles": roles})
        session = engine.add_session(self.project, {
            "actor_id": "actor", "headers": {"Cookie": "SID=ORIGINAL_TOOL_CREDENTIAL_123", "X-Business": "fixed"}})
        self.verify(session, subject, roles)
        return self.project.get("session", session["id"])

    def verify(self, session, subject, roles):
        with patch.object(engine, "request", side_effect=lambda *args: observed(*args, response={"subject": subject, "roles": roles})):
            engine.verify_identity(self.project, {"operation_id": self.identity["id"], "session_id": session["id"],
                                                   "subject_selector": "/subject", "roles_selector": "/roles"})

    def tool(self, session=None, *, extra_query=None, text=None):
        query = [("sort", "price"), *(extra_query or [])]

        def process(command, **options):
            options["stdout"].write((text if text is not None else "identified the following injection point(s)\ncurrent database: 'audit_db'\n").encode("utf-8"))
            Path(command[command.index("-t") + 1]).write_text(
                "HTTP request [#1]:\nGET /items?sort=price HTTP/1.1\n\nHTTP response [#1]:\nHTTP/1.1 200 OK\n\n", encoding="utf-8")

            class Process:
                returncode = 0

                def poll(self):
                    return 0

            return Process()

        args = {"operation_id": self.operation["id"], "url": self.operation["url"] + "?" + urlencode(query),
                "sqlmap_path": str(self.executable), "parameter": "sort", "effect": "read_only"}
        if session:
            args["session_id"] = session["id"]
        with patch.object(external.subprocess, "Popen", side_effect=process):
            return external.sqlmap_run(self.project, args)

    def controls(self, session=None, *, extra_query=None, baseline="price", headers=None, body=None):
        ids = []
        for value in (baseline, "price AND 1=1", "price AND 1=2"):
            query = [("sort", value), *(extra_query or [])]
            args = {"operation_id": self.operation["id"], "url": self.operation["url"] + "?" + urlencode(query)}
            if session:
                args["session_id"] = session["id"]
            if headers is not None:
                args["headers"] = headers
            if body is not None:
                args["body"] = body
            with patch.object(engine, "request", side_effect=observed):
                ids.append(engine.capture(self.project, args)["id"])
        return ids

    def confirm(self, tool, ids):
        engine.build_plan(self.project)
        obligation = next(row for row in self.project.list("obligation")
                          if row["operation_id"] == self.operation["id"] and row["kind"] == "input_test" and not row.get("superseded"))
        return evaluate(self.project, {"obligation_id": obligation["id"], "evidence_ids": ids,
                                      "oracle": {"type": "sql_metadata", "metadata_type": "database", "expected_value": "audit_db",
                                                 "baseline_selector": "/items", "baseline_expected": ["business-baseline"], "tool_run_id": tool["run_id"]}})

    def assert_stale(self, tool, reason):
        result = external.inspect(self.project, {"run_id": tool["run_id"]})
        self.assertEqual(result["integrity"], "valid")
        self.assertEqual(result["lineage"], "stale")
        self.assertEqual(result["lineage_reason_code"], reason)
        self.assertFalse(result["usable_for_confirmation"])

    def test_fresh_public_transcript_has_bound_proof_without_raw_context_values(self):
        tool = self.tool(extra_query=[("item", "FIXTURE_VALUE_NOT_PUBLIC")])
        result = external.inspect(self.project, {"run_id": tool["run_id"]})
        self.assertEqual(result["integrity"], "valid")
        self.assertEqual(result["lineage"], "current")
        self.assertTrue(result["usable_for_confirmation"])
        self.assertNotIn("FIXTURE_VALUE_NOT_PUBLIC", json.dumps(result))
        decision = self.confirm(tool, self.controls(extra_query=[("item", "FIXTURE_VALUE_NOT_PUBLIC")]))
        self.assertEqual(decision["outcome"], "confirmed")
        self.assertEqual(decision["proof"]["channel"], "sqlmap_metadata_transcript")

    def test_subject_change_cannot_relabel_old_transcript(self):
        session = self.session()
        tool = self.tool(session)
        engine.add_actor(self.project, {"actor_id": "actor", "subject": "bob"})
        self.verify(session, "bob", ["user"])
        self.assert_stale(tool, "actor_changed")
        with self.assertRaises(EngineError) as error:
            self.confirm(tool, self.controls(session))
        self.assertEqual(error.exception.code, "actor_changed")

    def test_role_change_and_restoration_keep_old_transcript_historical(self):
        session = self.session()
        tool = self.tool(session)
        for roles in (["guest"], ["user"]):
            engine.add_actor(self.project, {"actor_id": "actor", "roles": roles})
            self.verify(session, "alice", roles)
            self.assert_stale(tool, "actor_changed")

    def test_label_update_and_unrelated_input_addition_preserve_proof(self):
        session = self.session()
        tool = self.tool(session)
        ids = self.controls(session)
        engine.add_actor(self.project, {"actor_id": "actor", "label": "Updated display name"})
        engine.register_operation(self.project, {"url": self.operation["url"], "method": "GET",
                                                  "inputs": [{"name": "unused", "location": "query", "consumer": "sql_filter"}]})
        self.assertEqual(external.inspect(self.project, {"run_id": tool["run_id"]})["lineage"], "current")
        self.assertEqual(self.confirm(tool, ids)["outcome"], "confirmed")

    def test_session_rotation_rejects_old_tool_but_preserves_original_credential_redaction(self):
        session = self.session()
        tool = self.tool(session, text="current database: 'audit_db'\nserver repeated ORIGINAL_TOOL_CREDENTIAL_123\n")
        rotated = engine.add_session(self.project, {"actor_id": "actor", "session_id": session["id"],
                                                     "headers": {"Cookie": "SID=NEW_TOOL_CREDENTIAL_456", "X-Business": "fixed"}})
        self.verify(rotated, "alice", ["user"])
        self.assert_stale(tool, "session_changed")
        view = external.read_artifact(self.project, {"run_id": tool["run_id"], "name": "stdout"})
        self.assertNotIn("ORIGINAL_TOOL_CREDENTIAL_123", view["content"])
        self.assertIn("[credential redacted]", view["content"])

    def test_in_place_credential_change_is_not_a_valid_tool_identity(self):
        session = self.session()
        tool = self.tool(session)
        changed = self.project.get("session", session["id"])
        changed["headers"]["cookie"] = "SID=UNREGISTERED_REPLACEMENT_789"
        self.project.put("session", changed)
        self.assert_stale(tool, "credential_changed")

    def test_credential_reclassification_cannot_upgrade_old_tool_identity(self):
        session = self.session()
        tool = self.tool(session)
        changed = self.project.get("session", session["id"])
        changed["credential_header_names"].append("x-business")
        self.project.put("session", changed)
        self.assert_stale(tool, "credential_changed")

    def test_in_place_business_header_change_is_not_a_matching_tool_context(self):
        session = self.session()
        tool = self.tool(session)
        changed = self.project.get("session", session["id"])
        changed["headers"]["x-business"] = "another resource selector"
        self.project.put("session", changed)
        self.assert_stale(tool, "tool_headers_changed")

    def test_ttl_expiry_does_not_erase_historical_tool_proof(self):
        session = self.session()
        tool = self.tool(session)
        ids = self.controls(session)
        expired = self.project.get("session", session["id"])
        expired["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        self.project.put("session", expired)
        self.assertEqual(external.inspect(self.project, {"run_id": tool["run_id"]})["lineage"], "current")
        self.assertEqual(self.confirm(tool, ids)["outcome"], "confirmed")

    def test_selected_consumer_change_invalidates_tool_proof(self):
        tool = self.tool()
        engine.register_operation(self.project, {"url": self.operation["url"], "method": "GET",
                                                  "inputs": [{"name": "sort", "location": "query", "consumer": "sql_where"}]})
        self.assert_stale(tool, "tool_input_changed")
        with self.assertRaises(EngineError) as error:
            self.confirm(tool, self.controls())
        self.assertEqual(error.exception.code, "tool_input_changed")

    def test_new_selected_schema_branch_invalidates_tool_proof(self):
        tool = self.tool()
        engine.register_operation(self.project, {"url": self.operation["url"], "method": "GET",
                                                  "inputs": [{"name": "sort", "location": "query", "consumer": "sql_order_by", "schema_branch": "oneOf/1"}]})
        self.assert_stale(tool, "tool_input_changed")

    def test_operation_policy_change_invalidates_tool_proof(self):
        tool = self.tool()
        engine.register_operation(self.project, {"url": self.operation["url"], "method": "GET", "auth": "authenticated"})
        self.assert_stale(tool, "operation_changed")

    def test_another_resource_query_cannot_reuse_the_same_transcript(self):
        tool = self.tool(extra_query=[("item", "owned-fixture")])
        with self.assertRaises(EngineError) as error:
            self.confirm(tool, self.controls(extra_query=[("item", "another-fixture")]))
        self.assertEqual(error.exception.code, "tool_context_changed")

    def test_another_baseline_input_cannot_reuse_the_same_transcript(self):
        tool = self.tool()
        with self.assertRaises(EngineError) as error:
            self.confirm(tool, self.controls(baseline="name"))
        self.assertEqual(error.exception.code, "tool_baseline_changed")

    def test_extra_control_business_header_cannot_reuse_transcript(self):
        tool = self.tool()
        with self.assertRaises(EngineError) as error:
            self.confirm(tool, self.controls(headers={"X-Mode": "another-route"}))
        self.assertEqual(error.exception.code, "tool_context_changed")

    def test_control_body_cannot_reuse_a_bodyless_get_transcript(self):
        tool = self.tool()
        with self.assertRaises(EngineError) as error:
            self.confirm(tool, self.controls(body="a different business context"))
        self.assertEqual(error.exception.code, "tool_context_changed")

    def test_same_session_tool_cannot_be_used_as_anonymous_controls(self):
        tool = self.tool(self.session())
        with self.assertRaises(EngineError) as error:
            self.confirm(tool, self.controls())
        self.assertEqual(error.exception.code, "control_identity")

    def test_legacy_transcript_is_readable_but_cannot_be_promoted(self):
        run, _ = external._start(self.project, "sqlmap", "metadata", self.operation)
        run.update(status="succeeded", exit_code=0, metadata_only=True, input_location="query", input_selector="sort",
                   traffic_requests=1, traffic_responses=1, target_traffic_sent=True, metadata_candidates={"database": "audit_db"})
        tool = external._finish(self.project, run, {"metadata_candidates": {"database": "audit_db"}})
        result = external.inspect(self.project, {"run_id": tool["run_id"]})
        self.assertEqual(result["integrity"], "valid")
        self.assertEqual(result["lineage"], "legacy")
        self.assertFalse(result["usable_for_confirmation"])
        with self.assertRaises(EngineError) as error:
            self.confirm(tool, self.controls())
        self.assertEqual(error.exception.code, "tool_lineage_missing")
        view = external.read_artifact(self.project, {"run_id": tool["run_id"], "name": "result"})
        self.assertIn("audit_db", view["content"])
        self.assertNotIn("lineage_version", self.project.get("run", tool["run_id"]))

    def test_added_mutable_snapshot_fields_cannot_upgrade_a_legacy_run(self):
        fresh = self.tool()
        run, _ = external._start(self.project, "sqlmap", "metadata", self.operation)
        run.update(status="succeeded", exit_code=0, metadata_only=True, input_location="query", input_selector="sort",
                   traffic_requests=1, traffic_responses=1, metadata_candidates={"database": "audit_db"})
        legacy = external._finish(self.project, run, {"metadata_candidates": {"database": "audit_db"}})
        changed = self.project.get("run", legacy["run_id"])
        for field in external._TOOL_LINEAGE_FIELDS:
            changed[field] = fresh[field]
        self.project.put("run", changed)
        result = external.inspect(self.project, {"run_id": legacy["run_id"]})
        self.assertEqual(result["integrity"], "valid")
        self.assertEqual(result["lineage"], "legacy")
        self.assertFalse(result["usable_for_confirmation"])

    def test_existing_finding_reopens_when_selected_input_proof_changes(self):
        tool = self.tool()
        decision = self.confirm(tool, self.controls())
        finding = record_finding(self.project, {"decision_id": decision["id"], "title": "Mock metadata recovery", "category": "SQL Injection",
                                               "impact": "Only a synthetic database name", "remediation": "Parameterize the query"})
        engine.register_operation(self.project, {"url": self.operation["url"], "method": "GET",
                                                  "inputs": [{"name": "sort", "location": "query", "consumer": "sql_where"}]})
        result = next(row for row in engine.evaluate_coverage(self.project)["findings"] if row["id"] == finding["id"])
        self.assertFalse(result["current"])
        self.assertEqual(result["reason_code"], "tool_input_changed")

    def test_log_digest_metadata_is_part_of_the_digested_execution(self):
        tool = self.tool()
        document = self.project.read_artifact(tool)
        self.assertEqual(document["execution"]["files"], tool["files"])
        changed = self.project.get("run", tool["run_id"])
        log = self.project.base / changed["files"][0]["path"]
        log.write_text("substituted bytes", encoding="utf-8")
        changed["files"][0] = external._file_summary(self.project, log)
        self.project.put("run", changed)
        result = external.inspect(self.project, {"run_id": tool["run_id"]})
        self.assertEqual(result["integrity"], "invalid")
        self.assertFalse(result["usable_for_confirmation"])
        with self.assertRaises(EngineError) as error:
            external.read_artifact(self.project, {"run_id": tool["run_id"], "name": "stdout"})
        self.assertEqual(error.exception.code, "tool_artifact_changed")

    def test_concrete_path_template_target_is_supported(self):
        self.operation = engine.register_operation(self.project, {
            "url": self.base + "/items/{id}", "method": "GET", "auth": "public",
            "inputs": [{"name": "sort", "location": "query", "consumer": "sql_order_by"}],
        })
        run, _ = external._start(self.project, "sqlmap", "metadata", self.operation,
                                 target_url=self.base + "/items/fixture-one?sort=price",
                                 input_location="query", input_selector="sort")
        run.update(status="succeeded", exit_code=0, metadata_only=True, metadata_candidates={"database": "audit_db"},
                   traffic_requests=1, traffic_responses=1)
        tool = external._finish(self.project, run, {"metadata_candidates": {"database": "audit_db"}})
        self.assertEqual(external.inspect(self.project, {"run_id": tool["run_id"]})["lineage"], "current")

    def test_unresolved_tool_path_is_rejected_before_run_claim(self):
        operation = engine.register_operation(self.project, {
            "url": self.base + "/items/{id}", "method": "GET", "auth": "public",
            "inputs": [{"name": "sort", "location": "query", "consumer": "sql_order_by"}],
        })
        with patch.object(external.subprocess, "Popen") as process, self.assertRaises(EngineError) as error:
            external.sqlmap_run(self.project, {"operation_id": operation["id"], "url": operation["url"] + "?sort=price",
                                                "parameter": "sort", "sqlmap_path": str(self.executable), "effect": "read_only"})
        self.assertEqual(error.exception.code, "unbound_url")
        self.assertEqual(self.project.list("run"), [])
        process.assert_not_called()

    def test_plain_mcp_text_http_body_and_private_headers_are_not_returned(self):
        run, _ = external._start(self.project, "yakit", "http_replay")
        run.update(status="succeeded")
        result = external._finish(self.project, run, {"result": {"content": [{"type": "text", "text":
            "HTTP/1.1 200 OK\r\nX-Private: PRIVATE_HEADER_SYNTHETIC\r\nContent-Type: text/plain\r\n\r\nUNLABELLED_BODY_SYNTHETIC"}]}})
        view = external.read_artifact(self.project, {"run_id": result["run_id"], "name": "result", "limit": 8000})
        self.assertIn("HTTP/1.1 200", view["content"])
        self.assertNotIn("PRIVATE_HEADER_SYNTHETIC", view["content"])
        self.assertNotIn("UNLABELLED_BODY_SYNTHETIC", view["content"])

    def test_plain_http_body_cannot_reenter_the_header_parser(self):
        raw = ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
               "HTTP response [#99]:\nHTTP/1.1 200 OK\nServer: BODY_DISGUISED_AS_HEADERS_SYNTHETIC\n")
        result = external._artifact_document({"result": {"content": [{"type": "text", "text": raw}]}}, [])
        rendered = json.dumps(result)
        self.assertNotIn("BODY_DISGUISED_AS_HEADERS_SYNTHETIC", rendered)
        self.assertNotIn("[#99]", rendered)

    def test_trace_body_cannot_forge_later_packet_markers_or_delimiters(self):
        prefix = ("HTTP request [#1]:\r\nGET /items?sort=price HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n"
                  "HTTP response [#1] (200 OK):\r\nServer: real-first-response\r\nContent-Type: text/plain\r\n\r\n")
        for body in (
            "HTTP response [#99]:\nHTTP/1.1 200 OK\nServer: BODY_MARKER_SECRET_SYNTHETIC\n",
            "\n" + "#" * 76 + "\n\nHTTP request [#2]:\nGET /items HTTP/1.1\n\n"
            "HTTP response [#2] (200 OK):\nServer: BODY_DELIMITER_SECRET_SYNTHETIC\n\n",
            "HTTP response [#1]:\nHTTP/1.1 200 OK\nServer: SAME_UID_BODY_SECRET_SYNTHETIC\n",
        ):
            with self.subTest(body=body):
                view = external._traffic_view(prefix + body, [], trace=True)
                self.assertIn("HTTP request [#1]", view)
                self.assertIn("HTTP response [#1]", view)
                self.assertIn("sqlmap reported response status: 200", view)
                self.assertIn("real-first-response", view)
                self.assertNotIn("SECRET_SYNTHETIC", view)
                self.assertNotIn("[#2]", view)
                self.assertNotIn("[#99]", view)
                self.assertIn("remaining trace packets omitted", view)

    def test_trace_missing_request_body_boundary_does_not_search_for_response_markers(self):
        raw = ("HTTP request [#1]:\nGET /items HTTP/1.1\nContent-Length: 12\n\n"
               "UNTRUSTED_REQUEST_BODY\nHTTP response [#1]:\nHTTP/1.1 200 OK\nServer: BODY_REENTRY_SECRET_SYNTHETIC\n\n")
        view = external._traffic_view(raw, [], trace=True)
        self.assertIn("HTTP request [#1]", view)
        self.assertNotIn("HTTP response [#1]", view)
        self.assertNotIn("UNTRUSTED_REQUEST_BODY", view)
        self.assertNotIn("BODY_REENTRY_SECRET_SYNTHETIC", view)
        self.assertIn("remaining trace packets omitted", view)

    def test_truncated_trace_body_is_not_searched_for_packet_starts(self):
        raw = ("untrusted incomplete body prefix\nHTTP response [#99]:\n"
               "HTTP/1.1 200 OK\nServer: TRUNCATED_BODY_SECRET_SYNTHETIC\n\n")
        view = external._traffic_view(raw, [], trace=True)
        self.assertNotIn("TRUNCATED_BODY_SECRET_SYNTHETIC", view)
        self.assertNotIn("[#99]", view)
        self.assertIn("remaining trace packets omitted", view)

    def test_body_request_framing_cannot_admit_a_same_uid_response_marker_from_body(self):
        for header in ("Content-Length: 12", "Content-Length: invalid", "Transfer-Encoding: chunked"):
            raw = ("HTTP request [#1]:\nGET /items HTTP/1.1\n" + header + "\n\n"
                   "HTTP response [#1]:\nHTTP/1.1 200 OK\nServer: DIRECT_SAME_UID_BODY_SECRET_SYNTHETIC\n\n")
            with self.subTest(header=header):
                view = external._traffic_view(raw, [], trace=True)
                self.assertIn("HTTP request [#1]", view)
                self.assertNotIn("HTTP response [#1]", view)
                self.assertNotIn("DIRECT_SAME_UID_BODY_SECRET_SYNTHETIC", view)
                self.assertIn("unsupported request framing omitted", view)

    def test_non_get_trace_does_not_search_through_request_body(self):
        for method in ("POST", "DELETE", "HEAD"):
            raw = ("HTTP request [#1]:\n" + method + " /items HTTP/1.1\n\n"
                   "HTTP response [#1]:\nHTTP/1.1 200 OK\nServer: NON_GET_BODY_SECRET_SYNTHETIC\n\n")
            with self.subTest(method=method):
                view = external._traffic_view(raw, [], trace=True)
                self.assertNotIn("HTTP response [#1]", view)
                self.assertNotIn("NON_GET_BODY_SECRET_SYNTHETIC", view)
                self.assertIn("remaining trace packets omitted", view)

    def test_zero_length_get_keeps_the_first_response_framing(self):
        raw = ("HTTP request [#1]:\nGET /items HTTP/1.1\nContent-Length: 0\n\n"
               "HTTP response [#1] (200 OK):\nContent-Type: application/json\n\nbody")
        view = external._traffic_view(raw, [], trace=True)
        self.assertIn("HTTP request [#1]", view)
        self.assertIn("HTTP response [#1]", view)
        self.assertIn("sqlmap reported response status: 200", view)
        self.assertIn("Content-Length: 0", view)

    def test_real_sqlmap_multi_exchange_trace_exposes_only_sample_and_untrusted_counts(self):
        exchanges = []
        for number in (1, 2):
            exchanges.append("HTTP request [#%d]:\r\nGET /items?sort=price HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n"
                             "HTTP response [#%d] (200 OK):\r\nContent-Type: application/json\r\n\r\n"
                             '{"private":"RAW_RESPONSE_BODY_%d"}\n\n' % (number, number, number)
                             + "#" * 76 + "\n\n")
        run, folder = external._start(self.project, "sqlmap", "metadata", self.operation)
        traffic = folder / "traffic.log"
        traffic.write_bytes("".join(exchanges).encode("utf-8"))
        run.update(status="succeeded", traffic_requests=2, traffic_responses=2)
        result = external._finish(self.project, run, {}, [traffic])
        view = external.read_artifact(self.project, {"run_id": result["run_id"], "name": "traffic", "limit": 8000})
        self.assertIn("HTTP request [#1]", view["content"])
        self.assertIn("HTTP response [#1]", view["content"])
        self.assertNotIn("[#2]", view["content"])
        self.assertNotIn("RAW_RESPONSE_BODY", view["content"])
        self.assertIn("remaining trace packets omitted", view["content"])
        self.assertEqual(view["trace_summary"]["traffic_requests"], 2)
        self.assertEqual(view["trace_summary"]["traffic_responses"], 2)
        self.assertTrue(view["trace_summary"]["counts_are_untrusted"])
        self.assertFalse(view["trace_summary"]["complete_packet_view"])

    def test_sqlmap_response_reason_is_not_exposed_as_framing(self):
        raw = ("HTTP response [#1] (200 PRIVATE_REASON_SYNTHETIC):\nContent-Type: text/plain\n\nbody")
        view = external._traffic_view(raw, [], trace=True)
        self.assertIn("sqlmap reported response status: 200", view)
        self.assertNotIn("PRIVATE_REASON_SYNTHETIC", view)

    def test_folded_private_header_cannot_impersonate_public_header(self):
        headers = "Set-Cookie: hidden\n Server: FOLDED_COOKIE_SECRET_SYNTHETIC\n\nbody"
        for raw, trace in (("HTTP/1.1 200 OK\n" + headers, False),
                           ("HTTP response [#1] (200 OK):\n" + headers, True)):
            with self.subTest(trace=trace):
                self.assertNotIn("FOLDED_COOKIE_SECRET_SYNTHETIC", external._traffic_view(raw, [], trace=trace))


if __name__ == "__main__":
    unittest.main()
