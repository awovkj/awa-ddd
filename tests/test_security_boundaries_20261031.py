"""Offline regressions for ambiguous response proofs and private browser output."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

from awa_ddd import browser, completeness, continuation, engine
from awa_ddd.__main__ import dispatch
from awa_ddd.assessment import _extract_value, evaluate, record_finding, validate_confirmation
from awa_ddd.store import EngineError, Project, canonical, now
from awa_ddd.transport import response_json


def observed_response(url, method, headers, body, timeout, max_bytes, *, response):
    sent = (body if isinstance(body, bytes) else body.encode("utf-8") if isinstance(body, str)
            else json.dumps(body, separators=(",", ":")).encode("utf-8") if body is not None else b"")
    return {"request": {"url": url, "method": method, "headers": headers,
                        "body_base64": base64.b64encode(sent).decode("ascii")},
            "response": {"status": 200, "headers": [["content-type", "application/json"]],
                         "body_base64": base64.b64encode(response).decode("ascii"),
                         "body_sha256": hashlib.sha256(response).hexdigest(), "length": len(response)},
            "started_at": now(), "completed_at": now(), "complete": True}


INVALID_RESPONSES = (
    b'{"answer":"first","answer":"last"}',
    b'{"answer":"last","nested":{"id":1,"id":2}}',
    b'{"answer":"last","count":NaN}',
    b'{"answer":"last","count":Infinity}',
    b'{"answer":"last","count":-Infinity}',
    b'{"answer":"last","count":1e999}',
    b'{"answer":"last","unused":"\\ud800"}',
    b'{"answer":"last","\\udfff":1}',
)


class StrictResponseJsonTests(unittest.TestCase):
    def artifact(self, raw):
        return {"response": {"body_base64": base64.b64encode(raw).decode("ascii")}}

    def test_rejects_ambiguous_nonfinite_and_invalid_unicode_responses(self):
        for raw in (*INVALID_RESPONSES, b'"\xff"', b'{"x":', b"[" * 65 + b"0" + b"]" * 65):
            with self.subTest(raw=raw), self.assertRaises(EngineError) as caught:
                response_json(self.artifact(raw))
            self.assertEqual("response_json", caught.exception.code)
            self.assertNotIn("last", str(caught.exception))

    def test_valid_unicode_finite_numbers_and_utf8_bom_remain_supported(self):
        raw = b'\xef\xbb\xbf{"answer":"\\ud83d\\ude00","count":1e3,"other":[true,null]}'
        self.assertEqual({"answer": "\U0001f600", "count": 1000.0, "other": [True, None]},
                         response_json(self.artifact(raw)))
        self.assertEqual({"answer": "valid"}, response_json(self.artifact(b'{"answer":"valid"}')))

    def test_missing_or_invalid_base64_is_a_fixed_response_error(self):
        for artifact in ({}, {"response": {}}, {"response": {"body_base64": "not base64!"}},
                         {"response": {"body_base64": None}}):
            with self.subTest(artifact=artifact), self.assertRaises(EngineError) as caught:
                response_json(artifact)
            self.assertEqual("response_json", caught.exception.code)


class ResponseProofBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-response-security-")
        self.addCleanup(self.tmp.cleanup)
        self.base = "http://fixture.invalid"
        engine.create_project(self.tmp.name, {"project_id": "response", "target": self.base})
        self.project = Project(self.tmp.name, "response")
        self.addCleanup(self.project.close)

    def capture(self, operation, raw, **args):
        with patch.object(engine, "request", side_effect=lambda *values: observed_response(*values, response=raw)):
            return engine.capture(self.project, {"operation_id": operation["id"], **args})

    def test_identity_cannot_verify_a_last_duplicate_subject_or_invalid_unused_value(self):
        actor = engine.add_actor(self.project, {"subject": "bob", "roles": []})
        session = engine.add_session(self.project, {"actor_id": actor["id"],
                                                   "headers": {"Cookie": "session=synthetic-identity-cookie"}})
        operation = engine.register_operation(self.project, {"url": self.base + "/whoami", "method": "GET"})
        for raw in (b'{"subject":"alice","subject":"bob"}',
                    b'{"subject":"bob","unused":NaN}', b'{"subject":"bob","unused":"\\ud800"}'):
            with self.subTest(raw=raw):
                with patch.object(engine, "request", side_effect=lambda *values: observed_response(*values, response=raw)):
                    with self.assertRaises(EngineError) as caught:
                        engine.verify_identity(self.project, {"operation_id": operation["id"],
                            "session_id": session["id"], "subject_selector": "/subject"})
                self.assertEqual("response_json", caught.exception.code)
                current = self.project.get("session", session["id"])
                self.assertIsNone(current["verified_at"])
                self.assertIsNone(current["verification_evidence_id"])
        self.assertEqual(3, len(self.project.list("evidence")))
        self.assertFalse(self.project.list("decision"))

    def test_baseline_oracle_cannot_close_on_an_ambiguous_or_nonfinite_response(self):
        operation = engine.register_operation(self.project, {"url": self.base + "/read", "method": "GET", "auth": "public"})
        engine.build_plan(self.project)
        obligation = next(row for row in self.project.list("obligation") if row["kind"] == "baseline")
        for raw in INVALID_RESPONSES:
            with self.subTest(raw=raw):
                evidence = self.capture(operation, raw)
                with self.assertRaises(EngineError) as caught:
                    evaluate(self.project, {"obligation_id": obligation["id"], "evidence_ids": [evidence["id"]],
                        "oracle": {"type": "baseline", "selector": "/answer", "expected": "last"}})
                self.assertEqual("response_json", caught.exception.code)
                self.assertEqual("open", self.project.get("obligation", obligation["id"])["status"])
        self.assertFalse(self.project.list("decision"))

    def test_a_valid_finite_response_still_closes_the_normal_baseline(self):
        operation = engine.register_operation(self.project, {"url": self.base + "/read", "method": "GET", "auth": "public"})
        engine.build_plan(self.project)
        obligation = next(row for row in self.project.list("obligation") if row["kind"] == "baseline")
        evidence = self.capture(operation, b'{"answer":"normal","count":1}')
        decision = evaluate(self.project, {"obligation_id": obligation["id"], "evidence_ids": [evidence["id"]],
            "oracle": {"type": "baseline", "selector": "/answer", "expected": "normal"}})
        self.assertEqual("refuted", decision["outcome"])

    def input_operation(self, path, family, consumer):
        operation = engine.register_operation(self.project, {"url": self.base + path, "method": "GET", "auth": "public",
            "inputs": [{"name": "q", "location": "query", "consumer": consumer, "test_families": [family]}]})
        engine.build_plan(self.project)
        item = next(row for row in self.project.list("obligation") if row["operation_id"] == operation["id"]
                    and row["kind"] == "input_test" and not row.get("superseded"))
        return operation, item

    def input_capture(self, operation, value, raw):
        return self.capture(operation, raw, url=operation["url"] + "?" + urlencode({"q": value}))

    def assert_invalid_decision(self, item, evidence, oracle, code="response_json"):
        decisions = len(self.project.list("decision"))
        with self.assertRaises(EngineError) as caught:
            evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": [row["id"] for row in evidence], "oracle": oracle})
        self.assertEqual(code, caught.exception.code)
        self.assertEqual(decisions, len(self.project.list("decision")))
        self.assertEqual("open", self.project.get("obligation", item["id"])["status"])

    def test_sql_json_negative_must_be_valid_and_a_real_missing_selector_still_works(self):
        operation, item = self.input_operation("/sql", "sql_injection", "sql")
        baseline = self.input_capture(operation, "1", b'{"normal":"baseline"}')
        recovery = self.input_capture(operation, "1 UNION SELECT DATABASE()", b'{"metadata":"synthetic_database"}')
        oracle = {"type": "sql_metadata", "test_family": "sql_injection", "metadata_type": "database",
                  "expected_value": "synthetic_database", "selector": "/metadata",
                  "baseline_selector": "/normal", "baseline_expected": "baseline"}
        for raw in (b'{"metadata":"synthetic_database","metadata":"shadowed"}', b'{"unused":NaN}',
                    b'{"unused":"\\ud800"}', b"not-json"):
            with self.subTest(raw=raw):
                negative = self.input_capture(operation, "0 UNION SELECT DATABASE()", raw)
                self.assert_invalid_decision(item, [baseline, recovery, negative], oracle)
        negative = self.input_capture(operation, "0 UNION SELECT DATABASE()", b'{"normal":"no metadata"}')
        decision = evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": [row["id"] for row in (baseline, recovery, negative)],
            "oracle": oracle})
        self.assertEqual("confirmed", decision["outcome"])

    def test_sqlmap_equality_control_does_not_treat_json_failure_as_a_false_predicate(self):
        from awa_ddd.external import _start, _finish

        operation, item = self.input_operation("/sqlmap", "sql_injection", "sql")
        run, _ = _start(self.project, "sqlmap", "metadata", operation, None,
            target_url=operation["url"] + "?q=1", input_location="query", input_selector="q")
        run.update(status="succeeded", exit_code=0, metadata_only=True, traffic_requests=3, traffic_responses=3,
                   target_traffic_sent=True, operation_signature=engine.operation_signature(operation),
                   metadata_candidates={"database": "synthetic_database"})
        tool = _finish(self.project, run, {"metadata_candidates": run["metadata_candidates"]})
        baseline = self.input_capture(operation, "1", b'{"normal":"baseline"}')
        recovery = self.input_capture(operation, "1 AND DATABASE()='synthetic_database'", b'{"normal":"baseline"}')
        negative = self.input_capture(operation, "1 AND DATABASE()='synthetic_other'", b'{"normal":"baseline","normal":"shadowed"}')
        oracle = {"type": "sql_metadata", "test_family": "sql_injection", "metadata_type": "database",
                  "expected_value": "synthetic_database", "negative_value": "synthetic_other", "tool_run_id": tool["run_id"],
                  "baseline_selector": "/normal", "baseline_expected": "baseline"}
        self.assert_invalid_decision(item, [baseline, recovery, negative], oracle)
        negative = self.input_capture(operation, "1 AND DATABASE()='synthetic_other'", b'{"normal":"different"}')
        decision = evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": [row["id"] for row in (baseline, recovery, negative)],
            "oracle": oracle})
        self.assertEqual("confirmed", decision["outcome"])
        self.assertEqual("sqlmap_with_independent_predicates", decision["proof"]["channel"])

    def test_extraction_negative_and_legacy_proof_revalidation_reject_ambiguous_json(self):
        operation, item = self.input_operation("/ssrf", "ssrf", "server_fetch")
        source, expected = "http://source-fixture.invalid/metadata", "synthetic-extracted-value"
        recovery = self.input_capture(operation, source, b'{"out":"synthetic-extracted-value"}')
        oracle = {"type": "extraction", "test_family": "ssrf", "selector": "/out", "expect": expected,
                  "expected_value": expected, "source_reference": source}
        for raw in (b'{"out":"synthetic-extracted-value","out":"shadowed"}', b'{"unused":NaN}', b'{"unused":"\\ud800"}'):
            with self.subTest(raw=raw):
                negative = self.input_capture(operation, "ordinary", raw)
                self.assert_invalid_decision(item, [recovery, negative], oracle)
                legacy = {"id": self.project.id("D"), "outcome": "confirmed", "mode": "machine", "oracle": oracle,
                          "obligation_id": item["id"], "operation_id": operation["id"],
                          "operation_signature": engine.operation_signature(operation),
                          "evidence_ids": [recovery["id"], negative["id"]], "created_at": now(),
                          "proof": {"test_family": "ssrf", "source_reference": source, "recovered_value": expected,
                                    "scope": "bounded_input_extraction"}}
                self.project.put("decision", legacy)
                with self.assertRaises(EngineError) as caught:
                    validate_confirmation(self.project, legacy, "SSRF")
                self.assertEqual("response_json", caught.exception.code)
                self.assertEqual(legacy, self.project.get("decision", legacy["id"]))
        negative = self.input_capture(operation, "ordinary", b'{"other":"no extraction"}')
        decision = evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": [recovery["id"], negative["id"]], "oracle": oracle})
        self.assertEqual("confirmed", decision["outcome"])

    def test_legacy_baseline_refutation_with_ambiguous_json_reopens_without_deleting_history(self):
        operation = engine.register_operation(self.project, {"url": self.base + "/legacy", "method": "GET", "auth": "public"})
        engine.build_plan(self.project)
        item = next(row for row in self.project.list("obligation") if row["kind"] == "baseline")
        evidence = self.capture(operation, b'{"answer":"first","answer":"last"}')
        legacy = {"id": self.project.id("D"), "outcome": "refuted", "mode": "machine", "obligation_id": item["id"],
                  "operation_id": operation["id"], "operation_signature": engine.operation_signature(operation),
                  "oracle": {"type": "baseline", "selector": "/answer", "expected": "last"},
                  "evidence_ids": [evidence["id"]], "created_at": now()}
        self.project.put("decision", legacy)
        self.project.put("obligation", {**item, "status": "evaluated", "decision_id": legacy["id"]})
        evaluated = engine.evaluate_coverage(self.project)
        gap = next(row for row in evaluated["gaps"] if row["id"] == item["id"])
        self.assertEqual("evidence_invalid", gap["reason_code"])
        self.assertEqual("open", gap["status"])
        self.assertEqual(legacy, self.project.get("decision", legacy["id"]))

    def test_invalid_regex_response_encoding_is_not_a_missing_selector(self):
        observation = ({"id": "E-fixture"}, {"response": {"body_base64": base64.b64encode(b"\xff").decode("ascii")}})
        with self.assertRaises(EngineError) as caught:
            _extract_value(observation, {"response_pattern": r"(?P<value>metadata)"})
        self.assertEqual("response_encoding", caught.exception.code)


class BrowserPublicBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-browser-security-")
        self.addCleanup(self.tmp.cleanup)
        self.base = "http://fixture.invalid"
        engine.create_project(self.tmp.name, {"project_id": "browser", "target": self.base})
        self.project = Project(self.tmp.name, "browser")
        self.addCleanup(self.project.close)
        self.actor = engine.add_actor(self.project, {"actor_id": "actor-control", "subject": "principal-control", "roles": []})
        self.cookie = "synthetic-browser-cookie-012345"
        self.bearer = "synthetic-browser-bearer-012345"
        self.custom = "synthetic-browser-custom-012345"
        self.session = engine.add_session(self.project, {"session_id": "session-control", "actor_id": self.actor["id"],
            "headers": {"Cookie": "session=" + self.cookie, "Authorization": "Bearer " + self.bearer,
                        "X-Principal-Key": self.custom},
            "credential_header_names": ["Cookie", "Authorization", "X-Principal-Key"]})
        self.session = self.project.get("session", self.session["id"])
        self.marker = "AWA-XSS-0011223344556677"

    def raw(self, **overrides):
        url = self.base + "/ui?" + urlencode({"q": "ordinary", "reset_token": self.cookie})
        return {"url": url, "finalUrl": url, "status": 200, "signals": {"forms": 1},
                "network": [{"url": url, "method": "GET", "type": "document", "status": 200,
                             "request_headers": self.session["headers"],
                             "response_headers": {"Set-Cookie": "new=synthetic-response-cookie-012345; Path=/"}}],
                "title": "Cookie: session=" + self.cookie,
                "console": [{"type": "log", "text": "Observed " + self.cookie + " " + self.custom},
                            {"type": "log", "text": "synthetic-response-cookie-012345"}],
                "dialogs": [{"type": "alert", "message": "Bearer " + self.bearer},
                            {"type": "alert", "message": self.marker}],
                "actions": [{"index": 0, "action": "fill", "selector": "#password", "ok": True,
                             "value": "synthetic-unregistered-fill-012345", "finalUrl": url}],
                "source_meta": {"nested": {"password": "synthetic-nested-password-012345",
                                           "text": self.cookie + " " + self.custom,
                                           "headers": {"Authorization": "Bearer " + self.bearer}}},
                **overrides}

    def assert_public(self, public, raw):
        text = json.dumps(public, ensure_ascii=False)
        for secret in (self.cookie, self.bearer, self.custom, "synthetic-response-cookie-012345",
                       "synthetic-unregistered-fill-012345", "synthetic-nested-password-012345"):
            self.assertNotIn(secret, text)
        self.assertIn(self.marker, text)
        self.assertNotIn("value", public["actions"][0])
        self.assertTrue(public["url_redacted"])
        self.assertTrue(public["locator_requires_binding"])
        self.assertIn("q=ordinary", public["url"])
        self.assertEqual("visited", public["observation_status"])
        self.assertEqual(raw, self.project.read_artifact(public))
        record, stored = browser._verified_visit(self.project, public["id"], raw["url"])
        self.assertEqual(raw, stored)
        self.assertEqual(record["sha256"], public["sha256"])
        self.assertEqual(raw["url"], record["url"])

    def test_native_public_result_scrubs_nested_strings_but_not_private_runtime_material(self):
        raw = self.raw()
        with patch.object(browser, "_browser_identity", return_value=({}, self.session["headers"], self.base, [], self.session, self.actor)), \
                patch.object(browser, "probe", return_value={"available": True, "node": "fixture-node", "module_root": "fixture-runtime"}), \
                patch.object(browser.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(raw), "")):
            public = browser.visit(self.project, {"url": raw["url"], "actions": [{"type": "fill", "selector": "#password"}]})
        self.assert_public(public, raw)
        self.assertEqual(self.actor["id"], public["actor_id"])
        self.assertEqual(self.session["id"], public["session_id"])
        self.assertEqual("adopted", public["page_adoption"])

    def test_imported_mcp_public_result_is_redacted_without_upgrading_provenance(self):
        raw = self.raw()
        path = Path(self.tmp.name) / "mcp-observation.json"
        path.write_text(json.dumps(raw), encoding="utf-8")
        public = browser.import_observation(self.project, {"path": str(path)})
        self.assert_public(public, raw)
        self.assertEqual("imported_mcp", public["source"])
        self.assertFalse(public["machine_authenticated"])
        self.assertIsNone(public["session_id"])
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), public["source_file_sha256"])

    def test_credentials_cannot_escape_in_untrusted_nested_object_keys(self):
        raw = self.raw(source_meta={self.cookie: "plain", "nested": {"password=synthetic-key-secret-012345": "synthetic-key-secret-012345"}})
        public = browser._record_observation(self.project, raw, self.project.id("PV"), "imported_mcp")
        text = json.dumps(public)
        self.assertNotIn(self.cookie, text)
        self.assertNotIn("synthetic-key-secret-012345", text)
        self.assertEqual(raw, self.project.read_artifact(public))

    def test_numeric_sensitive_fields_are_redacted_without_changing_control_counts(self):
        raw = self.raw(source_meta={"otp": 123456, "verification_code": 234567, "pin": 456789,
                                   "count": 123456, "status": 200})
        public = browser._record_observation(self.project, raw, self.project.id("PV"), "imported_mcp")
        for field in ("otp", "verification_code", "pin"):
            self.assertIsInstance(public["source_meta"][field], str)
            self.assertNotEqual(str(raw["source_meta"][field]), public["source_meta"][field])
        self.assertIsInstance(public["source_meta"]["count"], str)
        self.assertEqual(200, public["source_meta"]["status"])
        self.assertEqual(raw, self.project.read_artifact(public))

    def test_known_numeric_credentials_cannot_escape_by_json_number_conversion_under_harmless_keys(self):
        value = "654321"
        engine.add_session(self.project, {"actor_id": self.actor["id"], "headers": {"X-OTP": value}, "credential_header_names": ["X-OTP"]})
        raw = self.raw(actions=[], signals={"forms": 654321}, source_meta={"debug_number": 654321, "data": 654321,
            "count": 654321, "nested": [654321.0]}, console=[{"type": "log", "data": 654321}],
            dialogs=[{"type": "alert", "message": 654321}])
        path = Path(self.tmp.name) / "numeric-context.json"
        path.write_text(json.dumps(raw), encoding="utf-8")
        public = browser.import_observation(self.project, {"path": str(path)})
        for field in ("debug_number", "data", "count"):
            self.assertIsInstance(public["source_meta"][field], str)
            self.assertNotEqual(value, public["source_meta"][field])
        self.assertIsInstance(public["source_meta"]["nested"][0], str)
        self.assertIsInstance(public["console"][0]["data"], str)
        self.assertIsInstance(public["dialogs"][0]["message"], str)
        self.assertEqual(654321, public["signals"]["forms"])
        self.assertEqual(200, public["status"])
        self.assertEqual(1, public["network_count"])
        self.assertEqual(raw, self.project.read_artifact(public))

    def test_leading_zero_otp_number_conversion_is_redacted_only_in_untrusted_payloads(self):
        engine.add_session(self.project, {"actor_id": self.actor["id"], "headers": {"X-OTP": "000012"}, "credential_header_names": ["X-OTP"]})
        raw = self.raw(actions=[], signals={"forms": 12}, source_meta={"debug_number": 12, "data": 12.0},
                       dialogs=[{"type": "alert", "message": 12}])
        path = Path(self.tmp.name) / "leading-zero-otp.json"
        path.write_text(json.dumps(raw), encoding="utf-8")
        public = browser.import_observation(self.project, {"path": str(path)})
        self.assertIsInstance(public["source_meta"]["debug_number"], str)
        self.assertIsInstance(public["source_meta"]["data"], str)
        self.assertIsInstance(public["dialogs"][0]["message"], str)
        self.assertEqual(12, public["signals"]["forms"])
        self.assertEqual(200, public["status"])
        self.assertEqual(raw, self.project.read_artifact(public))

    def test_unavailable_context_nonce_format_cannot_restore_a_known_cookie_secret(self):
        secret = "1a" * 16
        engine.add_session(self.project, {"actor_id": self.actor["id"], "headers": {"Cookie": "SID=" + secret}})
        marker = "AWA-XSS-" + secret
        raw = self.raw(actions=[{"action": "fill", "selector": "#password", "ok": True}],
                       dialogs=[{"type": "alert", "message": marker}])
        public = browser._record_observation(self.project, raw, self.project.id("PV"), "local_playwright")
        self.assertEqual("unavailable", public["redaction_context_status"])
        self.assertNotIn(secret, json.dumps(public))
        self.assertEqual(marker, self.project.read_artifact(public)["dialogs"][0]["message"])

    def test_malformed_function_handle_is_rejected_before_mutating_the_page_ledger(self):
        page = browser.register_page(self.project, {"url": self.base + "/ui"})
        for identity in (["not-a-handle"], {"secret": self.cookie}, 17, ""):
            with self.subTest(identity=type(identity).__name__), self.assertRaises(EngineError) as caught:
                dispatch(self.tmp.name, "page.function", {"project_id": "browser", "page_id": page["id"],
                    "function_id": identity, "name": "fixture function"})
            self.assertEqual("function_id", caught.exception.code)
        self.assertEqual([], self.project.get("page", page["id"])["functions"])

    def test_page_dispatch_and_derived_public_views_do_not_reexport_private_browser_secrets(self):
        raw = self.raw()
        visited = browser._record_observation(self.project, raw, self.project.id("PV"), "local_playwright",
                                             session=self.session, actor=self.actor)
        page_id = visited["page_ids"][0]

        def call(action, **args):
            return dispatch(self.tmp.name, action, {"project_id": "browser", **args})

        results = [call("page.register", url=raw["url"]),
                   call("page.function", page_id=page_id, name=self.custom, trigger="Render " + self.cookie,
                        apis=[raw["url"]]),
                   call("page.mark", page_id=page_id, target="page", status="visited", page_visit_id=visited["id"]),
                   call("page.adopt", page_visit_id=visited["id"])]
        coverage = call("page.coverage")
        results.append(coverage)
        self.assertTrue(coverage["untriggered"][0]["url_redacted"])
        self.assertTrue(coverage["untriggered"][0]["locator_requires_binding"])
        self.assertEqual(raw["url"], self.project.get("page", page_id)["url"])
        self.assertEqual(self.custom, self.project.get("page", page_id)["functions"][0]["name"])
        results += [call("plan.next", limit=25), call("plan.audit", limit=100), call("project.status", limit=100)]
        report = call("report.build", output_dir=str(Path(self.tmp.name) / "reports"))
        results.append(report)
        for result in results:
            text = json.dumps(result)
            for secret in (self.cookie, self.bearer, self.custom, "synthetic-unregistered-fill-012345",
                           "synthetic-nested-password-012345"):
                self.assertNotIn(secret, text)
        for path in (report["report"], report["summary"], report["manifest"]):
            text = Path(path).read_text(encoding="utf-8")
            for secret in (self.cookie, self.bearer, self.custom):
                self.assertNotIn(secret, text)

    def test_custom_credential_equal_to_a_ledger_actor_handle_does_not_rewrite_control_data(self):
        engine.add_session(self.project, {"session_id": "header-control", "actor_id": self.actor["id"],
            "headers": {"X-Actor": self.actor["id"]}, "credential_header_names": ["X-Actor"]})
        raw = self.raw(console=[{"type": "log", "text": "X-Actor " + self.actor["id"]}])
        public = browser._record_observation(self.project, raw, "PV-control-handle", "local_playwright",
                                            session=self.session, actor=self.actor)
        self.assertEqual("PV-control-handle", public["id"])
        self.assertEqual(self.actor["id"], public["actor_id"])
        self.assertNotIn(self.actor["id"], public["console"][0]["text"])

    def test_import_rejects_duplicate_and_invalid_unicode_before_recording_any_observation(self):
        path = Path(self.tmp.name) / "invalid-observation.json"
        valid = json.dumps(self.raw())
        for text in (valid[:-1] + ',"status":200}',
                     valid[:-1] + ',"extra":NaN}', valid[:-1] + ',"extra":"\\ud800"}'):
            with self.subTest(text=text[-40:]):
                path.write_text(text, encoding="utf-8")
                with self.assertRaises(EngineError) as caught:
                    browser.import_observation(self.project, {"path": str(path)})
                self.assertEqual("browser_import", caught.exception.code)
        self.assertFalse(self.project.list("page_visit"))

    def test_redaction_preserves_authenticated_typed_xss_proof_and_exact_nonsecret_query(self):
        identity = engine.register_operation(self.project, {"url": self.base + "/whoami", "method": "GET"})
        profile = json.dumps({"subject": self.actor["subject"]}).encode("utf-8")
        with patch.object(engine, "request", side_effect=lambda *values: observed_response(*values, response=profile)):
            engine.verify_identity(self.project, {"operation_id": identity["id"], "session_id": self.session["id"],
                "subject_selector": "/subject"})
        self.session = self.project.get("session", self.session["id"])
        operation = engine.register_operation(self.project, {"url": self.base + "/render", "method": "GET", "auth": "authenticated",
            "inputs": [{"name": "q", "location": "query", "consumer": "html_render", "test_families": ["xss"]}]})
        engine.build_plan(self.project)
        evidence = []
        for value in ("normal", "<img src=x onerror=alert('" + self.marker + "')>"):
            with patch.object(engine, "request", side_effect=lambda *values: observed_response(*values, response=b'{"ok":true}')):
                evidence.append(engine.capture(self.project, {"operation_id": operation["id"], "session_id": self.session["id"],
                    "url": operation["url"] + "?" + urlencode({"q": value})}))
        url = self.project.read_artifact(evidence[1])["request"]["url"]
        raw = self.raw(url=url, finalUrl=url, actions=[],
            dialogs=[{"type": "alert", "message": self.marker, "action_index": None}],
            network=[{"url": url, "method": "GET", "type": "document", "status": 200,
                      "request_headers": self.session["headers"]}])
        public = browser._record_observation(self.project, raw, self.project.id("PV"), "local_playwright",
                                            session=self.session, actor=self.actor)
        self.assertEqual(url, public["url"])
        self.assertEqual(self.marker, public["dialogs"][0]["message"])
        item = next(row for row in self.project.list("obligation") if row.get("kind") == "input_test"
                    and row["operation_id"] == operation["id"] and not row.get("superseded"))
        finding = record_finding(self.project, {"mode": "analyst", "title": "Controlled runtime", "category": "XSS",
            "impact": "Controlled fixture execution", "remediation": "Encode output", "reviewer": "fixture reviewer",
            "reason": "Exact controls and original same-identity dialog", "obligation_id": item["id"],
            "evidence_ids": [row["id"] for row in evidence], "runtime_visit_id": public["id"],
            "consumer_url": url, "runtime_marker": self.marker})
        self.assertEqual("evaluated", self.project.get("obligation", item["id"])["status"])
        decision = self.project.get("decision", finding["decision_id"])
        self.assertEqual(public["sha256"], decision["proof"]["artifact_sha256"])
        self.assertEqual(self.session["id"], decision["proof"]["identity"]["session_id"])


class BrowserRunLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-browser-run-security-")
        self.addCleanup(self.tmp.cleanup)
        self.base = "http://fixture.invalid"
        engine.create_project(self.tmp.name, {"project_id": "run", "target": self.base})
        self.project = Project(self.tmp.name, "run")
        self.addCleanup(self.project.close)
        self.url = self.base + "/ui"
        self.state = {"available": True, "node": "fixture-node", "module_root": "fixture-runtime"}

    def raw(self, **overrides):
        return {"url": self.url, "finalUrl": self.url, "status": 200, "signals": {"forms": 1},
                "network": [{"url": self.url, "method": "GET", "type": "document", "status": 200}], **overrides}

    def visit(self, outcome, **args):
        with patch.object(browser, "probe", return_value=self.state), patch.object(browser.subprocess, "run", side_effect=outcome):
            return browser.visit(self.project, {"url": self.url, **args})

    def test_run_is_claimed_before_runtime_dispatch_and_success_binds_original_visit_digest(self):
        def complete(command, **options):
            runs = self.project.list("run")
            self.assertEqual(1, len(runs))
            self.assertEqual("running", runs[0]["status"])
            self.assertEqual("read_only", runs[0]["effect"])
            return subprocess.CompletedProcess(command, 0, json.dumps(self.raw()), "")

        public = self.visit(complete)
        run = self.project.get("run", public["run_id"])
        self.assertEqual("browser", run["kind"])
        self.assertEqual("succeeded", run["status"])
        self.assertEqual(public["id"], run["page_visit_id"])
        self.assertEqual(public["id"], run["planned_page_visit_id"])
        self.assertEqual(public["sha256"], run["sha256"])
        self.assertEqual(self.raw(), self.project.read_artifact(run))
        self.assertEqual(public["run_id"], self.project.get("page_visit", public["id"])["run_id"])

    def test_timeout_keeps_recoverable_run_and_readonly_administrative_review_sends_no_requests(self):
        def timeout(command, **options):
            self.assertEqual("running", self.project.list("run")[0]["status"])
            raise subprocess.TimeoutExpired(command, options["timeout"])

        with self.assertRaises(EngineError) as caught:
            self.visit(timeout)
        self.assertEqual("browser_timeout", caught.exception.code)
        self.assertEqual("run.inspect", caught.exception.details["next_action"])
        run = self.project.get("run", caught.exception.details["run_id"])
        self.assertEqual("interrupted", run["status"])
        self.assertFalse(run["allow_write"])
        self.assertEqual("read_only", run["effect"])
        self.assertNotIn("page_visit_id", run)
        self.assertFalse(self.project.list("page_visit"))
        item = next(row for row in completeness.audit(self.project, {})["checklist"] if row["kind"] == "unreconciled_run")
        with patch.object(engine, "request") as network:
            continuation.review(self.project, {"checklist_id": item["id"], "status": "reviewed",
                "reviewer": "fixture reviewer", "reason": "Inspected owned read-only interrupted run; no target replay or security conclusion"})
        network.assert_not_called()
        self.assertEqual(0, completeness.audit(self.project, {})["completion"]["unreconciled_runs"])

    def test_unknown_browser_write_cannot_be_archived_as_reviewed_by_text_only(self):
        engine.update_project(self.project, {"allow_mutation": True})
        with self.assertRaises(EngineError) as caught:
            self.visit(subprocess.TimeoutExpired("fixture-runtime", 20), actions=[{"type": "click", "selector": "#submit"}])
        run = self.project.get("run", caught.exception.details["run_id"])
        self.assertEqual("test_resource_write", run["effect"])
        self.assertTrue(run["allow_write"])
        self.assertNotIn("resource_id", run)
        item = next(row for row in completeness.audit(self.project, {})["checklist"] if row["kind"] == "unreconciled_run")
        with self.assertRaises(EngineError) as rejected:
            continuation.review(self.project, {"checklist_id": item["id"], "status": "reviewed",
                "reviewer": "fixture reviewer", "reason": "A text assertion cannot establish whether the submit already changed state"})
        self.assertIn(rejected.exception.code, {"reconciliation_evidence", "reconciliation_context"})
        self.assertEqual(1, completeness.audit(self.project, {})["completion"]["unreconciled_runs"])

    def test_parse_nonzero_exit_and_spawn_failures_keep_owned_interrupted_runs(self):
        outcomes = (subprocess.CompletedProcess([], 0, "not-json", ""),
                    subprocess.CompletedProcess([], 0, '{"url":"http://fixture.invalid/ui","unused":NaN}', ""),
                    subprocess.CompletedProcess([], 1, json.dumps(self.raw()), ""), OSError("synthetic-private-diagnostic"))
        for outcome in outcomes:
            with self.subTest(outcome=type(outcome).__name__), self.assertRaises(EngineError) as caught:
                self.visit(outcome if isinstance(outcome, Exception) else lambda *args, outcome=outcome, **kwargs: outcome)
            run = self.project.get("run", caught.exception.details["run_id"])
            self.assertEqual("interrupted", run["status"])
            self.assertEqual("run.inspect", run["next_action"])
            self.assertNotIn("synthetic-private-diagnostic", str(caught.exception))
        self.assertEqual(len(outcomes), len(self.project.list("run")))
        self.assertFalse(self.project.list("page_visit"))

    def test_blocked_observation_retains_private_material_and_an_interrupted_run(self):
        raw = self.raw(blocked_requests=[{"url": self.base + "/private", "method": "POST", "reason": "write_operation_not_authorized"}])
        public = self.visit(lambda command, **options: subprocess.CompletedProcess(command, 0, json.dumps(raw), ""))
        run = self.project.get("run", public["run_id"])
        self.assertEqual("interrupted", public["run_status"])
        self.assertEqual("interrupted", run["status"])
        self.assertEqual("BLOCKED", public["observation_status"])
        self.assertEqual(raw, self.project.read_artifact(run))
        self.assertEqual(1, completeness.audit(self.project, {})["completion"]["unreconciled_runs"])

    def test_unknown_write_response_status_cannot_create_a_successful_browser_run(self):
        engine.update_project(self.project, {"allow_mutation": True})
        write = {"url": self.base + "/write", "method": "POST", "status": None, "write": True}
        raw = self.raw(network=[self.raw()["network"][0], write], write_authorized=True,
                      write_requests=[{"url": write["url"], "method": "POST", "status": None}])
        public = self.visit(lambda command, **options: subprocess.CompletedProcess(command, 0, json.dumps(raw), ""))
        self.assertEqual("BLOCKED", public["observation_status"])
        self.assertEqual("interrupted", self.project.get("run", public["run_id"])["status"])
        self.assertEqual(raw, self.project.read_artifact(public))
        self.assertEqual(1, completeness.audit(self.project, {})["completion"]["unreconciled_runs"])

    def test_unavailable_runtime_or_invalid_arguments_never_claim_a_dispatched_run(self):
        with patch.object(browser, "probe", return_value={"available": False, "reason": "fixture unavailable"}):
            with self.assertRaises(EngineError):
                browser.visit(self.project, {"url": self.url})
        for args in ({"url": "http://outside.invalid/"}, {"url": self.url, "allow_write": "false"},
                     {"url": self.url, "actions": [{"type": "evaluate"}]}):
            with self.subTest(args=args), patch.object(browser, "probe") as probe:
                with self.assertRaises(EngineError):
                    browser.visit(self.project, args)
                probe.assert_not_called()
        self.assertFalse(self.project.list("run"))

    def test_actual_native_fill_shape_preserves_private_seeds_across_page_plan_report_and_run_views(self):
        secret = "synthetic-filled-password-012345"
        raw = self.raw(title=secret, console=[{"type": "log", "text": secret}], dialogs=[{"type": "alert", "message": secret}],
            actions=[{"index": 0, "action": "fill", "selector": "#password", "ok": True, "finalUrl": self.url}])
        public = self.visit(lambda command, **options: subprocess.CompletedProcess(command, 0, json.dumps(raw), ""),
                            actions=[{"type": "fill", "selector": "#password", "value": secret}])
        self.assertNotIn(secret, json.dumps(public))
        run = self.project.get("run", public["run_id"])
        visit = self.project.get("page_visit", public["id"])
        self.assertEqual([secret], run["credentials"]["browser_fill_values"])
        self.assertEqual([secret], visit["credentials"]["browser_fill_values"])
        self.assertEqual(raw, self.project.read_artifact(visit))

        def call(action, **args):
            return dispatch(self.tmp.name, action, {"project_id": "run", **args})

        page_id = public["page_ids"][0]
        values = [public, call("run.inspect", run_id=public["run_id"]),
                  call("page.function", page_id=page_id, name=secret, trigger=secret),
                  call("page.mark", page_id=page_id, target="page", status="BLOCKED", reason=secret),
                  call("page.coverage"), call("plan.next", limit=25), call("plan.audit", limit=100), call("project.status", limit=100)]
        report = call("report.build", output_dir=str(Path(self.tmp.name) / "reports"))
        values.append(report)
        for value in values:
            self.assertNotIn(secret, json.dumps(value))
        for path in (report["report"], report["summary"], report["manifest"]):
            self.assertNotIn(secret, Path(path).read_text(encoding="utf-8"))

    def test_short_fill_pin_does_not_leak_or_rewrite_handles_timestamps_or_counts(self):
        pin = "123"
        raw = self.raw(title=pin, console=[{"type": "log", "text": pin}], dialogs=[{"type": "alert", "message": pin}],
                      signals={"forms": 123}, actions=[{"index": 0, "action": "fill", "selector": "#pin", "ok": True, "finalUrl": self.url}])
        public = self.visit(lambda command, **options: subprocess.CompletedProcess(command, 0, json.dumps(raw), ""),
                            actions=[{"type": "fill", "selector": "#pin", "value": pin}])
        for field in (public["title"], public["console"][0]["text"], public["dialogs"][0]["message"]):
            self.assertNotEqual(pin, field)
        self.assertEqual(123, public["signals"]["forms"])
        saved = self.project.get("page_visit", public["id"])
        self.assertEqual(saved["created_at"], public["created_at"])
        inspected = dispatch(self.tmp.name, "run.inspect", {"project_id": "run", "run_id": public["run_id"]})
        run = self.project.get("run", public["run_id"])
        self.assertEqual(run["id"], inspected["id"])
        self.assertEqual(run["started_at"], inspected["started_at"])
        self.assertEqual(run["finished_at"], inspected["finished_at"])
        self.assertEqual(run["request_signature"], inspected["request_signature"])
        self.assertNotIn("credentials", inspected)

    def test_fill_values_coinciding_with_runtime_codes_do_not_change_the_public_contract(self):
        for secret in ("visited", "browser", "fill"):
            with self.subTest(secret=secret):
                raw = self.raw(title=secret, console=[{"type": "log", "text": secret}],
                              actions=[{"index": 0, "action": "fill", "selector": "#password", "ok": True, "finalUrl": self.url}])
                public = self.visit(lambda command, **options: subprocess.CompletedProcess(command, 0, json.dumps(raw), ""),
                                    actions=[{"type": "fill", "selector": "#password", "value": secret}])
                self.assertNotEqual(secret, public["title"])
                self.assertNotEqual(secret, public["console"][0]["text"])
                self.assertEqual("visited", public["observation_status"])
                self.assertEqual("fill", public["actions"][0]["action"])
                inspected = dispatch(self.tmp.name, "run.inspect", {"project_id": "run", "run_id": public["run_id"]})
                self.assertEqual("browser", inspected["kind"])
                self.assertEqual("succeeded", inspected["status"])

    def test_private_redaction_nonce_blocks_short_pin_hash_guessing_without_entering_the_runner(self):
        pin = "12"
        raw = self.raw(title=pin, console=[{"type": "log", "text": pin}],
                      actions=[{"index": 0, "action": "fill", "selector": "#pin", "ok": True, "finalUrl": self.url}])
        def complete(command, **options):
            spec = Path(command[-1]).read_text(encoding="utf-8")
            nonce = self.project.list("run")[0]["credentials"]["redaction_nonce"]
            self.assertNotIn("redaction_nonce", spec)
            self.assertNotIn(nonce, spec)
            return subprocess.CompletedProcess(command, 0, json.dumps(raw), "")
        public = self.visit(complete, actions=[{"type": "fill", "selector": "#pin", "value": pin}])
        run = self.project.get("run", public["run_id"])
        visit = self.project.get("page_visit", public["id"])
        nonce = run["credentials"]["redaction_nonce"]
        self.assertRegex(nonce, r"^[a-f0-9]{64}$")
        self.assertEqual(run["credentials"], visit["credentials"])
        inspected = dispatch(self.tmp.name, "run.inspect", {"project_id": "run", "run_id": public["run_id"]})
        audit = dispatch(self.tmp.name, "plan.audit", {"project_id": "run"})
        exposed = json.dumps([public, inspected, audit])
        self.assertNotIn(nonce, exposed)
        self.assertNotIn("redaction_context_sha256", exposed)
        guesses = {hashlib.sha256(canonical({"browser_fill_values": [f"{value:02d}"]}).encode("utf-8")).hexdigest()
                   for value in range(100)}
        self.assertNotIn(run["redaction_context_sha256"], guesses)
        for digest in guesses:
            self.assertNotIn(digest, exposed)
        self.assertEqual(raw, self.project.read_artifact(visit))
        old_context = {"browser_fill_values": [pin]}
        self.project.put("run", {**run, "credentials": old_context,
            "redaction_context_sha256": hashlib.sha256(canonical(old_context).encode("utf-8")).hexdigest()})
        with self.assertRaises(EngineError) as caught:
            dispatch(self.tmp.name, "run.inspect", {"project_id": "run", "run_id": public["run_id"]})
        self.assertEqual("browser_redaction_context", caught.exception.code)

    def test_missing_or_changed_new_private_context_fails_closed_without_replaying(self):
        secret = "synthetic-new-context-secret-012345"
        raw = self.raw(console=[{"type": "log", "text": secret}],
                      actions=[{"index": 0, "action": "fill", "selector": "#password", "ok": True, "finalUrl": self.url}])
        public = self.visit(lambda command, **options: subprocess.CompletedProcess(command, 0, json.dumps(raw), ""),
                            actions=[{"type": "fill", "selector": "#password", "value": secret}])
        for kind in ("run", "page_visit"):
            record = self.project.get(kind, public["run_id"] if kind == "run" else public["id"])
            for credentials in (None, {"browser_fill_values": ["changed"]}):
                changed = dict(record)
                if credentials is None:
                    changed.pop("credentials")
                else:
                    changed["credentials"] = credentials
                self.project.put(kind, changed)
                with patch.object(engine, "request") as network, self.assertRaises(EngineError) as caught:
                    dispatch(self.tmp.name, "run.inspect", {"project_id": "run", "run_id": public["run_id"]})
                network.assert_not_called()
                self.assertEqual("browser_redaction_context", caught.exception.code)
                self.assertNotIn(secret, str(caught.exception))
                self.project.put(kind, record)
        self.assertEqual(raw, self.project.read_artifact(self.project.get("page_visit", public["id"])))

    def test_legacy_missing_fill_context_omits_only_related_prose_and_preserves_usable_other_visits(self):
        secret = "synthetic-legacy-unrecoverable-fill-012345"
        raw = self.raw(title=secret, console=[{"type": "log", "text": secret}],
                      source_meta={"sha256": secret, "artifact_path": secret, "created_at": secret},
                      actions=[{"index": 0, "action": "fill", "selector": "#password", "ok": True, "finalUrl": self.url}])
        legacy = browser._record_observation(self.project, raw, self.project.id("PV"), "local_playwright")
        self.assertEqual("unavailable", legacy["redaction_context_status"])
        self.assertNotIn(secret, json.dumps(legacy))
        self.assertEqual(raw, self.project.read_artifact(legacy))
        other_url = self.base + "/other"
        other_raw = self.raw(url=other_url, finalUrl=other_url, title="Known safe other page",
                             network=[{"url": other_url, "method": "GET", "type": "document", "status": 200}])
        other = browser._record_observation(self.project, other_raw, self.project.id("PV"), "local_playwright")
        self.assertEqual("Known safe other page", other["title"])
        self.assertNotIn("redaction_context_status", other)
        covered = dispatch(self.tmp.name, "page.coverage", {"project_id": "run"})
        self.assertNotIn(secret, json.dumps(covered))

    def test_bare_runtime_nonce_is_not_a_fill_secret_or_new_proof_channel(self):
        marker = "AWA-XSS-0011223344556677"
        raw = self.raw(dialogs=[{"type": "alert", "message": marker}],
                      actions=[{"index": 0, "action": "fill", "selector": "#input", "ok": True, "finalUrl": self.url}])
        public = self.visit(lambda command, **options: subprocess.CompletedProcess(command, 0, json.dumps(raw), ""),
                            actions=[{"type": "fill", "selector": "#input", "value": marker}])
        self.assertEqual(marker, public["dialogs"][0]["message"])
        self.assertEqual([], self.project.get("run", public["run_id"])["credentials"]["browser_fill_values"])
        self.assertFalse(self.project.list("decision"))
        self.assertFalse(self.project.list("finding"))


class AuthorizationProtectedDataTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-authorization-security-")
        self.addCleanup(self.tmp.cleanup)
        self.base = "http://fixture.invalid"
        engine.create_project(self.tmp.name, {"project_id": "access", "target": self.base})
        self.project = Project(self.tmp.name, "access")
        self.addCleanup(self.project.close)
        identity = engine.register_operation(self.project, {"url": self.base + "/whoami", "method": "GET", "auth": "authenticated"})
        self.sessions = {}
        for subject, role in (("admin", "admin"), ("user", "user")):
            actor = engine.add_actor(self.project, {"actor_id": subject, "subject": subject, "roles": [role]})
            session = engine.add_session(self.project, {"actor_id": actor["id"], "headers": {"Authorization": "Bearer synthetic-" + subject}})
            profile = json.dumps({"subject": subject, "roles": [role]}).encode("utf-8")
            with patch.object(engine, "request", side_effect=lambda *args, profile=profile: observed_response(*args, response=profile)):
                engine.verify_identity(self.project, {"operation_id": identity["id"], "session_id": session["id"],
                    "subject_selector": "/subject", "roles_selector": "/roles"})
            self.sessions[subject] = self.project.get("session", session["id"])
        self.operation = engine.register_operation(self.project, {"url": self.base + "/admin-data", "method": "GET",
            "auth": "restricted", "allowed_roles": ["admin"]})
        engine.build_plan(self.project)
        self.item = next(row for row in self.project.list("obligation") if row["operation_id"] == self.operation["id"]
                         and row["kind"] == "access" and row.get("actor_id") == "user")

    def capture(self, subject, body, status=200):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
        def response(*args):
            artifact = observed_response(*args, response=raw)
            artifact["response"]["status"] = status
            return artifact
        with patch.object(engine, "request", side_effect=response):
            return engine.capture(self.project, {"operation_id": self.operation["id"], "session_id": self.sessions[subject]["id"]})

    def decide(self, baseline, variant, selector):
        return evaluate(self.project, {"obligation_id": self.item["id"], "evidence_ids": [baseline["id"], variant["id"]],
            "oracle": {"type": "authorization", "selector": selector}})

    def test_generic_200_denial_flags_and_only_metadata_objects_cannot_confirm_access(self):
        for body, selector in (({"ok": False, "message": "denied"}, "/ok"),
                               ({"data": {"ok": False, "message": "denied"}}, "/data"),
                               ({"secret": False}, "/secret"), ({"secret": True}, "/secret"),
                               ({"secret": "denied"}, "/secret")):
            with self.subTest(selector=selector, body=body):
                baseline, variant = self.capture("admin", body), self.capture("user", body)
                with self.assertRaises(EngineError) as caught:
                    self.decide(baseline, variant, selector)
                self.assertIn(caught.exception.code, {"protected_selector", "protected_value"})
                self.assertEqual("open", self.project.get("obligation", self.item["id"])["status"])
        self.assertFalse(self.project.list("decision"))

    def test_metadata_selector_and_failed_business_baseline_cannot_replace_protected_data(self):
        data = {"ok": True, "secret": "synthetic-protected-data", "nonce": "same-nonce", "status": 200, "message": "done"}
        baseline, variant = self.capture("admin", data), self.capture("user", data)
        for selector in ("/ok", "/nonce", "/status", "/message"):
            with self.subTest(selector=selector), self.assertRaises(EngineError) as caught:
                self.decide(baseline, variant, selector)
            self.assertEqual("protected_selector", caught.exception.code)
        failed = self.capture("admin", {"ok": False, "secret": "synthetic-protected-data"})
        with self.assertRaises(EngineError) as caught:
            self.decide(failed, variant, "/secret")
        self.assertEqual("baseline_invalid", caught.exception.code)

    def test_real_protected_business_data_and_zero_balance_support_bounded_positive_proofs(self):
        for selector in ("/record/secret", "/record/balance"):
            with self.subTest(selector=selector):
                body = {"ok": True, "record": {"id": "shared-fixture", "secret": "synthetic-protected-data", "balance": 0}}
                baseline, variant = self.capture("admin", body), self.capture("user", body)
                decision = self.decide(baseline, variant, selector)
                self.assertEqual("confirmed", decision["outcome"])
                validate_confirmation(self.project, decision, "Access Control")

    def test_real_denial_status_refutes_the_concrete_access_without_requiring_json_error_body(self):
        baseline = self.capture("admin", {"record": {"secret": "synthetic-protected-data"}})
        variant = self.capture("user", b"Forbidden", 403)
        decision = self.decide(baseline, variant, "/record/secret")
        self.assertEqual("refuted", decision["outcome"])
        validate_confirmation(self.project, decision)

    def test_different_business_data_does_not_refute_or_confirm_the_cross_actor_hypothesis(self):
        baseline = self.capture("admin", {"record": {"secret": "synthetic-protected-data"}})
        variant = self.capture("user", {"record": {"secret": "different-data"}})
        self.assertEqual("inconclusive", self.decide(baseline, variant, "/record/secret")["outcome"])

    def test_old_generic_denial_confirmation_and_finding_reopen_without_deleting_history(self):
        body = {"ok": False, "message": "denied"}
        baseline, variant = self.capture("admin", body), self.capture("user", body)
        legacy = {"id": self.project.id("D"), "outcome": "confirmed", "mode": "machine", "created_at": now(),
                  "obligation_id": self.item["id"], "operation_id": self.operation["id"],
                  "operation_signature": engine.operation_signature(self.operation), "evidence_ids": [baseline["id"], variant["id"]],
                  "oracle": {"type": "authorization", "selector": "/ok"}}
        self.project.put("decision", legacy)
        self.project.put("obligation", {**self.item, "status": "evaluated", "decision_id": legacy["id"]})
        finding = {"id": self.project.id("F"), "title": "Legacy weak access result", "category": "Access Control",
                   "severity": "high", "decision_id": legacy["id"], "evidence_ids": legacy["evidence_ids"], "mode": "machine",
                   "status": "confirmed", "impact": "Unverified old claim", "remediation": "Review actual protected data", "created_at": now()}
        self.project.put("finding", finding)
        evaluated = engine.evaluate_coverage(self.project)
        gap = next(row for row in evaluated["gaps"] if row["id"] == self.item["id"])
        self.assertEqual("evidence_invalid", gap["reason_code"])
        self.assertFalse(next(row for row in evaluated["findings"] if row["id"] == finding["id"])["current"])
        self.assertEqual(legacy, self.project.get("decision", legacy["id"]))
        self.assertEqual(finding, self.project.get("finding", finding["id"]))


class LegacyXssProofTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-legacy-xss-security-")
        self.addCleanup(self.tmp.cleanup)
        self.base = "http://fixture.invalid"
        engine.create_project(self.tmp.name, {"project_id": "legacy", "target": self.base})
        self.project = Project(self.tmp.name, "legacy")
        self.addCleanup(self.project.close)

    def prepare(self, *, consumer="html_render", families=None, name="q"):
        entry = {"name": name, "location": "query", "consumer": consumer}
        if families is not None:
            entry["test_families"] = families
        path = "/render-" + ("declared-" if families else "inferred-") + name
        operation = engine.register_operation(self.project, {"url": self.base + path, "method": "GET", "auth": "public", "inputs": [entry]})
        engine.build_plan(self.project)
        item = next(row for row in self.project.list("obligation") if row["kind"] == "input_test"
                    and row["operation_id"] == operation["id"] and not row.get("superseded"))
        evidence = []
        for value, count in (("normal", 1), ("variant", 1), ("control", 2)):
            raw = json.dumps({"count": count}).encode("utf-8")
            with patch.object(engine, "request", side_effect=lambda *args, raw=raw: observed_response(*args, response=raw)):
                evidence.append(engine.capture(self.project, {"operation_id": operation["id"], "url": operation["url"] + "?" + urlencode({name: value})}))
        oracle = {"type": "semantic_negative", "selector": "/count", "baseline_expected": 1, "control_expected": 2}
        if families:
            oracle["test_family"] = families[0]
        return operation, item, evidence, oracle

    def test_concrete_legacy_xss_consumer_cannot_be_closed_by_http_only_negative_controls(self):
        operation, item, evidence, oracle = self.prepare()
        with self.assertRaises(EngineError) as caught:
            evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": [row["id"] for row in evidence], "oracle": oracle})
        self.assertEqual("xss_runtime_required", caught.exception.code)
        self.assertEqual("surface.declare_consumer", caught.exception.details["next_action"])
        self.assertEqual("open", self.project.get("obligation", item["id"])["status"])
        self.assertFalse(self.project.list("decision"))
        self.assertFalse(self.project.list("page_visit"))

    def test_old_static_xss_refutation_reopens_without_mutating_its_original_decision(self):
        operation, item, evidence, oracle = self.prepare()
        legacy = {"id": self.project.id("D"), "outcome": "refuted", "mode": "machine", "created_at": now(),
                  "obligation_id": item["id"], "operation_id": operation["id"],
                  "operation_signature": engine.operation_signature(operation), "oracle": oracle,
                  "evidence_ids": [row["id"] for row in evidence]}
        self.project.put("decision", legacy)
        self.project.put("obligation", {**item, "status": "evaluated", "decision_id": legacy["id"]})
        evaluated = engine.evaluate_coverage(self.project)
        self.assertEqual("evidence_invalid", next(row for row in evaluated["gaps"] if row["id"] == item["id"])["reason_code"])
        self.assertEqual(0, next(row for row in evaluated["security_coverage"]["by_family"] if row["test_family"] == "xss")["evaluated"])
        self.assertEqual(legacy, self.project.get("decision", legacy["id"]))

    def test_explicit_other_family_and_field_name_hints_do_not_become_xss_proof_obligations(self):
        for consumer, families, name in (("html_render", ["business_logic"], "amount"), ("generic_backend", None, "description")):
            with self.subTest(consumer=consumer):
                operation, item, evidence, oracle = self.prepare(consumer=consumer, families=families, name=name)
                decision = evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": [row["id"] for row in evidence], "oracle": oracle})
                self.assertEqual("refuted", decision["outcome"])


class MixedFamilyProofTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-mixed-family-security-")
        self.addCleanup(self.tmp.cleanup)
        self.base = "http://fixture.invalid"
        engine.create_project(self.tmp.name, {"project_id": "mixed", "target": self.base})
        self.project = Project(self.tmp.name, "mixed")
        self.addCleanup(self.project.close)

    def operation(self, consumer, families):
        operation = engine.register_operation(self.project, {"url": self.base + "/mixed", "method": "GET", "auth": "public",
            "inputs": [{"name": "q", "location": "query", "consumer": consumer, "test_families": families}]})
        engine.build_plan(self.project)
        items = {row["test_family"]: row for row in self.project.list("obligation") if row["kind"] == "input_test"
                 and row["operation_id"] == operation["id"] and not row.get("superseded")}
        return operation, items

    def capture(self, operation, value, response):
        raw = json.dumps(response).encode("utf-8")
        with patch.object(engine, "request", side_effect=lambda *args: observed_response(*args, response=raw)):
            return engine.capture(self.project, {"operation_id": operation["id"], "url": operation["url"] + "?" + urlencode({"q": value})})

    def generic_controls(self, operation, item):
        evidence = [self.capture(operation, value, {"count": count}) for value, count in
                    (("normal", 1), ("variant", 1), ("control", 2))]
        decision = evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": [row["id"] for row in evidence],
            "oracle": {"type": "semantic_negative", "test_family": "generic", "selector": "/count",
                       "baseline_expected": 1, "control_expected": 2}})
        self.assertEqual("refuted", decision["outcome"])
        return evidence, decision

    def test_explicit_generic_and_sql_on_one_input_close_independently_without_weakening_metadata(self):
        operation, items = self.operation("sql_like", ["generic", "sql_injection"])
        evidence, generic = self.generic_controls(operation, items["generic"])
        self.assertEqual("open", self.project.get("obligation", items["sql_injection"]["id"])["status"])
        with self.assertRaises(EngineError):
            validate_confirmation(self.project, generic, "SQL Injection")
        recovery = self.capture(operation, "1 UNION SELECT CASE WHEN 1=1 THEN DATABASE() END", {"metadata": "mixed_database"})
        negative = self.capture(operation, "1 UNION SELECT CASE WHEN 1=2 THEN DATABASE() END", {"count": 0})
        sql = evaluate(self.project, {"obligation_id": items["sql_injection"]["id"],
            "evidence_ids": [evidence[0]["id"], recovery["id"], negative["id"]],
            "oracle": {"type": "sql_metadata", "test_family": "sql_injection", "metadata_type": "database",
                       "expected_value": "mixed_database", "selector": "/metadata", "baseline_selector": "/count", "baseline_expected": 1}})
        self.assertEqual("confirmed", sql["outcome"])
        validate_confirmation(self.project, sql, "SQL Injection")
        self.assertNotEqual(generic["id"], sql["id"])
        for item in items.values():
            self.assertEqual("evaluated", self.project.get("obligation", item["id"])["status"])

    def test_explicit_generic_and_xss_keep_separate_http_and_controlled_runtime_closures(self):
        operation, items = self.operation("html_render", ["generic", "xss"])
        evidence, generic = self.generic_controls(operation, items["generic"])
        self.assertEqual("open", self.project.get("obligation", items["xss"]["id"])["status"])
        with self.assertRaises(EngineError) as caught:
            evaluate(self.project, {"obligation_id": items["xss"]["id"], "evidence_ids": [row["id"] for row in evidence],
                "oracle": {"type": "semantic_negative", "test_family": "xss", "selector": "/count",
                           "baseline_expected": 1, "control_expected": 2}})
        self.assertEqual("xss_runtime_required", caught.exception.code)
        marker = "AWA-XSS-0011223344556677"
        attack = self.capture(operation, "<img src=x onerror=alert('" + marker + "')>", {"count": 1})
        url = self.project.read_artifact(attack)["request"]["url"]
        raw = {"url": url, "finalUrl": url, "status": 200, "signals": {"forms": 1}, "actions": [],
               "network": [{"url": url, "method": "GET", "type": "document", "status": 200, "request_headers": {}}],
               "dialogs": [{"type": "alert", "message": marker, "action_index": None}]}
        visit = browser._record_observation(self.project, raw, self.project.id("PV"), "local_playwright")
        finding = record_finding(self.project, {"mode": "analyst", "title": "Mixed-input controlled runtime", "category": "XSS",
            "impact": "Isolated input executes in its actual consumer", "remediation": "Encode output", "reviewer": "fixture reviewer",
            "reason": "Original normal/attack captures and matching runtime dialog", "obligation_id": items["xss"]["id"],
            "evidence_ids": [evidence[0]["id"], attack["id"]], "runtime_visit_id": visit["id"], "consumer_url": url, "runtime_marker": marker})
        xss = self.project.get("decision", finding["decision_id"])
        self.assertEqual("confirmed", xss["outcome"])
        self.assertNotEqual(generic["id"], xss["id"])
        for item in items.values():
            self.assertEqual("evaluated", self.project.get("obligation", item["id"])["status"])


if __name__ == "__main__":
    unittest.main()
