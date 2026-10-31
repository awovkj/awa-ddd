"""Offline input binding, family separation and localized proof-gate regressions."""
from __future__ import annotations

import base64
import json
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, quote, urlsplit

from awa_ddd import engine
from awa_ddd.assessment import _input_controls, _input_view, evaluate, is_sql_category, is_xss_category, record_finding
from awa_ddd.inputs import json_document, locate_json, parse_form
from awa_ddd.store import EngineError, Project, now


def observation(body=b"", *, location="body", selector="amount", media="application/json", url=None, headers=None, method="POST"):
    raw = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
    request = {"url": url or "http://fixture.invalid/echo", "method": method,
               "headers": headers if headers is not None else {"content-type": media},
               "body_base64": base64.b64encode(raw).decode("ascii")}
    meta = {"actor_id": "alice", "session_id": "session", "session_generation": 1}
    item = {"input_location": location, "input_selector": selector}
    operation = {"url": "http://fixture.invalid/echo", "method": method,
                 "inputs": [{"name": selector, "selector": selector, "location": location}]}
    return (meta, {"request": request}), item, operation


class InputViewTests(unittest.TestCase):
    def test_plain_json_field_and_pointer_produce_the_same_mask(self):
        observed, item, operation = observation({"amount": 1, "id": "fixed"})
        value, context = _input_view(observed, item, operation)
        self.assertEqual(value, 1)
        self.assertEqual(context["body"], {"amount": None, "id": "fixed"})
        self.assertEqual((value, context), _input_view(observed, {**item, "input_selector": "/amount"}, operation))

    def test_plain_name_never_recursively_picks_a_nested_field(self):
        observed, item, operation = observation({"nested": {"amount": 1}})
        with self.assertRaises(EngineError):
            _input_view(observed, item, operation)
        self.assertEqual(_input_view(observed, {**item, "input_selector": "/nested/amount"}, operation)[0], 1)

    def test_root_array_requires_explicit_declaration_and_accepts_exact_array_pointer(self):
        observed, item, operation = observation([1, 9, 30], selector="$")
        self.assertEqual(_input_view(observed, item, operation)[0], [1, 9, 30])
        self.assertIsNone(_input_view(observed, item, operation)[1]["body"])
        with self.assertRaises(EngineError):
            _input_view(observed, item, {**operation, "inputs": []})
        self.assertEqual(locate_json([{"id": "one"}], "/0/id"), ("one", ("0", "id")))

    def test_arrays_are_concrete_controls_but_other_inputs_cannot_change(self):
        rows = [observation({"amount": weights, "id": "fixed"})[0]
                for weights in ([1, 9, 30], [100, 0, 0], [0, 0, 100])]
        _, item, operation = observation({"amount": []})
        _input_controls(rows, item, operation)
        rows[-1] = observation({"amount": [0, 0, 100], "id": "different"})[0]
        with self.assertRaises(EngineError) as error:
            _input_controls(rows, item, operation)
        self.assertEqual(error.exception.code, "input_binding")

    def test_duplicate_json_keys_and_nonfinite_numbers_are_rejected(self):
        for raw in (b'{"amount":1,"amount":2}', b'{"other":{"id":1,"id":2},"amount":1}',
                    b'{"amount":NaN}', b'{"amount":1e999}'):
            with self.assertRaises(EngineError):
                json_document(raw)
        for selector in ("/01", "/-1", "/bad~2escape"):
            with self.assertRaises(EngineError):
                locate_json([1, 2], selector)

    def test_urlencoded_fields_preserve_nontarget_fields_and_reject_duplicates(self):
        rows = [observation(raw, media="application/x-www-form-urlencoded")[0]
                for raw in (b"amount=normal&id=fixed", b"amount=variant&id=fixed", b"amount=control&id=fixed")]
        _, item, operation = observation({}, media="application/x-www-form-urlencoded")
        _input_controls(rows, item, operation)
        self.assertEqual(_input_view(rows[0], item, operation)[1]["body"], {"format": "form", "fields": [("id", "fixed")]})
        with self.assertRaises(EngineError):
            parse_form(b"amount=1&id=x&id=x")

    def test_multipart_keeps_binary_other_parts_and_target_headers_byte_for_byte(self):
        def body(value, filename=b"input.xml", other=b"\x89PNG\x00\xff"):
            return (b'--Bound\r\nContent-Disposition: form-data; name="amount"; filename="' + filename
                    + b'"\r\nContent-Type: text/xml\r\n\r\n' + value
                    + b'\r\n--Bound\r\nContent-Disposition: form-data; name="other"\r\n\r\n' + other + b'\r\n--Bound--\r\n')
        rows = [observation(body(value), media="multipart/form-data; boundary=Bound")[0] for value in (b"one", b"two", b"three")]
        _, item, operation = observation({}, media="multipart/form-data; boundary=Bound")
        _input_controls(rows, item, operation)
        value, context = _input_view(rows[0], item, operation)
        self.assertEqual(value, b"one")
        self.assertEqual(base64.b64decode(context["body"]["prefix_base64"]) + value
                         + base64.b64decode(context["body"]["suffix_base64"]), body(b"one"))
        rows[1] = observation(body(b"two", filename=b"changed.xml"), media="multipart/form-data; boundary=Bound")[0]
        with self.assertRaises(EngineError):
            _input_controls(rows, item, operation)

    def test_cookie_header_and_query_views_are_exact_and_case_sensitive_where_required(self):
        observed, item, operation = observation(location="cookie", selector="marker", headers={"Cookie": "SID=fixed; marker=one"})
        value, context = _input_view(observed, item, operation)
        self.assertEqual(value, "one")
        self.assertIn("SID=fixed", context["headers"]["cookie"])
        with self.assertRaises(EngineError):
            _input_view(observation(location="cookie", selector="marker", headers={"cookie": "marker=x; marker=y"})[0], item, operation)
        observed, item, operation = observation(location="header", selector="X-Choice", headers={"X-Choice": "one", "X-Other": "fixed"})
        self.assertEqual(_input_view(observed, item, operation)[0], "one")
        observed, item, operation = observation(location="query", selector="q", method="GET", media="", url="http://fixture.invalid/echo?q=a&id=fixed")
        self.assertEqual(_input_view(observed, item, operation)[1]["body"], "")
        self.assertEqual(_input_view(observed, item, operation)[1]["query"], [("id", "fixed")])

    def test_controls_cannot_change_identity_and_raw_xml_is_explicitly_blocked(self):
        first, item, operation = observation({"amount": 1})
        second = observation({"amount": 2})[0]
        second[0]["session_generation"] = 2
        with self.assertRaises(EngineError) as error:
            _input_controls([first, second], item, operation)
        self.assertEqual(error.exception.code, "control_identity")
        observed, item, operation = observation(b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///sentinel">]><x>&e;</x>', media="application/xml")
        with self.assertRaises(EngineError) as error:
            _input_view(observed, item, operation)
        self.assertEqual(error.exception.code, "input_adapter_blocked")


class FamilyAndLocalizedCategoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-input-controls-")
        self.addCleanup(self.tmp.cleanup)
        engine.create_project(self.tmp.name, {"project_id": "inputs", "target": "http://fixture.invalid"})
        self.project = Project(self.tmp.name, "inputs")
        self.addCleanup(self.project.close)
        self.operation = engine.register_operation(self.project, {"url": "http://fixture.invalid/echo", "method": "GET", "auth": "public",
            "inputs": [{"name": "q", "location": "query", "consumer": "query", "test_families": ["business_logic", "generic", "sql_injection", "xss"]}]})
        engine.build_plan(self.project)

    def capture(self, value):
        def observed(url, method, headers, body, timeout, max_bytes):
            result = {"value": "different" if parse_qs(urlsplit(url).query)["q"] == ["control"] else "same"}
            raw = json.dumps(result).encode()
            return {"request": {"url": url, "method": method, "headers": headers, "body_base64": ""},
                    "response": {"status": 200, "headers": [], "length": len(raw), "body_base64": base64.b64encode(raw).decode()},
                    "complete": True, "started_at": now(), "completed_at": now()}
        with patch.object(engine, "request", side_effect=observed):
            return engine.capture(self.project, {"operation_id": self.operation["id"], "url": self.operation["url"] + "?q=" + value})["id"]

    def test_one_family_cannot_close_another_and_sql_xss_keep_specialized_gates(self):
        ids = [self.capture(value) for value in ("normal", "variant", "control")]
        obligations = {row["test_family"]: row for row in self.project.list("obligation") if row.get("test_family")}
        oracle = {"type": "semantic_negative", "test_family": "business_logic", "selector": "/value", "baseline_expected": "same", "control_expected": "different"}
        decision = evaluate(self.project, {"obligation_id": obligations["business_logic"]["id"], "evidence_ids": ids, "oracle": oracle})
        self.assertEqual(decision["outcome"], "refuted")
        self.assertEqual(self.project.get("obligation", obligations["generic"]["id"])["status"], "open")
        for family, code in (("generic", "oracle_family"), ("sql_injection", "sql_metadata_required"), ("xss", "xss_runtime_required")):
            with self.assertRaises(EngineError) as error:
                evaluate(self.project, {"obligation_id": obligations[family]["id"], "evidence_ids": ids, "oracle": {**oracle, "test_family": family if family != "generic" else "business_logic"}})
            self.assertEqual(error.exception.code, code)

    def test_chinese_and_suffixed_sql_xss_categories_cannot_bypass_proof(self):
        evidence = self.capture("normal")
        fields = {"mode": "analyst", "reviewer": "fixture", "reason": "static response only", "evidence_ids": [evidence],
                  "title": "fixture", "impact": "fixture", "remediation": "fixture"}
        categories = [("\u6570\u636e\u5e93\u6ce8\u5165", "sql_metadata_required"), ("SQL\u6ce8\u5165", "sql_metadata_required"),
                      ("\u5b58\u50a8\u578b\u8de8\u7ad9\u811a\u672c", "xss_runtime_required"), ("Cross Site Scripting / Stored", "xss_runtime_required")]
        for category, code in categories:
            with self.assertRaises(EngineError) as error:
                record_finding(self.project, {**fields, "category": category})
            self.assertEqual(error.exception.code, code)
        self.assertEqual(self.project.list("finding"), [])
        self.assertFalse(is_sql_category("NoSQL Injection"))
        self.assertTrue(is_sql_category("\u6570\u636e\u5e93\u6ce8\u5165"))
        self.assertTrue(is_xss_category("\u53cd\u5c04\u578b\u8de8\u7ad9\u811a\u672c"))

    def test_typed_xxe_extraction_needs_source_and_cannot_be_relabelled(self):
        operation = engine.register_operation(self.project, {"url": "http://fixture.invalid/extract", "method": "GET", "auth": "public",
            "inputs": [{"name": "q", "location": "query", "consumer": "xml", "test_families": ["xxe"]}]})
        engine.build_plan(self.project)
        item = next(row for row in self.project.list("obligation") if row.get("test_family") == "xxe" and not row.get("superseded"))
        ids = []
        for value in ('<!DOCTYPE x [<!ENTITY e SYSTEM "file:///sentinel">]><x>&e;</x>', "<x>normal</x>"):
            def observed(url, method, headers, body, timeout, max_bytes):
                selected = parse_qs(urlsplit(url).query)["q"][0]
                raw = json.dumps({"data": {"value": "SERVER_CANARY_04"} if "file:///sentinel" in selected else {}}).encode()
                return {"request": {"url": url, "method": method, "headers": headers, "body_base64": ""},
                        "response": {"status": 200, "headers": [], "length": len(raw), "body_base64": base64.b64encode(raw).decode()},
                        "complete": True, "started_at": now(), "completed_at": now()}
            with patch.object(engine, "request", side_effect=observed):
                ids.append(engine.capture(self.project, {"operation_id": operation["id"], "url": operation["url"] + "?q=" + quote(value, safe="")})["id"])
        oracle = {"type": "extraction", "test_family": "xxe", "selector": "/data/value", "expect": "^SERVER_CANARY_04$",
                  "expected_value": "SERVER_CANARY_04", "source_reference": "file:///sentinel"}
        with self.assertRaises(EngineError) as error:
            evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": ids, "oracle": {**oracle, "source_reference": "file:///different"}})
        self.assertEqual(error.exception.code, "family_proof")
        decision = evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": ids, "oracle": oracle})
        self.assertEqual(decision["outcome"], "confirmed")
        fields = {"decision_id": decision["id"], "title": "fixture", "impact": "fixture", "remediation": "fixture"}
        with self.assertRaises(EngineError) as error:
            record_finding(self.project, {**fields, "category": "Business Logic Flaw"})
        self.assertEqual(error.exception.code, "oracle_family")
        self.assertEqual(record_finding(self.project, {**fields, "category": "XML External Entity (XXE)"})["status"], "confirmed")

    def test_no_sql_and_suffixed_xss_aliases_do_not_hide_explicit_claims(self):
        self.assertFalse(is_sql_category("NoSQL Injection"))
        self.assertTrue(is_sql_category("SQL Injection / NoSQL"))
        self.assertTrue(is_xss_category("Custom / XSS / Stored"))

    def test_unknown_family_and_untyped_oracle_are_explicit_errors(self):
        item = next(row for row in self.project.list("obligation") if row.get("test_family") == "generic")
        self.project.put("obligation", {**item, "test_family": "unknown-family"})
        with self.assertRaises(EngineError) as error:
            evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": [],
                                   "oracle": {"type": "extraction", "test_family": "unknown-family"}})
        self.assertEqual(error.exception.code, "oracle_family")
        with self.assertRaises(EngineError) as error:
            evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": [], "oracle": []})
        self.assertEqual(error.exception.code, "oracle")


if __name__ == "__main__":
    unittest.main()
