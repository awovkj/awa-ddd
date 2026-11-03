"""Offline client sink hypotheses, syntactic bindings and strict discovery JSON."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from awa_ddd.discovery import discover


class ClientSinkDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="awa-client-sinks-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.base = "https://app.invalid/app/"

    def javascript(self, text, name="bundle.js"):
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        result = discover(path, "javascript", self.base)
        self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())
        return result

    def sinks(self, result):
        return [row for row in result["candidates"] if row["kind"] == "client_sink"]

    def test_html_assignment_vue_property_and_insert_adjacent_html_find_fields(self):
        source = "\n".join([
            "axios.post('/api/register', {shop_name: form.shop_name});",
            "axios.post('/api/audit', {description: form.description});",
            "function render(item) {",
            "  const label = item.shop_name;",
            "  target.innerHTML = label;",
            "}",
            "const vnode = {innerHTML: item.description};",
            "target.insertAdjacentHTML('beforeend', item.description);",
        ])
        result = self.javascript(source)
        rows = {row["sink"]: row for row in self.sinks(result)}
        self.assertEqual(set(rows), {"innerHTML.assignment", "innerHTML.object_property", "insertAdjacentHTML"})
        assignment = rows["innerHTML.assignment"]
        self.assertEqual(assignment["referenced_fields"], ["shop_name"])
        self.assertEqual((assignment["source_line"], assignment["source_column"]), (5, 3))
        self.assertEqual(assignment["sources"][0]["locator"], "line:5:column:3")
        binding = assignment["possible_input_bindings"][0]
        self.assertEqual((binding["url"], binding["method"], binding["input_selector"]),
                         ("https://app.invalid/api/register", "POST", "/shop_name"))
        self.assertEqual(binding["matching_basis"], "same_bundle_field_name_only")
        self.assertEqual(binding["request_locator"], "line:1:column:1")
        for sink in ("innerHTML.object_property", "insertAdjacentHTML"):
            self.assertEqual(rows[sink]["referenced_fields"], ["description"])
            self.assertEqual(rows[sink]["possible_input_bindings"][0]["input_selector"], "/description")
        self.assertTrue(all(entry["consumer"] == "unknown" for operation in result["operations"] for entry in operation["inputs"]))
        for row in rows.values():
            self.assertEqual(row["status"], "unverified")
            self.assertEqual(row["verification_level"], "hint_only")
            self.assertTrue(row["hints_only"])
            self.assertFalse(row["taint_proven"])
            self.assertFalse(row["consumer_declaration_allowed"])
            self.assertFalse(row["usable_for_confirmation"])
            self.assertFalse(row["requestable"])

    def test_location_href_assign_replace_and_const_alias_retain_route_fields(self):
        source = "\n".join([
            "axios.get('/pay',{params:{redirect: route.query.redirect, return_url: route.query.return_url, next_url: route.query.next_url}});",
            "const destination = route.query.redirect ?? '/user/orders';",
            "window.location.href = destination;",
            "window.location.assign(route.query.return_url);",
            "location.replace(route.query.next_url);",
            "const loc = window.location;",
            "loc.replace(route.query.redirect);",
        ])
        rows = self.sinks(self.javascript(source))
        self.assertEqual([row["sink"] for row in rows], ["location.href", "location.assign", "location.replace", "location.replace"])
        self.assertEqual([row["referenced_fields"] for row in rows], [["redirect"], ["return_url"], ["next_url"], ["redirect"]])
        self.assertTrue(all(row["category"] == "client_navigation" for row in rows))
        self.assertTrue(all(row["binding_status"] == "possible" for row in rows))
        self.assertEqual(rows[0]["possible_input_bindings"][0]["input_location"], "query")
        self.assertEqual((rows[0]["source_line"], rows[0]["source_column"]), (3, 1))

    def test_query_names_in_literal_request_urls_join_without_query_values(self):
        result = self.javascript("fetch('/pay?redirect=SYNTHETIC_PRIVATE_DESTINATION'); window.location.href = route.query.redirect;")
        row = self.sinks(result)[0]
        self.assertEqual(row["binding_status"], "possible")
        self.assertEqual(row["possible_input_bindings"][0]["input_selector"], "redirect")
        self.assertNotIn("SYNTHETIC_PRIVATE_DESTINATION", json.dumps(result))

    def test_repeated_field_names_remain_ambiguous_without_chosen_taint_binding(self):
        result = self.javascript("\n".join([
            "axios.post('/one', {description: a.description});",
            "axios.post('/two', {description: b.description});",
            "target.innerHTML = item.description;",
        ]))
        row = self.sinks(result)[0]
        self.assertEqual(row["binding_status"], "ambiguous")
        self.assertEqual({binding["url"] for binding in row["possible_input_bindings"]},
                         {"https://app.invalid/one", "https://app.invalid/two"})
        self.assertNotIn("operation_id", row)
        self.assertFalse(row["taint_proven"])

    def test_a_separate_bundle_never_reuses_another_bundles_request_fields(self):
        self.javascript("axios.post('/audit',{description: form.description});", name="request.js")
        result = self.javascript("target.innerHTML = data.description;", name="consumer.js")
        row = self.sinks(result)[0]
        self.assertEqual(result["operations"], [])
        self.assertEqual(row["binding_status"], "unresolved")
        self.assertEqual(row["possible_input_bindings"], [])
        self.assertTrue(row["sources"][0]["path"].endswith("consumer.js"))

    def test_shadowed_window_and_location_are_not_claimed_global_navigation(self):
        result = self.javascript("\n".join([
            "function local(window, location) { window.location.href = input.redirect; location.assign(input.redirect); }",
            "const fake = {location: {}}; fake.location.href = input.redirect;",
            "globalThis.location.href = input.redirect;",
            "document.location.replace(input.redirect);",
        ]))
        rows = self.sinks(result)
        self.assertEqual([row["sink"] for row in rows], ["location.href", "location.replace"])
        self.assertEqual([row["source_line"] for row in rows], [3, 4])

    def test_static_and_dynamic_sink_sites_remain_candidates_without_literal_values(self):
        result = self.javascript("\n".join([
            "const secret = 'SYNTHETIC_PRIVATE_VALUE';",
            "target.innerHTML = secret;",
            "target.insertAdjacentHTML('beforeend', '<img src=x onerror=SYNTHETIC_PRIVATE_HTML>');",
            "window.location.assign(getDestination());",
            "target.innerHTML = data[chosen];",
        ]))
        rows = self.sinks(result)
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(row["binding_status"] == "unresolved" for row in rows))
        self.assertEqual(rows[0]["referenced_fields"], [])
        self.assertTrue(rows[-1]["references_limited"])
        public = json.dumps(result)
        self.assertNotIn("SYNTHETIC_PRIVATE", public)
        self.assertNotIn("<img", public)
        self.assertNotIn("onerror", public)
        self.assertFalse(any("snippet" in key or "source_text" in key for row in rows for key in row))

    def test_source_imports_calls_and_throw_statements_are_never_executed(self):
        marker = self.root / "must-not-exist.txt"
        result = self.javascript("\n".join([
            "import fs from 'node:fs';",
            "fs.writeFileSync(" + json.dumps(str(marker)) + ", 'SYNTHETIC_WRITTEN_SECRET');",
            "throw new Error('source-is-not-a-program-to-run');",
            "target.innerHTML = item.shop_name;",
        ]))
        self.assertFalse(marker.exists())
        self.assertEqual(self.sinks(result)[0]["referenced_fields"], ["shop_name"])
        self.assertNotIn("must-not-exist", json.dumps(result))
        self.assertNotIn("SYNTHETIC_WRITTEN_SECRET", json.dumps(result))

    def test_comments_and_quoted_fake_sink_code_are_not_discovered(self):
        result = self.javascript("\n".join([
            "// target.innerHTML = data.shop_name;",
            "const fake = 'window.location.href = secret;';",
            "const fake2 = 'target.insertAdjacentHTML(ignored, secret);';",
        ]))
        self.assertEqual(self.sinks(result), [])

    def test_reference_budget_is_explicit_and_never_discards_the_sink_site(self):
        source = "target.innerHTML = [" + ",".join("item.field" + str(index) for index in range(80)) + "].join('');"
        result = self.javascript(source)
        row = self.sinks(result)[0]
        self.assertEqual(len(row["referenced_fields"]), 64)
        self.assertTrue(row["references_limited"])
        self.assertIn("client_sink_reference_requires_review", {item["code"] for item in result["limitations"]})


class StrictDiscoveryJsonTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="awa-discovery-json-")
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "source.json"

    def read(self, text, format="openapi"):
        self.path.write_text(text, encoding="utf-8")
        return discover(self.path, format, "http://fixture.invalid/")

    def test_every_json_adapter_rejects_duplicate_keys_and_nonfinite_numbers(self):
        for format in ("openapi", "har", "artex", "sarif", "assessment_hints"):
            for text in ('{"value":1,"value":2}', '{"value":NaN}', '{"value":Infinity}', '{"value":1e999}'):
                with self.subTest(format=format, text=text), self.assertRaisesRegex(ValueError, "unambiguous finite"):
                    self.read(text, format)

    def test_unpaired_unicode_surrogates_are_rejected_in_keys_and_values(self):
        for text in (r'{"key":"\ud800"}', r'{"\udfff":"value"}'):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "UTF-8 JSON"):
                self.read(text)
        result = self.read(r'{"openapi":"3.0.3","paths":{},"example":"\ud83d\ude00"}')
        self.assertEqual(result["operations"], [])

    def test_assessment_hint_hook_only_creates_unverified_candidates(self):
        result = self.read(json.dumps({"schema_version": 1, "source_kind": "validator_export", "entries": [
            {"url": "/api/search", "method": "GET", "test_family": "sql_injection",
             "inputs": [{"name": "keyword", "location": "query"}], "result": "valid"}]}), "assessment_hints")
        self.assertEqual(result["operations"], [])
        self.assertEqual(len(result["candidates"]), 1)
        row = result["candidates"][0]
        self.assertEqual(row["kind"], "validator_hint")
        self.assertTrue(row["independent_evidence_required"])
        self.assertFalse(row["usable_for_confirmation"])
        self.assertFalse(row["requestable"])


if __name__ == "__main__":
    unittest.main()
