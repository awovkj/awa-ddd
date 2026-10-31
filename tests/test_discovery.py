"""Offline discovery behavior, source trust, bounds and credential minimization."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd.discovery import discover, MAX_BYTES


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="awa-discovery-")
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def run_input(self, value, format, base="https://app.invalid/app/"):
        path = self.root / ("input.js" if format == "javascript" else "input.json")
        raw = value if isinstance(value, str) else json.dumps(value)
        path.write_text(raw, encoding="utf-8")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        result = discover(path, format, base)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        return result

    def spec(self, operation, **kwargs):
        return {"openapi": "3.0.3", "servers": [{"url": "/api"}],
                "paths": {"/orders": {"post": operation}}, **kwargs}

    def codes(self, result):
        return {row["code"] for row in result["limitations"]}

    def test_openapi_nested_json_arrays_local_refs_and_no_values(self):
        schema = {"type": "object", "required": ["amount"], "properties": {
            "amount": {"type": "number", "example": "SYNTHETIC_SECRET"},
            "owner/id": {"type": "string"},
            "items": {"type": "array", "items": {"$ref": "#/components/schemas/Item"}},
        }}
        doc = self.spec({"requestBody": {"$ref": "#/components/requestBodies/Order"}},
            components={"schemas": {"Item": {"type": "object", "properties": {"sku": {"type": "string"}}}},
                        "requestBodies": {"Order": {"content": {"application/json": {"schema": schema}}}}})
        result = self.run_input(doc, "openapi")
        self.assertEqual(len(result["operations"]), 1)
        op = result["operations"][0]
        self.assertEqual((op["url"], op["method"], op["content_type"]), ("https://app.invalid/api/orders", "POST", "application/json"))
        fields = {field["selector"]: field for field in op["inputs"]}
        self.assertEqual(set(fields), {"/amount", "/owner~1id", "/items/0/sku"})
        self.assertTrue(fields["/amount"]["required"])
        self.assertTrue(fields["/items/0/sku"]["array_template"])
        self.assertNotIn("SYNTHETIC_SECRET", json.dumps(result))
        self.assertEqual(op["sources"][0]["trust"], "declared")

    def test_openapi_media_types_and_branches_remain_separate(self):
        schema = {"oneOf": [
            {"properties": {"amount": {"type": "number"}}},
            {"properties": {"amount": {"type": "string"}, "coupon": {"type": "string"}}},
        ]}
        result = self.run_input(self.spec({"requestBody": {"content": {
            "application/json": {"schema": schema},
            "multipart/form-data": {"schema": {"properties": {"file": {"type": "string", "format": "binary"}}}},
        }}}), "openapi")
        self.assertEqual(len(result["operations"]), 2)
        op = next(row for row in result["operations"] if row["content_type"] == "application/json")
        amount = [row for row in op["inputs"] if row["name"] == "amount"]
        self.assertEqual(len(amount), 2)
        self.assertNotEqual(amount[0]["schema_branch"], amount[1]["schema_branch"])

    def test_openapi_recursive_and_external_refs_are_explicit(self):
        schema = {"properties": {"self": {"$ref": "#/components/schemas/Node"},
                                 "external": {"$ref": "https://external.invalid/secret.json"}}}
        doc = self.spec({"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Node"}}}}}, components={"schemas": {"Node": schema}})
        result = self.run_input(doc, "openapi")
        self.assertIn("recursive_schema_reference", self.codes(result))
        self.assertIn("external_reference_not_loaded", self.codes(result))

    def test_openapi_operation_overrides_and_server_variables(self):
        doc = self.spec({"servers": [{"url": "./v2"}], "parameters": [{"name": "limit", "in": "query", "required": True}]})
        doc["paths"]["/orders"]["parameters"] = [{"name": "limit", "in": "query", "required": False}]
        result = self.run_input(doc, "openapi")
        op = result["operations"][0]
        self.assertEqual(op["url"], "https://app.invalid/app/v2/orders")
        self.assertTrue(op["inputs"][0]["required"])
        doc["paths"]["/orders"]["post"]["servers"] = [{"url": "https://{tenant}.invalid"}]
        result = self.run_input(doc, "openapi")
        self.assertFalse(result["operations"])
        self.assertIn("server_variable_requires_explicit_resolution", self.codes(result))

    def test_openapi_missing_base_is_not_guessed(self):
        result = self.run_input(self.spec({}), "openapi", None)
        self.assertEqual(result["operations"], [])
        self.assertIn("server_url_requires_base_url", self.codes(result))

    def test_openapi_allof_required_optional_auth_and_template(self):
        schema = {"allOf": [{"properties": {"id": {"type": "integer"}}}, {"required": ["id"]}]}
        doc = {"openapi": "3.1.0", "servers": [{"url": "/api"}], "paths": {
            "/orders/{id}": {"post": {"security": [{"bearer": []}, {}],
                "requestBody": {"content": {"application/json": {"schema": schema}}}}}}}
        result = self.run_input(doc, "openapi")
        self.assertEqual(len(result["operations"]), 1)
        self.assertTrue(result["operations"][0]["inputs"][0]["required"])
        self.assertEqual(result["operations"][0]["auth"], "unknown")
        self.assertTrue(result["operations"][0]["path_template"])
        self.assertIn("path_template_requires_resource_binding", self.codes(result))

    def test_unsupported_http_method_is_a_candidate(self):
        result = self.run_input({"log": {"entries": [{"request": {"method": "TRACE", "url": "/api"}}]}}, "har")
        self.assertFalse(result["operations"])
        self.assertEqual(result["candidates"][0]["method"], "TRACE")

    def test_har_deduplicates_preserves_distinct_methods_and_removes_credentials(self):
        request = {"url": "https://app.invalid/orders?access_token=SYNTHETIC_QUERY_SECRET&limit=10", "method": "POST",
                   "headers": [{"name": "Authorization", "value": "Bearer SYNTHETIC_HEADER_SECRET"}],
                   "postData": {"mimeType": "application/json", "text": json.dumps({"amount": 3, "password": "SYNTHETIC_BODY_SECRET", "items": [{"sku": "private-sku"}]})}}
        result = self.run_input({"log": {"entries": [{"request": request}, {"request": request}, {"request": {**request, "method": "GET"}}]}}, "har")
        self.assertEqual(len(result["operations"]), 2)
        op = result["operations"][0]
        self.assertEqual(op["url"], "https://app.invalid/orders")
        self.assertEqual(len(op["sources"]), 2)
        self.assertEqual(op["sources"][0]["trust"], "observed")
        self.assertIn("/items/0/sku", {row["selector"] for row in op["inputs"]})
        for secret in ("SYNTHETIC_QUERY_SECRET", "SYNTHETIC_HEADER_SECRET", "SYNTHETIC_BODY_SECRET", "private-sku"):
            self.assertNotIn(secret, json.dumps(result))

    def test_har_graphql_operations_stay_distinct(self):
        entries = []
        for name in ("ReadOrder", "UpdateOrder"):
            entries.append({"request": {"url": "https://app.invalid/graphql", "method": "POST",
                "postData": {"mimeType": "application/json", "text": json.dumps({"operationName": name, "query": "query omitted", "variables": {"id": "SYNTHETIC_ID"}})}}})
        result = self.run_input({"log": {"entries": entries}}, "har")
        self.assertEqual({row["operation_name"] for row in result["operations"]}, {"ReadOrder", "UpdateOrder"})
        self.assertTrue(all(row["protocol"] == "graphql" for row in result["operations"]))
        self.assertNotIn("SYNTHETIC_ID", json.dumps(result))

    def test_unnamed_graphql_is_candidate_and_har_header_cookie_names_are_kept(self):
        request = {"url": "/graphql", "method": "POST", "headers": [{"name": "X-Tenant", "value": "SYNTHETIC_TENANT"}],
                   "cookies": [{"name": "session", "value": "SYNTHETIC_COOKIE"}],
                   "postData": {"mimeType": "application/json", "text": '{"query":"query { me {id} }"}'}}
        result = self.run_input({"log": {"entries": [{"request": request}]}}, "har")
        self.assertFalse(result["operations"])
        self.assertEqual({(row["location"], row["name"]) for row in result["candidates"][0]["inputs"]}, {("header", "X-Tenant"), ("cookie", "session")})
        self.assertNotIn("SYNTHETIC", json.dumps(result))

    def test_json_search_query_is_not_a_graphql_operation(self):
        body = {"query": "ordinary search terms", "variables": {"category": "SYNTHETIC_PRIVATE"}}
        result = self.run_input({"log": {"entries": [{"request": {"url": "/search", "method": "POST",
            "postData": {"mimeType": "application/json", "text": json.dumps(body)}}}]}}, "har")
        op = result["operations"][0]
        self.assertEqual(op["protocol"], "http")
        self.assertEqual({row["selector"] for row in op["inputs"]}, {"/query", "/variables/category"})
        self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(result))

    def test_graphql_document_names_comments_fragments_and_selection(self):
        queries = [
            {"query": '# leading comment\nquery ReadOrder($filter: Input = {id: "secret"}) { order(filter:$filter) { ...Details } } fragment Details on Order { id }',
             "variables": {"filter": {"id": "SYNTHETIC_PRIVATE"}}},
            {"query": 'query First { me } query Second { me }'},
            {"query": 'query Actual { me }', "operationName": "Different"},
        ]
        entries = [{"request": {"url": "/graphql", "method": "POST", "postData": {
            "mimeType": "application/json", "text": json.dumps(body)}}} for body in queries]
        result = self.run_input({"log": {"entries": entries}}, "har")
        self.assertEqual([row["operation_name"] for row in result["operations"]], ["ReadOrder"])
        self.assertEqual(result["operations"][0]["inputs"][0]["selector"], "/variables/filter/id")
        self.assertEqual(len(result["candidates"]), 2)
        self.assertIn("graphql_operation_selection_mismatch", self.codes(result))
        self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(result))

    def test_graphql_string_contents_cannot_create_operation_definitions(self):
        body = {"query": 'query Read { search(text: "} query Fake { ") { id } }'}
        result = self.run_input({"log": {"entries": [{"request": {"url": "/graphql", "method": "POST",
            "postData": {"mimeType": "application/json", "text": json.dumps(body)}}}]}}, "har")
        self.assertEqual(result["operations"][0]["operation_name"], "Read")

    def test_graphql_content_type_preserves_named_document(self):
        result = self.run_input({"log": {"entries": [{"request": {"url": "/graphql", "method": "POST",
            "postData": {"mimeType": "application/graphql", "text": "query Read { me { id } }"}}}]}}, "har")
        self.assertEqual(result["operations"][0]["operation_name"], "Read")
        self.assertIn("graphql_variable_definitions_require_review", self.codes(result))

    def test_har_mock_is_not_observed_and_truncation_is_visible(self):
        doc = {"log": {"entries": [{"_capture_mode": "mock", "request": {"url": "/orders", "method": "POST", "postData": {"mimeType": "application/json", "text": '{"amount":'}}}]}}
        result = self.run_input(doc, "har")
        self.assertFalse(result["operations"])
        self.assertEqual(result["candidates"][0]["sources"][0]["trust"], "mock")
        self.assertIn("unparseable_or_truncated_json_body", self.codes(result))

    def test_artex_stock_exports_default_to_unknown_candidates(self):
        doc = {"shell": {"url": "https://app.invalid/"}, "rec": [{"m": "POST", "u": "/orders", "full": "https://app.invalid/orders?token=SYNTHETIC_SECRET", "b": '{"amount":1}', "resp": "SYNTHETIC_RESPONSE_SECRET", "ct": "application/json"}],
               "wsEndpoints": ["wss://app.invalid/events?token=SYNTHETIC_SECRET"], "sse": ["/events"]}
        result = self.run_input(doc, "artex")
        self.assertEqual(result["operations"], [])
        self.assertEqual(len(result["candidates"]), 3)
        self.assertEqual(result["candidates"][0]["sources"][0]["trust"], "unknown")
        self.assertNotIn("SYNTHETIC_SECRET", json.dumps(result))
        self.assertNotIn("SYNTHETIC_RESPONSE_SECRET", json.dumps(result))

    def test_artex_explicit_mock_overrides_claimed_observed(self):
        doc = {"capture_mode": "observed", "__API_RECON_DETAIL__": [{"method": "GET", "url": "/me", "source": "mock", "capture_mode": "observed"}]}
        result = self.run_input(doc, "artex")
        self.assertEqual(result["operations"], [])
        self.assertEqual(result["candidates"][0]["sources"][0]["trust"], "mock")

    def test_artex_route_contexts_and_ws_frames_do_not_copy_frame_values(self):
        doc = {"rec": [{"m": "GET", "u": "/api/orders"}],
               "perRoute": {"/orders?session=SYNTHETIC_SECRET": ["GET /api/orders"]},
               "ws": [{"url": "/socket", "dir": "recv", "data": "SYNTHETIC_SECRET"}]}
        result = self.run_input(doc, "artex")
        self.assertEqual(result["candidates"][0]["contexts"], ["https://app.invalid/orders"])
        self.assertEqual(result["candidates"][1]["url"], "wss://app.invalid/socket")
        self.assertNotIn("SYNTHETIC_SECRET", json.dumps(result))

    def test_sarif_imports_locations_without_snippets_or_messages(self):
        doc = {"version": "2.1.0", "runs": [{"results": [{"ruleId": "test/sql-flow", "level": "error",
                "message": {"text": "password=SYNTHETIC_SECRET"}, "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "src/app.py"}, "region": {"startLine": 24, "snippet": {"text": "SYNTHETIC_CODE_SECRET"}}}}]}]}]}
        result = self.run_input(doc, "sarif")
        candidate = result["candidates"][0]
        self.assertEqual(candidate["locations"], [{"uri": "src/app.py", "line": 24}])
        self.assertEqual(candidate["status"], "unverified")
        self.assertNotIn("SYNTHETIC_SECRET", json.dumps(result))
        self.assertNotIn("SYNTHETIC_CODE_SECRET", json.dumps(result))

    def test_sarif_preserves_versioned_artifact_and_call_path_without_values(self):
        def location(index, line):
            return {"physicalLocation": {"artifactLocation": {"index": index}, "region": {
                "startLine": line, "snippet": {"text": "SYNTHETIC_CODE_SECRET"}}}}
        doc = {"version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "fixture-analyzer", "semanticVersion": "1.2.3"}},
            "artifacts": [{"location": {"uri": "src/routes.py?token=SYNTHETIC_URI_SECRET"},
                           "hashes": {"sha-256": "a" * 64}}, {"location": {"uri": "src/store.py"}}],
            "results": [{"ruleId": "source-to-sink", "locations": [location(1, 30)],
                "codeFlows": [{"threadFlows": [{"locations": [
                    {"location": location(0, 10), "state": {"token": "SYNTHETIC_STATE_SECRET"}},
                    {"location": location(1, 30)}]}]}]}]}]}
        result = self.run_input(doc, "sarif")
        candidate = result["candidates"][0]
        self.assertEqual(candidate["analysis_tool"], {"name": "fixture-analyzer", "version": "1.2.3"})
        self.assertEqual(candidate["locations"], [{"uri": "src/store.py", "line": 30}])
        path = candidate["call_paths"][0]
        self.assertTrue(path["complete"])
        self.assertEqual(path["locations"][0], {"uri": "src/routes.py", "line": 10, "declared_artifact_sha256": "a" * 64})
        self.assertEqual(candidate["status"], "unverified")
        self.assertNotIn("SYNTHETIC", json.dumps(result))

    def test_sarif_invalid_collections_and_partial_call_paths_are_explicit(self):
        doc = {"version": "2.1.0", "runs": [{"results": [
            {"ruleId": "invalid-shapes", "locations": None, "codeFlows": "invalid", "level": []},
            {"ruleId": "partial", "codeFlows": [{"threadFlows": [{"locations": [
                {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/valid.py"}}}},
                {"location": {"physicalLocation": {"artifactLocation": {"uri": "https://user:SECRET@app.invalid/private"}}}},
                {"location": {"physicalLocation": {"artifactLocation": {"uri": "https://[invalid"}}}}]}]}]},
        ]}]}
        result = self.run_input(doc, "sarif")
        self.assertEqual(len(result["candidates"]), 2)
        self.assertFalse(result["candidates"][1]["call_paths"][0]["complete"])
        self.assertTrue({"invalid_sarif_locations", "invalid_sarif_code_flows", "sarif_call_path_incomplete"}.issubset(self.codes(result)))
        self.assertNotIn("SECRET", json.dumps(result))

    def test_sarif_conflicting_artifact_uri_does_not_attach_another_files_hash(self):
        doc = {"version": "2.1.0", "runs": [{"artifacts": [{"location": {"uri": "first.py"},
            "hashes": {"sha-256": "a" * 64}}], "results": [{"ruleId": "conflicting-reference",
            "locations": [{"physicalLocation": {"artifactLocation": {"index": 0, "uri": "second.py"}}}]}]}]}
        result = self.run_input(doc, "sarif")
        self.assertEqual(result["candidates"][0]["locations"], [{"uri": "second.py"}])

    def test_javascript_axios_literal_method_and_nested_fields(self):
        result = self.run_input("axios.post('/api/orders', {amount: price, ownerId: user, items:[{sku:item.sku}]}, {headers:{Authorization:'SYNTHETIC_SECRET'}});", "javascript")
        self.assertEqual(len(result["operations"]), 1, result)
        op = result["operations"][0]
        self.assertEqual((op["method"], op["url"]), ("POST", "https://app.invalid/api/orders"))
        self.assertEqual({row["selector"] for row in op["inputs"]}, {"/amount", "/ownerId", "/items/0/sku", "Authorization"})
        self.assertNotIn("SYNTHETIC_SECRET", json.dumps(result))

    def test_javascript_fetch_config_constants_and_axios_baseurl(self):
        code = """import ax from 'axios';
const api=ax.create({baseURL:'/v2'});
const data={filter:{enabled:true}};
const opts={method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)};
fetch('/settings',opts);
api.get('/users',{params:{limit:10}});
"""
        result = self.run_input(code, "javascript")
        self.assertEqual(len(result["operations"]), 2, result)
        by_url = {row["url"]: row for row in result["operations"]}
        self.assertEqual(by_url["https://app.invalid/settings"]["method"], "PATCH")
        self.assertIn("/filter/enabled", {row["selector"] for row in by_url["https://app.invalid/settings"]["inputs"]})
        self.assertEqual(by_url["https://app.invalid/v2/users"]["inputs"][0]["location"], "query")

    def test_javascript_dynamic_url_and_method_remain_candidates(self):
        result = self.run_input("fetch(`/orders/${id}`); fetch('/orders',{method:selected});", "javascript")
        self.assertEqual(result["operations"], [])
        self.assertEqual(len(result["candidates"]), 2)
        self.assertIn("dynamic_request_url", self.codes(result))
        self.assertIn("dynamic_request_method", self.codes(result))

    def test_javascript_scopes_shadowing_comments_and_reassignment(self):
        code = """// axios.post('/fake', {secret:1});
const path='/real';
function wrapped(path){fetch(path);}
{const path='/nested';fetch(path);}
fetch(path);
let changed='/first';changed='/second';fetch(changed);
function custom(fetch){fetch('/not-native');}
"""
        result = self.run_input(code, "javascript")
        self.assertEqual({row["url"] for row in result["operations"]}, {"https://app.invalid/nested", "https://app.invalid/real"})
        self.assertEqual(len(result["candidates"]), 2)

    def test_javascript_missing_parser_and_invalid_syntax_are_explicit(self):
        with patch("awa_ddd.discovery.shutil.which", return_value=None):
            result = self.run_input("fetch('/ok')", "javascript")
        self.assertFalse(result["operations"])
        self.assertIn("javascript_ast_parser_unavailable", self.codes(result))
        result = self.run_input("const x = <unsupportedJSX/>", "javascript")
        self.assertIn("javascript_syntax_not_supported", self.codes(result))

    def test_javascript_window_fetch_graphql_and_destructured_shadow(self):
        code = """window.fetch('/graphql',{method:'POST',body:JSON.stringify({operationName:'ReadOrder',query:'query omitted',variables:{id:secret}})});
function unrelated({fetch}){fetch('/not-native');}
"""
        result = self.run_input(code, "javascript")
        self.assertEqual(len(result["operations"]), 1, result)
        op = result["operations"][0]
        self.assertEqual((op["protocol"], op["operation_name"]), ("graphql", "ReadOrder"))
        self.assertEqual(op["inputs"][0]["selector"], "/variables/id")

    def test_javascript_search_fields_and_graphql_document_selection(self):
        code = """axios.post('/search', {query:'plain search', variables:{category:input}});
axios.post('/graphql', {query:'query Read { me { id } }', variables:{id:input}});
axios.post('/graphql', {query:'query First { me } query Second { me }'});
axios.post('/graphql', {query:'query Actual { me }', operationName:'Different'});
"""
        result = self.run_input(code, "javascript")
        self.assertEqual(len(result["operations"]), 2, result)
        self.assertEqual(result["operations"][0]["protocol"], "http")
        self.assertEqual({row["selector"] for row in result["operations"][0]["inputs"]}, {"/query", "/variables/category"})
        self.assertEqual(result["operations"][1]["operation_name"], "Read")
        self.assertEqual(len(result["candidates"]), 2)
        self.assertIn("graphql_operation_selection_mismatch", self.codes(result))

    def test_credentials_in_url_are_rejected(self):
        result = self.run_input({"log": {"entries": [{"request": {"method": "GET", "url": "https://user:SYNTHETIC_SECRET@app.invalid/api"}}]}}, "har")
        self.assertFalse(result["operations"])
        self.assertNotIn("SYNTHETIC_SECRET", json.dumps(result))

    def test_file_and_traversal_budgets(self):
        path = self.root / "huge.json"
        with path.open("wb") as stream:
            stream.truncate(MAX_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "8 MiB"):
            discover(path, "openapi")
        schema = {"type": "string"}
        for _ in range(30):
            schema = {"properties": {"nested": schema}}
        with self.assertRaisesRegex(ValueError, "budget"):
            self.run_input(self.spec({"requestBody": {"content": {"application/json": {"schema": schema}}}}), "openapi")

    def test_secret_file_and_unsupported_formats_are_rejected(self):
        path = self.root / "jwt.key"
        path.write_text("SYNTHETIC_SECRET", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "secret"):
            discover(path, "openapi")
        with self.assertRaisesRegex(ValueError, "format"):
            discover(path, "unknown")


if __name__ == "__main__":
    unittest.main()
