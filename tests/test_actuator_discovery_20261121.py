"""Bounded Spring actuator mapping discovery added on 2026-11-21."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from awa_ddd.discovery import FORMATS, MAX_ROWS, PARSER_VERSIONS, discover


class ActuatorMappingDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="awa-actuator-discovery-")
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, value, name="mappings.json", *, raw=False):
        path = self.root / name
        if raw:
            path.write_text(value, encoding="utf-8")
        else:
            path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def assert_source(self, result, path, format):
        raw = path.read_bytes()
        self.assertEqual(
            {
                "path": str(path.resolve()),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "byte_count": len(raw),
                "format": format,
                "parser_version": PARSER_VERSIONS[format],
            },
            result["source"],
        )

    @staticmethod
    def entry(handler, methods, patterns, *, params=None, headers=None):
        conditions = {
            "methods": methods,
            "patterns": patterns,
            "params": params or [],
            "headers": headers or [],
            "consumes": ["application/private-request-type"],
            "produces": ["application/private-response-type"],
        }
        return {
            "handler": handler,
            "predicate": "GET [/handler-prose-must-not-be-imported]",
            "details": {"requestMappingConditions": conditions},
        }

    def test_servlet_and_webflux_cartesian_routes_merge_sources(self):
        first = self.entry(
            "com.example.PrivateController#handler",
            ["GET", "POST", "GET"],
            ["/api/users", "/api/users/{id}", "/api/users", "/api/./users"],
            params=["tenant=tenant-condition-secret", "!verbose"],
            headers=["X-Tenant=header-condition-secret", "!X-Debug"],
        )
        duplicate = self.entry(
            "com.example.PrivateController#handler",
            ["GET"],
            ["/api/users"],
            params=["tenant=different-condition-secret"],
            headers=["X-Tenant=different-header-secret"],
        )
        doc = {
            "contexts": {
                "application": {
                    "mappings": {
                        "dispatcherServlets": {"dispatcherServlet": [first]},
                        "dispatcherHandlers": {"webHandler": [duplicate]},
                    }
                }
            }
        }
        path = self.write(doc)
        result = discover(path, "actuator_mappings", "https://app.invalid/base")

        self.assertEqual(4, len(result["operations"]))
        operation = next(row for row in result["operations"]
                         if row["method"] == "GET" and row["url"].endswith("/api/users"))
        self.assertEqual(2, len(operation["sources"]))
        self.assertEqual("declared", operation["sources"][0]["trust"])
        self.assertFalse(operation["requestable"])
        self.assertNotIn("auth", operation)
        self.assertEqual("", operation["content_type"])

        names = {(row["location"], row["selector"]) for row in operation["inputs"]}
        self.assertIn(("query", "tenant"), names)
        self.assertIn(("query", "verbose"), names)
        self.assertIn(("header", "x-tenant"), names)
        self.assertIn(("header", "x-debug"), names)
        self.assertNotIn(("body", "tenant"), names)
        self.assertTrue(all(row["consumer"] == "unknown" for row in operation["inputs"]))

        template = next(row for row in result["operations"]
                        if row["method"] == "POST" and row["url"].endswith("/api/users/{id}"))
        self.assertTrue(template["path_template"])
        self.assertTrue(template["native_input_requires_binding"])
        self.assertFalse(template["requestable"])
        self.assertIn({"name": "id", "location": "path", "selector": "id",
                       "source": "declared", "consumer": "unknown", "required": True},
                      template["inputs"])

        self.assertEqual({
            "mapping_total": 2,
            "handler_total": 1,
            "route_total": 4,
            "path_template_total": 2,
            "method_counts": {
                "GET": 2, "HEAD": 0, "OPTIONS": 0, "POST": 2, "PUT": 0,
                "PATCH": 0, "DELETE": 0, "TRACE": 0,
            },
            "unresolved_mapping_total": 0,
            "completeness": "source_inventory",
            "site_wide_discovery_allowed": False,
        }, result["inventory"])
        self.assert_source(result, path, "actuator_mappings")
        rendered = json.dumps(result)
        for excluded in (
            "PrivateController", "handler-prose-must-not-be-imported", "tenant-condition-secret",
            "header-condition-secret", "different-condition-secret", "application/private-request-type",
            "application/private-response-type",
        ):
            self.assertNotIn(excluded, rendered)

    def test_openapi_uses_shared_strict_path_template_classification(self):
        schema = {
            "required": ["email"],
            "properties": {"email": {"type": "string"}},
        }
        unsupported = [
            "/codes/{code:[0-9]+}",
            "/pairs/{id}/{id}",
            "/files/prefix-{name}",
            "/encoded/%7Bitem%7D",
            "/assets/**",
            "/encoded/%2a",
        ]
        operation = {
            "parameters": [
                {"name": "id", "in": "path", "required": True},
            ],
            "security": [{"bearer": []}],
            "requestBody": {
                "content": {
                    "application/json": {"schema": schema},
                }
            },
        }
        doc = {
            "openapi": "3.0.3",
            "servers": [{"url": "https://app.invalid/api"}],
            "paths": {
                "/users/{id}": {"post": operation},
                **{path: {"post": operation} for path in unsupported},
            },
        }
        path = self.write(doc, "openapi.json")
        result = discover(path, "openapi")

        self.assertEqual(2, result["source"]["parser_version"])
        self.assertEqual(1, len(result["operations"]))
        operation_row = result["operations"][0]
        self.assertTrue(operation_row["url"].endswith("/api/users/{id}"))
        self.assertTrue(operation_row["path_template"])
        self.assertTrue(operation_row["native_input_requires_binding"])
        self.assertFalse(operation_row["requestable"])
        self.assertEqual("application/json", operation_row["content_type"])
        self.assertEqual("authenticated", operation_row["auth"])
        self.assertEqual(
            [{"name": "id", "location": "path", "selector": "id",
              "source": "declared", "consumer": "unknown", "required": True}],
            [row for row in operation_row["inputs"] if row["location"] == "path"],
        )
        body_input = next(row for row in operation_row["inputs"]
                          if row["location"] == "body")
        self.assertEqual(
            ("email", "/email", "declared", True),
            (body_input["name"], body_input["selector"],
             body_input["source"], body_input["required"]),
        )
        self.assertIn("path_template_requires_resource_binding",
                      {row["code"] for row in result["limitations"]})

        self.assertEqual(6, len(result["candidates"]))
        self.assertEqual(
            {
                "regex_pattern",
                "duplicate_variable",
                "partial_segment",
                "encoded_placeholder",
                "wildcard_pattern",
                "encoded_wildcard",
            },
            {row["reason_code"] for row in result["candidates"]},
        )
        for candidate in result["candidates"]:
            self.assertFalse(candidate["path_template"])
            self.assertTrue(candidate["native_input_requires_binding"])
            self.assertFalse(candidate["requestable"])
            self.assertEqual("application/json", candidate["content_type"])
            self.assertEqual("authenticated", candidate["auth"])
            self.assertEqual(["email"], [
                row["name"] for row in candidate["inputs"]
                if row["location"] == "body"
            ])
            self.assertEqual(
                {"id"},
                {row["name"] for row in candidate["inputs"]
                 if row["location"] == "path"},
            )
        self.assertEqual(
            set(unsupported),
            {candidate["url"].removeprefix("https://app.invalid/api")
             for candidate in result["candidates"]},
        )
        self.assert_source(result, path, "openapi")

    def test_actuator_object_conditions_keep_only_valid_names(self):
        entry = self.entry(
            "object-condition-handler",
            ["GET"],
            ["/object-conditions"],
            params=[
                "tenant=string-query-secret",
                "tenant=different-string-query-secret",
                {"name": "region", "value": "OBJECT_QUERY_SECRET", "negated": True},
            ],
            headers=[
                "!X-Debug",
                {"name": "X-Tenant", "value": "OBJECT_HEADER_SECRET", "negated": False},
                {"name": "X-Tenant", "value": "OTHER_OBJECT_HEADER_SECRET"},
            ],
        )
        doc = {
            "contexts": {
                "application": {
                    "mappings": {"dispatcherServlets": {"dispatcherServlet": [entry]}}
                }
            }
        }
        path = self.write(doc, "actuator-object-conditions.json")
        result = discover(path, "actuator_mappings", "https://app.invalid")

        self.assertEqual(1, len(result["operations"]))
        operation = result["operations"][0]
        self.assertEqual(
            {
                ("query", "tenant", "tenant"),
                ("query", "region", "region"),
                ("header", "X-Debug", "x-debug"),
                ("header", "X-Tenant", "x-tenant"),
            },
            {(row["location"], row["name"], row["selector"])
             for row in operation["inputs"]},
        )
        self.assertFalse(any(row["location"] == "body" for row in operation["inputs"]))
        self.assertNotIn("auth", operation)
        rendered = json.dumps(result)
        for excluded in (
            "string-query-secret",
            "different-string-query-secret",
            "OBJECT_QUERY_SECRET",
            "OBJECT_HEADER_SECRET",
            "OTHER_OBJECT_HEADER_SECRET",
        ):
            self.assertNotIn(excluded, rendered)
        self.assert_source(result, path, "actuator_mappings")

    def test_template_and_unsupported_shapes_remain_typed_candidates(self):
        entries = [
            self.entry("handler-valid", ["GET"], ["/users/{userId}"]),
            self.entry("handler-wildcard", ["GET"], ["/assets/**"]),
            self.entry("handler-regex", ["GET"], ["/codes/{code:[0-9]+}"]),
            self.entry("handler-repeated", ["GET"], ["/pairs/{id}/{id}"]),
            self.entry("handler-partial", ["GET"], ["/files/prefix-{name}"]),
            self.entry("handler-encoded", ["GET"], ["/encoded/%7Bitem%7D"]),
            self.entry("handler-unicode", ["GET"], ["/unicode/{使用者}"]),
            self.entry("handler-unknown-method", ["M-SEARCH"], ["/search-method"]),
            self.entry("handler-special-method", ["TRACE"], ["/trace"]),
            self.entry("handler-empty-methods", [], ["/empty"]),
            self.entry("handler-missing-pattern", ["GET"], []),
        ]
        entries.append({
            "handler": "handler-predicate-only",
            "predicate": "GET [/predicate-prose-only]",
        })
        doc = {
            "contexts": {
                "application": {
                    "mappings": {"dispatcherServlets": {"dispatcherServlet": entries}}
                }
            }
        }
        path = self.write(doc)
        result = discover(path, "actuator_mappings", "https://app.invalid")

        self.assertEqual(1, len(result["operations"]))
        self.assertEqual("GET", result["operations"][0]["method"])
        self.assertTrue(result["operations"][0]["url"].endswith("/users/{userId}"))
        self.assertEqual(11, len(result["candidates"]))
        self.assertTrue(all(row["requestable"] is False for row in result["candidates"]))
        self.assertEqual(
            {
                "actuator_mapping_wildcard_pattern",
                "actuator_mapping_regex_pattern",
                "actuator_mapping_duplicate_variable",
                "actuator_mapping_partial_segment",
                "actuator_mapping_encoded_placeholder",
                "actuator_mapping_method_requires_binding",
                "actuator_mapping_missing_method",
                "actuator_mapping_missing_pattern",
                "actuator_mapping_missing_structured",
            },
            {row["reason_code"] for row in result["candidates"]},
        )
        self.assertFalse(any(
            row.get("method") == "GET" and row.get("url", "").endswith("/empty")
            for row in result["candidates"]
        ))
        self.assertTrue(any(
            row.get("method") == "M-SEARCH" and row.get("url", "").endswith("/search-method")
            for row in result["candidates"]
        ))
        self.assertNotIn("predicate-prose-only", json.dumps(result))
        inventory = result["inventory"]
        self.assertEqual(12, inventory["mapping_total"])
        self.assertEqual(11, inventory["unresolved_mapping_total"])
        self.assertEqual(9, inventory["route_total"])
        self.assertEqual(1, inventory["path_template_total"])
        self.assertEqual(7, inventory["method_counts"]["GET"])
        self.assertEqual(1, inventory["method_counts"]["TRACE"])
        self.assert_source(result, path, "actuator_mappings")

    def test_malformed_containers_are_counted_as_unresolved(self):
        doc = {
            "contexts": {
                "bad-context": [],
                "bad-mappings": {"mappings": []},
                "bad-dispatcher": {
                    "mappings": {"dispatcherServlets": "not-a-handler-container"}
                },
                "bad-group": {
                    "mappings": {
                        "dispatcherServlets": {"dispatcherServlet": {"not": "a-list"}}
                    }
                },
            }
        }
        path = self.write(doc)
        result = discover(path, "actuator_mappings", "https://app.invalid")

        self.assertEqual([], result["operations"])
        self.assertEqual([], result["candidates"])
        inventory = result["inventory"]
        self.assertEqual(0, inventory["mapping_total"])
        self.assertEqual(0, inventory["route_total"])
        self.assertEqual(4, inventory["unresolved_mapping_total"])
        self.assertEqual("source_inventory", inventory["completeness"])
        self.assertFalse(inventory["site_wide_discovery_allowed"])
        self.assertTrue({
            "actuator_mapping_context_unresolved",
            "actuator_mapping_mappings_unresolved",
            "actuator_mapping_dispatcher_unresolved",
            "actuator_mapping_handler_group_unresolved",
        }.issubset({row["code"] for row in result["limitations"]}))
        self.assert_source(result, path, "actuator_mappings")

    def test_encoded_wildcards_remain_candidates(self):
        entries = [
            self.entry("encoded-star", ["GET"], ["/encoded/%2a"]),
            self.entry("encoded-question", ["GET"], ["/encoded/%3f"]),
            self.entry("repeated-encoding", ["GET"], ["/encoded/%252A"]),
        ]
        doc = {
            "contexts": {
                "application": {
                    "mappings": {"dispatcherServlets": {"dispatcherServlet": entries}}
                }
            }
        }
        path = self.write(doc)
        result = discover(path, "actuator_mappings", "https://app.invalid")

        self.assertEqual([], result["operations"])
        self.assertEqual(3, len(result["candidates"]))
        self.assertEqual({"actuator_mapping_encoded_wildcard"},
                         {row["reason_code"] for row in result["candidates"]})
        self.assertTrue(all(row["requestable"] is False for row in result["candidates"]))
        self.assertEqual(3, result["inventory"]["route_total"])
        self.assertEqual(3, result["inventory"]["unresolved_mapping_total"])
        self.assert_source(result, path, "actuator_mappings")

    def test_exact_method_contract_and_invalid_method_lists_are_visible(self):
        entries = [
            self.entry("mixed-contract", ["GET", "get", "GET", "M-SEARCH", "TRACE"], ["/mixed"]),
            self.entry("mixed-invalid-list", ["GET", 7, {"method": "POST"}, "", "get"],
                       ["/invalid-list"]),
            self.entry("missing-patterns", ["POST", "PUT"], []),
            self.entry("non-list-methods", "GET", ["/method-container-invalid"]),
        ]
        doc = {
            "contexts": {
                "application": {
                    "mappings": {"dispatcherServlets": {"dispatcherServlet": entries}}
                }
            }
        }
        path = self.write(doc)
        result = discover(path, "actuator_mappings", "https://app.invalid")

        self.assertEqual(
            {("GET", "https://app.invalid/mixed"),
             ("GET", "https://app.invalid/invalid-list")},
            {(row["method"], row["url"]) for row in result["operations"]},
        )
        lowercase = [row for row in result["candidates"] if row.get("method") == "get"]
        self.assertEqual({"mixed", "invalid-list"},
                         {row["url"].rsplit("/", 1)[-1] for row in lowercase})
        invalid_methods = [row for row in result["candidates"]
                           if row["reason_code"] == "actuator_mapping_invalid_method"]
        self.assertEqual(1, len(invalid_methods))
        self.assertEqual(2, len(invalid_methods[0]["sources"]))
        self.assertEqual({"POST", "PUT"}, {
            row["method"] for row in result["candidates"]
            if row["reason_code"] == "actuator_mapping_missing_pattern"
        })
        self.assertFalse(any(row["method"] == "GET"
                             for row in result["candidates"]
                             if row.get("url", "").endswith("/method-container-invalid")))
        inventory = result["inventory"]
        self.assertEqual(4, inventory["mapping_total"])
        self.assertEqual(6, inventory["route_total"])
        self.assertEqual(4, inventory["unresolved_mapping_total"])
        self.assertEqual(2, inventory["method_counts"]["GET"])
        self.assertEqual(1, inventory["method_counts"]["TRACE"])
        self.assert_source(result, path, "actuator_mappings")

    def test_every_format_has_a_source_record_even_when_empty(self):
        fixtures = {
            "openapi": {"openapi": "3.0.3", "servers": [{"url": "https://app.invalid"}], "paths": {}},
            "javascript": "// no requests\n",
            "har": {"log": {"entries": []}},
            "artex": {"rec": []},
            "sarif": {"version": "2.1.0", "runs": []},
            "assessment_hints": {
                "schema_version": 1,
                "source_kind": "assessment_checklist",
                "entries": [],
            },
            "actuator_mappings": {
                "contexts": {
                    "application": {
                        "mappings": {"dispatcherServlets": {"dispatcherServlet": []}}
                    }
                }
            },
        }
        self.assertEqual(FORMATS, set(fixtures))
        for format, value in fixtures.items():
            with self.subTest(format=format):
                suffix = ".js" if format == "javascript" else ".json"
                path = self.write(value, format + suffix, raw=format == "javascript")
                result = discover(path, format, "https://app.invalid")
                self.assert_source(result, path, format)
                self.assertEqual([], result["operations"])
                if format == "actuator_mappings":
                    self.assertEqual({
                        "mapping_total": 0,
                        "handler_total": 0,
                        "route_total": 0,
                        "path_template_total": 0,
                        "method_counts": {
                            "GET": 0, "HEAD": 0, "OPTIONS": 0, "POST": 0, "PUT": 0,
                            "PATCH": 0, "DELETE": 0, "TRACE": 0,
                        },
                        "unresolved_mapping_total": 0,
                        "completeness": "source_inventory",
                        "site_wide_discovery_allowed": False,
                    }, result["inventory"])

    def test_base_url_row_budget_and_strict_json(self):
        doc = {
            "contexts": {
                "application": {
                    "mappings": {"dispatcherServlets": {"dispatcherServlet": [
                        self.entry("handler", ["GET"], ["/route/" + str(index)
                                                    for index in range(MAX_ROWS + 1)])
                    ]}}
                }
            }
        }
        path = self.write(doc)
        with self.assertRaisesRegex(ValueError, "row budget"):
            discover(path, "actuator_mappings", "https://app.invalid")
        with self.assertRaisesRegex(ValueError, "base_url"):
            discover(path, "actuator_mappings")

        duplicate = self.write('{"contexts":{},"contexts":{}}', "duplicate.json", raw=True)
        with self.assertRaisesRegex(ValueError, "unambiguous"):
            discover(duplicate, "actuator_mappings", "https://app.invalid")


if __name__ == "__main__":
    unittest.main()
