"""Regressions for the 2026-10-27 heasec-mall field session.

Each test pins one defect that actually cost work in that engagement:

* a short session TTL invalidated already-captured evidence;
* there was no renewal verb, so the only recovery was a new identity;
* resource binding compared JSON arrays as Python repr and could not read a
  multipart filename;
* a path probed only with GET never advertised its DELETE/PUT siblings;
* SPA navigation through a login action could not mark the destination page;
* destructive SQL injection had no proof channel because it returns no metadata.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json
import unittest
from urllib.parse import quote
from unittest.mock import patch

from awa_ddd import browser, engine
from awa_ddd.assessment import (
    _error_channel,
    _metadata_expression,
    _sql_behaviour_proof,
    _extract_value,
    evaluate,
    record_finding,
)
from awa_ddd.store import EngineError, Project


class ProjectFixture(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-upgrade-")
        self.addCleanup(self.tmp.cleanup)
        self.base = "http://shop.test"
        engine.create_project(self.tmp.name, {
            "project_id": "upgrade", "target": self.base + "/", "scope": [self.base + "/"]})
        self.project = Project(self.tmp.name, "upgrade")
        self.addCleanup(self.project.close)

    def operation(self, path="/api/items", method="GET", **extra):
        hint = {"url": self.base + path, "method": method, "protocol": "http",
                "operation_name": method + " " + path, "content_type": extra.pop("content_type", ""),
                "auth": extra.pop("auth", "public"), "allowed_roles": extra.pop("allowed_roles", ["anonymous"]),
                "ownership": extra.pop("ownership", False), "inputs": extra.pop("inputs", []),
                "sources": ["test"]}
        hint.update(extra)
        return engine.register_operation(self.project, hint)


class SessionLifecycleTests(ProjectFixture):
    def test_renew_keeps_identity_and_evidence_generation(self):
        engine.add_actor(self.project, {"actor_id": "alice", "label": "Alice", "roles": []})
        created = engine.add_session(self.project, {"actor_id": "alice", "headers": {"Cookie": "SID=abc"},
                                                   "ttl_seconds": 60})
        renewed = engine.add_session(self.project, {"actor_id": "alice", "session_id": created["id"],
                                                   "ttl_seconds": 3600, "renew": True})
        self.assertEqual(renewed["id"], created["id"])
        self.assertEqual(renewed["generation"], created["generation"])
        self.assertGreater(renewed["expires_at"], created["expires_at"])

    def test_renew_cannot_swap_credentials(self):
        engine.add_actor(self.project, {"actor_id": "alice", "label": "Alice", "roles": []})
        session = engine.add_session(self.project, {"actor_id": "alice", "headers": {"Cookie": "SID=abc"}})
        with self.assertRaises(EngineError) as raised:
            engine.add_session(self.project, {"actor_id": "alice", "session_id": session["id"],
                                              "headers": {"Cookie": "SID=other"}, "renew": True})
        self.assertEqual(raised.exception.code, "renew_shape")

    def test_expired_session_does_not_invalidate_capture_or_finding(self):
        engine.add_actor(self.project, {"actor_id": "alice", "label": "Alice", "subject": "alice", "roles": []})
        identity_op = self.operation("/whoami", auth="authenticated")
        data_op = self.operation("/data", auth="authenticated")
        session = engine.add_session(self.project, {"actor_id": "alice", "headers": {"X-Actor": "alice"},
                                                   "credential_header_names": ["X-Actor"]})
        response = {"request": {"url": identity_op["url"], "method": "GET", "headers": {"x-actor": "alice"}, "body_base64": ""},
                    "response": {"status": 200, "headers": [], "length": 14,
                                 "body_base64": base64.b64encode(b'{"id":"alice"}').decode()},
                    "complete": True, "started_at": datetime.now(timezone.utc).isoformat(),
                    "completed_at": datetime.now(timezone.utc).isoformat()}
        with patch.object(engine, "request", return_value=response):
            engine.verify_identity(self.project, {"operation_id": identity_op["id"], "session_id": session["id"],
                                                  "subject_selector": "/id"})
        evidence = self._capture_with_session(data_op, session)
        stored = self.project.get("session", session["id"])
        stored["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
        self.project.put("session", stored)
        current, _ = engine.verify_current_evidence(self.project, evidence["id"])
        self.assertEqual(current["id"], evidence["id"])
        with self.assertRaises(EngineError) as raised:
            engine.session_valid(self.project, stored)
        self.assertEqual(raised.exception.code, "session_expired")
        finding = record_finding(self.project, {
            "mode": "analyst", "reviewer": "test", "reason": "captured response differs",
            "title": "Expired-session evidence", "category": "Information Disclosure",
            "impact": "test", "remediation": "test", "evidence_ids": [evidence["id"]]})
        self.assertTrue(finding["id"].startswith("F-"))

    def _capture_with_session(self, operation, session):
        # A minimal in-process artifact is enough here; the capture path itself is
        # exercised by test_engine.py against a loopback server.
        body = b'{"ok":true,"value":"synthetic"}'
        artifact = {"request": {"url": operation["url"], "method": operation["method"], "headers": {"x-actor": "alice"},
                                "body_base64": base64.b64encode(b"").decode()},
                    "response": {"status": 200, "headers": {}, "body_base64": base64.b64encode(body).decode()},
                    "complete": True, "started_at": datetime.now(timezone.utc).isoformat(),
                    "completed_at": datetime.now(timezone.utc).isoformat()}
        evidence_id = self.project.id("E")
        path, digest = self.project.artifact(evidence_id, artifact)
        from awa_ddd.lineage import policy_digest, policy_snapshot
        evidence = {"id": evidence_id, "kind": "http", "operation_id": operation["id"],
                    "operation_signature": engine.operation_signature(operation),
                    "policy_digest": policy_digest(operation), "policy_snapshot": policy_snapshot(operation),
                    "session_id": session["id"], "session_generation": session["generation"],
                    "actor_id": session["actor_id"], "resource_id": None, "artifact_path": path,
                    "credential_header_names": session["credential_header_names"],
                    "credential_signature": session["credential_signature"],
                    "sha256": digest, "complete": True, "created_at": datetime.now(timezone.utc).isoformat(),
                    "trust": "observed", "run_id": "RUN-" + evidence_id, "status_code": 200,
                    "response_bytes": len(body), "auth_mode": "session"}
        self.project.put("evidence", evidence, create_only=True)
        return evidence


class ResourceBindingTests(ProjectFixture):
    def _resource(self, operation, external_id, selector, resource_id):
        return engine.add_resource(self.project, {
            "resource_id": resource_id, "operation_id": operation["id"], "owner_actor_id": "anon",
            "external_id": external_id, "request_binding": {"location": "body", "selector": selector}})

    def test_json_array_value_matches_structurally(self):
        engine.add_actor(self.project, {"actor_id": "anon", "label": "anon", "roles": ["anonymous"]})
        operation = self.operation("/api/lottery", method="POST", content_type="application/json")
        resource = self._resource(operation, "[100,0,0,0,0]", "/probabilities", "lottery")
        engine._resource_binding(resource, {}, self.base + "/api/lottery",
                                 '{"probabilities":[100,0,0,0,0]}', content_type="application/json")

    def test_multipart_filename_binding(self):
        engine.add_actor(self.project, {"actor_id": "anon", "label": "anon", "roles": ["anonymous"]})
        operation = self.operation("/api/upload", method="POST", content_type="multipart/form-data")
        resource = self._resource(operation, "awa_plain.txt", "file", "upload")
        body = (b"------awaUp1\r\nContent-Disposition: form-data; name=\"file\"; filename=\"awa_plain.txt\"\r\n"
                b"Content-Type: image/png\r\n\r\nMARKER\r\n------awaUp1--\r\n")
        engine._resource_binding(resource, {}, self.base + "/api/upload", body,
                                 content_type="multipart/form-data; boundary=----awaUp1")

    def test_mismatch_names_expected_and_actual(self):
        engine.add_actor(self.project, {"actor_id": "anon", "label": "anon", "roles": ["anonymous"]})
        operation = self.operation("/api/register", method="POST", content_type="application/json")
        resource = self._resource(operation, "xssshop6", "/username", "merchant")
        with self.assertRaises(EngineError) as raised:
            engine._resource_binding(resource, {}, self.base + "/api/register",
                                     '{"username":"xssshop7"}', content_type="application/json")
        self.assertIn("xssshop6", str(raised.exception))
        self.assertIn("xssshop7", str(raised.exception))


class CoverageTests(ProjectFixture):
    def test_sibling_verbs_are_reported_as_untested(self):
        self.operation("/api/merchant/products/{productNo}", method="GET")
        self.operation("/api/merchant/products/{productNo}", method="DELETE")
        coverage = engine.evaluate_coverage(self.project)
        row = next(item for item in coverage["method_coverage"] if "products" in "/".join(item["path_shape"]))
        self.assertEqual(row["registered_methods"], ["DELETE", "GET"])
        self.assertEqual(row["tested"], [])
        self.assertEqual(row["untested_registered_methods"], ["DELETE", "GET"])
        self.assertIn("PUT", row["untested_siblings"])
        self.assertIn("surface_coverage", coverage)
        self.assertIn("coverage_by_kind", coverage)

    def test_ownership_plan_uses_one_resource_fixture_per_operation(self):
        engine.add_actor(self.project, {"actor_id": "owner", "label": "owner", "roles": ["user"]})
        engine.add_actor(self.project, {"actor_id": "other1", "label": "other1", "roles": ["user"]})
        engine.add_actor(self.project, {"actor_id": "other2", "label": "other2", "roles": ["user"]})
        operation = self.operation("/api/orders/{id}", method="GET", auth="authenticated",
                                   ownership=True, inputs=[])
        for index in range(4):
            engine.add_resource(self.project, {"operation_id": operation["id"], "owner_actor_id": "owner",
                                               "external_id": "order-%s" % index,
                                               "request_binding": {"location": "path", "selector": "id"}})
        engine.build_plan(self.project)
        obligations = [item for item in self.project.list("obligation")
                       if item.get("kind") == "ownership" and item.get("operation_id") == operation["id"]]
        self.assertEqual(len(obligations), 1, "same-role actors and multiple fixtures must not multiply obligations")


class SpaNavigationTests(ProjectFixture):
    def test_destination_reached_by_action_is_a_valid_target(self):
        raw = {"url": "http://shop.test/admin/login", "finalUrl": "http://shop.test/admin/merchants",
               "actions": [{"index": 0, "action": "click", "ok": True,
                            "finalUrl": "http://shop.test/admin/merchants"}]}
        found, index = browser._visit_target(raw, "http://shop.test/admin/merchants")
        self.assertTrue(found)
        self.assertEqual(index, 0)
        found, _ = browser._visit_target(raw, "http://shop.test/admin/users")
        self.assertFalse(found)

    def test_trail_preserves_direct_and_action_urls(self):
        raw = {"url": "http://shop.test/a", "finalUrl": "http://shop.test/c",
               "actions": [{"ok": True, "finalUrl": "http://shop.test/b"}]}
        urls = [entry["url"] for entry in browser._navigation_trail(raw)]
        self.assertEqual(urls, ["http://shop.test/a", "http://shop.test/b", "http://shop.test/c"])

    def test_page_mark_accepts_a_page_reached_by_a_successful_action(self):
        raw = {"url": self.base + "/admin/login", "finalUrl": self.base + "/admin/merchants",
               "status": 200, "signals": {"hasApp": True, "forms": 1, "inputs": 2},
               "actions": [{"index": 0, "action": "click", "ok": True,
                            "finalUrl": self.base + "/admin/merchants"}],
               "network": [{"url": self.base + "/admin/login", "method": "GET", "status": 200},
                           {"url": self.base + "/admin/merchants", "method": "GET", "status": 200}]}
        visit = browser._record_observation(self.project, raw, "PV-spa", "local_playwright")
        page = browser.register_page(self.project, {"url": self.base + "/admin/merchants"})
        marked = browser.mark(self.project, {"page_id": page["id"], "target": "page",
                                             "status": "visited", "page_visit_id": visit["id"]})
        self.assertTrue(marked["visited"])
        self.assertEqual(marked["arrival"], "navigation")


class SqlProofChannelTests(ProjectFixture):
    def test_order_by_payload_is_recognised_as_metadata_expression(self):
        payload = "id,(SELECT (CASE WHEN (1=1) THEN 1 ELSE (SELECT DATABASE()) END))"
        self.assertIsNotNone(_metadata_expression(payload, "database"))
        self.assertIsNone(_metadata_expression("price", "database"))

    def test_error_channel_requires_named_value_group(self):
        artifact = {"response": {"body_base64": base64.b64encode(b"XPATH syntax error: '~shop_java'").decode()}}
        observation = ({"id": "E1"}, artifact)
        with self.assertRaises(EngineError):
            _extract_value(observation, {"response_pattern": r"~(\w+)"})
        self.assertEqual(_extract_value(observation, {"response_pattern": r"~(?P<value>\w+)"}), "shop_java")

    def test_order_by_sqlmap_transcript_is_direct_confirmation(self):
        operation = self.operation(
            "/api/products", method="GET",
            inputs=[{"name": "sort", "location": "query", "selector": "sort", "consumer": "sql_order_by"}])
        engine.build_plan(self.project)
        obligation = next(item for item in self.project.list("obligation")
                          if item.get("kind") == "input_test" and item.get("operation_id") == operation["id"])
        baseline = self._evidence(operation, "http://shop.test/api/products?sort=price",
                                  b'{"items":[{"price":10}]}', 200)
        recovery = self._evidence(
            operation, "http://shop.test/api/products?sort=" + quote("price,(SELECT (CASE WHEN (1=1) THEN 1 ELSE (SELECT DATABASE()) END))", safe=""),
            b'{"items":[{"price":10}]}', 200)
        negative = self._evidence(
            operation, "http://shop.test/api/products?sort=" + quote("price,(SELECT (CASE WHEN (1=2) THEN 1 ELSE (SELECT 0) END))", safe=""),
            b'{"items":[{"price":10}]}', 200)
        run = self._external_sqlmap_run(operation, "sort")
        decision = evaluate(self.project, {
            "obligation_id": obligation["id"],
            "evidence_ids": [baseline["id"], recovery["id"], negative["id"]],
            "oracle": {"type": "sql_metadata", "metadata_type": "database", "expected_value": "shop_java",
                       "baseline_selector": "/items/0/price", "baseline_expected": 10,
                       "tool_run_id": run["id"]}})
        self.assertEqual(decision["outcome"], "confirmed")
        self.assertEqual(decision["proof"]["channel"], "sqlmap_metadata_transcript")
        finding = record_finding(self.project, {
            "mode": "machine", "decision_id": decision["id"], "title": "ORDER BY SQL injection",
            "category": "SQL Injection", "impact": "database name recovered", "remediation": "parameterize"})
        self.assertEqual(finding["confirmed_scope"], "database_metadata")

    def _external_sqlmap_run(self, operation, parameter):
        from awa_ddd.external import _start, _finish
        metadata = {"database": "shop_java", "current_user": "root@%"}
        run, _ = _start(self.project, "sqlmap", "metadata", operation, None,
                        target_url=operation["url"] + "?" + parameter + "=price",
                        input_location="query", input_selector=parameter)
        run.update(status="succeeded", exit_code=0, metadata_only=True,
                   traffic_requests=3, traffic_responses=3, target_traffic_sent=True,
                   operation_signature=engine.operation_signature(operation), metadata_candidates=metadata)
        return _finish(self.project, run, {"metadata_candidates": metadata})

    def test_error_channel_recovers_database_from_dbms_error_text(self):
        operation = self.operation(
            "/api/search", method="GET",
            inputs=[{"name": "q", "location": "query", "selector": "q", "consumer": "sql_like"}])
        engine.build_plan(self.project)
        obligation = next(item for item in self.project.list("obligation")
                          if item.get("kind") == "input_test" and item.get("operation_id") == operation["id"])
        baseline = self._evidence(operation, "http://shop.test/api/search?q=hello", b'{"data":"ok"}', 200)
        recovery = self._evidence(
            operation, "http://shop.test/api/search?q=hello%27%20AND%20extractvalue(1,concat(0x7e,database()))--%20-",
            b"XPATH syntax error: '~shop_java'", 500)
        negative = self._evidence(
            operation, "http://shop.test/api/search?q=hello%27%20AND%20extractvalue(1,concat(0x7e,0x6e6f7065))--%20-",
            b'{"data":"ok"}', 200)
        decision = evaluate(self.project, {
            "obligation_id": obligation["id"], "evidence_ids": [baseline["id"], recovery["id"], negative["id"]],
            "oracle": {"type": "error_channel", "metadata_type": "database",
                       "expected_value": "shop_java",
                       "response_pattern": r"XPATH syntax error: '~(?P<value>[^']+)'"}})
        self.assertEqual(decision["outcome"], "confirmed")
        self.assertEqual(decision["proof"]["recovered_value"], "shop_java")
        finding = record_finding(self.project, {
            "mode": "machine", "decision_id": decision["id"], "title": "Error-based SQL injection",
            "category": "SQL Injection", "impact": "database name leaked", "remediation": "parameterize"})
        self.assertEqual(finding["confirmed_scope"], "database_metadata")

    def test_destructive_sql_uses_paired_behavioural_evidence(self):
        operation = self.operation("/api/merchant/products/{productNo}", method="DELETE", auth="public",
                                   inputs=[{"name": "productNo", "location": "path", "selector": "productNo", "consumer": "sql_where"}])
        engine.add_actor(self.project, {"actor_id": "anon", "label": "anon", "roles": ["anonymous"]})
        resources = [engine.add_resource(self.project, {
            "operation_id": operation["id"], "owner_actor_id": "anon", "external_id": value,
            "request_binding": {"location": "path", "selector": "productNo"}})
            for value in ("ZZZQQQ", "ZZZ'||0x31||'")]
        control = self._evidence(operation, "http://shop.test/api/merchant/products/ZZZQQQ",
                                 b'{"success":false,"message":"not found","deleted_count":0}', resource=resources[0])
        injection = self._evidence(operation, "http://shop.test/api/merchant/products/ZZZ'||0x31||'",
                                   b'{"success":true,"message":"deleted","deleted_count":8}', resource=resources[1])
        proof = _sql_behaviour_proof(self.project, {
            "control_evidence_id": control["id"], "injection_evidence_id": injection["id"],
            "input_location": "path", "input_selector": "productNo", "response_selector": "/deleted_count",
            "observed_change": "control returned not found; injection deleted every product row"})
        self.assertEqual(proof["channel"], "behavioural_diff")
        finding = record_finding(self.project, {
            "mode": "analyst", "reviewer": "test", "reason": "paired behaviour difference",
            "title": "Destructive SQL injection", "category": "SQL Injection",
            "impact": "test", "remediation": "parameterize", "origin": "independent",
            "sql_evidence": {"control_evidence_id": control["id"],
                             "injection_evidence_id": injection["id"],
                             "input_location": "path", "input_selector": "productNo", "response_selector": "/deleted_count",
                             "observed_change": "control returned not found; injection deleted every product row"}})
        self.assertEqual(finding["confirmed_scope"], "sql_behaviour")
        coverage = engine.evaluate_coverage(self.project)
        row = next(item for item in coverage["findings"] if item["id"] == finding["id"])
        self.assertTrue(row["current"])

    def _evidence(self, operation, url, body, status=200, *, resource=None):
        artifact = {"request": {"url": url, "method": operation["method"], "headers": {},
                                "body_base64": base64.b64encode(b"").decode()},
                    "response": {"status": status, "headers": {}, "body_base64": base64.b64encode(body).decode()},
                    "complete": True, "started_at": datetime.now(timezone.utc).isoformat(),
                    "completed_at": datetime.now(timezone.utc).isoformat()}
        evidence_id = self.project.id("E")
        path, digest = self.project.artifact(evidence_id, artifact)
        from awa_ddd.lineage import policy_digest, policy_snapshot
        evidence = {"id": evidence_id, "kind": "http", "operation_id": operation["id"],
                    "operation_signature": engine.operation_signature(operation),
                    "policy_digest": policy_digest(operation), "policy_snapshot": policy_snapshot(operation),
                    "session_id": None, "session_generation": None, "actor_id": None, "resource_id": None,
                    "artifact_path": path, "sha256": digest, "complete": True,
                    "created_at": datetime.now(timezone.utc).isoformat(), "trust": "observed",
                    "run_id": "RUN-" + evidence_id, "status_code": status, "response_bytes": len(body)}
        if resource:
            evidence.update(resource_id=resource["id"], resource_signature=engine.resource_signature(resource))
        self.project.put("evidence", evidence, create_only=True)
        return evidence


if __name__ == "__main__":
    unittest.main()
