"""A query-free inventory locator never substitutes for an exact scoped request."""
from __future__ import annotations

import base64
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import browser, engine, workflow
from awa_ddd.__main__ import dispatch
from awa_ddd.assessment import evaluate
from awa_ddd.store import EngineError, Project, now


class QueryScopeReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="awa-query-readiness-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.base = "http://fixture.invalid"
        self.url = self.base + "/items?tenant=fixture-one"
        engine.create_project(self.root, {"project_id": "query-scope", "target": self.url})
        self.project = Project(self.root, "query-scope")
        self.addCleanup(self.project.close)
        guard = patch.object(engine, "request")
        self.network = guard.start()
        self.addCleanup(guard.stop)
        self.operation = self.register(self.url)

    def tearDown(self):
        self.network.assert_not_called()

    def call(self, action, **args):
        return dispatch(self.root, action, {"project_id": "query-scope", **args})

    def register(self, url, **extra):
        return self.call("surface.register", url=url, method=extra.pop("method", "GET"), auth=extra.pop("auth", "public"),
                         inputs=extra.pop("inputs", [{"name": "tenant", "location": "query", "consumer": "fixture_predicate",
                                                      "test_families": ["generic"]}]), **extra)

    def rows(self, operation=None):
        operation = operation or self.operation
        result = self.call("plan.next", include_blocked=True, limit=25)
        self.assertEqual(0, result["requests_sent"])
        return [row for row in result["work_items"] if row["operation_id"] == operation["id"]], result

    def assert_prep(self, row):
        self.assertEqual("review", row["queue_status"])
        self.assertEqual(["exact_scoped_url_query_binding"], row["missing_prerequisites"])
        self.assertTrue(row["scope_binding_review_required"])
        self.assertTrue(row["execution_blocked"])
        self.assertTrue(row["native_input_requires_binding"])
        self.assertFalse(row["requestable"])
        self.assertEqual("surface.inspect", row["suggested_action"])
        self.assertEqual({"operation_id": row["operation_id"]}, row["input_template"])
        self.assertEqual("http.preflight", row["scope_binding_followup_action"])
        self.assertEqual(["url"], row["scope_binding_required_input_fields"])
        self.assertNotIn("url", row["scope_binding_followup_template"])
        self.assertEqual([], row.get("recommended_tools", []))
        self.assertFalse(row["browser_testing"]["invoke_now"])

    def test_exact_query_scope_has_offline_binding_work_despite_a_query_free_inventory_url(self):
        config = deepcopy(self.project.config)
        original = deepcopy(self.project.list("obligation"))
        self.assertEqual(self.base + "/items", self.operation["url"])
        rows, result = self.rows()
        self.assertEqual(2, len(rows))
        for row in rows:
            self.assert_prep(row)
        self.assertEqual((0, 2, 0), tuple(result["continuation"][key] for key in ("ready_total", "review_total", "blocked_total")))
        self.assertTrue(result["continuation"]["continue_required"])
        self.assertFalse(result["continuation"]["automatic_stop_allowed"])
        self.assertEqual(config, self.project.config)
        self.assertEqual(original, self.project.list("obligation"))
        self.assertEqual([], self.project.list("run"))

    def test_explicit_current_binding_preflights_but_missing_or_changed_query_does_not(self):
        result = self.call("http.preflight", operation_id=self.operation["id"], url=self.url)
        self.assertTrue(result["ready"])
        self.assertEqual(0, result["requests_sent"])
        for url in (None, self.base + "/items?tenant=fixture-two", self.url + "&q=normal"):
            with self.subTest(url=url), self.assertRaises(EngineError) as caught:
                self.call("http.preflight", operation_id=self.operation["id"], **({"url": url} if url else {}))
            self.assertEqual("out_of_scope", caught.exception.code)
        rows, _ = self.rows()
        self.assertTrue(all(row["queue_status"] != "ready" for row in rows))

    def test_scope_query_values_are_not_published_or_copied_into_any_template(self):
        rows, _ = self.rows()
        self.assertNotIn("fixture-one", json.dumps(rows))
        self.assertNotIn(self.url, json.dumps(rows))
        for row in rows:
            self.assertNotIn("url", row["input_template"])
            self.assertNotIn("url", row["scope_binding_followup_template"])
        self.assertEqual([self.url], self.project.config["scope"])

    def test_caller_blocked_binding_preparation_is_reconciled_offline_without_scope_changes(self):
        config = deepcopy(self.project.config)
        for item in self.project.list("obligation"):
            self.call("plan.disposition", obligation_id=item["id"], status="blocked", reason="Caller-only declaration; no prerequisite changed.")
        rows, _ = self.rows()
        for row in rows:
            self.assertEqual("review", row["queue_status"])
            self.assertEqual("review", row["underlying_queue_status"])
            self.assertTrue(row["blocker_reconciliation_required"])
            self.assertEqual("plan.disposition", row["suggested_action"])
            self.assertEqual("open", row["input_template"]["status"])
            self.assertFalse(row["browser_testing"]["invoke_now"])
            self.call(row["suggested_action"], **row["input_template"])
        reopened, _ = self.rows()
        for row in reopened:
            self.assert_prep(row)
        self.assertEqual(config, self.project.config)
        self.assertEqual([], self.project.list("run"))

    def test_a_real_path_exclusion_remains_blocked(self):
        child_url = self.base + "/items/child?tenant=fixture-one"
        operation = self.register(child_url)
        self.call("project.update", exclude=[self.base + "/items/child"])
        rows, _ = self.rows(operation)
        self.assertTrue(all(row["queue_status"] == "blocked" and "authorized_operation_scope" in row["missing_prerequisites"]
                            and not row.get("scope_binding_review_required") for row in rows))
        with self.assertRaises(EngineError) as caught:
            self.call("http.preflight", operation_id=operation["id"], url=child_url)
        self.assertEqual("out_of_scope", caught.exception.code)

    def test_an_exclusion_covering_every_exact_scope_binding_is_a_real_blocker(self):
        child_url = self.base + "/items/child?tenant=fixture-one"
        operation = self.register(child_url)
        self.call("project.update", exclude=[child_url])
        rows, _ = self.rows(operation)
        self.assertTrue(all(row["queue_status"] == "blocked" and "authorized_operation_scope" in row["missing_prerequisites"] for row in rows))
        self.assertFalse(workflow._query_scope_binding_possible(self.project.config, operation["url"]))

    def test_a_different_query_exclusion_does_not_hide_an_authorized_binding(self):
        child_url = self.base + "/items/child?tenant=fixture-one"
        operation = self.register(child_url)
        self.call("project.update", exclude=[self.base + "/items/child?tenant=fixture-two"])
        rows, _ = self.rows(operation)
        for row in rows:
            self.assert_prep(row)
        self.assertTrue(self.call("http.preflight", operation_id=operation["id"], url=child_url)["ready"])

    def test_other_origin_path_and_query_free_scope_do_not_invent_binding_preparation(self):
        for url in ("http://other-fixture.invalid/items", self.base + "/unrelated", "https://fixture.invalid/items"):
            with self.subTest(url=url):
                self.assertFalse(workflow._query_scope_binding_possible(self.project.config, url))
        self.assertFalse(workflow._query_scope_binding_possible({"scope": [self.base], "exclude": []}, self.operation["url"]))

    def test_identity_write_fixture_and_concrete_path_gates_are_not_reopened(self):
        self.call("identity.actor", actor_id="alice", subject="alice")
        protected = self.register(self.url, auth="authenticated")
        rows, _ = self.rows(protected)
        item = next(row for row in rows if row["obligation_kind"] == "input_test")
        self.assertEqual("blocked", item["queue_status"])
        self.assertIn("live_verified_allowed_session", item["missing_prerequisites"])
        self.assertNotIn("scope_binding_review_required", item)
        write = self.register(self.url, method="POST")
        rows, _ = self.rows(write)
        self.assertTrue(all(row["queue_status"] == "blocked" and "project_allow_mutation" in row["missing_prerequisites"]
                            and "matching_test_resource_or_declared_actor_state" in row["missing_prerequisites"] for row in rows))
        templated = self.register(self.base + "/items/{id}?tenant=fixture-one")
        rows, _ = self.rows(templated)
        self.assertTrue(all(row["queue_status"] == "blocked" and "concrete_url_with_bound_path_values" in row["missing_prerequisites"] for row in rows))

    def xss_operation(self):
        return self.register(self.url, inputs=[{"name": "tenant", "location": "query", "consumer": "html_render", "test_families": ["xss"]}])

    def test_required_browser_scope_binding_only_prepares_and_never_invokes(self):
        operation = self.xss_operation()
        rows, _ = self.rows(operation)
        item = next(row for row in rows if row["obligation_kind"] == "input_test")
        self.assert_prep(item)
        policy = item["browser_testing"]
        self.assertEqual("required", policy["requirement"])
        self.assertTrue(policy["must_call_playwright"])
        self.assertEqual("prepare", policy["stage"])
        self.assertFalse(policy["invoke_now"])
        self.assertNotIn("native_visit_input", policy)

    def test_real_blocked_browser_page_still_prevents_runtime_work(self):
        operation = self.xss_operation()
        page = self.call("page.register", url=self.url)
        self.call("page.function", page_id=page["id"], name="Fixture interaction", apis=[{"operation_id": operation["id"]}])
        self.call("page.mark", page_id=page["id"], target="page", status="BLOCKED", reason="Actual unavailable fixture page.")
        rows, _ = self.rows(operation)
        item = next(row for row in rows if row["obligation_kind"] == "input_test")
        self.assertEqual("blocked", item["queue_status"])
        self.assertIn("explicit_consumer_page_unblock_or_authorized_alternative", item["missing_prerequisites"])
        self.assertFalse(item["browser_testing"]["invoke_now"])
        self.assertNotIn("blocker_reconciliation_required", item)

    def test_current_qualified_evidence_remains_offline_evaluation_not_binding_replay(self):
        def response(url, method, headers, body, timeout, max_bytes):
            data = json.dumps({"count": 1}).encode("utf-8")
            return {"request": {"url": url, "method": method, "headers": headers, "body_base64": ""},
                    "response": {"status": 200, "headers": [["content-type", "application/json"]], "length": len(data),
                                 "body_base64": base64.b64encode(data).decode("ascii")},
                    "started_at": now(), "completed_at": now(), "complete": True}

        with patch.object(engine, "request", side_effect=response):
            evidence = engine.capture(self.project, {"operation_id": self.operation["id"], "url": self.url})
        rows, _ = self.rows()
        baseline = next(row for row in rows if row["obligation_kind"] == "baseline")
        self.assertEqual("ready", baseline["queue_status"])
        self.assertEqual("assessment.evaluate", baseline["suggested_action"])
        self.assertEqual([evidence["id"]], baseline["input_template"]["evidence_ids"])
        self.assertTrue(baseline["execution_blocked"])
        item = next(row for row in rows if row["obligation_kind"] == "input_test")
        self.assertEqual("review", item["queue_status"])
        self.assertEqual("evidence.inspect", item["suggested_action"])
        evaluate(self.project, {"obligation_id": baseline["obligation_id"], "evidence_ids": [evidence["id"]],
                               "oracle": {"type": "baseline", "selector": "/count", "expected": 1}})
        self.assertEqual([self.url], self.project.config["scope"])


if __name__ == "__main__":
    unittest.main()
