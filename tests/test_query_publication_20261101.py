"""Scope preparation survives project redaction without restoring business secrets."""
from __future__ import annotations

from copy import deepcopy
import json
import unittest

from awa_ddd.store import canonical
import test_query_scope_readiness_20261101 as query_fixtures


class QueryPublicationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = query_fixtures.QueryScopeReadinessTests(
            "test_exact_query_scope_has_offline_binding_work_despite_a_query_free_inventory_url")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()

    def tearDown(self):
        self.fixture.tearDown()

    def credential(self, secret):
        self.fixture.call("identity.actor", actor_id="integration-actor", subject="integration-subject")
        self.fixture.call("identity.session", actor_id="integration-actor", headers={"Cookie": "pin=" + secret})

    def legacy_context(self):
        material = {"url": self.fixture.url, "finalUrl": self.fixture.url, "status": 200,
                    "signals": {"forms": 1},
                    "network": [{"url": self.fixture.url, "method": "GET", "status": 200}],
                    "actions": [{"type": "fill", "selector": "#legacy", "ok": True,
                                 "finalUrl": self.fixture.url}]}
        source = self.fixture.root / "legacy-fill.json"
        source.write_text(json.dumps(material), encoding="utf-8")
        visit = self.fixture.call("browser.import_mcp", path=str(source))
        self.assertFalse(self.fixture.project.get("page_visit", visit["id"])["redaction_context_available"])

    def published_rows(self, operation):
        before = {kind: canonical(self.fixture.project.list(kind))
                  for kind in ("operation", "obligation", "session", "page", "page_visit", "run")}
        config = deepcopy(self.fixture.project.config)
        result = self.fixture.call("plan.next", include_blocked=True, limit=25)
        audit = self.fixture.call("plan.audit", limit=100)
        row = next(item for item in result["work_items"]
                   if item["operation_id"] == operation["id"] and item.get("hypothesis_family") == "xss")
        checklist = next(item for item in audit["checklist"] if item.get("obligation_id") == row["obligation_id"])
        self.assertEqual(config, self.fixture.project.config)
        for kind, snapshot in before.items():
            self.assertEqual(snapshot, canonical(self.fixture.project.list(kind)), kind)
        self.assertEqual([], self.fixture.project.list("run"))
        self.assertEqual(0, result["requests_sent"])
        self.assertEqual(0, audit["requests_sent"])
        self.assertIs(type(result["review_total"]), int)
        self.assertIs(type(audit["checklist_total"]), int)
        self.assertEqual(len(result["work_items"]), sum(result[key] for key in ("ready_total", "review_total", "blocked_total")))
        self.assertEqual(len(audit["checklist"]), audit["checklist_total"])
        self.assertTrue(result["continuation"]["continue_required"])
        self.assertFalse(result["continuation"]["automatic_stop_allowed"])
        self.assertNotIn("fixture-one", json.dumps([result, audit]))
        self.assertNotIn(self.fixture.url, json.dumps([result, audit]))
        return row, checklist, result, audit

    def assert_handoff(self, row, operation):
        self.assertEqual("review", row["queue_status"])
        self.assertEqual(["exact_scoped_url_query_binding"], row["missing_prerequisites"])
        for flag in ("scope_binding_review_required", "url_requires_binding", "native_input_requires_binding", "execution_blocked"):
            self.assertIs(row[flag], True, flag)
        self.assertIs(row["requestable"], False)
        self.assertEqual("http.preflight", row["scope_binding_followup_action"])
        self.assertEqual(["url"], row["scope_binding_required_input_fields"])
        self.assertEqual({"operation_id": operation["id"]}, row["scope_binding_followup_template"])
        self.assertIn("scope_handoff_note", row)

    def assert_secret_case(self, secret):
        self.credential(secret)
        business = int(secret) if secret.isdigit() else secret
        operation = self.fixture.register(self.fixture.url, inputs=[{
            "name": secret, "selector": secret, "location": "query", "consumer": "html_render",
            "schema_branch": business, "test_families": ["xss"]}])
        for unavailable in (False, True):
            with self.subTest(secret=secret, unavailable=unavailable):
                if unavailable:
                    self.legacy_context()
                row, checklist, result, audit = self.published_rows(operation)
                for item in (row, checklist):
                    self.assert_handoff(item, operation)
                    self.assertEqual("surface.inspect", item["suggested_action"])
                    self.assertEqual({"operation_id": operation["id"]}, item["input_template"])
                    self.assertEqual({"name": "surface.inspect"}, item["help_input"])
                    self.assertNotEqual(secret, item["input_selector"])
                self.assertEqual("surface.inspect", checklist["action"])
                self.assertNotEqual(business, row["schema_branch"])
                self.assertIsInstance(row["schema_branch"], str)
                policy = row["browser_testing"]
                self.assertEqual("required", policy["requirement"])
                self.assertEqual("prepare", policy["stage"])
                self.assertIs(policy["invoke_now"], False)
                self.assertIs(policy["native_input_requires_binding"], True)
                self.assertEqual(["exact_scoped_url_query_binding", "scoped_consumer_url"], policy["required_input_fields"])
                self.assertNotIn("native_visit_input", policy)
                inspected = self.fixture.call(checklist["action"], **checklist["input_template"])
                self.assertEqual(operation["id"], inspected["operation"]["id"])
                if unavailable:
                    self.assertEqual("unavailable", result["redaction_context_status"])
                    self.assertEqual("unavailable", audit["redaction_context_status"])
                    self.assertIn("project redaction context unavailable", row["scope_handoff_note"])

    def test_ready_credential_does_not_restore_a_business_selector_as_readiness(self):
        self.assert_secret_case("ready")

    def test_review_credential_does_not_rename_scope_control_fields(self):
        self.assert_secret_case("review")

    def test_prepare_credential_is_only_restored_in_the_actual_browser_stage(self):
        self.assert_secret_case("prepare")

    def test_short_numeric_credential_keeps_counts_but_redacts_a_numeric_business_branch(self):
        self.assert_secret_case("1")

    def test_leading_zero_credential_keeps_counts_but_redacts_its_numeric_alias(self):
        self.assert_secret_case("000002")

    def test_prerequisite_credential_is_only_restored_as_a_closed_engine_code(self):
        self.assert_secret_case("exact_scoped_url_query_binding")

    def test_action_credential_is_only_restored_as_the_closed_preflight_action(self):
        self.assert_secret_case("http.preflight")

    def test_field_name_credential_is_only_restored_in_the_closed_url_binding_list(self):
        self.assert_secret_case("url")

    def test_caller_blocker_still_overrides_scope_inspection_with_offline_reconciliation(self):
        secret = "review"
        self.credential(secret)
        operation = self.fixture.xss_operation()
        obligation = next(item for item in self.fixture.project.list("obligation")
                          if item.get("operation_id") == operation["id"] and item.get("test_family") == "xss")
        self.fixture.call("plan.disposition", obligation_id=obligation["id"], status="blocked", reason=secret)
        for unavailable in (False, True):
            with self.subTest(unavailable=unavailable):
                if unavailable:
                    self.legacy_context()
                row, checklist, _, _ = self.published_rows(operation)
                for item in (row, checklist):
                    self.assert_handoff(item, operation)
                    self.assertIs(item["blocker_reconciliation_required"], True)
                    self.assertEqual("plan.disposition", item["suggested_action"])
                    self.assertEqual("open", item["input_template"]["status"])
                    self.assertEqual(obligation["id"], item["input_template"]["obligation_id"])
                    self.assertNotIn("url", item["input_template"])
                    self.assertNotEqual(secret, item["operator_reason"])
                self.assertEqual("plan.disposition", checklist["action"])
                self.assertIs(row["browser_testing"]["invoke_now"], False)
                self.assertEqual(["offline_obligation_blocker_reconciliation"], row["browser_testing"]["required_input_fields"])
        self.assertEqual("blocked", self.fixture.project.get("obligation", obligation["id"])["status"])

    def test_real_required_browser_page_blocker_does_not_create_audit_preparation(self):
        self.credential("prepare")
        operation = self.fixture.xss_operation()
        page = self.fixture.call("page.register", url=self.fixture.url)
        self.fixture.call("page.function", page_id=page["id"], name="Fixture interaction", apis=[{"operation_id": operation["id"]}])
        self.fixture.call("page.mark", page_id=page["id"], target="page", status="BLOCKED", reason="Actual unavailable fixture.")
        for unavailable in (False, True):
            with self.subTest(unavailable=unavailable):
                if unavailable:
                    self.legacy_context()
                row, checklist, _, _ = self.published_rows(operation)
                for item in (row, checklist):
                    self.assertEqual("blocked", item["queue_status"])
                    self.assertIn("explicit_consumer_page_unblock_or_authorized_alternative", item["missing_prerequisites"])
                    self.assertNotIn("blocker_reconciliation_required", item)
                self.assertNotIn("scope_binding_review_required", checklist)
                self.assertNotIn("scope_binding_followup_template", checklist)
                self.assertNotIn("input_template", checklist)
                self.assertEqual("plan.next", checklist["action"])
                self.assertIs(row["browser_testing"]["invoke_now"], False)

    def test_real_identity_blocker_does_not_create_audit_preparation(self):
        self.credential("ready")
        operation = self.fixture.register(self.fixture.url, auth="authenticated", inputs=[{
            "name": "tenant", "location": "query", "consumer": "html_render", "test_families": ["xss"]}])
        self.legacy_context()
        row, checklist, _, _ = self.published_rows(operation)
        for item in (row, checklist):
            self.assertEqual("blocked", item["queue_status"])
            self.assertIn("live_verified_allowed_session", item["missing_prerequisites"])
            self.assertNotIn("scope_binding_review_required", item)
        self.assertNotIn("input_template", checklist)
        self.assertEqual("plan.next", checklist["action"])


if __name__ == "__main__":
    unittest.main()
