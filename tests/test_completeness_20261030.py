"""Offline regressions for declared hypotheses, tenant sampling and honest closure."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import browser, completeness, engine, workflow
from awa_ddd.assessment import evaluate, record_finding
from awa_ddd.candidates import link_candidate, store_candidate
from awa_ddd.store import EngineError, Project, now


def observation(url, method, headers, body, timeout, max_bytes, *, response=None):
    raw = json.dumps({"count": 1} if response is None else response).encode("utf-8")
    sent = body if isinstance(body, bytes) else body.encode("utf-8") if isinstance(body, str) else b""
    return {"request": {"url": url, "method": method, "headers": headers,
                        "body_base64": base64.b64encode(sent).decode("ascii")},
            "response": {"status": 200, "headers": [["content-type", "application/json"]],
                         "length": len(raw), "body_base64": base64.b64encode(raw).decode("ascii")},
            "started_at": now(), "completed_at": now(), "complete": True}


class CompletenessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-completeness-")
        self.addCleanup(self.tmp.cleanup)
        self.base = "http://fixture.invalid"
        engine.create_project(self.tmp.name, {"project_id": "complete", "target": self.base})
        self.project = Project(self.tmp.name, "complete")
        self.addCleanup(self.project.close)

    def operation(self, path="/items", **extra):
        return engine.register_operation(self.project, {"url": self.base + path,
            "method": "GET", "auth": "public", **extra})

    def actor(self, identity, tenant="", roles=("user",)):
        return engine.add_actor(self.project, {"actor_id": identity, "subject": identity,
            "tenant_id": tenant, "roles": list(roles)})

    def resource(self, operation, owner="alice", external="7", binding=None, **extra):
        return engine.add_resource(self.project, {"operation_id": operation["id"], "owner_actor_id": owner,
            "external_id": external, "request_binding": binding or {"location": "query", "selector": "id"}, **extra})

    def capture(self, operation, *, response=None, **args):
        with patch.object(engine, "request", side_effect=lambda *values: observation(*values, response=response)):
            return engine.capture(self.project, {"operation_id": operation["id"], **args})

    def active(self, operation=None, kind=None):
        return [item for item in self.project.list("obligation") if not item.get("superseded")
                and (operation is None or item["operation_id"] == operation["id"])
                and (kind is None or item["kind"] == kind)]

    def imported_visit(self, path="/page", blocked=False):
        raw = {"url": self.base + path, "finalUrl": self.base + path, "status": 200,
               "signals": {"forms": 1}, "network": [{"url": self.base + path, "method": "GET", "status": 200}]}
        if blocked:
            raw["error"] = "fixture observation was blocked"
        source = Path(self.tmp.name) / ("blocked-visit.json" if blocked else "visit.json")
        source.write_text(json.dumps(raw), encoding="utf-8")
        return browser.import_observation(self.project, {"path": str(source)})

    def test_legacy_input_identity_is_preserved(self):
        operation = self.operation(inputs=[{"name": "q", "location": "query", "consumer": "business_input"}])
        engine.build_plan(self.project)
        entry = operation["inputs"][0]
        expected = engine.stable("OB", {"kind": "input_test", "input_selector": "q", "input_location": "query",
            "schema_branch": None, "input_signature": engine.stable("I", entry), "operation_id": operation["id"]})
        items = self.active(operation, "input_test")
        self.assertEqual([item["id"] for item in items], [expected])
        self.assertNotIn("test_family", items[0])

    def test_explicit_families_create_independent_hypotheses(self):
        operation = self.operation(inputs=[{"name": "q", "location": "query", "consumer": "business_input",
                                           "test_families": ["generic", "business_logic"]}])
        engine.build_plan(self.project)
        items = self.active(operation, "input_test")
        self.assertEqual({item["test_family"] for item in items}, {"generic", "business_logic"})
        self.assertEqual(len({item["id"] for item in items}), 2)
        snapshot = workflow.inspect_surface(self.project, {"operation_id": operation["id"]})
        self.assertEqual(snapshot["inputs"][0]["test_families"], ["business_logic", "generic"])
        self.assertTrue(all("test_family" in item for item in snapshot["obligations"] if item["kind"] == "input_test"))

    def test_unknown_consumer_is_not_promoted_by_families_or_hints(self):
        operation = self.operation(inputs=[{"name": "image_url", "location": "query",
                                           "test_families": ["ssrf", "xss"]}])
        engine.build_plan(self.project)
        self.assertEqual(len(self.active(operation, "input_review")), 1)
        self.assertEqual(self.active(operation, "input_test"), [])
        result = completeness.audit(self.project, {})
        matrix = {row["test_family"]: row for row in result["category_matrix"]}
        self.assertEqual(matrix["ssrf"]["status"], "review_required")
        self.assertEqual(matrix["ssrf"]["evaluated"], 0)
        self.assertEqual(self.project.get("operation", operation["id"])["inputs"][0]["consumer"], "unknown")

    def test_invalid_family_lists_fail_before_registration(self):
        for families in ([], ["invalid"], ["generic", "generic"], "generic", None):
            with self.subTest(families=families), self.assertRaises(EngineError) as caught:
                self.operation(inputs=[{"name": "q", "location": "query", "test_families": families}])
            self.assertEqual(caught.exception.code, "test_families")
        self.assertEqual(self.project.list("operation"), [])

    def test_family_order_does_not_change_obligation_identity(self):
        fields = {"name": "q", "location": "query", "consumer": "business_input"}
        operation = self.operation(inputs=[{**fields, "test_families": ["generic", "business_logic"]}])
        engine.build_plan(self.project)
        before = {item["id"] for item in self.active(operation, "input_test")}
        self.operation(inputs=[{**fields, "test_families": ["business_logic", "generic"]}])
        engine.build_plan(self.project)
        self.assertEqual(before, {item["id"] for item in self.active(operation, "input_test")})

    def test_descriptive_registration_does_not_silently_remove_families(self):
        fields = {"name": "q", "location": "query", "consumer": "business_input"}
        self.operation(inputs=[{**fields, "test_families": ["generic", "business_logic"]}])
        result = self.operation(inputs=[fields])
        self.assertEqual(result["inputs"][0]["test_families"], ["business_logic", "generic"])

    def test_declaring_families_replans_without_relabelling_old_obligations(self):
        operation = self.operation(inputs=[{"name": "q", "location": "query", "consumer": "business_input"}])
        engine.build_plan(self.project)
        old = self.active(operation, "input_test")[0]
        engine.declare_consumer(self.project, {"operation_id": operation["id"], "input_location": "query",
            "input_selector": "q", "consumer": "business_input", "test_families": ["generic", "business_logic"]})
        self.assertTrue(self.project.get("obligation", old["id"])["superseded"])
        self.assertNotIn("test_family", self.project.get("obligation", old["id"]))
        self.assertEqual(len(self.active(operation, "input_test")), 2)

    def test_consumer_declaration_requires_exact_schema_branch(self):
        operation = self.operation(inputs=[{"name": "q", "location": "query", "schema_branch": branch}
                                           for branch in ("one", "two")])
        args = {"operation_id": operation["id"], "input_location": "query", "input_selector": "q", "consumer": "business_input"}
        with self.assertRaises(EngineError) as caught:
            engine.declare_consumer(self.project, args)
        self.assertEqual(caught.exception.code, "input_ambiguous")
        engine.declare_consumer(self.project, {**args, "schema_branch": "two", "test_families": ["generic"]})
        self.assertEqual(len(self.active(operation, "input_review")), 1)
        self.assertEqual(self.active(operation, "input_test")[0]["schema_branch"], "two")

    def test_tenant_boundaries_survive_same_role_sampling(self):
        for identity, tenant in (("alice", "t1"), ("bob", "t1"), ("carol", "t2"), ("dave", "")):
            self.actor(identity, tenant)
        operation = self.operation(auth="authenticated", ownership=True,
            inputs=[{"name": "id", "location": "query", "consumer": "resource_reference"}])
        resource = self.resource(operation)
        engine.build_plan(self.project)
        items = self.active(operation, "ownership")
        self.assertEqual({item["actor_id"] for item in items}, {"bob", "carol", "dave"})
        self.assertEqual({item["tenant_boundary"] for item in items}, {"same_tenant", "cross_tenant", "unknown_tenant"})
        self.assertTrue(all(item["resource_id"] == resource["id"] for item in items))

    def test_fixture_contexts_include_owner_tenant_role_and_binding(self):
        self.actor("alice", "t1")
        self.actor("bob", "t1")
        self.actor("carol", "t2")
        self.actor("admin", "t1", ("admin",))
        operation = self.operation(auth="authenticated", ownership=True)
        self.resource(operation, "alice", "first")
        self.resource(operation, "alice", "duplicate-context")
        self.resource(operation, "carol", "other-tenant")
        self.resource(operation, "admin", "other-role")
        self.resource(operation, "alice", "other-binding", {"location": "body", "selector": "/id"})
        engine.build_plan(self.project)
        samples = self.project.get("operation", operation["id"])["ownership_sampling"]
        self.assertEqual(samples["contexts_total"], 4)
        self.assertEqual(samples["fixtures_total"], 5)
        self.assertEqual(samples["fixtures_sampled"], 4)
        self.assertFalse(samples["limited"])
        self.assertEqual(len({item["resource_id"] for item in self.active(operation, "ownership")}), 4)

    def test_existing_representative_and_legacy_ownership_id_are_preserved(self):
        self.actor("alice")
        self.actor("bob")
        operation = self.operation(auth="authenticated", ownership=True)
        first = self.resource(operation)
        engine.build_plan(self.project)
        old = self.active(operation, "ownership")[0]
        self.assertEqual(old["id"], engine.stable("OB", {"kind": "ownership", "actor_id": "bob",
            "baseline_actor_id": "alice", "resource_id": first["id"], "operation_id": operation["id"]}))
        later = self.resource(operation, external="later")
        later["created_at"] = "2000-01-01T00:00:00+00:00"
        self.project.put("resource", later)
        engine.build_plan(self.project)
        self.assertEqual([item["id"] for item in self.active(operation, "ownership")], [old["id"]])

    def test_ownership_caps_remain_explicit_coverage_limits(self):
        for identity, tenant in (("alice", "t1"), ("bob", "t1"), ("carol", "t2"), ("dave", "t3")):
            self.actor(identity, tenant)
        operation = self.operation(auth="authenticated", ownership=True)
        self.resource(operation, "alice")
        self.resource(operation, "carol", "other-tenant")
        with patch.object(engine, "MAX_OWNERSHIP_CONTEXTS", 1), patch.object(engine, "MAX_OWNERSHIP_VARIANTS", 2):
            result = engine.build_plan(self.project)
        self.assertLessEqual(len(self.active(operation, "ownership")), 2)
        self.assertTrue(self.project.get("operation", operation["id"])["ownership_sampling"]["limited"])
        self.assertEqual(result["completion"]["limited_ownership_sampling"], 1)
        self.assertEqual(result["completion"]["status"], "partial")

    def test_fair_queue_does_not_starve_input_reviews_or_risky_families(self):
        for index in range(55):
            self.operation("/baseline-" + str(index))
        review = self.operation("/review", inputs=[{"name": "keyword", "location": "query"}])
        risky = self.operation("/risky", inputs=[{"name": "q", "location": "query", "consumer": "business_input",
            "test_families": ["business_logic", "generic"]}])
        engine.build_plan(self.project)
        with patch.object(engine, "request") as network:
            result = workflow.next_work(self.project, {"limit": 4})
        network.assert_not_called()
        rows = result["work_items"]
        self.assertTrue(any(row["operation_id"] == review["id"] and row["obligation_kind"] == "input_review" for row in rows))
        self.assertEqual({row["test_family"] for row in rows if row["operation_id"] == risky["id"] and "test_family" in row}, {"business_logic", "generic"})
        self.assertTrue(any(row["obligation_kind"] == "baseline" for row in rows))
        self.assertEqual(result["queue_policy"], "family_round_robin")

    def test_xss_family_requires_reviewed_runtime_not_static_machine_proof(self):
        operation = self.operation(inputs=[{"name": "description", "location": "query", "consumer": "html_render",
                                           "test_families": ["xss"]}])
        engine.build_plan(self.project)
        result = workflow.next_work(self.project, {"include_blocked": True})
        row = next(row for row in result["work_items"] if row.get("test_family") == "xss")
        self.assertEqual(row["queue_status"], "review")
        self.assertTrue(row["analyst_binding_supported"])
        self.assertEqual(row["proof_channels"], ["analyst_runtime"])
        self.assertEqual(row["manual_followup_action"], "finding.record")
        self.assertNotIn("xss_execution", row["proof_channels"])

    def test_caller_blocked_review_needs_offline_reopen_not_implicit_readiness(self):
        operation = self.operation(inputs=[{"name": "q", "location": "query"}])
        engine.build_plan(self.project)
        item = self.active(operation, "input_review")[0]
        engine.disposition(self.project, {"obligation_id": item["id"], "status": "blocked", "reason": "fixture sink not accessible"})
        result = workflow.next_work(self.project, {"include_blocked": True})
        row = next(row for row in result["work_items"] if row["obligation_id"] == item["id"])
        self.assertEqual(row["queue_status"], "review")
        self.assertEqual(row["declared_status"], "blocked")
        self.assertEqual(row["underlying_queue_status"], "review")
        self.assertTrue(row["blocker_reconciliation_required"])
        self.assertEqual(row["suggested_action"], "plan.disposition")
        self.assertEqual(row["input_template"]["status"], "open")
        self.assertTrue(row["execution_blocked"])
        self.assertEqual(self.project.get("obligation", item["id"])["status"], "blocked")

    def test_baseline_is_observed_and_assessed_but_not_security_complete(self):
        operation = self.operation()
        engine.build_plan(self.project)
        evidence = self.capture(operation)
        item = self.active(operation, "baseline")[0]
        evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": [evidence["id"]],
            "oracle": {"type": "baseline", "selector": "/count", "expected": 1}})
        result = completeness.audit(self.project, {})
        self.assertEqual(result["layers"]["observed"]["operations"], 1)
        self.assertEqual(result["layers"]["assessed"]["operations"], 1)
        self.assertEqual(result["security_coverage"]["operations_complete"], 0)
        self.assertEqual(result["completion"]["status"], "partial")
        self.assertTrue(any(row["kind"] == "security_plan_missing" for row in result["checklist"]))

    def test_audit_is_read_only_and_paginates_without_losing_rows(self):
        for index in range(18):
            self.operation("/route-" + str(index), inputs=[{"name": "q", "location": "query"}])
        engine.build_plan(self.project)
        before = [tuple(row) for row in self.project.connection.execute("SELECT * FROM entities ORDER BY kind,id")]
        events = self.project.connection.execute("SELECT count(*) FROM events").fetchone()[0]
        offset, identities = 0, []
        with patch.object(engine, "request") as network:
            while True:
                result = completeness.audit(self.project, {"offset": offset, "limit": 7})
                identities += [row["id"] for row in result["checklist"]]
                if result["next_offset"] is None:
                    break
                offset = result["next_offset"]
        network.assert_not_called()
        self.assertEqual(len(identities), result["checklist_total"])
        self.assertEqual(len(set(identities)), len(identities))
        self.assertEqual(before, [tuple(row) for row in self.project.connection.execute("SELECT * FROM entities ORDER BY kind,id")])
        self.assertEqual(events, self.project.connection.execute("SELECT count(*) FROM events").fetchone()[0])
        self.assertEqual(result["requests_sent"], 0)

    def test_new_project_is_not_started_not_complete(self):
        result = completeness.audit(self.project, {})
        self.assertEqual(result["completion"]["status"], "not_started")
        self.assertTrue(result["completion"]["registered_scope_only"])
        self.assertTrue(all(row["status"] == "not_planned" for row in result["category_matrix"]))

    def test_candidates_remain_pending_after_linking(self):
        operation = self.operation()
        engine.build_plan(self.project)
        identity, _ = store_candidate(self.project, {"kind": "tool_signal", "url": operation["url"],
            "source": {"sha256": "a" * 64, "locator": "fixture-tool#signal"}})
        link_candidate(self.project, {"candidate_id": identity, "operation_id": operation["id"]})
        result = completeness.audit(self.project, {})
        self.assertEqual(result["completion"]["unresolved_candidates"], 1)
        self.assertTrue(any(row.get("candidate_id") == identity for row in result["checklist"]))

    def test_current_capture_and_analyst_finding_expose_unclosed_work(self):
        operation = self.operation()
        engine.build_plan(self.project)
        evidence = self.capture(operation)
        self.assertEqual(completeness.audit(self.project, {})["completion"]["unassessed_observations"], 1)
        record_finding(self.project, {"mode": "analyst", "title": "Fixture disclosure", "category": "Information Disclosure",
            "impact": "A reviewed fixture field is exposed", "remediation": "Restrict the fixture field",
            "reviewer": "fixture reviewer", "reason": "Reviewed immutable fixture evidence", "evidence_ids": [evidence["id"]]})
        result = completeness.audit(self.project, {})
        self.assertEqual(result["completion"]["unassessed_observations"], 0)
        self.assertEqual(result["completion"]["unlinked_analyst_findings"], 1)
        self.assertEqual(result["layers"]["assessed"]["operations"], 1)
        queue = workflow.next_work(self.project, {})
        self.assertTrue(any(row["kind"] == "unlinked_analyst_finding" for row in queue["review_followups"]))

    def test_orphan_browser_visit_requires_adoption_not_fake_coverage(self):
        visit = self.imported_visit()
        result = completeness.audit(self.project, {})
        self.assertEqual(result["completion"]["orphan_browser_visits"], 1)
        row = next(row for row in result["checklist"] if row["kind"] == "orphan_browser_visit")
        self.assertEqual(row["suggested_action"], "page.adopt")
        self.assertEqual(row["input_template"], {"page_visit_id": visit["id"]})
        self.assertEqual(self.project.list("page"), [])

    def test_failed_browser_visit_cannot_be_adopted_as_success(self):
        visit = self.imported_visit(blocked=True)
        result = completeness.audit(self.project, {})
        row = next(row for row in result["checklist"] if row["kind"] == "orphan_browser_visit")
        self.assertEqual(row["status"], "open")
        self.assertEqual(row["suggested_action"], "plan.review")
        self.assertEqual(row["input_template"]["status"], "reviewed")
        self.assertNotEqual(row["action"], "page.adopt")
        with self.assertRaises(EngineError):
            browser.adopt_visit(self.project, {"page_visit_id": visit["id"]})
        self.assertEqual(browser.coverage(self.project)["pages_visited"], 0)
        self.assertEqual(self.project.list("page"), [])

    def test_partial_tool_failure_is_not_a_security_negative(self):
        operation = self.operation()
        self.project.put("run", {"id": "RUN-timeout", "adapter": "sqlmap", "status": "failed",
            "operation_id": operation["id"], "error_code": "tool_timeout", "target_traffic_sent": True,
            "traffic_requests": 2, "effect": "test_resource_write"})
        self.project.put("run", {"id": "RUN-no-execution", "adapter": "sqlmap", "status": "failed",
            "operation_id": operation["id"], "error_code": "tool_process_failed", "target_traffic_sent": False})
        result = completeness.audit(self.project, {})
        self.assertEqual(result["completion"]["failed_partial_tools"], 1)
        rows = [row for row in result["checklist"] if row["kind"] == "failed_partial_tool"]
        self.assertEqual([row["run_id"] for row in rows], ["RUN-timeout"])
        self.assertEqual(result["security_coverage"]["evaluated"], 0)

    def test_session_specific_hints_do_not_declare_sinks(self):
        for name in ("use_points", "coupon", "discount", "qty", "order_time", "timestamp", "sign"):
            self.assertIn("business_logic", completeness.suggested_families({"name": name}, {"url": self.base}))
        self.assertIn("template_injection", completeness.suggested_families({"name": "rules"}, {"url": self.base + "/promo-rule"}))
        self.assertIn("deserialization", completeness.suggested_families({"name": "root", "location": "body"}, {"url": self.base + "/import-json"}))
        self.operation(inputs=[{"name": "image_url", "location": "query"}])
        engine.build_plan(self.project)
        result = completeness.audit(self.project, {})
        note = next(row for row in result["technical_blindspots"] if row["code"] == "ssrf_observer_reachability")
        self.assertIn("Windows/WSL", note["detail_zh"])
        self.assertEqual(self.active(kind="input_test"), [])

    def test_audit_budget_is_validated_without_side_effects(self):
        for args in ({"offset": -1}, {"offset": True}, {"limit": 0}, {"limit": 101}, {"limit": False}):
            with self.subTest(args=args), self.assertRaises(EngineError):
                completeness.audit(self.project, args)
        self.assertEqual(self.project.list("run"), [])

    def test_known_custom_auth_headers_cannot_be_captured_as_anonymous(self):
        self.actor("alice")
        engine.add_session(self.project, {"actor_id": "alice", "headers": {"X-Actor": "alice", "X-Region": "zone-a"},
            "credential_header_names": ["X-Actor"]})
        operation = self.operation()
        for action in (engine.preflight_capture, engine.capture):
            with self.subTest(action=action.__name__), patch.object(engine, "request") as network:
                with self.assertRaises(EngineError) as caught:
                    action(self.project, {"operation_id": operation["id"], "headers": {"X-Actor": "alice"}})
                self.assertEqual(caught.exception.code, "credential_override")
                network.assert_not_called()
        self.assertEqual(self.project.list("run"), [])
        self.assertEqual(self.project.list("evidence"), [])

    def test_a_refuted_family_does_not_close_other_input_hypotheses(self):
        operation = self.operation(inputs=[{"name": "q", "location": "query", "consumer": "business_input",
            "test_families": ["generic", "business_logic"]}])
        engine.build_plan(self.project)
        evidence = [self.capture(operation, url=self.base + "/items?q=" + value, response={"count": count})
                    for value, count in (("normal", 1), ("variant", 1), ("sensitivity", 2))]
        item = next(item for item in self.active(operation, "input_test") if item["test_family"] == "generic")
        decision = evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": [row["id"] for row in evidence],
            "oracle": {"type": "semantic_negative", "test_family": "generic", "selector": "/count",
                       "baseline_expected": 1, "control_expected": 2}})
        self.assertEqual(decision["outcome"], "refuted")
        result = completeness.audit(self.project, {})
        matrix = {row["test_family"]: row for row in result["category_matrix"]}
        self.assertEqual(matrix["generic"]["evaluated"], 1)
        self.assertEqual(matrix["business_logic"]["open"], 1)
        self.assertEqual(result["completion"]["status"], "partial")

    def test_verified_custom_auth_session_and_unknown_business_headers_still_work(self):
        self.actor("alice")
        session = engine.add_session(self.project, {"actor_id": "alice", "headers": {"X-Actor": "alice", "X-Region": "zone-a"},
            "credential_header_names": ["X-Actor"]})
        profile = self.operation("/profile", auth="authenticated")
        with patch.object(engine, "request", side_effect=lambda *args: observation(*args, response={"subject": "alice", "roles": ["user"]})):
            engine.verify_identity(self.project, {"operation_id": profile["id"], "session_id": session["id"],
                "subject_selector": "/subject", "roles_selector": "/roles"})
        operation = self.operation("/business", auth="authenticated")
        captured = self.capture(operation, session_id=session["id"], headers={"X-Region": "zone-a", "X-Workflow": "fixture"})
        self.assertEqual(captured["actor_id"], "alice")
        self.assertEqual(captured["auth_mode"], "session")
        public = self.operation("/public")
        anonymous = self.capture(public, headers={"X-Workflow": "fixture"})
        self.assertIsNone(anonymous["actor_id"])
        self.assertEqual(anonymous["auth_mode"], "none")


if __name__ == "__main__":
    unittest.main()
