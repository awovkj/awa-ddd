"""Independent, source-bound review properties never become proof or coverage."""
from __future__ import annotations

import base64
from contextlib import ExitStack, contextmanager
import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import engine, security_hypotheses
from awa_ddd.__main__ import dispatch
from awa_ddd.reconnaissance import profile
from awa_ddd.store import Project, canonical, now
import test_finding_binding_20261103 as binding_fixtures


class SecurityHypothesesTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="awa-security-properties-")
        self.addCleanup(temporary.cleanup)
        self.base = "http://fixture.invalid"
        engine.create_project(temporary.name, {"project_id": "properties", "target": self.base, "allow_mutation": True})
        self.project = Project(temporary.name, "properties")
        self.addCleanup(self.project.close)

    def operation(self, path="/app/public", **extra):
        return engine.register_operation(self.project, {"url": self.base + path, "method": "GET", "auth": "public", **extra})

    def capture(self, operation, *, response=None, complete=True, url=None):
        def request(url, method, headers, body, timeout, max_bytes):
            raw = json.dumps(response if response is not None else {"data": "fixture"}).encode("utf-8")
            return {"request": {"url": url, "method": method, "headers": headers, "body_base64": ""},
                    "response": {"status": 200, "headers": [["content-type", "application/json"]], "length": len(raw),
                                 "body_base64": base64.b64encode(raw).decode("ascii")},
                    "complete": complete, "started_at": now(), "completed_at": now()}
        with patch.object(engine, "request", side_effect=request):
            return engine.capture(self.project, {"operation_id": operation["id"], **({"url": url} if url else {})})

    def state(self, *, include_baseline=False):
        where = "" if include_baseline else " WHERE kind!='recon_baseline'"
        return ([tuple(row) for row in self.project.connection.execute("SELECT * FROM entities" + where + " ORDER BY kind,id")],
                [tuple(row) for row in self.project.connection.execute("SELECT * FROM events ORDER BY seq")], self.project.config)

    def artifacts(self):
        folder = self.project.base / "evidence"
        return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in folder.glob("*.json")}

    @contextmanager
    def passive(self, *, no_material=False):
        with ExitStack() as stack:
            mocks = [stack.enter_context(patch(target, side_effect=AssertionError("Security hypotheses executed a target action")))
                     for target in ("awa_ddd.engine.request", "awa_ddd.transport.request", "awa_ddd.browser.visit",
                                    "subprocess.run", "subprocess.Popen", "socket.create_connection")]
            if no_material:
                mocks.extend(stack.enter_context(patch(target, side_effect=AssertionError("Prepare read material")))
                             for target in ("awa_ddd.engine.verify_current_evidence", "awa_ddd.store.Project.read_artifact"))
            yield
            for mock in mocks:
                mock.assert_not_called()

    def call(self, mode="aggregate", section="hypotheses", **extra):
        with self.passive(no_material=mode == "prepare"):
            result = profile(self.project, {"mode": mode, "section": section, "limit": 50, **extra})
        self.assertEqual(0, result["requests_sent"])
        self.assertFalse(result["profile_is_security_evidence"])
        self.assertFalse(result["completion_claim_allowed"])
        for row in result["items"] if section == "hypotheses" else []:
            self.assertIn(row["security_property"], security_hypotheses.SECURITY_PROPERTIES)
            self.assertTrue(set(row["missing_context"]).issubset(security_hypotheses.MISSING_CONTEXT_CODES))
            self.assertIn("property_specific_controls", row["missing_context"])
            self.assertTrue(row["hint_only"])
            self.assertFalse(row["requestable"])
            self.assertFalse(row["usable_for_confirmation"])
            self.assertFalse(row["observations_are_property_proof"])
            self.assertEqual("declared", row["source"]["context_trust"])
            self.assertEqual(row["operation_id"], row["source"]["operation_id"])
            self.assertEqual("assessment.prepare", row["next_action"])
            self.assertIn(set(row["input_template"]), ({"obligation_id"}, {"operation_id"}))
            self.assertLessEqual(len(row["observed_evidence_ids"]), 3)
            self.assertNotIn("status", row)
            self.assertNotIn("decision_id", row)
        return result

    def test_general_authentication_and_token_properties_are_independent_review_entries(self):
        operation = self.operation("/accounts/authenticate", method="POST", inputs=[
            {"name": "username", "location": "body"}, {"name": "password", "location": "body"},
            {"name": "verificationCode", "location": "body"}, {"name": "resetToken", "location": "body"}])
        engine.build_plan(self.project)
        before = self.state(include_baseline=True)
        result = self.call("prepare")
        properties = {row["security_property"] for row in result["items"]}
        self.assertTrue({"authentication_factor_enforcement", "authentication_retry_limits", "token_single_use",
                         "token_expiry_invalidation", "operation_idempotency", "state_transition_authorization"}.issubset(properties))
        token = [row for row in result["items"] if row.get("input_selector") == "resetToken"]
        self.assertEqual({"token_single_use", "token_expiry_invalidation"}, {row["security_property"] for row in token})
        self.assertEqual(2, len({row["id"] for row in token}))
        self.assertTrue(all(row["operation_id"] == operation["id"] for row in result["items"]))
        self.assertTrue(all("actual_input_consumer" in row["missing_context"] for row in token))
        self.assertEqual(before, self.state(include_baseline=True))
        self.assertTrue(all(entry["consumer"] == "unknown" for entry in self.project.get("operation", operation["id"])["inputs"]))
        self.assertEqual([], self.project.list("decision"))
        self.assertEqual([], self.project.list("candidate"))

    def test_business_values_time_and_state_have_concrete_properties_without_creating_families(self):
        operation = self.operation("/commerce/adjustment", method="POST", auth="authenticated", ownership=True, inputs=[
            {"name": "amount", "location": "body"}, {"name": "quantity", "location": "body"},
            {"name": "order_time", "location": "body"}, {"name": "status", "location": "body"},
            {"name": "probabilities", "location": "body"}])
        engine.build_plan(self.project)
        before = self.state()
        result = self.call()
        indexed = {(row["security_property"], row.get("input_selector")): row for row in result["items"]}
        for selector in ("amount", "quantity", "probabilities"):
            self.assertEqual(["business_logic"], indexed[("numeric_business_bounds", selector)]["suggested_test_families"])
        self.assertIn(("time_window_enforcement", "order_time"), indexed)
        self.assertIn(("state_transition_authorization", "status"), indexed)
        self.assertIn(("principal_tenant_boundary", None), indexed)
        self.assertEqual(before, self.state())
        self.assertTrue(all("test_families" not in entry for entry in self.project.get("operation", operation["id"])["inputs"]))
        self.assertTrue(all(row["status"] == "open" for row in self.project.list("obligation")))

    def test_public_static_operation_with_no_inputs_has_a_review_entry_and_an_honest_missing_channel(self):
        operation = self.operation("/app/assets/settings.js", content_type="application/javascript")
        engine.build_plan(self.project)
        result = self.call("prepare")
        self.assertEqual(1, len(result["items"]))
        row = result["items"][0]
        self.assertEqual("public_sensitive_exposure", row["security_property"])
        self.assertEqual(operation["id"], row["operation_id"])
        self.assertIn("public_field_classification", row["missing_context"])
        self.assertIn("operation_level_proof_channel", row["missing_context"])
        self.assertNotIn("input_selector", row)
        self.assertEqual([], row["observed_evidence_ids"])

    def test_navigation_parser_and_upload_controls_preserve_exact_separate_inputs(self):
        self.operation("/app/navigation", inputs=[{"name": "redirect", "location": "query"}])
        self.operation("/app/parse", method="POST", content_type="application/json", inputs=[
            {"name": "payload", "location": "body", "selector": "/payload", "schema_type": "object"}])
        self.operation("/app/receive", method="POST", content_type="multipart/form-data", inputs=[
            {"name": "file", "location": "body"}, {"name": "file.filename", "location": "body"}])
        engine.build_plan(self.project)
        rows = self.call("prepare")["items"]
        navigation = next(row for row in rows if row["security_property"] == "navigation_destination_policy")
        self.assertEqual("redirect", navigation["input_selector"])
        self.assertIn("browser_consumer_context", navigation["missing_context"])
        parser = next(row for row in rows if row["security_property"] == "structured_parser_safety" and row.get("input_selector") == "/payload")
        self.assertIn("deserialization", parser["suggested_test_families"])
        upload = [row for row in rows if row["security_property"] == "upload_path_and_content" and row.get("input_selector")]
        self.assertEqual({"file", "file.filename"}, {row["input_selector"] for row in upload})
        self.assertEqual(2, len({row["id"] for row in upload}))

    def test_observed_references_are_current_bounded_and_do_not_export_response_values(self):
        operation = self.operation()
        captures = [self.capture(operation, response={"token": "PRIVATE-FACTOR-" + str(index)}) for index in range(5)]
        before, artifacts = self.state(), self.artifacts()
        first = self.call()
        row = first["items"][0]
        self.assertEqual([capture["id"] for capture in captures[-3:]], row["observed_evidence_ids"])
        self.assertNotIn("PRIVATE-FACTOR", canonical(first))
        self.assertIn("normal_business_assertion", row["missing_context"])
        self.assertNotIn("current_http_observation", row["missing_context"])
        self.assertEqual(before, self.state())
        self.assertEqual(artifacts, self.artifacts())
        path = self.project.base / captures[-1]["artifact_path"]
        path.write_bytes(path.read_bytes() + b" ")
        second = self.call()
        self.assertNotIn(captures[-1]["id"], canonical(second["items"]))
        self.assertEqual([capture["id"] for capture in captures[-4:-1]], second["items"][0]["observed_evidence_ids"])
        self.assertEqual(first["baseline_id"], second["baseline_id"])

    def test_partial_and_wrong_operation_references_never_become_current_source_context(self):
        operation = self.operation()
        partial = self.capture(operation, complete=False)
        other = self.operation("/app/other")
        foreign = self.capture(other)
        with self.passive():
            built = security_hypotheses.build(self.project, [operation], {operation["id"]: [partial["id"], foreign["id"]]})
        self.assertEqual([], built["items"][0]["observed_evidence_ids"])
        self.assertIn("current_http_observation", built["items"][0]["missing_context"])

    def test_scope_changes_exclude_old_operations_and_evidence_without_leaking_locators(self):
        allowed = self.operation("/app/allowed")
        excluded = self.operation("/app/excluded")
        outside = self.operation("/app-other/private")
        captures = [self.capture(operation) for operation in (allowed, excluded, outside)]
        config = self.project.config
        config.update(target=self.base + "/app", scope=[self.base + "/app"], exclude=[excluded["url"]])
        self.project.set_config(config)
        before = self.state()
        result = self.call()
        self.assertEqual({allowed["id"]}, {row["operation_id"] for row in result["items"]})
        self.assertNotIn(excluded["id"], canonical(result["items"]))
        self.assertNotIn(outside["id"], canonical(result["items"]))
        self.assertNotIn(captures[1]["id"], canonical(result["items"]))
        self.assertNotIn(captures[2]["id"], canonical(result["items"]))
        self.assertEqual(before, self.state())
        # The module also rechecks scope when independently supplied old rows.
        with self.passive():
            direct = security_hypotheses.build(self.project, [excluded, outside], {
                excluded["id"]: [captures[1]["id"]], outside["id"]: [captures[2]["id"]]})
        self.assertEqual([], direct["items"])

    def test_exact_query_scope_requires_an_actual_scoped_capture_and_never_uses_scope_as_a_request(self):
        exact = self.base + "/app/item?fixed=allowed-fixture"
        operation = self.operation("/app/item?fixed=allowed-fixture")
        permitted = self.capture(operation, url=exact)
        outside = self.capture(operation, url=self.base + "/app/item?fixed=outside-fixture")
        config = self.project.config
        config.update(target=exact, scope=[exact])
        self.project.set_config(config)
        prepare = self.call("prepare")
        self.assertEqual([], prepare["items"])
        aggregate = self.call()
        self.assertTrue(aggregate["items"])
        for row in aggregate["items"]:
            self.assertEqual([permitted["id"]], row["observed_evidence_ids"])
            self.assertIn("exact_authorized_url", row["missing_context"])
            self.assertNotIn("url", row["input_template"])
        self.assertNotIn(outside["id"], canonical(aggregate["items"]))
        self.assertNotIn("allowed-fixture", canonical(aggregate["items"]))
        self.assertNotIn("outside-fixture", canonical(aggregate["items"]))

    def test_stable_ids_distinguish_schema_branches_and_templates_use_only_unique_current_obligations(self):
        operation = self.operation("/app/billing", method="POST", inputs=[
            {"name": "amount", "location": "body", "selector": "/amount", "schema_branch": "branch-a"},
            {"name": "amount", "location": "body", "selector": "/amount", "schema_branch": "branch-b"}])
        engine.build_plan(self.project)
        first = self.call("prepare")
        numeric = [row for row in first["items"] if row["security_property"] == "numeric_business_bounds"]
        self.assertEqual(2, len({row["id"] for row in numeric}))
        self.assertEqual({"branch-a", "branch-b"}, {row["schema_branch"] for row in numeric})
        for row in numeric:
            self.assertIn("schema_branch_controls", row["missing_context"])
            obligation = self.project.get("obligation", row["input_template"]["obligation_id"])
            self.assertEqual(row["schema_branch"], obligation["schema_branch"])
        updated = self.operation("/app/billing", method="POST", inputs=[
            {"name": "amount", "location": "body", "selector": "/amount", "schema_branch": "branch-a",
             "consumer": "business_amount", "test_families": ["business_logic", "generic"]},
            {"name": "amount", "location": "body", "selector": "/amount", "schema_branch": "branch-b"}])
        self.assertEqual(operation["id"], updated["id"])
        engine.build_plan(self.project)
        second = self.call("prepare")
        current = [row for row in second["items"] if row["security_property"] == "numeric_business_bounds"]
        self.assertEqual({row["id"] for row in numeric}, {row["id"] for row in current})
        branch_a = next(row for row in current if row["schema_branch"] == "branch-a")
        self.assertEqual({"operation_id": operation["id"]}, branch_a["input_template"])

    def test_default_overview_has_only_a_small_pointer_and_reuses_semantics_across_capture_ids(self):
        operation = self.operation()
        self.capture(operation)
        first = self.call(section="overview")
        self.capture(operation)
        second = self.call(section="overview")
        self.assertEqual("site", second["items"][0]["kind"])
        self.assertNotIn("hypotheses", second)
        self.assertEqual(1, second["summary"]["hypothesis_total"])
        self.assertEqual({"action": "surface.recon", "input": {"mode": "aggregate", "section": "hypotheses", "limit": 10}},
                         second["hypothesis_entry"])
        self.assertEqual(first["baseline_id"], second["baseline_id"])
        self.assertTrue(second["baseline_reused"])
        self.assertEqual(1, len(self.project.list("recon_baseline")))

    def test_hypothesis_pages_are_stable_and_limit_is_not_a_coverage_claim(self):
        self.operation("/app/change", method="POST", inputs=[
            {"name": "amount", "location": "body"}, {"name": "token", "location": "body"},
            {"name": "time", "location": "body"}])
        whole = self.call("prepare")
        pages = [self.call("prepare", offset=offset, limit=2) for offset in range(0, whole["total"], 2)]
        self.assertEqual([row["id"] for row in whole["items"]], [row["id"] for page in pages for row in page["items"]])
        with patch.object(security_hypotheses, "MAX_HYPOTHESES", 3):
            limited = self.call()
        self.assertEqual(3, limited["summary"]["hypothesis_total"])
        self.assertTrue(limited["summary"]["hypothesis_limited"])
        self.assertTrue(limited["summary"]["source_limited"])
        self.assertFalse(limited["completion_claim_allowed"])

    def test_dispatch_publishes_safe_nonproof_properties_without_mutating_security_coverage(self):
        operation = self.operation(inputs=[{"name": "amount", "location": "query"}])
        engine.build_plan(self.project)
        before = engine.evaluate_coverage(self.project)
        with self.passive():
            result = dispatch(self.project.workspace, "surface.recon", {"project_id": self.project.project_id,
                "mode": "aggregate", "section": "hypotheses", "limit": 10})
        after = engine.evaluate_coverage(self.project)
        self.assertTrue(result["items"])
        self.assertEqual(before["security_coverage"], after["security_coverage"])
        self.assertEqual(before["completion"], after["completion"])
        self.assertEqual(0, after["evaluated"])
        self.assertEqual([], self.project.list("finding"))
        self.assertTrue(all(row["operation_id"] == operation["id"] for row in result["items"]))


class ClosedFamilyPropertyTests(unittest.TestCase):
    def test_existing_family_proof_never_dismisses_an_independent_property(self):
        fixture = binding_fixtures.FindingBindingTests("test_analyst_reuses_current_typed_proof_without_changing_its_decision_or_obligation")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        proof, _, item = fixture.proof()
        before = fixture.snapshot()
        with patch.object(engine, "request") as network:
            prepared = profile(fixture.project, {"mode": "prepare", "section": "hypotheses", "limit": 50})
        network.assert_not_called()
        self.assertEqual(before, fixture.snapshot())
        row = next(row for row in prepared["items"] if row["security_property"] == "outbound_destination_policy")
        self.assertEqual({"obligation_id": item["id"]}, row["input_template"])
        self.assertIn("property_specific_controls", row["missing_context"])
        self.assertFalse(row["usable_for_confirmation"])
        self.assertFalse(row["observations_are_property_proof"])
        self.assertNotIn("completed", canonical(row))
        self.assertNotIn("decision_id", row)
        self.assertEqual(proof["id"], fixture.project.get("obligation", item["id"])["decision_id"])


if __name__ == "__main__":
    unittest.main()
