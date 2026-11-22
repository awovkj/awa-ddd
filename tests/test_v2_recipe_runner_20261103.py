"""2.0 frozen recipes, durable runs and oracle proof-scope regressions."""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

import v2_fixtures as fx
from awa_ddd import engine
from awa_ddd.domain import new_hypothesis, new_recipe
from awa_ddd.domain.repository import Repository
from awa_ddd.domain.test_recipe import assert_current, assert_override_allowed, public_view
from awa_ddd.execution import fixtures, oracle_profiles
from awa_ddd.store import EngineError


def make_hypothesis(**changes):
    base = dict(family="template_injection", security_property="unexpected_expression_evaluation",
                operation_id="O-1", input_key="IN-1", scope_epoch="scope", target_build="build",
                source_kind="declared_family", statement="expression may evaluate")
    base.update(changes)
    return new_hypothesis(**base)


def control(role, url, value):
    return {"id": role, "role": role, "request": {"url": url, "method": "GET"},
            "expected": {"selector": "/value", "value": value},
            "observe_as": {"normal": "normal_control", "attack": "attack_control",
                           "negative": "negative_control"}[role]}


def make_recipe(hypothesis=None, *, url="http://fixture.invalid/render?label={{label}}",
                private=None, effect="read_only", fixture_binding=None):
    hypothesis = hypothesis or make_hypothesis()
    controls = [control("normal", url, "AWA-NORMAL"), control("attack", url, "49"),
                control("negative", url, "AWA-NORMAL-2")]
    manifest = private if private is not None else {"control_groups": [{"id": "primary", "controls": controls}]}
    return new_recipe(
        hypothesis=hypothesis,
        provider={"name": "http", "profile": "native_http_read", "version": "1"},
        bindings={"scope_epoch": "scope", "target_build": "build", "operation_id": "O-1",
                  "operation_signature": "S-1", "session": None, "resource": None,
                  "fixture": fixture_binding, "consumer_context": {}},
        control_groups=[{"id": "primary", "identity_role": "anonymous", "controls": controls}],
        oracle={"id": "OR-1", "type": "unexpected_expression_evaluation", "version": "1",
                "proof_scope": "unexpected_expression_evaluation", "selector": "/value",
                "expected_value": "49"},
        steps=["normal", "attack", "negative"],
        limits={"step_total": 3, "time_ms": 10000, "max_writes": 0, "effect": effect},
        variables={"label": {"source": "caller", "max_length": 128}},
        private_manifest=manifest,
    )


class RecipeContractTests(unittest.TestCase):
    def test_spec_hash_is_frozen_and_public_view_hides_private_body(self):
        recipe = make_recipe()
        self.assertTrue(recipe["immutable"])
        self.assertTrue(recipe["spec_hash"])
        view = public_view(recipe)
        self.assertFalse(view["executable"])
        self.assertNotIn("control_groups", view.get("private_capsule", {}))
        serialized = str(view)
        self.assertNotIn("AWA-NORMAL", serialized)

    def test_only_declared_data_variables_can_be_overridden(self):
        recipe = make_recipe()
        self.assertEqual({"label": "safe"}, assert_override_allowed(recipe, {"label": "safe"}))
        with self.assertRaises(EngineError) as caught:
            assert_override_allowed(recipe, {"url": "http://evil.invalid"})
        self.assertEqual("v2_recipe_override", caught.exception.code)
        with self.assertRaises(EngineError):
            assert_override_allowed(recipe, {"label": "x" * 500})

    def test_variables_cannot_select_paths_or_security_fields(self):
        with self.assertRaises(EngineError):
            make_recipe(private={"control_groups": [{"id": "primary", "controls": [
                {"id": "normal", "role": "normal",
                 "request": {"url": "http://fixture.invalid/{{label}}", "method": "GET"}}]}],
                "bindings": {}})

    def test_stale_bindings_are_rejected(self):
        recipe = make_recipe()
        with self.assertRaises(EngineError) as caught:
            assert_current(recipe, {"scope_epoch": "scope", "target_build": "build",
                                    "operation_signature": "DIFFERENT"})
        self.assertEqual("v2_recipe_stale", caught.exception.code)


class OracleNegativeTests(unittest.TestCase):
    def test_parser_identification_never_confirms_unsafe_deserialization(self):
        result = oracle_profiles.evaluate("parser_identification", {
            "normal_parse": True, "attack_parse": True})
        self.assertFalse(result["finding_allowed"])
        self.assertEqual("inconclusive", result["outcome"])

    def test_plain_reflection_is_not_expression_evaluation(self):
        result = oracle_profiles.evaluate("unexpected_expression_evaluation", {
            "declared_formula_field": True, "normal_plain_value": "AWA-NORMAL",
            "attack_arithmetic_value": "7*7", "negative_literal_value": "AWA-NORMAL-2",
            "expected_arithmetic_result": "49", "reflection_exclusion": False,
            "reflection": "reflected"})
        self.assertFalse(result["finding_allowed"])

    def test_timing_only_is_not_bounded_side_effect(self):
        result = oracle_profiles.evaluate("bounded_side_effect", {
            "normal_control": False, "attack_canary": True, "negative_control": False,
            "isolated_canary": True, "reflection_exclusion": True,
            "timing_not_sole_evidence": False})
        self.assertFalse(result["finding_allowed"])

    def test_returned_upload_path_without_readback_is_not_escape(self):
        result = oracle_profiles.evaluate("upload_path_escape", {
            "declared_storage_contract": True, "owned_upload": True,
            "stored_path": "/var/www/uploads/../../evil.txt",
            "readback_content": None, "filename_content_separated": True,
            "outside_allowed_root": True, "allowed_root": "/var/www/uploads"})
        self.assertFalse(result["finding_allowed"])

    def test_manual_browser_dialog_is_not_application_triggered(self):
        result = oracle_profiles.evaluate("browser_runtime", {
            "trigger_source": "manual", "application_triggered": False,
            "attack_dialog": True, "normal_dialog": False,
            "consumer_page": "http://x", "same_identity": True, "content_version": "v1"})
        self.assertFalse(result["finding_allowed"])


class FixtureLifecycleTests(unittest.TestCase):
    def test_lease_readback_and_cleanup_failure_remain_explicit(self):
        temporary, root = fx.workspace()
        self.addCleanup(temporary.cleanup)
        row = fx.project(root)
        operation = fx.register(row, "http://fixture.invalid/write", "POST", "public", [
            {"name": "id", "location": "body", "selector": "id",
             "consumer": "resource_reference"}])
        engine.add_actor(row, {"actor_id": "alice", "subject": "alice", "roles": []})
        resource = engine.add_resource(row, {
            "operation_id": operation["id"], "owner_actor_id": "alice",
            "external_id": "1", "request_binding": {"location": "body", "selector": "id"}})
        fixture = fixtures.create(row, operation_id=operation["id"], owner_actor_id="alice",
                                  resource_id=resource["id"], initial_state={"v": 1}, cleanup_plan={})
        fixtures.verify(row, fixture["id"], observed_state={"v": 1})
        fixtures.lease(row, fixture["id"], worker_id="a", ttl_seconds=60)
        with self.assertRaises(EngineError):
            fixtures.lease(row, fixture["id"], worker_id="b", ttl_seconds=60)
        fixtures.mutate(row, fixture["id"], worker_id="a", intended_effect={"v": 2})
        fixtures.readback(row, fixture["id"], observed_state={"v": 2}, expected_state={"v": 2})
        fixtures.cleanup(row, fixture["id"], worker_id="a", succeeded=False, error="synthetic")
        final = fixtures.public_view(Repository(row).get("fixture", fixture["id"]))
        self.assertTrue(final["unresolved"])
        self.assertEqual("cleanup_failed", final["state"])
        row.close()


class TestRunTests(unittest.TestCase):
    def setUp(self):
        self.temporary, self.root = fx.workspace()
        self.addCleanup(self.temporary.cleanup)

    def _template_campaign(self):
        row = fx.project(self.root)
        fx.register(row, "http://fixture.invalid/render", "GET", "public", [
            {"name": "label", "location": "query", "selector": "label",
             "consumer": "template_engine", "test_families": ["template_injection"]}])
        row.close()
        start = fx.start(self.root)
        return start["campaign"]["id"]

    def test_one_call_produces_evidence_oracle_and_machine_finding(self):
        campaign_id = self._template_campaign()
        next_page = fx.dispatch(self.root, "campaign.next", {"project_id": "v2", "limit": 1})
        recipe_id = next_page["recipes"][0]["recipe"]["id"]
        transport = fx.Sequence([{"value": "AWA-NORMAL"}, {"value": "49"}, {"value": "AWA-NORMAL-2"}])
        with patch("awa_ddd.engine.request", side_effect=transport):
            result = fx.dispatch(self.root, "test.run", {"project_id": "v2", "campaign_id": campaign_id,
                                                          "recipe_id": recipe_id, "idempotency_key": "one"})
        self.assertEqual("supported", result["outcome"])
        self.assertEqual("machine_confirmed", result["finding"]["status"])
        self.assertEqual(result["run"]["id"], result["proof_receipt"]["run_id"])
        self.assertEqual(
            result["proof_receipt"]["id"],
            result["finding"]["proof_receipt_id"])
        self.assertEqual(3, len(result["dispatch_receipts"]))
        self.assertEqual(3, transport.calls)
        row = fx.project(self.root)
        self.assertEqual(3, len(row.list("evidence")))
        self.assertEqual("evaluated", row.list("v2_run")[0]["status"])
        self.assertEqual(1, len(row.list("v2_review_proof_receipt")))
        self.assertEqual(3, len(row.list("execution_dispatch")))
        for evidence in row.list("evidence"):
            self.assertNotEqual(
                result["run"]["id"], evidence["run_id"],
                "the V1 capture receipt must not be used as the V2 TestRun identity")
        row.close()

    def test_idempotency_key_never_replays_a_request(self):
        campaign_id = self._template_campaign()
        recipe_id = fx.dispatch(self.root, "campaign.next", {"project_id": "v2", "limit": 1})["recipes"][0]["recipe"]["id"]
        transport = fx.Sequence([{"value": "AWA-NORMAL"}, {"value": "49"}, {"value": "AWA-NORMAL-2"}])
        with patch("awa_ddd.engine.request", side_effect=transport):
            fx.dispatch(self.root, "test.run", {"project_id": "v2", "campaign_id": campaign_id,
                                                "recipe_id": recipe_id, "idempotency_key": "same"})
            calls = transport.calls
            again = fx.dispatch(self.root, "test.run", {"project_id": "v2", "campaign_id": campaign_id,
                                                        "recipe_id": recipe_id, "idempotency_key": "same"})
        self.assertEqual(calls, transport.calls)
        self.assertFalse(again["replayed"])

    def test_observe_mode_records_evidence_without_finding(self):
        campaign_id = self._template_campaign()
        recipe_id = fx.dispatch(self.root, "campaign.next", {"project_id": "v2", "limit": 1})["recipes"][0]["recipe"]["id"]
        transport = fx.Sequence([{"value": "AWA-NORMAL"}])
        with patch("awa_ddd.engine.request", side_effect=transport):
            result = fx.dispatch(self.root, "test.run", {"project_id": "v2", "campaign_id": campaign_id,
                                                          "recipe_id": recipe_id, "mode": "observe",
                                                          "idempotency_key": "observe"})
        self.assertEqual("observed", result["outcome"])
        self.assertIsNone(result.get("finding"))
        self.assertEqual(1, transport.calls)

    def test_multiple_write_controls_are_rejected_by_the_public_recipe_constructor(self):
        with self.assertRaises(EngineError) as caught:
            self._write_recipe(single_write=False)
        self.assertEqual("v2_recipe_write_budget", caught.exception.code)
        self.assertEqual(3, caught.exception.details["planned_writes"])
        self.assertEqual(1, caught.exception.details["max_writes"])
        row = fx.project(self.root)
        self.assertEqual([], row.list("v2_run"))
        self.assertEqual([], row.list("execution_dispatch"))
        self.assertEqual("leased", row.list("v2_fixture")[0]["state"])
        row.close()

    def test_public_single_write_executes_and_records_the_real_fixture_mutation(self):
        row, campaign_id, recipe, fixture, _hypothesis = self._write_recipe(single_write=True)
        row.close()
        calls = []

        def transport(url, method, headers, body, timeout, max_bytes):
            calls.append(1)
            wire = json.dumps(body).encode("utf-8") if isinstance(body, (dict, list)) else body
            return fx.observation(url, method, headers, wire, timeout, max_bytes, {"value": "49"})

        with patch("awa_ddd.engine.request", side_effect=transport):
            result = fx.dispatch(self.root, "test.run", {
                "project_id": "v2", "campaign_id": campaign_id,
                "recipe_id": recipe["id"], "idempotency_key": "public-single-write"})
        self.assertEqual("inconclusive", result["outcome"])
        self.assertIsNone(result["finding"])
        self.assertEqual(1, len(calls))
        self.assertEqual(1, len(result["dispatch_receipts"]))
        row = fx.project(self.root)
        current = Repository(row).get("fixture", fixture["id"])
        self.assertEqual("mutated", current["state"])
        self.assertEqual(1, len(current["mutations"]))
        effect = current["mutations"][0]["intended_effect"]
        self.assertEqual(result["run"]["evidence_ids"][0], effect["evidence_id"])
        self.assertEqual(result["dispatch_receipts"][0]["id"], effect["dispatch_receipt_id"])
        self.assertEqual("49", effect["actual"])
        self.assertEqual(current["fence"], current["mutations"][0]["fence"])
        row.close()
        offline = fx.dispatch(self.root, "test.run", {
            "project_id": "v2", "campaign_id": campaign_id,
            "recipe_id": recipe["id"], "run_id": result["run"]["id"],
            "mode": "verify", "idempotency_key": "verify-public-single-write"})
        self.assertEqual("inconclusive", offline["outcome"])
        self.assertEqual(0, offline["requests_sent"])
        self.assertEqual(result["run"]["id"], offline["verification_of_run_id"])

    def test_unknown_write_is_fenced_not_replayed_and_remains_reconcilable(self):
        row, campaign_id, recipe, fixture, hypothesis = self._write_recipe(single_write=True)
        row.close()
        transport = fx.Sequence([{"value": "unreachable"}])

        def disconnect(*_args):
            transport.calls += 1
            raise ConnectionError("connection dropped after submission")

        with patch("awa_ddd.engine.request", side_effect=disconnect):
            result = fx.dispatch(self.root, "test.run", {
                "project_id": "v2",
                "campaign_id": campaign_id,
                "recipe_id": recipe["id"],
                "idempotency_key": "unknown-write",
            })
            calls_after_unknown = transport.calls
            replay = fx.dispatch(self.root, "test.run", {
                "project_id": "v2",
                "campaign_id": campaign_id,
                "recipe_id": recipe["id"],
                "idempotency_key": "unknown-write",
            })
        self.assertEqual("effect_unknown", result["outcome"])
        self.assertTrue(result["requires_reconciliation"])
        self.assertEqual(1, len(result["dispatch_receipts"]))
        self.assertEqual(1, calls_after_unknown)
        self.assertEqual(calls_after_unknown, transport.calls)
        self.assertFalse(replay["replayed"])
        self.assertEqual("effect_unknown", replay["run"]["status"])
        row = fx.project(self.root)
        runs = row.list("v2_run")
        dispatches = row.list("execution_dispatch")
        self.assertEqual(1, len(runs))
        self.assertEqual("effect_unknown", runs[0]["status"])
        self.assertTrue(runs[0]["effect"]["unknown"])
        self.assertEqual([dispatches[0]["id"]], runs[0]["dispatch_receipt_ids"])
        self.assertEqual(
            {"max_requests": 1, "max_writes": 1,
             "requests_used": 1, "writes_used": 1},
            runs[0]["dispatch_budget"])
        self.assertEqual("blocked", Repository(row).get("hypothesis", hypothesis["id"])["status"])
        inspected = fx.dispatch(self.root, "test.inspect", {
            "project_id": "v2", "run_id": runs[0]["id"]})
        self.assertEqual("effect_unknown", inspected["run"]["status"])
        self.assertEqual(recipe["id"], inspected["recipe"]["id"])
        self.assertIs(False, inspected["recipe"]["executable"])
        fixture_row = Repository(row).get("fixture", fixture["id"])
        self.assertEqual("leased", fixture_row["state"])
        self.assertEqual(runs[0]["id"], fixture_row["in_flight"]["run_id"])
        with self.assertRaises(EngineError) as cleanup:
            fx.dispatch(self.root, "test.fixture_cleanup", {
                "project_id": "v2", "fixture_id": fixture["id"],
                "worker_id": "local", "succeeded": False,
            })
        self.assertEqual("v2_fixture_state", cleanup.exception.code)
        row.close()

    def _write_recipe(self, *, single_write=True):
        row = fx.project(self.root)
        operation = fx.register(row, "http://fixture.invalid/write", "POST", "public", [
            {"name": "id", "location": "body", "selector": "id", "consumer": "resource_reference"},
            {"name": "label", "location": "body", "selector": "label",
             "consumer": "template_engine", "test_families": ["template_injection"]}])
        engine.add_actor(row, {"actor_id": "alice", "subject": "alice", "roles": []})
        resource = engine.add_resource(row, {"operation_id": operation["id"], "owner_actor_id": "alice",
                                             "external_id": "7", "request_binding": {"location": "body", "selector": "id"}})
        engine.update_project(row, {"allow_mutation": True})
        campaign = fx.start(self.root)
        campaign_id = campaign["campaign"]["id"]
        universe = Repository(row).get("universe", Repository(row).get("campaign", campaign_id)["universe_id"])
        target_build = universe["target_build"]
        fixture = fixtures.create(row, operation_id=operation["id"], owner_actor_id="alice",
                                  resource_id=resource["id"], initial_state={"label": "AWA-NORMAL"},
                                  cleanup_plan={"reset": True})
        fixtures.verify(row, fixture["id"], observed_state={"label": "AWA-NORMAL"})
        fixtures.lease(row, fixture["id"], worker_id="local", ttl_seconds=60)
        fixture = Repository(row).get("fixture", fixture["id"])
        hypothesis = new_hypothesis(
            family="template_injection", security_property="unexpected_expression_evaluation",
            operation_id=operation["id"], input_key=None, scope_epoch=campaign["campaign"]["scope_epoch"],
            target_build=target_build, source_kind="declared_family", statement="write expression",
            campaign_id=campaign_id,
            universe_id=Repository(row).get("campaign", campaign_id)["universe_id"])
        Repository(row).add("hypothesis", hypothesis, immutable=False)
        controls = [
            {"id": "normal", "role": "normal", "request": {"url": "http://fixture.invalid/write", "method": "POST", "body": {"id": "7", "label": "AWA-NORMAL"}},
             "expected": {"selector": "/value", "value": "AWA-NORMAL"}},
            {"id": "attack", "role": "attack", "request": {"url": "http://fixture.invalid/write", "method": "POST", "body": {"id": "7", "label": "7*7"}},
             "expected": {"selector": "/value", "value": "49"}},
            {"id": "negative", "role": "negative", "request": {"url": "http://fixture.invalid/write", "method": "POST", "body": {"id": "7", "label": "AWA-NORMAL-2"}},
             "expected": {"selector": "/value", "value": "AWA-NORMAL-2"}},
        ]
        group = {"id": "primary", "identity_role": "alice", "controls": controls}
        limits = {"step_total": 3, "time_ms": 10000, "max_writes": 1,
                  "effect": "test_resource_write"}
        if single_write:
            group["execution_strategy"] = "single_write_attack_only"
            limits["control_strategy"] = "single_write_attack_only"
            for control in controls:
                control["dispatch"] = control["role"] == "attack"
        bindings = {"scope_epoch": campaign["campaign"]["scope_epoch"], "target_build": target_build,
                    "operation_id": operation["id"], "operation_signature": engine.operation_signature(operation),
                    "session": None, "resource": {"resource_id": resource["id"], "revision": resource.get("revision", 1)},
                    "fixture": {"fixture_id": fixture["id"], "revision": fixture["revision"]}}
        try:
            recipe = new_recipe(
                hypothesis=hypothesis, provider={"name": "http", "profile": "native_http_fixture_write", "version": "1"},
                bindings=bindings, control_groups=[group],
                oracle={"id": "OR-1", "type": "unexpected_expression_evaluation", "version": "1",
                        "proof_scope": "unexpected_expression_evaluation", "selector": "/value", "expected_value": "49"},
                steps=["write"], limits=limits,
                variables={"label": {"source": "caller"}},
                private_manifest={"control_groups": [group], "bindings": bindings},
                campaign_id=campaign_id, universe_id=universe["id"])
        except Exception:
            row.close()
            raise
        Repository(row).add("recipe", recipe, immutable=True)
        return row, campaign_id, recipe, fixture, hypothesis


if __name__ == "__main__":
    unittest.main()
