"""2.0 frozen recipes, durable runs and oracle proof-scope regressions."""
from __future__ import annotations

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
        fixture = fixtures.create(row, operation_id="O-1", owner_actor_id="alice",
                                  resource_id="R-1", initial_state={"v": 1}, cleanup_plan={})
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
        self.assertEqual(3, transport.calls)
        row = fx.project(self.root)
        self.assertEqual(3, len(row.list("evidence")))
        self.assertEqual("evaluated", row.list("v2_run")[0]["status"])
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

    def test_unknown_write_is_effect_unknown_and_not_replayed(self):
        row = fx.project(self.root)
        operation = fx.register(row, "http://fixture.invalid/write", "POST", "public", [
            {"name": "id", "location": "body", "selector": "id", "consumer": "resource_reference"},
            {"name": "label", "location": "body", "selector": "label",
             "consumer": "template_engine", "test_families": ["template_injection"]}])
        actor = engine.add_actor(row, {"actor_id": "alice", "subject": "alice", "roles": []})
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
            target_build=target_build, source_kind="declared_family", statement="write expression")
        Repository(row).add("hypothesis", hypothesis, immutable=False)
        recipe = new_recipe(
            hypothesis=hypothesis, provider={"name": "http", "profile": "native_http_fixture_write", "version": "1"},
            bindings={"scope_epoch": campaign["campaign"]["scope_epoch"], "target_build": target_build,
                      "operation_id": operation["id"], "operation_signature": engine.operation_signature(operation),
                      "session": None, "resource": {"resource_id": resource["id"], "revision": resource.get("revision", 1)},
                      "fixture": {"fixture_id": fixture["id"], "revision": fixture["revision"]}},
            control_groups=[{"id": "primary", "identity_role": "alice", "controls": [
                {"id": "normal", "role": "normal", "request": {"url": "http://fixture.invalid/write", "method": "POST", "body": {"id": "7", "label": "AWA-NORMAL"}},
                 "expected": {"selector": "/value", "value": "AWA-NORMAL"}},
                {"id": "attack", "role": "attack", "request": {"url": "http://fixture.invalid/write", "method": "POST", "body": {"id": "7", "label": "7*7"}},
                 "expected": {"selector": "/value", "value": "49"}},
                {"id": "negative", "role": "negative", "request": {"url": "http://fixture.invalid/write", "method": "POST", "body": {"id": "7", "label": "AWA-NORMAL-2"}},
                 "expected": {"selector": "/value", "value": "AWA-NORMAL-2"}},
            ]}],
            oracle={"id": "OR-1", "type": "unexpected_expression_evaluation", "version": "1",
                    "proof_scope": "unexpected_expression_evaluation", "selector": "/value", "expected_value": "49"},
            steps=["write"], limits={"step_total": 3, "time_ms": 10000, "max_writes": 1,
                                      "effect": "test_resource_write"},
            variables={"label": {"source": "caller"}},
            private_manifest={"control_groups": [{"id": "primary", "identity_role": "alice", "controls": [
                {"id": "normal", "role": "normal", "request": {"url": "http://fixture.invalid/write", "method": "POST", "body": {"id": "7", "label": "AWA-NORMAL"}},
                 "expected": {"selector": "/value", "value": "AWA-NORMAL"}},
                {"id": "attack", "role": "attack", "request": {"url": "http://fixture.invalid/write", "method": "POST", "body": {"id": "7", "label": "7*7"}},
                 "expected": {"selector": "/value", "value": "49"}},
                {"id": "negative", "role": "negative", "request": {"url": "http://fixture.invalid/write", "method": "POST", "body": {"id": "7", "label": "AWA-NORMAL-2"}},
                 "expected": {"selector": "/value", "value": "AWA-NORMAL-2"}},
            ]}]})
        Repository(row).add("recipe", recipe, immutable=True)
        row.close()
        with patch("awa_ddd.engine.request", side_effect=OSError("connection dropped after dispatch")):
            result = fx.dispatch(self.root, "test.run", {"project_id": "v2", "campaign_id": campaign_id,
                                                          "recipe_id": recipe["id"], "idempotency_key": "write-one"})
        self.assertEqual("effect_unknown", result["outcome"])
        row = fx.project(self.root)
        run_row = row.list("v2_run")[0]
        self.assertEqual("effect_unknown", run_row["status"])
        self.assertTrue(run_row["effect"]["unknown"])
        row.close()


if __name__ == "__main__":
    unittest.main()
