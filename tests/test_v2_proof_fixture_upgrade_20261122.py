"""Regression coverage for strict V2 proof binding and fenced fixtures."""
from __future__ import annotations

import threading
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import v2_fixtures as fx
from awa_ddd import engine
from awa_ddd.domain.repository import Repository
from awa_ddd.domain.test_recipe import render
from awa_ddd.execution import fixtures, oracle_profiles, recipe_builder, review_engine, test_runner
from awa_ddd.store import EngineError


class PersistedRunVerifyTests(unittest.TestCase):
    def setUp(self):
        self.temporary, self.root = fx.workspace()
        self.addCleanup(self.temporary.cleanup)
        row = fx.project(self.root)
        self.operation = fx.register(row, "http://fixture.invalid/render", "GET", "public", [
            {"name": "label", "location": "query", "selector": "label",
             "consumer": "template_engine", "test_families": ["template_injection"]}])
        row.close()
        self.campaign_id = fx.start(self.root)["campaign"]["id"]
        self.recipe_id = fx.dispatch(self.root, "campaign.next", {
            "project_id": "v2", "limit": 1})["recipes"][0]["recipe"]["id"]
        transport = fx.Sequence([
            {"value": "AWA-NORMAL"}, {"value": "49"}, {"value": "AWA-NORMAL-2"},
        ])
        with patch("awa_ddd.engine.request", side_effect=transport):
            self.original = fx.dispatch(self.root, "test.run", {
                "project_id": "v2", "campaign_id": self.campaign_id,
                "recipe_id": self.recipe_id, "idempotency_key": "bound-source"})
        self.project = fx.project(self.root)
        self.addCleanup(self.project.close)
        self.repository = Repository(self.project)

    def _args(self, **changes):
        args = {
            "campaign_id": self.campaign_id,
            "recipe_id": self.recipe_id,
            "run_id": self.original["run"]["id"],
            "mode": "verify",
            "idempotency_key": "strict-offline-verify",
        }
        args.update(changes)
        return args

    def _assert_rejected_without_new_authority(self, args, *, legacy=None):
        before_runs = len(self.project.list("v2_run"))
        before_findings = len(self.project.list("v2_finding"))
        with self.assertRaises(EngineError) as caught:
            test_runner.run(self.project, args)
        self.assertEqual("v2_run_verify", caught.exception.code)
        self.assertFalse(caught.exception.details["finding_created"])
        self.assertEqual(0, caught.exception.details["requests_sent"])
        if legacy is not None:
            self.assertEqual(legacy, caught.exception.details["legacy"])
        self.assertEqual(before_runs, len(self.project.list("v2_run")))
        self.assertEqual(before_findings, len(self.project.list("v2_finding")))
        return caught.exception

    def _replace_attack_evidence(self, evidence_id):
        prior = self.repository.get("run", self.original["run"]["id"])
        evidence = self.project.get("evidence", evidence_id)
        prior["evidence_ids"][1] = evidence_id
        prior["steps"][1]["evidence_id"] = evidence_id
        prior["steps"][1]["response_digest"] = evidence["sha256"]
        self.repository.save("run", prior)

    def test_verify_uses_the_persisted_run_without_index_rebinding_or_traffic(self):
        with patch("awa_ddd.engine.request", side_effect=AssertionError("network used")):
            result = test_runner.run(self.project, self._args())
        self.assertEqual("supported", result["outcome"])
        self.assertEqual(0, result["requests_sent"])
        self.assertEqual(self.original["run"]["id"], result["verification_of_run_id"])
        self.assertEqual(3, len(result["control_bindings"]))
        self.assertEqual(
            ["normal", "attack", "negative"],
            [row["control_id"] for row in result["control_bindings"]])
        stored = self.repository.get("run", result["run"]["id"])
        self.assertEqual("verified", stored["binding_status"])
        self.assertEqual(self.original["run"]["id"], stored["verification_of_run_id"])

    def test_bare_evidence_and_legacy_steps_are_unverified(self):
        self._assert_rejected_without_new_authority(self._args(
            run_id=None, evidence_ids=self.original["run"]["evidence_ids"]))
        prior = self.repository.get("run", self.original["run"]["id"])
        prior["steps"] = []
        self.repository.save("run", prior)
        error = self._assert_rejected_without_new_authority(
            self._args(idempotency_key="legacy-steps"), legacy=True)
        self.assertEqual("legacy_unverified", error.details["binding_status"])

    def test_unrelated_evidence_url_is_rejected(self):
        with patch("awa_ddd.engine.request", side_effect=fx.Sequence([{"value": "49"}])):
            unrelated = engine.capture(self.project, {
                "operation_id": self.operation["id"],
                "url": self.operation["url"] + "?label=unrelated",
                "idempotency_key": "unrelated-url-evidence",
            })
        self._replace_attack_evidence(unrelated["id"])
        self._assert_rejected_without_new_authority(
            self._args(idempotency_key="wrong-url"))

    def test_unrelated_evidence_identity_is_rejected(self):
        original = self.project.get(
            "evidence", self.original["run"]["evidence_ids"][1])
        forged = dict(original)
        forged["id"] = self.project.id("E")
        forged["actor_id"] = "mallory"
        forged["actor_signature"] = None
        self.project.put("evidence", forged, create_only=True)
        self._replace_attack_evidence(forged["id"])
        self._assert_rejected_without_new_authority(
            self._args(idempotency_key="wrong-identity"))

    def test_unrelated_evidence_resource_is_rejected(self):
        engine.add_actor(self.project, {
            "actor_id": "alice", "subject": "alice", "roles": []})
        resource = engine.add_resource(self.project, {
            "operation_id": self.operation["id"], "owner_actor_id": "alice",
            "external_id": "7*7",
            "request_binding": {"location": "query", "selector": "label"},
        })
        original = self.project.get(
            "evidence", self.original["run"]["evidence_ids"][1])
        forged = dict(original)
        forged["id"] = self.project.id("E")
        forged["resource_id"] = resource["id"]
        forged["resource_signature"] = engine.resource_signature(resource)
        self.project.put("evidence", forged, create_only=True)
        self._replace_attack_evidence(forged["id"])
        self._assert_rejected_without_new_authority(
            self._args(idempotency_key="wrong-resource"))


class FirstRunEvidenceReuseTests(unittest.TestCase):
    def test_existing_native_evidence_cannot_be_adopted_by_a_new_v2_run(self):
        temporary, root = fx.workspace()
        self.addCleanup(temporary.cleanup)
        project = fx.project(root)
        operation = fx.register(project, "http://fixture.invalid/render", "GET", "public", [
            {"name": "label", "location": "query", "selector": "label",
             "consumer": "template_engine", "test_families": ["template_injection"]}])
        project.close()
        campaign_id = fx.start(root)["campaign"]["id"]
        recipe_id = fx.dispatch(root, "campaign.next", {
            "project_id": "v2", "limit": 1})["recipes"][0]["recipe"]["id"]
        project = fx.project(root)
        recipe = Repository(project).get("recipe", recipe_id)
        transport = fx.Sequence([
            {"value": "AWA-NORMAL"}, {"value": "49"}, {"value": "AWA-NORMAL-2"},
        ])
        with patch("awa_ddd.engine.request", side_effect=transport):
            for control in recipe["control_groups"][0]["controls"]:
                engine.capture(project, {
                    "operation_id": operation["id"], "url": control["request"]["url"],
                    "idempotency_key": "reuse:" + control["role"],
                })
        self.assertEqual(3, transport.calls)
        with self.assertRaises(EngineError) as caught:
            fx.dispatch(root, "test.run", {
                "project_id": "v2", "campaign_id": campaign_id, "recipe_id": recipe_id,
                "idempotency_key": "reuse",
            })
        self.assertEqual("idempotency_conflict", caught.exception.code)
        self.assertEqual(3, transport.calls)
        self.assertEqual([], project.list("v2_finding"))
        self.assertEqual([], project.list("v2_review_proof_receipt"))
        project.close()


class FixtureConcurrencyTests(unittest.TestCase):
    def test_two_connections_cannot_acquire_or_transition_the_same_fence(self):
        temporary, root = fx.workspace()
        self.addCleanup(temporary.cleanup)
        first = fx.project(root)
        second = fx.project(root)
        self.addCleanup(first.close)
        self.addCleanup(second.close)
        operation = fx.register(first, "http://fixture.invalid/write", "POST", "public", [
            {"name": "id", "location": "body", "selector": "id",
             "consumer": "resource_reference"}])
        engine.add_actor(first, {"actor_id": "alice", "subject": "alice", "roles": []})
        resource = engine.add_resource(first, {
            "operation_id": operation["id"], "owner_actor_id": "alice",
            "external_id": "7", "request_binding": {"location": "body", "selector": "id"}})
        fixture = fixtures.create(
            first, operation_id=operation["id"], owner_actor_id="alice",
            resource_id=resource["id"], initial_state={"v": 1}, cleanup_plan={})
        fixtures.verify(first, fixture["id"], observed_state={"v": 1})

        barrier = threading.Barrier(2)
        outcomes = []

        def acquire(project, worker):
            barrier.wait()
            try:
                row = fixtures.lease(project, fixture["id"], worker_id=worker, ttl_seconds=60)
                outcomes.append(("acquired", worker, row))
            except EngineError as exc:
                outcomes.append(("rejected", worker, exc))

        threads = [
            threading.Thread(target=acquire, args=(first, "worker-a")),
            threading.Thread(target=acquire, args=(second, "worker-b")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(2, len(outcomes))
        acquired = [row for row in outcomes if row[0] == "acquired"]
        rejected = [row for row in outcomes if row[0] == "rejected"]
        self.assertEqual(1, len(acquired))
        self.assertEqual(1, len(rejected))
        self.assertEqual("v2_fixture_lease", rejected[0][2].code)
        winner, loser = acquired[0][1], rejected[0][1]
        leased = acquired[0][2]
        self.assertEqual(1, leased["fence"])
        self.assertEqual(leased["fence"], leased["lease"]["fence"])

        winner_project = first if winner == "worker-a" else second
        loser_project = first if loser == "worker-a" else second
        with self.assertRaises(EngineError):
            fixtures.mutate(loser_project, fixture["id"], worker_id=loser,
                            intended_effect={"v": 2})
        mutated = fixtures.mutate(
            winner_project, fixture["id"], worker_id=winner,
            intended_effect={"v": 2})
        expected = mutated["current_state"]
        readback = fixtures.readback(
            winner_project, fixture["id"], observed_state=expected,
            expected_state=expected)
        self.assertEqual("readback_ok", readback["state"])
        self.assertEqual(leased["fence"], readback["readback"]["fence"])
        with self.assertRaises(EngineError):
            fixtures.cleanup(loser_project, fixture["id"], worker_id=loser, succeeded=True)
        cleaned = fixtures.cleanup(
            winner_project, fixture["id"], worker_id=winner, succeeded=True,
            observed_state={"v": 1})
        self.assertEqual("cleaned", cleaned["state"])
        self.assertEqual(leased["fence"], cleaned["fence"])
        with self.assertRaises(EngineError):
            fixtures.mutate(loser_project, fixture["id"], worker_id=loser,
                            intended_effect={"v": 3})


class AutomaticWriteBudgetTests(unittest.TestCase):
    def test_automatic_write_recipe_dispatches_one_explicit_attack_and_marks_other_controls_unobserved(self):
        temporary, root = fx.workspace(allow_mutation=True)
        self.addCleanup(temporary.cleanup)
        project = fx.project(root)
        self.addCleanup(project.close)
        operation = fx.register(project, "http://fixture.invalid/write", "POST", "public", [
            {"name": "id", "location": "body", "selector": "id", "consumer": "resource_reference"},
            {"name": "label", "location": "body", "selector": "label",
             "consumer": "template_engine", "test_families": ["template_injection"]}])
        engine.add_actor(project, {"actor_id": "alice", "subject": "alice", "roles": []})
        resource = engine.add_resource(project, {
            "operation_id": operation["id"], "owner_actor_id": "alice",
            "external_id": "7", "request_binding": {"location": "body", "selector": "id"}})
        campaign_id = fx.start(root)["campaign"]["id"]
        repository = Repository(project)
        campaign = repository.get("campaign", campaign_id)
        universe = repository.get("universe", campaign["universe_id"])
        fixture = fixtures.create(
            project, operation_id=operation["id"], owner_actor_id="alice",
            resource_id=resource["id"], initial_state={"label": "AWA-NORMAL"},
            cleanup_plan={})
        fixtures.verify(project, fixture["id"], observed_state={"label": "AWA-NORMAL"})
        fixtures.lease(project, fixture["id"], worker_id="local", ttl_seconds=60)
        hypothesis = next(row for row in repository.list_campaign(
            "hypothesis", campaign_id, limit=None)[0]
            if row.get("operation_id") == operation["id"]
            and row.get("family") == "template_injection")
        built = recipe_builder.build(project, campaign, universe, hypothesis)
        self.assertEqual("ready", built["status"])
        recipe = built["recipe"]
        self.assertEqual("single_write_attack_only", recipe["limits"]["control_strategy"])
        planned = [control for group in recipe["control_groups"]
                   for control in group["controls"] if control.get("dispatch", True)]
        self.assertEqual(["attack"], [control["role"] for control in planned])
        repository.add("recipe", recipe, immutable=True)
        transport = fx.Sequence([{"value": "49"}])
        with patch("awa_ddd.engine.request", side_effect=transport):
            result = fx.dispatch(root, "test.run", {
                "project_id": "v2", "campaign_id": campaign_id, "recipe_id": recipe["id"],
                "idempotency_key": "automatic-single-write", "worker_id": "local",
            })
        self.assertEqual(1, transport.calls)
        self.assertEqual("inconclusive", result["outcome"])
        self.assertEqual(1, len(result["run"]["evidence_ids"]))
        self.assertEqual("mutated", fixtures._get(project, fixture["id"])["state"])
        steps = result["run"]["steps"]
        self.assertEqual(["attack"], [step["step_id"] for step in steps])


class FixtureResourceBindingTests(unittest.TestCase):
    def test_builder_does_not_mix_one_resource_with_another_resources_fixture(self):
        temporary, root = fx.workspace(allow_mutation=True)
        self.addCleanup(temporary.cleanup)
        project = fx.project(root)
        self.addCleanup(project.close)
        operation = fx.register(project, "http://fixture.invalid/write", "POST", "public", [
            {"name": "id", "location": "body", "selector": "id", "consumer": "resource_reference"},
            {"name": "label", "location": "body", "selector": "label",
             "consumer": "template_engine", "test_families": ["template_injection"]}])
        engine.add_actor(project, {"actor_id": "alice", "subject": "alice", "roles": []})
        first = engine.add_resource(project, {
            "operation_id": operation["id"], "owner_actor_id": "alice", "external_id": "resource-a",
            "request_binding": {"location": "body", "selector": "id"}})
        second = engine.add_resource(project, {
            "operation_id": operation["id"], "owner_actor_id": "alice", "external_id": "resource-b",
            "request_binding": {"location": "body", "selector": "id"}})
        campaign_id = fx.start(root)["campaign"]["id"]
        repository = Repository(project)
        campaign = repository.get("campaign", campaign_id)
        universe = repository.get("universe", campaign["universe_id"])
        selected_resource = recipe_builder._resource(project, operation, None)
        other_resource = second if selected_resource["id"] == first["id"] else first
        fixture_b = fixtures.create(
            project, operation_id=operation["id"], owner_actor_id="alice",
            resource_id=other_resource["id"], initial_state={"label": "AWA-NORMAL"}, cleanup_plan={})
        fixtures.verify(project, fixture_b["id"], observed_state={"label": "AWA-NORMAL"})
        fixtures.lease(project, fixture_b["id"], worker_id="local", ttl_seconds=60)
        hypothesis = next(row for row in repository.list_campaign(
            "hypothesis", campaign_id, limit=None)[0]
            if row.get("operation_id") == operation["id"]
            and row.get("family") == "template_injection")
        built = recipe_builder.build(project, campaign, universe, hypothesis)
        self.assertEqual("blocked", built["status"])
        self.assertIn("owned_test_fixture", built["missing"])
        self.assertEqual(selected_resource["id"], recipe_builder._resource(project, operation, None)["id"])
        self.assertNotEqual(selected_resource["id"], fixture_b["resource_id"])
        self.assertEqual([], project.list("execution_dispatch"))


class RequestEncodingTests(unittest.TestCase):
    def test_sql_query_payload_is_component_encoded_and_round_trips_exactly(self):
        payload = "AWA' OR '1'='1"
        request = recipe_builder._request_for(
            {"url": "http://fixture.invalid/search?fixed=1", "method": "GET"},
            {"name": "q", "selector": "q", "location": "query"},
            payload,
        )
        normalized = engine.require_scope(
            {"scope": ["http://fixture.invalid/"], "exclude": []}, request["url"])
        self.assertNotIn(" OR ", normalized)
        query = parse_qs(urlsplit(normalized).query)
        self.assertEqual([payload], query["q"])
        self.assertEqual(["1"], query["fixed"])

    def test_query_override_cannot_inject_another_parameter(self):
        recipe = {
            "variables": {"label": {"source": "caller", "max_length": 64}},
            "private_capsule": {"control_groups": [{"controls": [{
                "request": {"url": "http://fixture.invalid/search?q={{label}}", "method": "GET"},
            }]}]},
        }
        rendered = render(recipe, {"label": "x&role=admin#fragment"})
        url = rendered["control_groups"][0]["controls"][0]["request"]["url"]
        query = parse_qs(urlsplit(url).query)
        self.assertEqual(["x&role=admin#fragment"], query["q"])
        self.assertNotIn("role", query)
        self.assertNotIn("fragment", query)


class GenericReviewChannelTests(unittest.TestCase):
    def setUp(self):
        self.temporary, self.root = fx.workspace()
        self.addCleanup(self.temporary.cleanup)
        row = fx.project(self.root)
        self.operation = fx.register(row, "http://fixture.invalid/search", "GET", "public", [
            {"name": "q", "location": "query", "selector": "q",
             "consumer": "business_input", "test_families": ["generic"]}])
        row.close()
        self.campaign_id = fx.start(self.root)["campaign"]["id"]
        selected = fx.dispatch(self.root, "campaign.next", {
            "project_id": "v2", "limit": 1})["recipes"][0]
        self.recipe_id = selected["recipe"]["id"]
        transport = fx.Sequence([
            {"count": "plain"}, {"count": "attack"}, {"count": "negative"},
        ])
        with patch("awa_ddd.engine.request", side_effect=transport):
            self.run = fx.dispatch(self.root, "test.run", {
                "project_id": "v2", "campaign_id": self.campaign_id,
                "recipe_id": self.recipe_id, "idempotency_key": "generic-review-source"})
        self.project = fx.project(self.root)
        self.addCleanup(self.project.close)
        self.repository = Repository(self.project)
        self.hypothesis_id = self.run["run"]["hypothesis_id"]
        ids = self.run["run"]["evidence_ids"]
        attack_artifact = self.project.read_artifact(self.project.get("evidence", ids[1]))
        self.args = {
            "campaign_id": self.campaign_id,
            "hypothesis_id": self.hypothesis_id,
            "run_id": self.run["run"]["id"],
            "evidence_ids": ids,
            "control_groups": [{
                "id": "primary", "identity_role": "anonymous",
                "controls": [
                    {"id": "normal", "role": "normal", "evidence_id": ids[0]},
                    {"id": "attack", "role": "attack", "evidence_id": ids[1]},
                    {"id": "negative", "role": "negative", "evidence_id": ids[2]},
                ],
            }],
            "observation": {"selector": "/count", "expected": "attack"},
            "consumer_point": {
                "type": "http_json", "url": attack_artifact["request"]["url"],
                "identity_role": "anonymous",
            },
            "source_trust": {"kind": "self-declared", "trust": "verified"},
            "reviewer": {"type": "analyst_recorded", "id": "reviewer-1", "source": "test"},
            "proof_scope": {"accepted": ["other"], "not_proven": ["machine proof"]},
            "material": {"evidence_ids": ids},
            "verification": {"version": "1", "method": "manual_review"},
            "reason": "The current attack control contains the declared observation.",
        }

    def _assert_no_review_authority(self, args, code):
        with self.assertRaises(EngineError) as caught:
            review_engine.accept(self.project, args)
        self.assertEqual(code, caught.exception.code)
        self.assertEqual([], self.project.list("v2_review"))
        self.assertEqual([], self.project.list("v2_review_proof_receipt"))
        self.assertEqual([], self.project.list("v2_finding"))

    def test_generic_review_derives_actual_source_and_identity(self):
        result = review_engine.accept(self.project, self.args)
        self.assertFalse(result["machine_proof"])
        self.assertFalse(result["reviewer_independent"])
        self.assertEqual("reviewed", result["finding"]["mode"])
        self.assertEqual("attack", result["review"]["observation"]["actual"])
        self.assertEqual("current_run_evidence", result["review"]["source_trust"]["kind"])
        self.assertEqual("verified", result["review"]["source_trust"]["trust"])
        self.assertEqual(
            self.run["run"]["evidence_ids"][1],
            result["review"]["observation"]["evidence_id"])

    def test_generic_reviewer_and_actual_injection_are_rejected(self):
        for reviewer in (
                {"type": "human_independent", "id": "mallory", "source": "self"},
                {"type": "analyst_recorded", "id": "mallory", "source": "self",
                 "independent_human": True}):
            with self.subTest(reviewer=reviewer):
                self._assert_no_review_authority(
                    {**self.args, "reviewer": reviewer}, "v2_review_reviewer")
        self._assert_no_review_authority({
            **self.args,
            "observation": {"selector": "/count", "expected": "attack", "actual": "forged"},
        }, "v2_review_observation")

    def test_generic_control_evidence_must_belong_to_the_run(self):
        with patch("awa_ddd.engine.request", side_effect=fx.Sequence([{"value": "outside"}])):
            outside = engine.capture(self.project, {
                "operation_id": self.operation["id"],
                "url": self.operation["url"] + "?q=outside",
                "idempotency_key": "outside-generic-review",
            })
        groups = [{
            **self.args["control_groups"][0],
            "controls": [dict(control) for control in self.args["control_groups"][0]["controls"]],
        }]
        groups[0]["controls"][2]["evidence_id"] = outside["id"]
        self._assert_no_review_authority(
            {**self.args, "control_groups": groups}, "v2_review_material")


class OracleFieldConsistencyTests(unittest.TestCase):
    def test_reflection_exclusion_is_the_field_actually_evaluated(self):
        extraction = oracle_profiles.evaluate("extraction", {
            "normal_value": "normal", "attack_value": "secret",
            "expected_extraction": "secret", "extraction_matched": True,
            "reflection_exclusion": True,
        })
        side_effect = oracle_profiles.evaluate("bounded_side_effect", {
            "normal_control": False, "attack_canary": True, "negative_control": False,
            "isolated_canary": True, "reflection_exclusion": True,
            "timing_not_sole_evidence": True,
        })
        self.assertEqual("supported", extraction["outcome"])
        self.assertEqual("supported", side_effect["outcome"])


if __name__ == "__main__":
    unittest.main()
