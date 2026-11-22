"""Unknown effects clear only through the exact retained dispatch or readback."""
from __future__ import annotations

from copy import deepcopy
import unittest
from unittest.mock import patch

import test_continuation_20261030 as fixtures
import test_v2_recipe_runner_20261103 as v2_cases
import v2_fixtures as v2
from awa_ddd import continuation, engine, execution_coordinator as coordinator
from awa_ddd.execution import test_runner
from awa_ddd.store import EngineError, now


class ReadbackRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ContinuationTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.project = self.fixture.project

    def interrupted_write(self):
        operation, resource, run = self.fixture.write_fixture()
        run.update(status="effect_unknown", effect_unknown=True, remote_state_unknown=True)
        self.project.put("run", run)
        self.project.connection.execute("UPDATE execution_leases SET expires_at=0")
        return operation, resource, run

    def readback(self, source, *, owner="alice", external_id="7", response=None, earlier=False):
        if owner != "alice":
            engine.add_actor(self.project, {"actor_id": owner, "subject": owner, "roles": []})
        operation = self.fixture.register("/readback", inputs=[
            {"name": "id", "location": "query", "consumer": "resource_reference"}])
        resource = engine.add_resource(self.project, {
            "operation_id": operation["id"], "owner_actor_id": owner, "external_id": external_id,
            "request_binding": {"location": "query", "selector": "id"}})
        payload = {"balance": 10} if response is None else response
        def observed(*args):
            value = fixtures.observation(*args, payload)
            if earlier:
                value["started_at"] = "2000-01-01T00:00:00+00:00"
            return value
        with patch.object(engine, "request", side_effect=observed):
            evidence = engine.capture(self.project, {"operation_id": operation["id"], "resource_id": resource["id"],
                                                      "url": operation["url"] + "?id=" + external_id})
        binding = {"source_resource_id": source["id"], "resource_id": resource["id"],
                   "relation": "Read back the exact fixture balance", "selector": "/balance", "expected": 10}
        return evidence, binding

    def test_matching_business_state_releases_the_fence_without_replay_or_proof(self):
        _, resource, run = self.interrupted_write()
        evidence, binding = self.readback(resource)
        before_dispatches = len(self.project.list("execution_dispatch"))
        with patch.object(engine, "request", side_effect=AssertionError("recovery replayed a request")):
            recovered = coordinator.reconcile(self.project, {"run_id": run["id"], "evidence_ids": [evidence["id"]],
                                                              "readback_bindings": [binding]})
            repeated = coordinator.reconcile(self.project, {"run_id": run["id"], "evidence_ids": [evidence["id"]],
                                                             "readback_bindings": [binding]})
        self.assertTrue(recovered["lease_released"])
        self.assertEqual(0, recovered["requests_sent"])
        self.assertEqual(0, recovered["requests_replayed"])
        self.assertEqual(recovered["reconciliation_id"], repeated["reconciliation_id"])
        self.assertEqual("interrupted", self.project.get("run", run["id"])["status"])
        self.assertEqual(before_dispatches, len(self.project.list("execution_dispatch")))
        self.assertEqual([], self.project.list("decision"))
        self.assertEqual([], self.project.list("finding"))
        self.assertEqual(1, len(self.project.list("execution_reconciliation")))

    def test_wrong_owner_or_external_id_cannot_reconcile_the_fixture(self):
        _, source, run = self.interrupted_write()
        for owner, identity in (("bob", "7"), ("alice", "8")):
            with self.subTest(owner=owner, identity=identity):
                evidence, binding = self.readback(source, owner=owner, external_id=identity)
                with self.assertRaises(EngineError) as caught:
                    coordinator.reconcile(self.project, {"run_id": run["id"], "evidence_ids": [evidence["id"]],
                                                          "readback_bindings": [binding]})
                self.assertEqual("reconciliation_context", caught.exception.code)
        self.assertEqual([], self.project.list("execution_reconciliation"))
        self.assertTrue(self.project.get("run", run["id"])["effect_unknown"])

    def test_earlier_observation_or_success_flag_cannot_establish_business_state(self):
        _, source, run = self.interrupted_write()
        earlier, binding = self.readback(source, earlier=True)
        with self.assertRaises(EngineError):
            coordinator.reconcile(self.project, {"run_id": run["id"], "evidence_ids": [earlier["id"]],
                                                  "readback_bindings": [binding]})
        ordinary, binding = self.readback(source, response={"success": True})
        binding.update(selector="/success", expected=True)
        with self.assertRaises(EngineError):
            coordinator.reconcile(self.project, {"run_id": run["id"], "evidence_ids": [ordinary["id"]],
                                                  "readback_bindings": [binding]})
        self.assertEqual([], self.project.list("execution_reconciliation"))

    def test_fixture_context_change_and_live_worker_are_rejected(self):
        _, source, run = self.interrupted_write()
        evidence, binding = self.readback(source)
        self.project.connection.execute("UPDATE execution_leases SET expires_at=9999999999")
        with self.assertRaises(EngineError) as active:
            coordinator.reconcile(self.project, {"run_id": run["id"], "evidence_ids": [evidence["id"]],
                                                  "readback_bindings": [binding]})
        self.assertEqual("run_active", active.exception.code)
        self.project.connection.execute("UPDATE execution_leases SET expires_at=0")
        self.project.put("resource", {**source, "external_id": "changed-external-fixture"})
        with self.assertRaises(EngineError) as changed:
            coordinator.reconcile(self.project, {"run_id": run["id"], "evidence_ids": [evidence["id"]],
                                                  "readback_bindings": [binding]})
        self.assertEqual("reconciliation_context", changed.exception.code)
        self.assertEqual([], self.project.list("execution_reconciliation"))

    def test_a_lease_renewed_during_validation_cannot_be_released(self):
        _, source, run = self.interrupted_write()
        evidence, binding = self.readback(source)
        validate = continuation._readback_bindings
        def renewed(*args):
            result = validate(*args)
            self.project.connection.execute("UPDATE execution_leases SET expires_at=9999999999")
            return result
        with patch.object(continuation, "_readback_bindings", side_effect=renewed), self.assertRaises(EngineError) as caught:
            coordinator.reconcile(self.project, {"run_id": run["id"], "evidence_ids": [evidence["id"]],
                                                  "readback_bindings": [binding]})
        self.assertEqual("run_active", caught.exception.code)
        self.assertEqual([], self.project.list("execution_reconciliation"))
        self.assertTrue(self.project.get("run", run["id"])["effect_unknown"])

    def test_context_mutation_during_validation_rolls_back_the_reconciliation(self):
        _, source, run = self.interrupted_write()
        evidence, binding = self.readback(source)
        validate = continuation._readback_bindings
        def changed(*args):
            result = validate(*args)
            self.project.put("resource", {**source, "external_id": "changed-during-validation"})
            return result
        with patch.object(continuation, "_readback_bindings", side_effect=changed), self.assertRaises(EngineError) as caught:
            coordinator.reconcile(self.project, {"run_id": run["id"], "evidence_ids": [evidence["id"]],
                                                  "readback_bindings": [binding]})
        self.assertEqual("revision_conflict", caught.exception.code)
        self.assertEqual([], self.project.list("execution_reconciliation"))
        self.assertTrue(self.project.get("run", run["id"])["effect_unknown"])


class V2RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = v2_cases.TestRunTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_all_three_native_control_dispatches_need_their_actual_responses(self):
        campaign_id = self.fixture._template_campaign()
        recipe_id = v2.dispatch(self.fixture.root, "campaign.next", {"project_id": "v2", "limit": 1})["recipes"][0]["recipe"]["id"]
        with v2.project(self.fixture.root) as project, \
                patch.object(engine, "request", side_effect=v2.Sequence([
                    {"value": "AWA-NORMAL"}, {"value": "49"}, {"value": "AWA-NORMAL-2"}])), \
                patch.object(coordinator, "release", return_value=False):
            result = test_runner.run(project, {"campaign_id": campaign_id, "recipe_id": recipe_id,
                                               "idempotency_key": "recovery-three-controls"})
            run = project.get("v2_run", result["run"]["id"])
            run.update(status="effect_unknown", effect_unknown=True, remote_state_unknown=True)
            project.put("v2_run", run)
            with project.transaction():
                project.connection.execute("UPDATE execution_leases SET expires_at=0")
            evidence_ids = run["evidence_ids"]
            with self.assertRaises(EngineError) as incomplete:
                coordinator.reconcile(project, {"run_id": run["id"], "evidence_ids": evidence_ids[:1]})
            self.assertEqual("reconciliation_evidence", incomplete.exception.code)
        with v2.project(self.fixture.root) as project, \
                patch.object(engine, "request", side_effect=AssertionError("recovery replayed controls")):
            recovered = coordinator.reconcile(project, {"run_id": run["id"], "evidence_ids": evidence_ids})
            self.assertEqual(3, len(recovered["dispatch_ids"]))
            self.assertEqual(0, recovered["requests_replayed"])
            self.assertEqual("interrupted", project.get("v2_run", run["id"])["status"])

    def interrupted_native_write(self):
        project, campaign_id, recipe, fixture, hypothesis = self.fixture._write_recipe()
        self.addCleanup(project.close)
        # Model a crash after one authorized native write was durably dispatched.
        # The normal runner independently rejects a three-write / one-write-budget plan.
        parent = {"id": "RUN2-write-recovery", "recipe_id": recipe["id"], "campaign_id": campaign_id,
                  "universe_id": recipe["universe_id"], "hypothesis_id": hypothesis["id"],
                  "status": "effect_unknown", "started_at": now(), "effect_unknown": True,
                  "effect": {"type": "test_resource_write", "unknown": True}}
        args = {"operation_id": recipe["bindings"]["operation_id"],
                "resource_id": recipe["bindings"]["resource"]["resource_id"],
                "body": {"id": "7", "label": "AWA-NORMAL"}, "effect": "test_resource_write"}
        prepared = engine.preflight_capture(project, args)
        lease = coordinator.claim(project, "v2-write-recovery", ttl=60)
        receipt = coordinator.dispatch(project, lease, action="http.capture", run_id=parent["id"],
                                        request_hash=prepared["dispatch_spec"]["request_hash"],
                                        effect="test_resource_write", max_requests=1, max_writes=1)
        parent["dispatch_receipt_ids"] = [receipt["id"]]
        project.put("v2_run", parent)
        with patch.object(engine, "request", side_effect=OSError("fixture crash after dispatch")), self.assertRaises(EngineError):
            engine.capture(project, args, dispatch_context={"receipt_id": receipt["id"], **prepared["dispatch_spec"],
                            "run_id": parent["id"], "lease_name": lease["name"], "fence": lease["fence"]})
        project.connection.execute("UPDATE execution_leases SET expires_at=0")
        resource = project.get("resource", args["resource_id"])
        read = v2.register(project, "http://fixture.invalid/read-fixture", inputs=[
            {"name": "id", "location": "query", "consumer": "resource_reference"}])
        read_resource = engine.add_resource(project, {"operation_id": read["id"], "owner_actor_id": "alice",
            "external_id": "7", "request_binding": {"location": "query", "selector": "id"}})
        with patch.object(engine, "request", side_effect=v2.Sequence([{"label": "AWA-NORMAL"}])):
            evidence = engine.capture(project, {"operation_id": read["id"], "resource_id": read_resource["id"],
                                                "url": read["url"] + "?id=7"})
        binding = {"source_resource_id": resource["id"], "resource_id": read_resource["id"], "selector": "/label",
                   "expected": "AWA-NORMAL", "relation": "Exact owned fixture readback"}
        return project, parent, resource, evidence, binding

    def test_v2_write_uses_captured_native_resource_signature(self):
        project, parent, resource, evidence, binding = self.interrupted_native_write()
        changed = deepcopy(resource)
        changed["external_id"] = "8"
        project.put("resource", changed)
        with self.assertRaises(EngineError) as mismatch:
            coordinator.reconcile(project, {"run_id": parent["id"], "evidence_ids": [evidence["id"]],
                                            "readback_bindings": [binding]})
        self.assertEqual("reconciliation_context", mismatch.exception.code)
        project.put("resource", resource)
        with patch.object(engine, "request", side_effect=AssertionError("recovery repeated a write")):
            recovered = coordinator.reconcile(project, {"run_id": parent["id"], "evidence_ids": [evidence["id"]],
                                                        "readback_bindings": [binding]})
        self.assertTrue(recovered["lease_released"])
        self.assertFalse(project.get("v2_run", parent["id"])["effect"]["unknown"])
        self.assertEqual(0, recovered["requests_sent"])


if __name__ == "__main__":
    unittest.main()
