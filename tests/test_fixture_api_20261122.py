"""Public fixture facade: state transitions require real bound captures."""
from __future__ import annotations

import threading
import unittest
from unittest.mock import patch

import v2_fixtures as fx
from awa_ddd import engine
from awa_ddd.domain.repository import Repository
from awa_ddd.execution import fixture_api, fixtures


class FixtureApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary, self.root = fx.workspace(allow_mutation=True)
        self.addCleanup(self.temporary.cleanup)
        self.row = fx.project(self.root)
        self.addCleanup(self.row.close)
        self.operation = fx.register(self.row, "http://fixture.invalid/fixture", "GET", "public", [
            {"name": "id", "location": "query", "selector": "id", "consumer": "resource_reference"},
        ])
        self.actor = engine.add_actor(self.row, {"actor_id": "alice", "subject": "alice", "roles": []})
        self.session = engine.add_session(self.row, {
            "actor_id": "alice", "session_id": "S-alice",
            "headers": {"authorization": "Bearer synthetic-fixture"},
        })
        profile = fx.register(self.row, "http://fixture.invalid/profile", "GET", "public", [])
        with patch("awa_ddd.engine.request", side_effect=fx.Sequence([{"subject": "alice"}])):
            engine.verify_identity(self.row, {
                "operation_id": profile["id"], "session_id": "S-alice", "subject_selector": "/subject",
            })
        self.resource = engine.add_resource(self.row, {
            "operation_id": self.operation["id"], "owner_actor_id": "alice", "external_id": "7",
            "request_binding": {"location": "query", "selector": "id"},
        })

    def capture(self, value):
        with patch("awa_ddd.engine.request", side_effect=fx.Sequence([{"state": value}])):
            return engine.capture(self.row, {
                "operation_id": self.operation["id"], "url": "http://fixture.invalid/fixture?id=7",
                "session_id": "S-alice", "resource_id": self.resource["id"],
            })["id"]

    def call(self, action, args):
        return fx.dispatch(self.root, action, {"project_id": "v2", **args})

    def create(self, value):
        return self.call("test.fixture_create", {
            "operation_id": self.operation["id"], "owner_actor_id": "alice", "resource_id": self.resource["id"],
            "initial_evidence_id": self.capture(value), "state_selector": "/state",
        })["fixture"]

    def test_evidence_backed_lifecycle_and_idempotency(self):
        fixture = self.create({"value": 1})
        self.assertEqual("verified", fixture["state"])
        fixture_id = fixture["id"]
        again = self.call("test.fixture_create", {
            "operation_id": self.operation["id"], "owner_actor_id": "alice", "resource_id": self.resource["id"],
            "initial_evidence_id": self.capture({"value": 1}), "state_selector": "/state",
        })
        self.assertTrue(again["idempotent"])
        leased = self.call("test.fixture_lease", {"fixture_id": fixture_id, "worker_id": "worker-a"})["fixture"]
        self.assertEqual("leased", leased["state"])
        fixtures.mutate(self.row, fixture_id, worker_id="worker-a", intended_effect={"value": 2})
        changed = self.call("test.fixture_readback", {
            "fixture_id": fixture_id, "evidence_id": self.capture({"value": 2}), "state_selector": "/state",
        })["fixture"]
        self.assertEqual("readback_ok", changed["state"])
        # The second create is idempotent and does not reset the fixture lease or revision history.
        self.create({"value": 1})
        self.assertEqual({"value": 1}, fixtures._get(self.row, fixture_id)["initial_state"])
        self.assertEqual("readback_ok", fixtures._get(self.row, fixture_id)["state"])
        cleaned = self.call("test.fixture_cleanup", {
            "fixture_id": fixture_id, "worker_id": "worker-a", "succeeded": True,
            "evidence_id": self.capture({"value": 1}), "state_selector": "/state",
        })["fixture"]
        self.assertEqual("cleaned", cleaned["state"])

    def test_post_fixture_uses_dedicated_readback_operation(self):
        write = fx.register(self.row, "http://fixture.invalid/write", "POST", "public", [
            {"name": "id", "location": "body", "selector": "id", "consumer": "resource_reference"},
            {"name": "label", "location": "body", "selector": "label",
             "consumer": "template_engine", "test_families": ["template_injection"]},
        ])
        write_resource = engine.add_resource(self.row, {
            "operation_id": write["id"], "owner_actor_id": "alice", "external_id": "7",
            "request_binding": {"location": "body", "selector": "id"},
        })
        read = fx.register(self.row, "http://fixture.invalid/read", "GET", "public", [
            {"name": "id", "location": "query", "selector": "id", "consumer": "resource_reference"},
        ])
        read_resource = engine.add_resource(self.row, {
            "operation_id": read["id"], "owner_actor_id": "alice", "external_id": "7",
            "request_binding": {"location": "query", "selector": "id"},
        })
        def capture_state(value):
            with patch("awa_ddd.engine.request", side_effect=fx.Sequence([{"state": value}])):
                return engine.capture(self.row, {
                    "operation_id": read["id"], "url": "http://fixture.invalid/read?id=7",
                    "session_id": "S-alice", "resource_id": read_resource["id"],
                })["id"]
        initial_evidence = capture_state({"value": 1})
        fixture = self.call("test.fixture_create", {
            "operation_id": write["id"], "owner_actor_id": "alice", "resource_id": write_resource["id"],
            "readback_operation_id": read["id"], "readback_resource_id": read_resource["id"],
            "initial_evidence_id": initial_evidence, "state_selector": "/state/value",
        })["fixture"]
        self.assertEqual("verified", fixture["state"])
        self.assertEqual(read["id"], fixture["readback_operation_id"])
        self.assertEqual(read_resource["id"], fixture["readback_resource_id"])
        self.call("test.fixture_lease", {"fixture_id": fixture["id"], "worker_id": "worker-post"})
        campaign_id = fx.start(self.root)["campaign"]["id"]
        repository = Repository(self.row)
        hypothesis = next(row for row in repository.list_campaign(
            "hypothesis", campaign_id, limit=None)[0]
            if row.get("operation_id") == write["id"]
            and row.get("family") == "template_injection")
        with patch("awa_ddd.engine.request", side_effect=fx.Sequence([{"value": "49"}])):
            executed = self.call("test.run", {
                "campaign_id": campaign_id, "hypothesis_id": hypothesis["id"],
                "idempotency_key": "post-fixture-public-write", "worker_id": "worker-post",
            })
        self.assertEqual("inconclusive", executed["outcome"])
        self.assertEqual(1, len(executed["run"]["evidence_ids"]))
        changed = self.call("test.fixture_readback", {
            "fixture_id": fixture["id"], "evidence_id": capture_state({"value": "49"}),
            "state_selector": "/state/value",
        })["fixture"]
        self.assertEqual("readback_ok", changed["state"], fixtures._get(self.row, fixture["id"]))
        with self.assertRaises(Exception) as stale:
            self.call("test.fixture_cleanup", {
                "fixture_id": fixture["id"], "worker_id": "worker-post", "succeeded": True,
                "evidence_id": initial_evidence, "state_selector": "/state/value",
            })
        self.assertEqual("v2_fixture_evidence_stale", stale.exception.code)
        self.assertEqual("readback_ok", fixtures._get(self.row, fixture["id"])["state"])
        cleaned = self.call("test.fixture_cleanup", {
            "fixture_id": fixture["id"], "worker_id": "worker-post", "succeeded": True,
            "evidence_id": capture_state({"value": 1}), "state_selector": "/state/value",
        })["fixture"]
        self.assertEqual("cleaned", cleaned["state"])

    def test_cleanup_and_concurrent_mutation_share_one_transaction(self):
        fixture = self.create({"value": 1})
        self.call("test.fixture_lease", {"fixture_id": fixture["id"], "worker_id": "worker-a"})
        evidence = self.capture({"value": 1})
        validated, release, mutation_done = threading.Event(), threading.Event(), threading.Event()
        original = fixture_api._state_from_evidence
        def paused(*args, **kwargs):
            result = original(*args, **kwargs)
            validated.set()
            release.wait(timeout=5)
            return result
        mutation_errors = []
        def mutate(second):
            try:
                fixtures.mutate(second, fixture["id"], worker_id="worker-a", intended_effect={"value": 2})
                mutation_done.set()
            except Exception as exc:
                mutation_errors.append(exc)
        with patch("awa_ddd.execution.fixture_api._state_from_evidence", side_effect=paused):
            second = fx.project(self.root)
            self.addCleanup(second.close)
            cleanup_result = []
            cleanup_errors = []
            def clean():
                try:
                    cleanup_result.append(self.call("test.fixture_cleanup", {
                        "fixture_id": fixture["id"], "worker_id": "worker-a", "succeeded": True,
                        "evidence_id": evidence, "state_selector": "/state",
                    }))
                except Exception as exc:
                    cleanup_errors.append(exc)
            cleaner = threading.Thread(target=clean)
            cleaner.start()
            self.assertTrue(validated.wait(timeout=5))
            mutator = threading.Thread(target=mutate, args=(second,))
            mutator.start()
            self.assertFalse(mutation_done.wait(timeout=0.1))
            release.set()
            cleaner.join(timeout=10)
            mutator.join(timeout=10)
        self.assertFalse(cleaner.is_alive())
        self.assertFalse(mutator.is_alive())
        self.assertEqual([], cleanup_errors)
        self.assertEqual("cleaned", cleanup_result[0]["fixture"]["state"])
        self.assertFalse(mutation_done.is_set())
        self.assertTrue(mutation_errors)
        self.assertEqual("cleaned", fixtures._get(self.row, fixture["id"])["state"])

    def test_cleanup_cannot_overtake_an_in_flight_target_write(self):
        write = fx.register(self.row, "http://fixture.invalid/write", "POST", "public", [
            {"name": "id", "location": "body", "selector": "id", "consumer": "resource_reference"},
            {"name": "label", "location": "body", "selector": "label",
             "consumer": "template_engine", "test_families": ["template_injection"]},
        ])
        write_resource = engine.add_resource(self.row, {
            "operation_id": write["id"], "owner_actor_id": "alice", "external_id": "7",
            "request_binding": {"location": "body", "selector": "id"},
        })
        fixture = self.call("test.fixture_create", {
            "operation_id": write["id"], "owner_actor_id": "alice", "resource_id": write_resource["id"],
            "readback_operation_id": self.operation["id"], "readback_resource_id": self.resource["id"],
            "initial_evidence_id": self.capture({"value": 1}), "state_selector": "/state",
        })["fixture"]
        self.call("test.fixture_lease", {"fixture_id": fixture["id"], "worker_id": "worker-post"})
        evidence = self.capture({"value": 1})
        campaign_id = fx.start(self.root)["campaign"]["id"]
        hypothesis = next(row for row in Repository(self.row).list_campaign(
            "hypothesis", campaign_id, limit=None)[0]
            if row.get("operation_id") == write["id"]
            and row.get("family") == "template_injection")
        request_started, release, run_done = threading.Event(), threading.Event(), threading.Event()
        run_results, run_errors = [], []
        def blocking_request(url, method, headers, body, timeout, max_bytes):
            request_started.set()
            if not release.wait(timeout=5):
                raise TimeoutError("synthetic write did not receive test release")
            return fx.observation(url, method, headers, body, timeout, max_bytes, {"value": "49"})
        def execute():
            try:
                run_results.append(self.call("test.run", {
                    "campaign_id": campaign_id, "hypothesis_id": hypothesis["id"],
                    "idempotency_key": "in-flight-write", "worker_id": "worker-post",
                }))
            except Exception as exc:
                run_errors.append(exc)
            finally:
                run_done.set()
        with patch("awa_ddd.engine.request", side_effect=blocking_request):
            worker = threading.Thread(target=execute)
            worker.start()
            self.assertTrue(request_started.wait(timeout=5))
            current = fixtures._get(self.row, fixture["id"])
            self.assertEqual("leased", current["state"])
            self.assertIsNotNone(current["in_flight"])
            with self.assertRaises(Exception) as blocked:
                self.call("test.fixture_cleanup", {
                    "fixture_id": fixture["id"], "worker_id": "worker-post", "succeeded": True,
                    "evidence_id": evidence, "state_selector": "/state",
                })
            self.assertEqual("v2_fixture_state", blocked.exception.code)
            self.assertEqual("leased", fixtures._get(self.row, fixture["id"])["state"])
            release.set()
            worker.join(timeout=10)
        self.assertTrue(run_done.is_set())
        self.assertEqual([], run_errors)
        self.assertEqual(1, len(run_results[0]["run"]["evidence_ids"]))
        final = fixtures._get(self.row, fixture["id"])
        self.assertEqual("mutated", final["state"])
        self.assertIsNone(final["in_flight"])

    def test_caller_supplied_identity_or_state_cannot_substitute_evidence(self):
        fixture = self.create({"value": 1})
        other = fx.register(self.row, "http://fixture.invalid/other", "GET", "public", [])
        with self.assertRaises(Exception) as caught:
            fixture_api.verify(self.row, {
                "fixture_id": fixture["id"], "evidence_id": self.capture({"value": 999}),
                "state_selector": "/state",
            })
        self.assertTrue(getattr(caught.exception, "code", ""))
        self.assertEqual("quarantined", fixtures._get(self.row, fixture["id"])["state"])
        self.assertEqual("GET", other["method"])


if __name__ == "__main__":
    unittest.main()
