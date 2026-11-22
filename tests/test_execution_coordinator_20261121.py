"""Fencing, replay prevention and pre-dispatch budget regressions."""
from __future__ import annotations

import unittest
from unittest.mock import patch

import v2_fixtures as fx
from awa_ddd import engine, execution_coordinator as coordinator
from awa_ddd.__main__ import dispatch as dispatch_action
from awa_ddd.domain.common import digest
from awa_ddd.store import EngineError


class ExecutionCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temporary, self.root = fx.workspace()
        self.addCleanup(self.temporary.cleanup)
        self.project = fx.project(self.root)
        self.addCleanup(self.project.close)

    def _lease(self, name="experiment"):
        return coordinator.claim(
            self.project, name, owner="worker", ttl=60)

    def _dispatch(self, lease, request, *, run="RUN2-1", budget="experiment",
                  requests=1, writes=0, effect="read_only",
                  max_requests=None, max_writes=None):
        return coordinator.dispatch(
            self.project,
            lease,
            action="http.capture",
            run_id=run,
            request_hash=digest(request),
            budget=budget,
            max_requests=requests if max_requests is None else max_requests,
            max_writes=writes if max_writes is None else max_writes,
            effect=effect,
            requests=requests,
            writes=writes,
        )

    def test_same_fence_allows_distinct_controls_but_not_exact_replay(self):
        lease = self._lease()
        first = self._dispatch(
            lease, {"selector": "normal"}, max_requests=2)
        second = self._dispatch(
            lease, {"selector": "attack"}, max_requests=2)
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(
            2, len(self.project.list("execution_dispatch")))
        with self.assertRaises(EngineError) as caught:
            self._dispatch(
                lease, {"selector": "attack"}, max_requests=2)
        self.assertEqual(
            "dispatch_already_attempted", caught.exception.code)
        self.assertEqual(
            2, len(self.project.list("execution_dispatch")))

    def test_write_budget_is_consumed_before_the_second_dispatch(self):
        lease = self._lease()
        self._dispatch(
            lease, {"selector": "attack-1"},
            requests=1, writes=1, effect="test_resource_write",
            max_requests=2, max_writes=1)
        with self.assertRaises(EngineError) as caught:
            self._dispatch(
                lease, {"selector": "attack-2"},
                requests=1, writes=1, effect="test_resource_write",
                max_requests=2, max_writes=1)
        self.assertEqual(
            "execution_budget_exhausted", caught.exception.code)
        budget = self.project.connection.execute(
            "SELECT requests_used,writes_used FROM execution_budget "
            "WHERE name='experiment'").fetchone()
        self.assertEqual((1, 1), tuple(budget))
        self.assertEqual(
            1, len(self.project.list("execution_dispatch")))

    def test_budget_rejection_does_not_create_a_dispatch_receipt(self):
        lease = self._lease()
        with self.assertRaises(EngineError) as caught:
            self._dispatch(
                lease, {"selector": "normal"},
                max_requests=0, max_writes=0)
        self.assertEqual(
            "execution_budget_exhausted", caught.exception.code)
        self.assertEqual([], self.project.list("execution_dispatch"))
        stored = self.project.connection.execute(
            "SELECT dispatched FROM execution_leases WHERE name='experiment'"
        ).fetchone()
        self.assertEqual(0, stored[0])

    def test_expired_dispatched_lease_cannot_be_retaken(self):
        lease = self._lease()
        self._dispatch(lease, {"selector": "normal"})
        self.project.connection.execute(
            "UPDATE execution_leases SET expires_at=0 WHERE name='experiment'")
        with self.assertRaises(EngineError) as caught:
            coordinator.claim(
                self.project, "experiment", owner="replacement", ttl=60)
        self.assertEqual("execution_lease_busy", caught.exception.code)
        self.assertTrue(caught.exception.details["effect_unknown"])
        self.assertEqual(
            0, caught.exception.details["requests_replayed"])

    def test_dispatched_lease_requires_reconciled_release(self):
        lease = self._lease()
        self._dispatch(lease, {"selector": "normal"})
        with self.assertRaises(EngineError) as caught:
            coordinator.release(self.project, lease)
        self.assertEqual(
            "execution_effect_unknown", caught.exception.code)
        self.assertTrue(
            coordinator.release(
                self.project, lease, reconciled=True))
        self.assertIsNone(self.project.connection.execute(
            "SELECT name FROM execution_leases WHERE name='experiment'"
        ).fetchone())

    def test_terminal_evidence_reconciles_without_replaying_the_request(self):
        operation = fx.register(
            self.project,
            "http://fixture.invalid/reconcile",
            "GET",
            "public",
        )
        with patch(
                "awa_ddd.engine.request",
                side_effect=fx.Sequence([{"value": "terminal"}]),
        ), patch.object(coordinator, "release", return_value=False):
            evidence = engine.capture(self.project, {
                "operation_id": operation["id"],
                "url": operation["url"],
                "idempotency_key": "reconcile-source",
            })
        run = self.project.get("run", evidence["run_id"])
        dispatch = self.project.get("execution_dispatch", run["dispatch_id"])
        lease_name = dispatch["lease_name"]
        self.project.connection.execute("UPDATE execution_leases SET expires_at=0 WHERE name=?", (lease_name,))
        run.update({
            "status": "effect_unknown",
            "effect_unknown": True,
            "remote_state_unknown": True,
        })
        self.project.put("run", run)
        with patch(
                "awa_ddd.engine.request",
                side_effect=AssertionError("reconciliation must not replay"),
        ):
            result = coordinator.reconcile(self.project, {
                "run_id": run["id"],
                "evidence_ids": [evidence["id"]],
            })
        self.assertFalse(result["effect_unknown"])
        self.assertEqual(0, result["requests_replayed"])
        self.assertEqual(0, result["requests_sent"])
        self.assertTrue(result["lease_released"])
        current = self.project.get("run", run["id"])
        self.assertEqual("interrupted", current["status"])
        self.assertEqual(
            result["reconciliation_id"],
            current["reconciliation_id"],
        )
        self.assertIsNone(self.project.connection.execute(
            "SELECT name FROM execution_leases WHERE name=?", (lease_name,)
        ).fetchone())
        self.assertEqual(
            1, len(self.project.list("execution_reconciliation")))
        repeated = coordinator.reconcile(self.project, {"run_id": run["id"], "evidence_ids": [evidence["id"]]})
        self.assertEqual(result["reconciliation_id"], repeated["reconciliation_id"])
        self.assertEqual(1, len(self.project.list("execution_reconciliation")))

    def test_public_reconciliation_route_returns_receipt_and_never_replays(self):
        operation = fx.register(
            self.project,
            "http://fixture.invalid/public-reconcile",
            "GET",
            "public",
        )
        with patch(
                "awa_ddd.engine.request",
                side_effect=fx.Sequence([{"value": "terminal"}]),
        ), patch.object(coordinator, "release", return_value=False):
            evidence = engine.capture(self.project, {
                "operation_id": operation["id"],
                "url": operation["url"],
                "idempotency_key": "public-reconcile-source",
            })
        run = self.project.get("run", evidence["run_id"])
        dispatch = self.project.get(
            "execution_dispatch", run["dispatch_id"])
        self.project.connection.execute(
            "UPDATE execution_leases SET expires_at=0 WHERE name=?",
            (dispatch["lease_name"],),
        )
        run.update({
            "status": "effect_unknown",
            "effect_unknown": True,
            "remote_state_unknown": True,
        })
        self.project.put("run", run)
        self.project.connection.commit()
        # Exercise the public process boundary with the fixture connection
        # closed; Windows otherwise keeps the SQLite file locked while the
        # route opens its own project connection.
        self.project.close()

        with patch(
                "awa_ddd.engine.request",
                side_effect=AssertionError(
                    "public reconciliation route must not replay"),
        ):
            result = dispatch_action(self.root, "execution.reconcile", {
                "project_id": self.project.project_id,
                "run_id": run["id"],
                "evidence_ids": [evidence["id"]],
            })
            inspected = dispatch_action(self.root, "run.inspect", {
                "project_id": self.project.project_id,
                "run_id": run["id"],
            })

        self.assertRegex(
            result["reconciliation_id"],
            r"^REC-[a-f0-9]{64}$",
        )
        self.assertEqual(run["dispatch_id"], result["dispatch_ids"][0])
        self.assertEqual([evidence["id"]], result["evidence_ids"])
        self.assertTrue(result["lease_released"])
        self.assertFalse(result["effect_unknown"])
        self.assertEqual(0, result["requests_replayed"])
        self.assertEqual(0, result["requests_sent"])
        self.assertEqual("run.inspect", result["next_action"])
        self.assertEqual(
            result["reconciliation_id"], inspected["reconciliation_id"])
        self.assertFalse(inspected["effect_unknown"])
        reopened = fx.project(self.root)
        try:
            self.assertEqual(
                1, len(reopened.list("execution_reconciliation")))
            self.assertIsNone(reopened.connection.execute(
                "SELECT name FROM execution_leases WHERE name=?",
                (dispatch["lease_name"],),
            ).fetchone())
        finally:
            reopened.close()

    def test_released_undispatched_claim_does_not_reuse_a_fence(self):
        old = self._lease("aba")
        coordinator.release(self.project, old)
        new = self._lease("aba")
        self.assertGreater(new["fence"], old["fence"])
        with self.assertRaises(EngineError) as caught:
            self._dispatch(old, {"selector": "stale"}, budget="aba")
        self.assertEqual("execution_fence", caught.exception.code)
        self.assertEqual([], self.project.list("execution_dispatch"))

    def test_budget_unit_and_authorization_cannot_change_after_reservation(self):
        coordinator.reserve_budget(self.project, "bounded", 2, 1, budget_unit="request_slots")
        for maximum, unit in ((3, "request_slots"), (2, "request")):
            with self.assertRaises(EngineError) as caught:
                coordinator.reserve_budget(self.project, "bounded", maximum, 1, budget_unit=unit)
            self.assertEqual("execution_budget_changed", caught.exception.code)
        with self.assertRaises(EngineError):
            self._dispatch(self._lease(), {"write": 1}, effect="read_only", writes=1)

    def test_ipc_failure_keeps_durable_budget_and_prevents_replay(self):
        lease = self._lease("ipc-failure")
        with patch("awa_ddd.ipc.emit_dispatch", side_effect=OSError("fixture IPC lost")):
            with self.assertRaises(OSError):
                self._dispatch(lease, {"selector": "once"}, budget="ipc-failure")
        self.assertEqual(1, len(self.project.list("execution_dispatch")))
        self.assertEqual(1, self.project.connection.execute(
            "SELECT requests_used FROM execution_budget WHERE name='ipc-failure'").fetchone()[0])
        with self.assertRaises(EngineError) as caught:
            self._dispatch(lease, {"selector": "once"}, budget="ipc-failure")
        self.assertEqual("dispatch_already_attempted", caught.exception.code)

    def test_unrelated_response_cannot_release_a_live_or_unknown_dispatch(self):
        operation = fx.register(self.project, "http://fixture.invalid/retained", "GET", "public")
        with patch("awa_ddd.engine.request", side_effect=fx.Sequence([{"value": "ok"}])), \
                patch.object(coordinator, "release", return_value=False):
            evidence = engine.capture(self.project, {"operation_id": operation["id"]})
        run = self.project.get("run", evidence["run_id"])
        run["status"] = "effect_unknown"
        self.project.put("run", run)
        with self.assertRaises(EngineError) as active:
            coordinator.reconcile(self.project, {"run_id": run["id"], "evidence_ids": [evidence["id"]]})
        self.assertEqual("run_active", active.exception.code)
        self.project.connection.execute("UPDATE execution_leases SET expires_at=0")
        with patch("awa_ddd.engine.request", side_effect=fx.Sequence([{"value": "ok"}])):
            unrelated = engine.capture(self.project, {"operation_id": operation["id"]})
        with self.assertRaises(EngineError) as invalid:
            coordinator.reconcile(self.project, {"run_id": run["id"], "evidence_ids": [unrelated["id"]]})
        self.assertEqual("reconciliation_evidence", invalid.exception.code)
        self.assertEqual([], self.project.list("execution_reconciliation"))


if __name__ == "__main__":
    unittest.main()
