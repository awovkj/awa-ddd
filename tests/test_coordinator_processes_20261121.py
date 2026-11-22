"""Independent processes contend on the real SQLite claims, budgets and CAS."""
from __future__ import annotations

import multiprocessing
import unittest

import v2_fixtures as fx
from awa_ddd import execution_coordinator as coordinator
from awa_ddd.store import EngineError, Project


def contend(root, mode, barrier, results):
    with Project(root, "v2") as project:
        barrier.wait(timeout=15)
        try:
            if mode == "lease":
                coordinator.claim(project, "contended", ttl=60)
            elif mode == "budget":
                coordinator.consume_budget(project, "contended", requests=1)
            else:
                project.compare_and_swap("run", {"id": "RUN-contended", "status": "claimed"}, 1)
            results.put("won")
        except EngineError as exc:
            results.put(exc.code)


class ProcessCoordinationTests(unittest.TestCase):
    def test_only_one_process_can_claim_consume_or_update_the_same_fact(self):
        context = multiprocessing.get_context("spawn")
        for mode, refused in (("lease", "execution_lease_busy"),
                              ("budget", "execution_budget_exhausted"), ("cas", "revision_conflict")):
            with self.subTest(mode=mode):
                temporary, root = fx.workspace()
                try:
                    with fx.project(root) as project:
                        coordinator.reserve_budget(project, "contended", 1, 0)
                        project.put("run", {"id": "RUN-contended", "status": "pending"})
                    barrier, results = context.Barrier(2), context.Queue()
                    processes = [context.Process(target=contend, args=(str(root), mode, barrier, results)) for _ in range(2)]
                    for process in processes:
                        process.start()
                    for process in processes:
                        process.join(timeout=20)
                        if process.is_alive():
                            process.terminate()
                            process.join(timeout=5)
                        self.assertEqual(0, process.exitcode)
                    self.assertCountEqual(["won", refused], [results.get(timeout=5) for _ in processes])
                    results.close()
                    results.join_thread()
                finally:
                    temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
