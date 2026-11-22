"""Storage migration, read-only rollback and durable query projection regressions."""
from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from awa_ddd import engine, migration, read_model
from awa_ddd.__main__ import dispatch
from awa_ddd.contracts import EngineError
from awa_ddd.planning import migration as campaign_migration
from awa_ddd.store import Project


class MigrationProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="awa-migration-projection-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        engine.create_project(self.root, {
            "project_id": "storage",
            "target": "http://fixture.invalid",
            "allow_mutation": True,
        })
        self.project = Project(self.root, "storage")
        self.addCleanup(self.project.close)
        self.operation = engine.register_operation(self.project, {
            "url": "http://fixture.invalid/items?q=fixture",
            "method": "GET",
            "auth": "public",
            "inputs": [{"name": "q", "location": "query", "consumer": "business_input",
                        "test_families": ["generic"]}],
        })
        engine.build_plan(self.project)

    def database_bytes(self):
        result = {}
        for suffix in ("", "-wal", "-shm"):
            path = Path(str(self.project.database_path) + suffix)
            if path.exists():
                result[suffix] = hashlib.sha256(path.read_bytes()).hexdigest()
        return result

    def test_dry_run_is_byte_stable_and_apply_is_idempotent(self):
        before = self.database_bytes()
        with Project(self.root, "storage", read_only=True) as snapshot:
            preview = migration.migrate(snapshot, {"mode": "dry_run"})
        after = self.database_bytes()
        self.assertEqual(before, after, "dry-run must not change the database, WAL or SHM bytes")
        self.assertEqual("preview", preview["migration"]["state"])
        self.assertEqual(0, preview["writes"])
        self.assertEqual(0, preview["requests_sent"])

        applied = migration.migrate(self.project, {"mode": "apply"})
        repeated = migration.migrate(self.project, {"mode": "apply"})
        self.assertEqual("applied", applied["migration"]["state"])
        self.assertEqual("legacy_read_only", applied["migration"]["rollback_mode"])
        self.assertEqual(preview["migration"]["id"], applied["migration"]["id"])
        self.assertEqual(0, repeated["writes"])
        self.assertEqual(applied["migration"]["id"], repeated["migration"]["id"])
        self.assertEqual("canonical_compatibility", self.project.get_metadata("storage_mode"))

    def test_rollback_switches_the_view_without_deleting_newer_facts(self):
        applied = migration.migrate(self.project, {"mode": "apply"})
        newer = engine.register_operation(self.project, {
            "url": "http://fixture.invalid/after-migration",
            "method": "GET",
            "auth": "public",
        })
        result = migration.rollback(self.project, {"ledger_id": applied["migration"]["id"]})
        self.assertEqual("legacy_read_only", result["rolled_back_to"])
        self.assertTrue(result["new_facts_preserved"])
        self.assertEqual(0, result["requests_replayed"])
        self.assertEqual(0, result["requests_sent"])
        self.assertEqual("legacy_read_only", self.project.get_metadata("storage_mode"))
        self.assertEqual(newer, self.project.get("operation", newer["id"]))
        self.assertEqual(applied["migration"]["id"], self.project.get_metadata("storage_rollback_id"))

    def test_projection_inspect_compare_rebuild_and_reuse_are_offline(self):
        metadata, reused = read_model.snapshot(self.project)
        self.assertFalse(reused)
        self.assertGreater(metadata["valid_until"], time.time())
        generation = self.project.generation()
        inspected = read_model.maintain(self.project, {"mode": "inspect"})
        compared = read_model.maintain(self.project, {"mode": "compare"})
        self.assertEqual(generation, self.project.generation())
        self.assertTrue(inspected["projection_reused"])
        self.assertTrue(compared["comparison"]["equal"])
        self.assertEqual([], compared["comparison"]["differences"])
        self.assertEqual(0, inspected["requests_sent"])
        self.assertEqual(0, compared["requests_sent"])

        rebuilt = read_model.maintain(self.project, {"mode": "rebuild"})
        verified = read_model.maintain(self.project, {"mode": "compare"})
        self.assertTrue(rebuilt["rebuilt"])
        self.assertEqual("strong_artifacts", rebuilt["material_verification"])
        self.assertTrue(verified["comparison"]["equal"])
        self.assertEqual(0, rebuilt["requests_sent"])

    def test_campaign_migration_apply_is_atomic(self):
        with patch.object(
                self.project, "set_config",
                side_effect=RuntimeError("injected config failure")):
            with self.assertRaisesRegex(
                    RuntimeError, "injected config failure"):
                campaign_migration.project_legacy(
                    self.project, apply=True, confirm=True)
        self.assertEqual("v1", self.project.config.get("assessment_model", "v1"))
        self.assertEqual([], self.project.list("v2_migration"))
        self.assertEqual([], self.project.list("v2_hypothesis"))
        self.assertEqual([], self.project.list("v2_legacy_evaluation"))

        applied = campaign_migration.project_legacy(
            self.project, apply=True, confirm=True)
        repeated = campaign_migration.project_legacy(
            self.project, apply=True, confirm=True)
        self.assertEqual(applied["ledger"]["id"], repeated["ledger"]["id"])
        self.assertTrue(repeated["reused"])
        self.assertEqual(0, repeated["writes"])
        self.assertEqual(1, len(self.project.list("v2_migration")))

    def test_campaign_public_rollback_then_reapply_reuses_generation(self):
        first = dispatch(self.root, "campaign.migrate", {
            "project_id": "storage", "apply": True, "confirm": True,
        })
        hypothesis_total = len(self.project.list("v2_hypothesis"))
        rolled_back = dispatch(self.root, "campaign.rollback", {
            "project_id": "storage", "ledger_id": first["ledger"]["id"],
        })
        self.assertEqual("v1", rolled_back["rolled_back_to"])
        self.assertEqual("v1", self.project.config.get("assessment_model"))

        reapplied = dispatch(self.root, "campaign.migrate", {
            "project_id": "storage", "apply": True, "confirm": True,
        })
        self.assertEqual(first["ledger"]["id"], reapplied["ledger"]["id"])
        self.assertEqual("v2", self.project.config.get("assessment_model"))
        self.assertEqual(1, len(self.project.list("v2_migration")))
        self.assertEqual(hypothesis_total, len(self.project.list("v2_hypothesis")))
        self.assertEqual([], self.project.list("v2_run"))

    def test_non_string_modes_fail_with_stable_contract_errors(self):
        for mode in ([], {}, 1, True):
            with self.subTest(operation="migration", mode=mode):
                with self.assertRaises(EngineError) as raised:
                    migration.migrate(self.project, {"mode": mode})
                self.assertEqual("migration_mode", raised.exception.code)
            with self.subTest(operation="projection", mode=mode):
                with self.assertRaises(EngineError) as raised:
                    read_model.maintain(self.project, {"mode": mode})
                self.assertEqual("projection_mode", raised.exception.code)


if __name__ == "__main__":
    unittest.main()
