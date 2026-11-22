"""Storage migration safety regressions for read-only and rollback boundaries."""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import assessment_mode, engine, execution_coordinator, migration
from awa_ddd.store import EngineError, Project, canonical


class StorageMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="awa-storage-migration-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        engine.create_project(self.root, {
            "project_id": "storage-migration",
            "target": "http://fixture.invalid",
            "allow_mutation": True,
        })
        self.project = Project(self.root, "storage-migration")
        self.addCleanup(self.project.close)
        self.operation = engine.register_operation(self.project, {
            "url": "http://fixture.invalid/items?q=fixture",
            "method": "GET",
            "auth": "public",
            "inputs": [{
                "name": "q",
                "location": "query",
                "consumer": "business_input",
                "test_families": ["generic"],
            }],
        })
        engine.build_plan(self.project)
        self.material_bytes = b'{"fixture":"legacy-material","value":7}\n'
        self.material = self.project.material(self.material_bytes, format="json")
        self.project.put("obligation", {
            "id": "OBL-LEGACY-NO-RECEIPT",
            "status": "not_applicable",
            "applicability_receipt_id": None,
        })
        self.project.put("v2_run", {
            "id": "V2RUN-ORPHANED",
            "campaign_id": "CAMP-MISSING",
            "status": "recorded",
        })

    def file_state(self):
        state = {}
        for suffix in ("", "-wal", "-shm"):
            path = Path(str(self.project.database_path) + suffix)
            if path.exists():
                stat = path.stat()
                state[suffix] = {
                    "bytes": path.read_bytes(),
                    "mtime_ns": stat.st_mtime_ns,
                    "size": stat.st_size,
                }
        return state

    def backup_folders(self):
        parent = self.project.base / "migrations"
        if not parent.exists():
            return []
        return sorted(path for path in parent.iterdir() if path.name.startswith("SMIG-"))

    def apply(self):
        return migration.migrate(self.project, {"mode": "apply"})

    def test_dry_run_is_byte_and_mtime_stable_for_writable_and_snapshot_projects(self):
        before = self.file_state()

        public_preview = migration.migrate(self.project, {"mode": "dry_run"})
        self.assertEqual(before, self.file_state())
        self.assertEqual("preview", public_preview["migration"]["state"])
        self.assertEqual(0, public_preview["writes"])
        self.assertEqual(0, public_preview["requests_sent"])

        with Project(self.root, "storage-migration", read_only=True) as snapshot:
            snapshot_preview = migration.migrate(snapshot, {"mode": "dry_run"})
            self.assertEqual(before, self.file_state())

        self.assertEqual(public_preview["migration"]["id"], snapshot_preview["migration"]["id"])
        self.assertEqual([], self.backup_folders())

    def test_readonly_store_surface_refuses_every_public_mutation(self):
        before = self.file_state()
        with Project(self.root, "storage-migration", read_only=True) as snapshot:
            operation = snapshot.get("operation", self.operation["id"])
            advisory_called = False

            def advisory_update(state):
                nonlocal advisory_called
                advisory_called = True
                state["changed"] = True

            cases = {
                "set_config": lambda: snapshot.set_config(dict(snapshot.config)),
                "set_metadata": lambda: snapshot.set_metadata("blocked", True),
                "put": lambda: snapshot.put("advisory", {"id": "ADV-1"}),
                "event": lambda: snapshot.event("blocked.event", {}),
                "artifact": lambda: snapshot.artifact("EV-BLOCKED", {"blocked": True}),
                "material": lambda: snapshot.material(b'{"blocked":true}', format="json"),
                "projection_put": lambda: snapshot.projection_put("blocked", 0, {}),
                "advisory_update": lambda: snapshot.advisory_update("blocked", advisory_update),
                "compare_and_swap": lambda: snapshot.compare_and_swap("operation", operation, 1),
                "claim": lambda: snapshot.claim({"id": "RUN-BLOCKED", "status": "queued"}),
                "migration_apply": lambda: migration.migrate(snapshot, {"mode": "apply"}),
            }
            for name, mutate in cases.items():
                with self.subTest(operation=name):
                    with self.assertRaises(EngineError) as raised:
                        mutate()
                    self.assertEqual("read_only", raised.exception.code)

            self.assertFalse(advisory_called)
            self.assertIsNone(snapshot.get("run", "RUN-BLOCKED", required=False))
            self.assertFalse((snapshot.base / "evidence" / "EV-BLOCKED.json").exists())

        self.assertEqual(before, self.file_state())

    def test_readonly_transaction_refuses_direct_sql_with_typed_error(self):
        with Project(self.root, "storage-migration", read_only=True) as snapshot:
            with self.assertRaises(EngineError) as raised:
                with snapshot.transaction():
                    snapshot.connection.execute(
                        "INSERT INTO metadata(key,value) VALUES('blocked','true')")
        self.assertEqual("read_only", raised.exception.code)

    def test_apply_preserves_legacy_ids_documents_and_material_bytes(self):
        operation_before = self.project.get("operation", self.operation["id"])
        material_before = self.project.get("material", self.material["id"])

        applied = self.apply()
        ledger = applied["migration"]

        self.assertEqual("applied", ledger["state"])
        self.assertTrue(ledger["legacy_ids_preserved"])
        self.assertEqual(operation_before, self.project.get("operation", self.operation["id"]))
        self.assertEqual(material_before, self.project.get("material", self.material["id"]))
        stored, decoded = self.project.read_material(self.material["id"])
        self.assertEqual(material_before, stored)
        self.assertEqual(json.loads(self.material_bytes), decoded)

        backup = self.backup_folders()[0]
        manifest = json.loads((backup / "manifest.json").read_bytes())
        material_entry = next(
            entry for entry in manifest["files"]
            if entry.get("source_path") == self.material["artifact_path"]
        )
        backup_material = backup / material_entry["path"]
        self.assertEqual(self.material_bytes, backup_material.read_bytes())
        self.assertEqual(
            self.material["sha256"],
            hashlib.sha256(backup_material.read_bytes()).hexdigest(),
        )

    def test_unverified_and_quarantine_records_do_not_create_authority(self):
        applied = self.apply()
        ledger = applied["migration"]
        unverified = self.project.list("legacy_unverified")
        quarantine = self.project.list("migration_quarantine")

        self.assertEqual(1, ledger["legacy_unverified_total"])
        self.assertEqual(1, ledger["quarantine_total"])
        self.assertEqual(0, ledger["synthetic_test_runs"])
        self.assertEqual("OBL-LEGACY-NO-RECEIPT", unverified[0]["source_id"])
        self.assertEqual("V2RUN-ORPHANED", quarantine[0]["source_id"])
        self.assertEqual(
            "legacy_applicability_without_receipt",
            unverified[0]["reason_code"],
        )
        self.assertEqual("campaign_membership_unavailable", quarantine[0]["reason_code"])
        for annotation in (*unverified, *quarantine):
            self.assertFalse(annotation["authority_granted"])
            self.assertEqual(ledger["id"], annotation["migration_id"])
        for kind in ("run", "execution_dispatch", "evidence", "decision"):
            self.assertEqual([], self.project.list(kind), kind)

    def test_ledger_failure_rolls_back_atomically_and_reuses_orphan_backup(self):
        preview = migration.migrate(self.project, {"mode": "dry_run"})
        preview_id = preview["migration"]["id"]
        original_put = self.project.put

        def fail_ledger(kind, record, create_only=False):
            if kind == "storage_migration":
                raise RuntimeError("injected migration ledger failure")
            return original_put(kind, record, create_only=create_only)

        with patch.object(self.project, "put", side_effect=fail_ledger):
            with self.assertRaisesRegex(RuntimeError, "injected migration ledger failure"):
                self.apply()

        self.assertIsNone(self.project.get("storage_migration", preview_id, required=False))
        self.assertEqual([], self.project.list("legacy_unverified"))
        self.assertEqual([], self.project.list("migration_quarantine"))
        self.assertIsNone(self.project.get_metadata("storage_mode"))
        self.assertIsNone(self.project.get_metadata("storage_migration_id"))
        self.assertEqual(
            [],
            [row for row in self.project.list_page("storage_migration", limit=100)["items"]],
        )
        self.assertEqual(0, self.project.connection.execute(
            "SELECT COUNT(*) FROM events WHERE type='storage.migrated'").fetchone()[0])
        self.assertEqual([preview_id], [path.name for path in self.backup_folders()])

        applied = self.apply()
        repeated = self.apply()
        self.assertEqual(preview_id, applied["migration"]["id"])
        self.assertEqual(preview_id, repeated["migration"]["id"])
        self.assertEqual(0, repeated["writes"])
        self.assertEqual([preview_id], [path.name for path in self.backup_folders()])

    def test_backup_copy_hash_and_publication_failures_leave_no_partial_batch(self):
        preview_id = migration.migrate(self.project, {"mode": "dry_run"})["migration"]["id"]
        destination = self.project.base / "migrations" / preview_id
        material_before = (self.project.base / self.material["artifact_path"]).read_bytes()
        faults = (
            ("hash", patch.object(migration, "_hash_file", side_effect=OSError("injected hash failure"))),
            ("copy", patch.object(migration.os, "fsync", side_effect=OSError("injected copy failure"))),
            ("publication", patch.object(migration.os, "rename", side_effect=OSError("injected publication failure"))),
        )
        for name, fault in faults:
            with self.subTest(boundary=name), fault:
                with self.assertRaises(EngineError) as raised:
                    self.apply()
                self.assertEqual("migration_backup", raised.exception.code)
            self.assertFalse(destination.exists())
            self.assertEqual([], list(destination.parent.iterdir()))
            self.assertIsNone(self.project.get("storage_migration", preview_id, required=False))
            self.assertIsNone(self.project.get_metadata("storage_mode"))
            self.assertEqual([], self.project.list("legacy_unverified"))
            self.assertEqual(material_before, (self.project.base / self.material["artifact_path"]).read_bytes())
        self.assertEqual(preview_id, self.apply()["migration"]["id"])

    def test_formal_backup_is_published_only_after_complete_manifest_and_closed_handles(self):
        preview_id = migration.migrate(self.project, {"mode": "dry_run"})["migration"]["id"]
        destination = self.project.base / "migrations" / preview_id
        real_rename = migration.os.rename
        observed = []

        def inspect_publication(source, target):
            self.assertEqual(destination, target)
            self.assertFalse(destination.exists())
            source = Path(source)
            self.assertTrue(source.resolve().is_relative_to(destination.parent.resolve()))
            manifest = json.loads((source / "manifest.json").read_bytes())
            self.assertGreater(len(manifest["files"]), 1)
            for entry in manifest["files"]:
                artifact = source / entry["path"]
                self.assertEqual(entry["sha256"], hashlib.sha256(artifact.read_bytes()).hexdigest())
                self.assertEqual(entry["size_bytes"], artifact.stat().st_size)
            real_rename(source, target)
            observed.append(target)

        with patch.object(migration.os, "rename", side_effect=inspect_publication):
            applied = self.apply()
        self.assertEqual([destination], observed)
        self.assertTrue((destination / "manifest.json").is_file())
        self.assertFalse((destination / ".incomplete").exists())
        self.assertEqual(applied["migration"]["backup_manifest_sha256"],
                         migration._verify_backup(self.project, preview_id)[0])

    def test_identified_interrupted_backup_is_preserved_before_retry(self):
        preview_id = migration.migrate(self.project, {"mode": "dry_run"})["migration"]["id"]
        destination = self.project.base / "migrations" / preview_id
        destination.mkdir(parents=True)
        (destination / ".incomplete").write_bytes(b"awa-storage-backup/v1\n")
        (destination / "partial-material.bin").write_bytes(b"interrupted-private-material")
        self.assertEqual(preview_id, self.apply()["migration"]["id"])
        preserved = list(destination.parent.glob(".interrupted-*"))
        self.assertEqual(1, len(preserved))
        self.assertEqual(b"interrupted-private-material", (preserved[0] / "partial-material.bin").read_bytes())
        self.assertEqual(b"awa-storage-backup/v1\n", (preserved[0] / ".incomplete").read_bytes())
        self.assertTrue((destination / "manifest.json").is_file())

    def test_interrupted_backup_preservation_failure_is_typed_and_retains_material(self):
        preview_id = migration.migrate(self.project, {"mode": "dry_run"})["migration"]["id"]
        destination = self.project.base / "migrations" / preview_id
        destination.mkdir(parents=True)
        (destination / ".incomplete").write_bytes(b"awa-storage-backup/v1\n")
        (destination / "partial-material.bin").write_bytes(b"interrupted-private-material")
        with patch.object(migration.os, "rename", side_effect=OSError("injected preservation failure")):
            with self.assertRaises(EngineError) as raised:
                self.apply()
        self.assertEqual("migration_backup", raised.exception.code)
        self.assertEqual(b"interrupted-private-material", (destination / "partial-material.bin").read_bytes())
        self.assertIsNone(self.project.get_metadata("storage_mode"))
        self.assertIsNone(self.project.get("storage_migration", preview_id, required=False))

    def test_unknown_existing_backup_directory_is_never_deleted_or_adopted(self):
        preview_id = migration.migrate(self.project, {"mode": "dry_run"})["migration"]["id"]
        destination = self.project.base / "migrations" / preview_id
        destination.mkdir(parents=True)
        material = destination / "existing-private-material.bin"
        material.write_bytes(b"retain-this-original")
        for marker in (None, b"unrecognized-marker\n"):
            with self.subTest(marker=marker):
                if marker is not None:
                    (destination / ".incomplete").write_bytes(marker)
                with self.assertRaises(EngineError) as raised:
                    self.apply()
                self.assertEqual("migration_backup", raised.exception.code)
                self.assertEqual(b"retain-this-original", material.read_bytes())
                self.assertFalse((destination / "manifest.json").exists())
                self.assertIsNone(self.project.get_metadata("storage_mode"))
                self.assertIsNone(self.project.get("storage_migration", preview_id, required=False))

    def test_incomplete_marker_blocks_even_an_otherwise_valid_backup(self):
        ledger = self.apply()["migration"]
        destination = self.project.base / "migrations" / ledger["id"]
        (destination / ".incomplete").write_bytes(b"awa-storage-backup/v1\n")
        with self.assertRaises(EngineError) as raised:
            migration.rollback(self.project, {"ledger_id": ledger["id"]})
        self.assertEqual("migration_backup", raised.exception.code)
        self.assertEqual("canonical_compatibility", self.project.get_metadata("storage_mode"))
        self.assertIsNone(self.project.get_metadata("storage_rollback_id"))

    def test_backup_tampering_blocks_rollback_without_changing_the_view(self):
        applied = self.apply()
        ledger_id = applied["migration"]["id"]
        manifest = self.project.base / "migrations" / ledger_id / "manifest.json"
        manifest.write_bytes(manifest.read_bytes() + b"\n")

        with self.assertRaises(EngineError) as raised:
            migration.rollback(self.project, {"ledger_id": ledger_id})

        self.assertEqual("migration_backup", raised.exception.code)
        self.assertEqual("canonical_compatibility", self.project.get_metadata("storage_mode"))
        self.assertIsNone(self.project.get_metadata("storage_rollback_id"))

    def test_backup_database_must_match_the_source_manifest(self):
        applied = self.apply()
        ledger_id = applied["migration"]["id"]
        backup = self.project.base / "migrations" / ledger_id
        database_path = backup / "assessment.sqlite3"
        manifest_path = backup / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())

        changed = self.project.get("operation", self.operation["id"])
        changed["url"] = "http://fixture.invalid/changed-after-manifest"
        with closing(sqlite3.connect(str(database_path))) as database:
            database.execute(
                "UPDATE entities SET document=? WHERE kind='operation' AND id=?",
                (canonical(changed), self.operation["id"]),
            )
            database.commit()

        database_digest = hashlib.sha256(database_path.read_bytes()).hexdigest()
        for entry in manifest["files"]:
            if entry["path"] == "assessment.sqlite3":
                entry["sha256"] = database_digest
                entry["size_bytes"] = database_path.stat().st_size
        manifest_path.write_bytes(canonical(manifest).encode("utf-8"))

        with self.assertRaises(EngineError) as raised:
            migration._verify_backup(self.project, ledger_id)

        self.assertEqual("migration_backup", raised.exception.code)
        self.assertIn("source manifest", str(raised.exception))
        self.assertEqual("canonical_compatibility", self.project.get_metadata("storage_mode"))

    def test_rollback_rejects_active_lease_preserves_new_facts_and_closes_write_gate(self):
        applied = self.apply()
        ledger_id = applied["migration"]["id"]
        newer_operation = engine.register_operation(self.project, {
            "url": "http://fixture.invalid/after-migration",
            "method": "POST",
            "auth": "public",
        })
        newer_material_bytes = b'{"fixture":"after-migration"}\n'
        newer_material = self.project.material(newer_material_bytes, format="json")
        newer_run = {"id": "RUN-AFTER-MIGRATION", "status": "recorded", "effect_unknown": False}
        self.project.put("run", newer_run)
        lease = execution_coordinator.claim(
            self.project, "rollback-active", owner="worker", ttl=60)

        with self.assertRaises(EngineError) as raised:
            migration.rollback(self.project, {"ledger_id": ledger_id})
        self.assertEqual("migration_busy", raised.exception.code)
        self.assertEqual("canonical_compatibility", self.project.get_metadata("storage_mode"))
        self.assertEqual(newer_operation, self.project.get("operation", newer_operation["id"]))
        self.assertEqual(newer_run, self.project.get("run", newer_run["id"]))

        self.assertTrue(execution_coordinator.release(self.project, lease, reconciled=False))
        rolled_back = migration.rollback(self.project, {"ledger_id": ledger_id})
        self.assertEqual("legacy_read_only", rolled_back["rolled_back_to"])
        self.assertTrue(rolled_back["new_facts_preserved"])
        self.assertEqual(0, rolled_back["requests_replayed"])
        self.assertEqual(0, rolled_back["requests_sent"])
        self.assertEqual("legacy_read_only", self.project.get_metadata("storage_mode"))
        self.assertEqual(ledger_id, self.project.get_metadata("storage_rollback_id"))

        self.assertEqual(newer_operation, self.project.get("operation", newer_operation["id"]))
        self.assertEqual(newer_run, self.project.get("run", newer_run["id"]))
        stored, decoded = self.project.read_material(newer_material["id"])
        self.assertEqual(newer_material, stored)
        self.assertEqual(json.loads(newer_material_bytes), decoded)

        blocked_actions = (
            "http.capture",
            "identity.verify",
            "surface.register",
            "plan.checkpoint",
            "plan.finalize",
            "plan.accept_partial",
            "campaign.start",
            "campaign.checkpoint",
            "test.run",
            "review.finding",
        )
        unblocked = []
        for action in blocked_actions:
            try:
                assessment_mode.require_action(self.project, action, {})
            except EngineError as exc:
                self.assertEqual("read_only", exc.code, action)
            else:
                unblocked.append(action)
        self.assertEqual([], unblocked, "rolled-back compatibility view left write actions open")

        for action in (
            "project.migrate",
            "project.rollback",
            "project.projection",
            "execution.reconcile",
        ):
            with self.subTest(allowed=action):
                assessment_mode.require_action(self.project, action, {})


if __name__ == "__main__":
    unittest.main()
