"""Reversible storage upgrades with a zero-write preview and private backups.

Legacy facts retain their IDs and bytes. Migration annotates unverifiable and
ambiguous history; it never manufactures a target execution or a proof receipt.
Rollback selects a read-only compatibility view and preserves newer facts.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from uuid import uuid4

from .store import EngineError, Project, canonical, contained, now

SCHEMA = "awa-storage-migration/v1"
_ANNOTATIONS = {"storage_migration", "migration_quarantine", "legacy_unverified"}


def _sha(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _hash_file(path):
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _plan(project):
    from .fingerprint import core_manifest
    from .domain.taxonomy import FAMILIES

    rows = project.connection.execute(
        "SELECT kind,id,document FROM entities ORDER BY kind,id").fetchall()
    documents = [(row[0], row[1], json.loads(row[2])) for row in rows if row[0] not in _ANNOTATIONS]
    counts, unverified, quarantine = {}, [], []
    decisions = {identity: document for kind, identity, document in documents if kind == "decision"}
    campaigns = {identity: document for kind, identity, document in documents if kind == "v2_campaign"}
    for kind, identity, document in documents:
        counts[kind] = counts.get(kind, 0) + 1
        reason = None
        if kind == "obligation" and document.get("status") == "not_applicable" \
                and not document.get("applicability_receipt_id"):
            reason = "legacy_applicability_without_receipt"
        if kind == "finding" and document.get("mode") == "analyst":
            decision = decisions.get(document.get("decision_id"), {})
            oracle = decision.get("oracle") or {}
            if oracle.get("type") == "analyst_review" and not decision.get("proof_decision_id"):
                reason = "legacy_untyped_analyst_conclusion"
        if reason:
            unverified.append({"source_kind": kind, "source_id": identity, "reason_code": reason})
        if kind.startswith("v2_") and kind not in {"v2_campaign", "v2_universe", "v2_known_case", "v2_capability", "v2_migration"}:
            campaign = campaigns.get(document.get("campaign_id"))
            if campaign is None:
                quarantine.append({"source_kind": kind, "source_id": identity,
                                   "reason_code": "campaign_membership_unavailable"})
            elif document.get("universe_id") and document["universe_id"] != campaign.get("universe_id"):
                quarantine.append({"source_kind": kind, "source_id": identity,
                                   "reason_code": "campaign_universe_conflict"})
        family = document.get("family") or document.get("test_family")
        if family is not None and family not in FAMILIES:
            quarantine.append({"source_kind": kind, "source_id": identity,
                               "reason_code": "unknown_taxonomy_preserved"})
    source = [(kind, identity, _sha(document)) for kind, identity, document in documents]
    facts = {"schema": SCHEMA, "project_id": project.project_id, "source_schema_version": 1,
             "core_manifest_sha256": core_manifest()["sha256"], "source_sha256": _sha(source),
             "config_sha256": _sha(project.config), "source_counts": counts,
             "legacy_unverified_total": len(unverified), "quarantine_total": len(quarantine),
             "synthetic_test_runs": 0, "requests_sent": 0,
             "legacy_ids_preserved": True, "automatic_campaign_assignment": False}
    identity = "SMIG-" + _sha(facts)
    return {"id": identity, **facts}, unverified, quarantine, documents


def _references(project, documents):
    result = {}
    for kind, identity, document in documents:
        references = ([{"path": document["artifact_path"], "sha256": document.get("sha256")}]
                      if document.get("artifact_path") else [])
        references.extend(row for row in (document.get("files") or []) if isinstance(row, dict) and row.get("path"))
        for field in ("screenshot", "html", "after_actions_html"):
            if document.get(field):
                references.append({"path": document[field], "sha256": document.get(field + "_sha256")})
        for reference in references:
            relative = reference["path"]
            if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
                raise EngineError("migration_material", "A legacy artifact locator is not a contained project path")
            path = contained(project.base / relative, project.base)
            if not path.is_file():
                raise EngineError("migration_material", "A referenced legacy artifact is missing; restore it before applying migration")
            entry = result.setdefault(relative, {"path": relative, "declared_sha256": set()})
            if reference.get("sha256"):
                entry["declared_sha256"].add(reference["sha256"])
    return result


def _backup(project, plan, documents):
    try:
        parent = contained(project.base / "migrations", project.base)
        parent.mkdir(exist_ok=True, mode=0o700)
        destination = contained(parent / plan["id"], parent)
        if destination.exists():
            if not destination.is_dir():
                raise EngineError("migration_backup", "The saved migration backup locator is not a directory")
            marker = contained(destination / ".incomplete", destination)
            if marker.exists():
                # Preserve interrupted backups from the older direct-write layout.
                # An arbitrary pre-existing directory is never removed or adopted.
                if not marker.is_file() or marker.stat().st_size > 64 \
                        or marker.read_bytes() != b"awa-storage-backup/v1\n":
                    raise EngineError("migration_backup", "The existing incomplete backup cannot be identified; its files were preserved")
                preserved = contained(parent / (".interrupted-" + uuid4().hex[:16]), parent)
                os.rename(destination, preserved)
            else:
                digest, manifest = _verify_backup(project, plan["id"])
                if any(manifest.get(key) != plan[key] for key in ("source_sha256", "config_sha256", "core_manifest_sha256")):
                    raise EngineError("migration_backup", "An orphaned backup does not match the current migration plan")
                return digest, manifest
        # Only this freshly created, contained temporary directory is cleaned
        # on failure. The formal SMIG directory appears in one atomic rename.
        with tempfile.TemporaryDirectory(prefix=".stage-", dir=parent) as temporary:
            staging = contained(Path(temporary), parent)
            target_db = contained(staging / "assessment.sqlite3", staging)
            # Use the stable DB/WAL snapshot instead of backing up a connection
            # that already owns the caller's BEGIN IMMEDIATE transaction.
            with Project(project.workspace, project.project_id, read_only=True) as source:
                source_plan, _, _, _ = _plan(source)
                if source_plan["source_sha256"] != plan["source_sha256"] or source_plan["config_sha256"] != plan["config_sha256"]:
                    raise EngineError("migration_busy", "Project changed after preview; retry migration from a fresh snapshot")
                # The Windows handle must close before publishing the directory.
                with closing(sqlite3.connect(str(target_db))) as target:
                    source.connection.backup(target)
                    if target.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                        raise EngineError("migration_snapshot", "The migration database backup failed its consistency check")
            digest, size = _hash_file(target_db)
            files = [{"path": "assessment.sqlite3", "sha256": digest, "size_bytes": size}]
            for relative, reference in sorted(_references(project, documents).items()):
                original = contained(project.base / relative, project.base)
                before = original.stat()
                # Compact object names keep the final backup within Windows'
                # legacy path limit, while source_path preserves the locator.
                object_name = hashlib.sha256(relative.encode("utf-8")).hexdigest()[:32]
                target = contained(staging / "objects" / object_name, staging)
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                digest, size = hashlib.sha256(), 0
                with original.open("rb") as incoming, target.open("xb") as outgoing:
                    while chunk := incoming.read(1024 * 1024):
                        outgoing.write(chunk)
                        digest.update(chunk)
                        size += len(chunk)
                    outgoing.flush()
                    os.fsync(outgoing.fileno())
                after = original.stat()
                actual = digest.hexdigest()
                if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != \
                        (after.st_size, after.st_mtime_ns, after.st_ctime_ns) or size != before.st_size \
                        or any(value != actual for value in reference["declared_sha256"]):
                    raise EngineError("migration_material", "A legacy artifact changed; the upgrade cannot accept its declared digest")
                files.append({"path": "objects/" + object_name, "source_path": relative,
                              "sha256": actual, "size_bytes": size})
            manifest = {"schema": "awa-storage-backup/v1", "migration_id": plan["id"],
                        "source_sha256": plan["source_sha256"], "config_sha256": plan["config_sha256"],
                        "core_manifest_sha256": plan["core_manifest_sha256"],
                        "created_at": now(), "files": files, "contains_private_material": True}
            raw = canonical(manifest).encode("utf-8")
            with (staging / "manifest.json").open("xb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            if destination.exists():
                raise EngineError("migration_backup", "A migration backup appeared during preparation; its files were preserved")
            os.rename(staging, destination)
    except OSError as exc:
        raise EngineError("migration_backup", "The private migration backup could not be published; existing backup files were preserved") from exc
    return hashlib.sha256(raw).hexdigest(), manifest


def _verify_backup(project, ledger_id, expected=None):
    if not isinstance(ledger_id, str) or not ledger_id.startswith("SMIG-") or len(ledger_id) != 69 \
            or any(char not in "0123456789abcdef" for char in ledger_id[5:]):
        raise EngineError("migration_ledger", "Use an exact saved storage migration ledger ID")
    folder = contained(project.base / "migrations" / ledger_id, project.base)
    if (folder / ".incomplete").exists():
        raise EngineError("migration_backup", "An incomplete migration backup cannot be used for rollback")
    path = contained(folder / "manifest.json", project.base)
    if not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
        raise EngineError("migration_backup", "The saved migration backup manifest is unavailable")
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    try:
        manifest = json.loads(raw)
    except ValueError:
        raise EngineError("migration_backup", "The saved migration backup manifest is invalid") from None
    if not isinstance(manifest, dict) or expected is not None and digest != expected \
            or manifest.get("migration_id") != ledger_id or manifest.get("schema") != "awa-storage-backup/v1":
        raise EngineError("migration_backup", "The saved migration backup manifest changed")
    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries or sum(isinstance(entry, dict) and
            entry.get("path") == "assessment.sqlite3" for entry in entries) != 1:
        raise EngineError("migration_backup", "The saved backup must contain its exact database snapshot")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str) \
                or Path(entry["path"]).is_absolute() or ".." in Path(entry["path"]).parts \
                or entry["path"] in seen or type(entry.get("size_bytes")) is not int or entry["size_bytes"] < 0 \
                or not isinstance(entry.get("sha256"), str):
            raise EngineError("migration_backup", "A saved backup file descriptor is invalid")
        seen.add(entry["path"])
        artifact = contained(folder / entry["path"], folder)
        if not artifact.is_file() or _hash_file(artifact) != (entry["sha256"], entry["size_bytes"]):
            raise EngineError("migration_backup", "A saved migration backup file changed")
    try:
        with closing(sqlite3.connect(
                (folder / "assessment.sqlite3").as_uri() + "?mode=ro&immutable=1",
                uri=True)) as database:
            if database.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise EngineError("migration_backup", "The saved database snapshot is inconsistent")
            source = [(kind, identity, _sha(json.loads(document))) for kind, identity, document in database.execute(
                "SELECT kind,id,document FROM entities ORDER BY kind,id") if kind not in _ANNOTATIONS]
            config = database.execute("SELECT value FROM metadata WHERE key='config'").fetchone()
            config_document = json.loads(config[0]) if config else {}
            if config_document:
                config_document.setdefault("assessment_mode", "assessment")
            if _sha(source) != manifest.get("source_sha256") or config is None \
                    or _sha(config_document) != manifest.get("config_sha256"):
                raise EngineError("migration_backup", "The saved database does not match its migration source manifest")
    except EngineError:
        raise
    except (sqlite3.Error, ValueError, TypeError) as exc:
        raise EngineError("migration_backup", "The saved database could not be verified") from exc
    return digest, manifest


def migrate(project, args):
    if not isinstance(args, dict):
        raise EngineError("migration_mode", "Migration arguments must be an object")
    mode = args.get("mode", "dry_run")
    if not isinstance(mode, str) or mode not in {"dry_run", "apply"}:
        raise EngineError("migration_mode", "Migration mode must be dry_run or apply")
    if mode == "dry_run" and not project.read_only:
        with Project(project.workspace, project.project_id, read_only=True) as snapshot:
            return migrate(snapshot, args)
    plan, unverified, quarantine, documents = _plan(project)
    if mode == "dry_run":
        return {"migration": {**plan, "state": "preview", "backup_available": False},
                "mode": mode, "writes": 0, "requests_sent": 0, "next_action": "project.migrate"}
    if project.read_only:
        raise EngineError("read_only", "Migration apply requires the writable project connection")
    with project.transaction():
        plan, unverified, quarantine, documents = _plan(project)
        existing = project.get("storage_migration", plan["id"], required=False)
        if existing:
            _verify_backup(project, existing["id"], existing["backup_manifest_sha256"])
            return {"migration": existing, "mode": mode, "writes": 0, "requests_sent": 0,
                    "next_action": "project.projection"}
        busy = project.connection.execute(
            "SELECT COUNT(*) FROM execution_leases WHERE dispatched=1 OR expires_at>strftime('%s','now')").fetchone()[0]
        if busy:
            raise EngineError("migration_busy", "Reconcile retained executions before switching storage views")
        backup_digest, manifest = _backup(project, plan, documents)
        ledger = {**plan, "state": "applied", "backup_available": True,
                  "backup_manifest_sha256": backup_digest, "backup_file_total": len(manifest["files"]),
                  "created_at": now(), "rollback_mode": "legacy_read_only"}
        project.put("storage_migration", ledger, create_only=True)
        for kind, annotations in (("legacy_unverified", unverified), ("migration_quarantine", quarantine)):
            for annotation in annotations:
                record = {"id": "ML-" + _sha([plan["id"], kind, annotation]),
                          "migration_id": plan["id"], **annotation, "authority_granted": False, "created_at": now()}
                project.put(kind, record, create_only=True)
        project.set_metadata("storage_mode", "canonical_compatibility")
        project.set_metadata("storage_migration_id", plan["id"])
        project.event("storage.migrated", {"migration_id": plan["id"], "synthetic_test_runs": 0})
    return {"migration": ledger, "mode": mode, "writes": 1 + len(unverified) + len(quarantine),
            "requests_sent": 0, "next_action": "project.projection"}


def rollback(project, args):
    ledger = project.get("storage_migration", args.get("ledger_id"))
    with project.transaction():
        busy = project.connection.execute(
            "SELECT COUNT(*) FROM execution_leases WHERE dispatched=1 OR expires_at>strftime('%s','now')").fetchone()[0]
        if busy:
            raise EngineError("migration_busy", "Reconcile retained executions before switching storage views")
        _verify_backup(project, ledger["id"], ledger["backup_manifest_sha256"])
        if project.get_metadata("storage_mode") == "legacy_read_only" \
                and project.get_metadata("storage_rollback_id") == ledger["id"]:
            return {"rolled_back_to": "legacy_read_only", "ledger_id": ledger["id"],
                    "new_facts_preserved": True, "requests_replayed": 0, "requests_sent": 0,
                    "next_action": "project.status"}
        project.set_metadata("storage_mode", "legacy_read_only")
        project.set_metadata("storage_rollback_id", ledger["id"])
        project.event("storage.rollback_read_only", {"migration_id": ledger["id"], "new_facts_preserved": True})
    return {"rolled_back_to": "legacy_read_only", "ledger_id": ledger["id"],
            "new_facts_preserved": True, "requests_replayed": 0, "requests_sent": 0,
            "next_action": "project.status"}
