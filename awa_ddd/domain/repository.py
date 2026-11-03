"""Document repository and bounded indexes for the 2.0 entities.

The v1 store remains the single SQLite fact database.  v2 records live in the
same ``entities`` table under ``v2_*`` kinds, with an auxiliary index table used
for bounded status/family/operation queries.  A read-only shadow repository
never executes DDL and falls back to scanning existing documents.
"""
from __future__ import annotations

from ..store import EngineError, canonical
from .common import clone, digest, fail, stable_id, utc_now

KINDS = {
    "campaign": "v2_campaign",
    "universe": "v2_universe",
    "known_case": "v2_known_case",
    "hypothesis": "v2_hypothesis",
    "recipe": "v2_recipe",
    "run": "v2_run",
    "review": "v2_review",
    "finding": "v2_finding",
    "gap": "v2_gap",
    "checkpoint": "v2_checkpoint",
    "migration": "v2_migration",
    "fixture": "v2_fixture",
    "capability": "v2_capability",
    "legacy_evaluation": "v2_legacy_evaluation",
    "route_source": "v2_route_source",
    "event": "v2_event",
}
IMMUTABLE = {"universe", "recipe", "review", "checkpoint", "migration", "legacy_evaluation", "event"}
INDEX_KEYS = {
    "campaign": ("state", "model"),
    "known_case": ("source_group", "track", "status"),
    "hypothesis": ("status", "family", "operation_id", "source_kind", "known_case_id"),
    "recipe": ("hypothesis_id",),
    "run": ("status", "hypothesis_id", "recipe_id", "campaign_id"),
    "review": ("hypothesis_id", "run_id"),
    "finding": ("status", "mode", "hypothesis_id"),
    "gap": ("kind", "status"),
    "checkpoint": ("campaign_id",),
    "fixture": ("state", "operation_id"),
    "capability": ("provider", "readiness"),
}


class Repository:
    def __init__(self, project, *, read_only=False):
        self.project = project
        self.read_only = bool(read_only)
        self._index_ready = False
        if not self.read_only:
            self._ensure_index()

    @property
    def connection(self):
        return self.project.connection

    def _ensure_index(self):
        if self._index_ready:
            return
        with self.project.transaction():
            self.connection.execute("""
                CREATE TABLE IF NOT EXISTS v2_entity_index (
                    kind TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, id TEXT NOT NULL,
                    PRIMARY KEY(kind, key, value, id))""")
            self.connection.execute(
                "CREATE INDEX IF NOT EXISTS v2_entity_index_lookup ON v2_entity_index(kind, key, value, id)")
        self._index_ready = True

    def _kind(self, kind):
        if kind not in KINDS:
            fail("v2_repository_kind", f"Unknown v2 entity kind: {kind}")
        return KINDS[kind]

    def add(self, kind, record, *, immutable=True, index=None):
        """Create a new record; immutable kinds cannot be replaced."""
        if self.read_only:
            fail("v2_read_only", "Shadow repository is read-only")
        if not isinstance(record, dict) or not isinstance(record.get("id"), str):
            fail("v2_repository_record", "Records require a nonempty ID")
        self._ensure_index()
        entity_kind = self._kind(kind)
        keys = index if index is not None else INDEX_KEYS.get(kind, ())
        with self.project.transaction():
            self.project.put(entity_kind, record, create_only=immutable or kind in IMMUTABLE)
            for key in keys:
                value = record.get(key)
                if value is None:
                    continue
                self.connection.execute(
                    "INSERT OR REPLACE INTO v2_entity_index(kind,key,value,id) VALUES(?,?,?,?)",
                    (entity_kind, key, canonical(value), record["id"]))
        return record

    def save(self, kind, record, *, index=None):
        if self.read_only:
            fail("v2_read_only", "Shadow repository is read-only")
        if kind in IMMUTABLE:
            fail("v2_repository_immutable", f"{kind} records are immutable; append a new revision")
        entity_kind = self._kind(kind)
        keys = index if index is not None else INDEX_KEYS.get(kind, ())
        with self.project.transaction():
            # Drop old index entries for fields that may have changed (status,
            # lease, family), then insert the current values atomically.
            self.connection.execute("DELETE FROM v2_entity_index WHERE kind=? AND id=?", (entity_kind, record["id"]))
            self.project.put(entity_kind, record, create_only=False)
            for key in keys:
                value = record.get(key)
                if value is None:
                    continue
                self.connection.execute(
                    "INSERT OR REPLACE INTO v2_entity_index(kind,key,value,id) VALUES(?,?,?,?)",
                    (entity_kind, key, canonical(value), record["id"]))
        return record

    def get(self, kind, identity, required=True):
        return self.project.get(self._kind(kind), identity, required=required)

    def list(self, kind, *, where=None, offset=0, limit=None):
        entity_kind = self._kind(kind)
        where = dict(where or {})
        records = None
        if where and not self.read_only:
            keys = set(INDEX_KEYS.get(kind, ()))
            if set(where).issubset(keys):
                ids = None
                for key, value in sorted(where.items()):
                    rows = self.connection.execute(
                        "SELECT id FROM v2_entity_index WHERE kind=? AND key=? AND value=?",
                        (entity_kind, key, canonical(value))).fetchall()
                    current = {row[0] for row in rows}
                    ids = current if ids is None else ids & current
                records = [self.project.get(entity_kind, identity) for identity in (ids or set())]
        if records is None:
            records = self.project.list(entity_kind)
            if where:
                records = [row for row in records if all(row.get(key) == value for key, value in where.items())]
        records.sort(key=lambda row: (row.get("created_at", ""), row.get("id", "")))
        total = len(records)
        if offset:
            records = records[offset:]
        if limit is not None:
            records = records[:limit]
        return records, total

    def find_one(self, kind, **where):
        records, _ = self.list(kind, where=where, limit=1)
        return records[0] if records else None

    def count(self, kind, *, where=None):
        _, total = self.list(kind, where=where, limit=0)
        return total


def checkpoint_record(*, campaign_id, universe, coverage, hypotheses, known_cases, gaps, label=None):
    body = {
        "schema": 2,
        "campaign_id": campaign_id,
        "label": label,
        "universe_snapshot_hash": universe.get("snapshot_hash"),
        "universe_summary": {key: len(universe.get(key, [])) for key in
                             ("origins", "routes", "pages", "functions", "operations", "inputs", "consumers")},
        "hypothesis_counts": _status_counts(hypotheses),
        "family_matrix": coverage.get("family_matrix", []),
        "known_case_matrix": known_cases,
        "coverage": coverage,
        "gaps": gaps,
        "created_at": utc_now(),
    }
    body["id"] = stable_id("CP2", body)
    body["snapshot_hash"] = digest(body)
    return body


def _status_counts(rows):
    counts = {}
    for row in rows:
        status = row.get("status", "unknown")
        counts[status] = counts.get(status, 0) + 1
    return counts
