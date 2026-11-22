"""Document repository and bounded indexes for the 2.0 entities.

The v1 store remains the single SQLite fact database.  v2 records live in the
same ``entities`` table under ``v2_*`` kinds, with an auxiliary index table used
for bounded status/family/operation queries.  A read-only shadow repository
never executes DDL and falls back to scanning existing documents.
"""
from __future__ import annotations

import json

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
    "applicability_receipt": "v2_applicability_receipt",
    "proof_receipt": "v2_review_proof_receipt",
    "frontier_receipt": "v2_frontier_receipt",
    "completion_acceptance": "v2_completion_acceptance",
    "finding": "v2_finding",
    "gap": "v2_gap",
    "checkpoint": "v2_checkpoint",
    "migration": "v2_migration",
    "fixture": "v2_fixture",
    "capability": "v2_capability",
    "legacy_evaluation": "v2_legacy_evaluation",
    "route_source": "v2_route_source",
    "event": "v2_event",
    "execution_dispatch": "v2_execution_dispatch",
}
IMMUTABLE = {
    "universe", "recipe", "review", "checkpoint", "migration", "legacy_evaluation",
    "event", "applicability_receipt", "proof_receipt", "frontier_receipt",
    "completion_acceptance", "execution_dispatch",
}
INDEX_KEYS = {
    "campaign": ("state", "model"),
    "known_case": ("source_group", "track", "status"),
    "hypothesis": ("campaign_id", "universe_id", "status", "family", "operation_id",
                   "source_kind", "known_case_id", "mechanism_key"),
    "recipe": ("campaign_id", "universe_id", "hypothesis_id", "family"),
    "run": ("status", "hypothesis_id", "recipe_id", "campaign_id"),
    "review": ("campaign_id", "hypothesis_id", "run_id"),
    "applicability_receipt": ("campaign_id", "hypothesis_id", "security_property", "input_key"),
    "proof_receipt": ("campaign_id", "hypothesis_id", "run_id", "review_id", "mode"),
    "frontier_receipt": ("campaign_id", "state"),
    "completion_acceptance": ("campaign_id", "state"),
    "finding": ("campaign_id", "status", "mode", "hypothesis_id", "proof_receipt_id"),
    "gap": ("campaign_id", "kind", "status"),
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

    def add(self, kind, record, *, immutable=True, index=None, create_only=None):
        """Create a new record; immutable kinds cannot be replaced."""
        if self.read_only:
            fail("v2_read_only", "Shadow repository is read-only")
        if not isinstance(record, dict) or not isinstance(record.get("id"), str):
            fail("v2_repository_record", "Records require a nonempty ID")
        self._ensure_index()
        entity_kind = self._kind(kind)
        keys = index if index is not None else INDEX_KEYS.get(kind, ())
        if create_only is None:
            create_only = immutable or kind in IMMUTABLE
        with self.project.transaction():
            self.project.put(entity_kind, record, create_only=create_only)
            for key in keys:
                value = record.get(key)
                if value is None:
                    continue
                self.connection.execute(
                    "INSERT OR REPLACE INTO v2_entity_index(kind,key,value,id) VALUES(?,?,?,?)",
                    (entity_kind, key, canonical(value), record["id"]))
        return record

    def get_revision(self, kind, identity):
        return self.project.get_revision(self._kind(kind), identity)

    def save(self, kind, record, *, index=None, expected_revision=None):
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
            if expected_revision is None:
                self.project.put(entity_kind, record, create_only=False)
            else:
                self.project.compare_and_swap(entity_kind, record, expected_revision)
            for key in keys:
                value = record.get(key)
                if value is None:
                    continue
                self.connection.execute(
                    "INSERT OR REPLACE INTO v2_entity_index(kind,key,value,id) VALUES(?,?,?,?)",
                    (entity_kind, key, canonical(value), record["id"]))
        return record

    def list_campaign(self, kind, campaign_id, *, where=None, offset=0, limit=None):
        """List only records explicitly owned by one campaign."""
        query = {"campaign_id": campaign_id}
        query.update(where or {})
        return self.list(kind, where=query, offset=offset, limit=limit)

    def require_campaign(self, kind, identity, campaign_id):
        """Load a campaign-owned fact and reject cross-campaign references."""
        row = self.get(kind, identity)
        actual = row.get("campaign_id")
        if actual != campaign_id:
            fail("v2_campaign_scope",
                 f"{kind} does not belong to campaign {campaign_id}",
                 entity_id=identity, expected_campaign_id=campaign_id,
                 actual_campaign_id=actual)
        return row

    def get(self, kind, identity, required=True):
        return self.project.get(self._kind(kind), identity, required=required)

    def list(self, kind, *, where=None, offset=0, limit=None):
        entity_kind = self._kind(kind)
        where = dict(where or {})
        if type(offset) is not int or offset < 0 \
                or (limit is not None and (type(limit) is not int or limit < 0)):
            fail("pagination", "offset and limit must be nonnegative integers")
        # An explicit unbounded request is reserved for internal projection
        # builders. Public and campaign-scoped reads use SQL count/page so only
        # the current page is JSON-decoded.
        if limit is None:
            records = self.project.list(entity_kind)
            if where:
                records = [
                    row for row in records
                    if all(row.get(key) == value for key, value in where.items())
                ]
            records.sort(key=lambda row: (row.get("created_at", ""), row.get("id", "")))
            total = len(records)
            return records[offset:], total

        clauses, params = ["e.kind=?"], [entity_kind]
        indexed = set(INDEX_KEYS.get(kind, ()))
        for position, (key, value) in enumerate(sorted(where.items())):
            if not isinstance(key, str):
                fail("v2_repository_where", "Repository filters require string field names")
            if key in indexed and not self.read_only:
                # Use the maintained V2 index without materializing every entity.
                # EXISTS keeps multi-filter intersection semantics and avoids the
                # duplicate-row risk of joining the one-to-many index table.
                alias = "ix" + str(position)
                clauses.append(
                    "EXISTS (SELECT 1 FROM v2_entity_index " + alias
                    + " WHERE " + alias + ".kind=? AND " + alias + ".id=e.id"
                    + " AND " + alias + ".key=? AND " + alias + ".value=?)"
                )
                params.extend([entity_kind, key, canonical(value)])
            else:
                clauses.append("json_extract(e.document,?) IS ?")
                params.extend(["$." + key, value])
        where_sql = " AND ".join(clauses)
        with self.project._lock:
            total = self.connection.execute(
                "SELECT COUNT(*) FROM entities e WHERE " + where_sql, params
            ).fetchone()[0]
            if limit == 0:
                return [], total
            rows = self.connection.execute(
                "SELECT e.document FROM entities e WHERE " + where_sql
                + " ORDER BY e.created_at,e.id LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        return [json.loads(row[0]) for row in rows], total

    def find_one(self, kind, **where):
        records, _ = self.list(kind, where=where, limit=1)
        return records[0] if records else None

    def count(self, kind, *, where=None):
        _, total = self.list(kind, where=where, limit=0)
        return total


def checkpoint_record(*, campaign_id, universe, coverage, hypotheses, known_cases, gaps,
                      frontier_receipt_ids=None, label=None):
    hypothesis_projection = sorted([
        [row.get("id"), row.get("status"), row.get("state_reason"),
         row.get("proof_receipt_id"), row.get("applicability_receipt_id")]
        for row in hypotheses
    ])
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
        "hypotheses": hypothesis_projection,
        "frontier_receipt_ids": sorted(frontier_receipt_ids or []),
        "work_semantic_hash": digest({
            "hypotheses": hypothesis_projection,
            "gaps": sorted(gaps),
            "frontier_receipt_ids": sorted(frontier_receipt_ids or []),
        }),
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
