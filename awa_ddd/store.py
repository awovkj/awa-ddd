"""Transactional local entities and append-only events; no global mutable state."""
from __future__ import annotations
import hashlib
import base64
import json
import os
from pathlib import Path
import re
import sqlite3
import shutil
import threading
import tempfile
from datetime import datetime, timezone
from uuid import uuid4
from contextlib import contextmanager


def now():
    return datetime.now(timezone.utc).isoformat()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


class EngineError(ValueError):
    def __init__(self, code, message, details=None):
        self.code = code
        self.details = details or {}
        super().__init__(message)


def contained(path, root):
    path, root = Path(path), Path(root).resolve()
    resolved = path.resolve()
    if not resolved.is_relative_to(root):
        raise EngineError("path_escape", "Path escapes the project workspace")
    current = path
    while current != root and current != current.parent:
        if current.is_symlink() or (current.exists() and getattr(current.stat(follow_symlinks=False), "st_file_attributes", 0) & 0x400):
            raise EngineError("path_link", "Runtime paths must not contain symlinks or junctions")
        current = current.parent
    return resolved


class Project:
    def __init__(self, workspace, project_id, create=False, *, read_only=False):
        if not isinstance(project_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", project_id):
            raise EngineError("project_id", "Invalid project ID")
        self.workspace = Path(workspace).expanduser().resolve()
        self.project_id = project_id
        self.base = contained(self.workspace / "projects" / project_id, self.workspace)
        db = contained(self.base / "assessment.sqlite3", self.workspace)
        self.database_path = db
        self.read_only = bool(read_only)
        self._read_snapshot = None
        if not create and not db.is_file():
            raise EngineError("project_missing", "Project does not exist")
        if create:
            if read_only:
                raise EngineError("read_only", "A read-only snapshot cannot create a project")
            self.base.mkdir(parents=True, exist_ok=True, mode=0o700)
        if read_only:
            # Opening a WAL database directly can create/update its shared-memory
            # sidecar even with mode=ro. Copy a stable DB/WAL bundle first, so a
            # dry-run never writes the original database or its journal files.
            self._read_snapshot = tempfile.TemporaryDirectory(prefix="awa-read-snapshot-")
            snapshot = Path(self._read_snapshot.name) / db.name
            paths = [db, Path(str(db) + "-wal")]
            for attempt in range(3):
                try:
                    before = {str(path): (path.stat().st_size, path.stat().st_mtime_ns, path.stat().st_ctime_ns)
                              for path in paths if path.exists()}
                    for path in paths:
                        destination = snapshot.parent / path.name
                        if str(path) in before:
                            shutil.copyfile(path, destination)
                        elif destination.exists():
                            destination.unlink()
                    after = {str(path): (path.stat().st_size, path.stat().st_mtime_ns, path.stat().st_ctime_ns)
                             for path in paths if path.exists()}
                except OSError:
                    continue
                if before == after:
                    break
            else:
                self._read_snapshot.cleanup()
                raise EngineError("migration_busy", "Project changed while its read-only snapshot was captured; retry the dry-run")
            try:
                self.connection = sqlite3.connect(snapshot.as_uri() + "?mode=ro", uri=True,
                                                 timeout=15, check_same_thread=False)
            except sqlite3.Error as exc:
                self._read_snapshot.cleanup()
                self._read_snapshot = None
                raise EngineError("migration_snapshot", "The copied database snapshot could not be opened") from exc
        else:
            self.connection = sqlite3.connect(str(db), timeout=15, check_same_thread=False)
        # Concurrent scenario steps capture from several threads but share one
        # connection. Serialize every transaction through this re-entrant lock so
        # nested SAVEPOINT usage stays consistent within a thread.
        self._lock = threading.RLock()
        self.metrics = {"records_decoded": 0, "sql_pages": 0, "artifact_bytes_hashed": 0, "material_bytes_hashed": 0}
        self.connection.row_factory = sqlite3.Row
        if read_only:
            try:
                self.connection.execute("PRAGMA query_only=ON")
                if self.connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise EngineError("migration_snapshot", "Read-only database snapshot failed its consistency check")
                version = self.connection.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()
                if version is None or version[0] != "1":
                    raise EngineError("schema_version", "Unsupported workspace schema version")
            except (sqlite3.Error, EngineError) as exc:
                self.close()
                if isinstance(exc, EngineError):
                    raise
                raise EngineError("migration_snapshot", "The copied read-only snapshot is inconsistent") from exc
            return
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA busy_timeout=15000")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS entities (
                kind TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1,
                document TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                PRIMARY KEY(kind,id));
            CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL,
                document TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS entities_page ON entities(kind,created_at,id);
            CREATE INDEX IF NOT EXISTS entities_status ON entities(kind,json_extract(document,'$.status'),created_at,id);
            CREATE INDEX IF NOT EXISTS entities_campaign ON entities(kind,json_extract(document,'$.campaign_id'),created_at,id);
            CREATE INDEX IF NOT EXISTS entities_snapshot ON entities(kind,json_extract(document,'$.snapshot_id'),id);
            CREATE INDEX IF NOT EXISTS entities_operation ON entities(kind,json_extract(document,'$.operation_id'),created_at,id);
            CREATE INDEX IF NOT EXISTS entities_route ON entities(kind,json_extract(document,'$.url'),json_extract(document,'$.method'));
            CREATE TABLE IF NOT EXISTS entity_changes (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT NOT NULL,id TEXT NOT NULL,
                revision INTEGER NOT NULL,operation TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS changes_kind ON entity_changes(kind,seq);
            CREATE TRIGGER IF NOT EXISTS entities_insert_change AFTER INSERT ON entities BEGIN
                INSERT INTO entity_changes(kind,id,revision,operation) VALUES(NEW.kind,NEW.id,NEW.revision,'insert');
            END;
            CREATE TRIGGER IF NOT EXISTS entities_update_change AFTER UPDATE ON entities BEGIN
                INSERT INTO entity_changes(kind,id,revision,operation) VALUES(NEW.kind,NEW.id,NEW.revision,'update');
            END;
            CREATE TRIGGER IF NOT EXISTS entities_delete_change AFTER DELETE ON entities BEGIN
                INSERT INTO entity_changes(kind,id,revision,operation) VALUES(OLD.kind,OLD.id,OLD.revision,'delete');
            END;
            CREATE TABLE IF NOT EXISTS projection_store (
                name TEXT PRIMARY KEY,schema_version INTEGER NOT NULL,generation INTEGER NOT NULL,
                document TEXT NOT NULL,updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS artifact_parse_cache (
                sha256 TEXT NOT NULL,parser_version TEXT NOT NULL,document TEXT NOT NULL,
                PRIMARY KEY(sha256,parser_version));
            CREATE TABLE IF NOT EXISTS advisory_state (
                name TEXT PRIMARY KEY,document TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS source_projection_items (
                id TEXT PRIMARY KEY,source_id TEXT NOT NULL,snapshot_id TEXT NOT NULL,
                position INTEGER NOT NULL,status TEXT NOT NULL,pending_import INTEGER NOT NULL,
                current_snapshot INTEGER NOT NULL,needs_binding INTEGER NOT NULL,
                operation_key TEXT,candidate_key TEXT,route_url TEXT,route_method TEXT,document TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS source_projection_page ON source_projection_items(snapshot_id,position);
            CREATE INDEX IF NOT EXISTS source_projection_status ON source_projection_items(status,source_id,position);
            CREATE INDEX IF NOT EXISTS source_projection_operation ON source_projection_items(operation_key);
            CREATE INDEX IF NOT EXISTS source_projection_candidate ON source_projection_items(candidate_key);
            CREATE TABLE IF NOT EXISTS source_projection_sources (
                id TEXT PRIMARY KEY,position INTEGER NOT NULL,document TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS recon_projection_items (
                mode TEXT NOT NULL,section TEXT NOT NULL,position INTEGER NOT NULL,document TEXT NOT NULL,
                PRIMARY KEY(mode,section,position));
            CREATE TABLE IF NOT EXISTS execution_leases (
                name TEXT PRIMARY KEY,owner TEXT NOT NULL,fence INTEGER NOT NULL,
                expires_at REAL NOT NULL,dispatched INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS execution_fences (
                name TEXT PRIMARY KEY,fence INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS execution_budget (
                name TEXT PRIMARY KEY,max_requests INTEGER NOT NULL,max_writes INTEGER NOT NULL,
                requests_used INTEGER NOT NULL DEFAULT 0,writes_used INTEGER NOT NULL DEFAULT 0,
                budget_unit TEXT NOT NULL DEFAULT 'request');
            CREATE TABLE IF NOT EXISTS ready_queue_items (
                queue TEXT NOT NULL,id TEXT NOT NULL,position INTEGER NOT NULL,
                status TEXT NOT NULL,operation_id TEXT,document TEXT NOT NULL,
                PRIMARY KEY(queue,id));
            CREATE INDEX IF NOT EXISTS ready_queue_page ON ready_queue_items(queue,status,position,id);
        """)
        if "budget_unit" not in {row[1] for row in self.connection.execute("PRAGMA table_info(execution_budget)")}:
            self.connection.execute("ALTER TABLE execution_budget ADD COLUMN budget_unit TEXT NOT NULL DEFAULT 'request'")
        self.connection.commit()
        self.connection.execute("INSERT OR IGNORE INTO metadata VALUES ('schema_version','1')")
        self.connection.commit()
        version = self.connection.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()[0]
        if version != "1":
            raise EngineError("schema_version", "Unsupported workspace schema version")

    @property
    def config(self):
        with self._lock:
            row = self.connection.execute("SELECT value FROM metadata WHERE key='config'").fetchone()
        config = json.loads(row[0]) if row else {}
        if config:
            config.setdefault("assessment_mode", "assessment")
        return config

    def set_config(self, config):
        self._require_writable()
        with self.transaction():
            from .assessment_mode import normalize_mode
            existing = self.config
            proposed = dict(config)
            selected = normalize_mode(proposed.get("assessment_mode", existing.get("assessment_mode")))
            if existing and selected != normalize_mode(existing.get("assessment_mode")):
                raise EngineError("assessment_mode_immutable", "Project assessment mode cannot be changed; create a separate project")
            if selected == "src" and proposed.get("allow_mutation"):
                raise EngineError("src_write_denied", "SRC projects cannot enable mutation")
            proposed["assessment_mode"] = selected
            self.connection.execute(
                "INSERT INTO metadata(key,value) VALUES('config',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (canonical(proposed),))

    def get_metadata(self, key, default=None):
        """Read a small JSON metadata value without exposing project secrets."""
        with self._lock:
            row = self.connection.execute("SELECT value FROM metadata WHERE key=?", (str(key),)).fetchone()
        if not row:
            return default
        try:
            return json.loads(row[0])
        except (TypeError, ValueError):
            return default

    def set_metadata(self, key, value):
        """Persist a small JSON value used for local scheduling state."""
        self._require_writable()
        with self.transaction():
            self.connection.execute(
                "INSERT INTO metadata(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(key), canonical(value)))

    @contextmanager
    def transaction(self):
        """Compose entity/event writes atomically, including nested operations.

        The lock makes this safe when scenario steps capture concurrently: all writes
        serialize on one connection while the HTTP requests themselves still overlap.
        """
        self._require_writable()
        with self._lock:
            nested = self.connection.in_transaction
            name = "awa_" + uuid4().hex
            self.connection.execute("SAVEPOINT " + name if nested else "BEGIN IMMEDIATE")
            try:
                yield self
            except BaseException:
                if nested:
                    self.connection.execute("ROLLBACK TO SAVEPOINT " + name)
                    self.connection.execute("RELEASE SAVEPOINT " + name)
                else:
                    self.connection.rollback()
                raise
            else:
                if nested:
                    self.connection.execute("RELEASE SAVEPOINT " + name)
                else:
                    self.connection.commit()

    @staticmethod
    def id(prefix):
        return prefix + "-" + uuid4().hex

    def get(self, kind, id, required=True):
        # Reads share the connection with concurrent captures; the lock prevents two
        # threads from interleaving cursors and returning another query's rows.
        with self._lock:
            row = self.connection.execute("SELECT document FROM entities WHERE kind=? AND id=?", (kind, id)).fetchone()
        if row:
            self.metrics["records_decoded"] += 1
            return json.loads(row[0])
        if required:
            raise EngineError("not_found", f"Unknown {kind} ID")
        return None

    def list(self, kind):
        with self._lock:
            rows = self.connection.execute(
                "SELECT document FROM entities WHERE kind=? ORDER BY created_at,id", (kind,)).fetchall()
        self.metrics["records_decoded"] += len(rows)
        return [json.loads(row[0]) for row in rows]

    def list_inserted(self, kind):
        """List mutable facts in durable insert order for within-timestamp tie-breaks."""
        with self._lock:
            rows = self.connection.execute(
                "SELECT document FROM entities WHERE kind=? ORDER BY rowid", (kind,)).fetchall()
        self.metrics["records_decoded"] += len(rows)
        return [json.loads(row[0]) for row in rows]

    def list_chronological(self, kind):
        """List facts by recorded time with durable insertion as the tie-break."""
        with self._lock:
            rows = self.connection.execute(
                "SELECT document FROM entities WHERE kind=? ORDER BY created_at,rowid", (kind,)).fetchall()
        self.metrics["records_decoded"] += len(rows)
        return [json.loads(row[0]) for row in rows]

    def generation(self, kinds=None):
        """A durable change watermark, including direct SQL updates/deletions."""
        where, params = "", []
        if kinds:
            params = list(kinds)
            where = " WHERE kind IN (" + ",".join("?" for _ in params) + ")"
        with self._lock:
            return self.connection.execute("SELECT COALESCE(MAX(seq),0) FROM entity_changes" + where, params).fetchone()[0]

    def get_revision(self, kind, identity):
        with self._lock:
            row = self.connection.execute("SELECT revision FROM entities WHERE kind=? AND id=?", (kind, identity)).fetchone()
        if not row:
            raise EngineError("not_found", f"Unknown {kind} ID")
        return row[0]

    def compare_and_swap(self, kind, record, expected_revision):
        """Update one mutable fact only if the caller's revision is still current."""
        self._require_writable()
        if type(expected_revision) is not int or expected_revision < 1:
            raise EngineError("expected_revision", "expected_revision must be a positive integer")
        if kind in self.IMMUTABLE_KINDS:
            raise EngineError("immutable_record", "Immutable facts require an appended revision")
        text = canonical(record)
        if not isinstance(record.get("id"), str) or len(text.encode("utf-8")) > 4 * 1024 * 1024:
            raise EngineError("record_budget", "Invalid record or storage budget exceeded")
        with self.transaction():
            updated = self.connection.execute(
                "UPDATE entities SET document=?,updated_at=?,revision=revision+1 WHERE kind=? AND id=? AND revision=?",
                (text, now(), kind, record["id"], expected_revision)).rowcount
            if updated != 1:
                raise EngineError("revision_conflict", "Entity changed after it was read; reload its current revision",
                                  {"entity_id": record["id"], "expected_revision": expected_revision})
        return record

    def list_page(self, kind, *, offset=0, limit=25, filters=None, cursor=None, order_desc=False):
        """SQL count/keyset page: only returned records are decoded from JSON."""
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 100:
            raise EngineError("pagination", "offset must be nonnegative and limit between 1 and 100")
        if type(order_desc) is not bool:
            raise EngineError("query_order", "order_desc must be a boolean")
        if filters is not None and not isinstance(filters, dict):
            raise EngineError("query_filter", "Indexed filters must be an object")
        filters = dict(filters or {})
        if any(not isinstance(key, str) or type(value) not in {str, int, float, bool, type(None)}
               for key, value in filters.items()):
            raise EngineError("query_filter", "Indexed filters require named scalar values")
        clauses, params = ["kind=?"], [kind]
        for key, value in sorted(filters.items()):
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", key):
                raise EngineError("query_filter", "Invalid indexed field")
            clauses.append("json_extract(document,?) IS ?")
            params.extend(["$." + key, value])
        query_key = hashlib.sha256(canonical([self.project_id, kind, filters, order_desc]).encode("utf-8")).hexdigest()
        generation = self.generation([kind])
        after = None
        if cursor is not None:
            if not isinstance(cursor, str) or not cursor or len(cursor) > 8192:
                raise EngineError("cursor_invalid", "Cursor must be the saved bounded query token")
            try:
                decoded = json.loads(base64.urlsafe_b64decode(cursor.encode("ascii")))
                if decoded["query"] != query_key or decoded["generation"] != generation:
                    raise EngineError("cursor_stale", "Query facts changed; restart this page from offset zero")
                after = decoded["after"]
                if not isinstance(after, list) or len(after) != 2 or not all(isinstance(part, str) for part in after):
                    raise ValueError("cursor")
                offset = decoded["offset"]
                if type(offset) is not int or offset < 0:
                    raise ValueError("cursor offset")
            except EngineError:
                raise
            except (ValueError, TypeError, KeyError, UnicodeError):
                raise EngineError("cursor_invalid", "Cursor does not bind this query") from None
        where = " AND ".join(clauses)
        with self._lock:
            total = self.connection.execute("SELECT COUNT(*) FROM entities WHERE " + where, params).fetchone()[0]
            page_where, page_params = where, list(params)
            if after:
                comparator = "<" if order_desc else ">"
                page_where += " AND (created_at" + comparator + "? OR (created_at=? AND id" + comparator + "?))"
                page_params.extend([after[0], after[0], after[1]])
            ordering = "created_at DESC,id DESC" if order_desc else "created_at,id"
            sql = "SELECT document,created_at,id FROM entities WHERE " + page_where + " ORDER BY " + ordering + " LIMIT ?"
            page_params.append(limit + 1)
            if not after:
                sql += " OFFSET ?"
                page_params.append(offset)
            rows = self.connection.execute(sql, page_params).fetchall()
        more, rows = len(rows) > limit, rows[:limit]
        self.metrics["records_decoded"] += len(rows)
        self.metrics["sql_pages"] += 1
        next_offset = offset + len(rows) if more else None
        next_cursor = (base64.urlsafe_b64encode(canonical({"query": query_key, "generation": generation,
            "after": [rows[-1][1], rows[-1][2]], "offset": next_offset}).encode("utf-8")).decode("ascii") if more else None)
        return {"items": [json.loads(row[0]) for row in rows], "total": total, "offset": offset, "limit": limit,
                "next_offset": next_offset, "cursor": next_cursor, "projection_revision": generation}

    def projection_get(self, name, generation, *, schema_version=1):
        with self._lock:
            row = self.connection.execute(
                "SELECT document FROM projection_store WHERE name=? AND generation=? AND schema_version=?",
                (name, generation, schema_version)).fetchone()
        return json.loads(row[0]) if row else None

    def projection_put(self, name, generation, document, *, schema_version=1):
        self._require_writable()
        text = canonical(document)
        if len(text.encode("utf-8")) > 32 * 1024 * 1024:
            return False
        with self.transaction():
            self.connection.execute("INSERT INTO projection_store VALUES(?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET "
                "schema_version=excluded.schema_version,generation=excluded.generation,document=excluded.document,updated_at=excluded.updated_at",
                (name, schema_version, generation, text, now()))
        return True

    def advisory_update(self, name, update):
        """Cross-process atomic counters; advisory state never changes proof facts."""
        self._require_writable()
        with self.transaction():
            row = self.connection.execute("SELECT document FROM advisory_state WHERE name=?", (name,)).fetchone()
            state = json.loads(row[0]) if row else {}
            result = update(state)
            self.connection.execute("INSERT INTO advisory_state VALUES(?,?) ON CONFLICT(name) DO UPDATE SET document=excluded.document",
                                    (name, canonical(state)))
        return result

    unit_of_work = transaction

    IMMUTABLE_KINDS = {"evidence", "decision", "finding_revision", "checkpoint", "closure_review", "finalization", "src_stop",
                       "integration_import", "discovery_snapshot", "discovery_item", "applicability_receipt", "review_proof_receipt",
                       "completion_acceptance", "frontier_receipt", "execution_dispatch", "execution_reconciliation", "material",
                       "storage_migration", "migration_quarantine", "legacy_unverified"}

    def put(self, kind, record, create_only=False):
        self._require_writable()
        if not isinstance(record, dict) or not isinstance(record.get("id"), str) or not record["id"]:
            raise EngineError("record_id", "Record requires a nonempty ID")
        text = canonical(record)
        if len(text.encode("utf-8")) > 4 * 1024 * 1024:
            raise EngineError("record_budget", "Record exceeds storage budget")
        if kind in self.IMMUTABLE_KINDS:
            create_only = True
        stamp = now()
        sql = "INSERT INTO entities(kind,id,document,created_at,updated_at) VALUES(?,?,?,?,?)"
        if not create_only:
            sql += " ON CONFLICT(kind,id) DO UPDATE SET document=excluded.document,updated_at=excluded.updated_at,revision=entities.revision+1"
        try:
            with self.transaction():
                self.connection.execute(sql, (kind, record["id"], text, stamp, stamp))
        except sqlite3.IntegrityError as exc:
            raise EngineError("immutable_record", "Record already exists; append a new version instead") from exc
        return record

    def event(self, event_type, payload):
        self._require_writable()
        with self.transaction():
            self.connection.execute("INSERT INTO events(type,document,created_at) VALUES(?,?,?)",
                                    (event_type, canonical(payload), now()))

    def claim(self, run):
        """An idempotency key can be claimed once, across concurrent processes."""
        self.put("run", run, create_only=True)
        return run

    def artifact(self, evidence_id, document):
        self._require_writable()
        data = canonical(document).encode("utf-8")
        folder = contained(self.base / "evidence", self.base)
        folder.mkdir(exist_ok=True, mode=0o700)
        path = contained(folder / (evidence_id + ".json"), self.base)
        # Exclusive creation prevents overwriting prior evidence, even after a crash.
        with path.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        return path.relative_to(self.base).as_posix(), hashlib.sha256(data).hexdigest()

    def read_artifact(self, evidence):
        path = contained(self.base / evidence["artifact_path"], self.base)
        if not path.is_file() or path.stat().st_size > 12 * 1024 * 1024:
            raise EngineError("evidence_missing", "Evidence artifact is missing or exceeds budget")
        data = path.read_bytes()
        self.metrics["artifact_bytes_hashed"] += len(data)
        if hashlib.sha256(data).hexdigest() != evidence["sha256"]:
            raise EngineError("evidence_changed", "Evidence digest does not match")
        return json.loads(data)

    def material(self, data, *, format="json"):
        """Copy reviewed local bytes into a private content-addressed store."""
        self._require_writable()
        if not isinstance(data, bytes) or len(data) > 12 * 1024 * 1024:
            raise EngineError("material_budget", "Material requires at most 12 MiB of explicit bytes")
        digest = hashlib.sha256(data).hexdigest()
        identity = "MAT-" + digest
        folder = contained(self.base / "materials", self.base)
        folder.mkdir(exist_ok=True, mode=0o700)
        path = contained(folder / (digest + ".json"), self.base)
        if path.exists():
            if path.stat().st_size > 12 * 1024 * 1024 or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise EngineError("material_changed", "Content-addressed material differs from its identity")
        else:
            try:
                with path.open("xb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            except FileExistsError:
                if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                    raise EngineError("material_changed", "Concurrent material creation differs from its identity") from None
        record = self.get("material", identity, required=False)
        if record is None:
            record = {"id": identity, "sha256": digest, "byte_count": len(data), "format": format,
                      "artifact_path": path.relative_to(self.base).as_posix(), "created_at": now()}
            self.put("material", record, create_only=True)
        return record

    def read_material(self, identity):
        record = self.get("material", identity)
        path = contained(self.base / record["artifact_path"], self.base)
        if not path.is_file() or path.stat().st_size > 12 * 1024 * 1024:
            raise EngineError("material_missing", "Material is missing or exceeds its byte budget")
        data = path.read_bytes()
        self.metrics["material_bytes_hashed"] += len(data)
        if hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise EngineError("material_changed", "Material digest does not match its immutable identity")
        return record, json.loads(data.decode("utf-8-sig"))

    def _require_writable(self):
        if self.read_only:
            raise EngineError("read_only", "A read-only project snapshot cannot persist facts or artifacts")

    def close(self):
        self.connection.close()
        if self._read_snapshot is not None:
            self._read_snapshot.cleanup()
            self._read_snapshot = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
