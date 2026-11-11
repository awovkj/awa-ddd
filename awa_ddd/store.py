"""Transactional local entities and append-only events; no global mutable state."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
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
    def __init__(self, workspace, project_id, create=False):
        if not isinstance(project_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", project_id):
            raise EngineError("project_id", "Invalid project ID")
        self.workspace = Path(workspace).expanduser().resolve()
        self.project_id = project_id
        self.base = contained(self.workspace / "projects" / project_id, self.workspace)
        db = contained(self.base / "assessment.sqlite3", self.workspace)
        if not create and not db.is_file():
            raise EngineError("project_missing", "Project does not exist")
        if create:
            self.base.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(str(db), timeout=15, check_same_thread=False)
        # Concurrent scenario steps capture from several threads but share one
        # connection. Serialize every transaction through this re-entrant lock so
        # nested SAVEPOINT usage stays consistent within a thread.
        self._lock = threading.RLock()
        self.connection.row_factory = sqlite3.Row
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
        """)
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
            return json.loads(row[0])
        if required:
            raise EngineError("not_found", f"Unknown {kind} ID")
        return None

    def list(self, kind):
        with self._lock:
            rows = self.connection.execute(
                "SELECT document FROM entities WHERE kind=? ORDER BY created_at,id", (kind,)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def put(self, kind, record, create_only=False):
        if not isinstance(record, dict) or not isinstance(record.get("id"), str) or not record["id"]:
            raise EngineError("record_id", "Record requires a nonempty ID")
        text = canonical(record)
        if len(text.encode("utf-8")) > 4 * 1024 * 1024:
            raise EngineError("record_budget", "Record exceeds storage budget")
        if kind in {"evidence", "decision", "finding_revision", "checkpoint", "closure_review", "finalization", "src_stop", "integration_import"}:
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
        with self.transaction():
            self.connection.execute("INSERT INTO events(type,document,created_at) VALUES(?,?,?)",
                                    (event_type, canonical(payload), now()))

    def claim(self, run):
        """An idempotency key can be claimed once, across concurrent processes."""
        self.put("run", run, create_only=True)
        return run

    def artifact(self, evidence_id, document):
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
        if hashlib.sha256(data).hexdigest() != evidence["sha256"]:
            raise EngineError("evidence_changed", "Evidence digest does not match")
        return json.loads(data)

    def close(self):
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
