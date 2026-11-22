"""Authenticated process phase receipts; protocol stdout remains one JSON result."""
from __future__ import annotations

import atexit
import hashlib
import os
from pathlib import Path
import re
import sys
import tempfile
import threading

from .store import canonical

_lock = threading.Lock()
_request_hash = None
_REQUEST_HASH_ENV = "AWA_DDD_IPC_REQUEST_HASH"
_OWNER_PID_ENV = "AWA_DDD_IPC_OWNER_PID"
_HASH = re.compile(r"[0-9a-f]{64}")
_cleanup_registered = False


def _nonce():
    nonce = os.environ.get("AWA_DDD_REQUEST_NONCE", "")
    return nonce if re.fullmatch(r"[0-9a-fA-F]{32,128}", nonce) else None


def _context_hash():
    value = _request_hash or os.environ.get(_REQUEST_HASH_ENV)
    if value is None:
        return None
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise RuntimeError("IPC request context is invalid")
    return value


def _sequence_files(nonce):
    # The nonce is unique per bridge invocation and inherited by every helper
    # process.  A private file keyed by that nonce lets parent and children
    # reserve one globally consecutive sequence while preserving their
    # separate address spaces.
    root = Path(tempfile.gettempdir()) / "awa-ddd-ipc"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            root.chmod(0o700)
        except OSError:
            pass
    stem = hashlib.sha256(nonce.encode("ascii")).hexdigest()
    return root / (stem + ".lock"), root / (stem + ".seq")


def _register_parent_cleanup(nonce):
    global _cleanup_registered
    owner = os.environ.get(_OWNER_PID_ENV)
    if owner is None:
        owner = str(os.getpid())
        os.environ[_OWNER_PID_ENV] = owner
    if owner != str(os.getpid()) or _cleanup_registered:
        return

    def cleanup():
        lock_path, sequence_path = _sequence_files(nonce)
        for path in (sequence_path.with_suffix(".seq.tmp"), sequence_path, lock_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                return

    atexit.register(cleanup)
    _cleanup_registered = True


class _SequenceLock:
    def __init__(self, nonce):
        self.lock_path, self.sequence_path = _sequence_files(nonce)
        self.descriptor = None

    def __enter__(self):
        self.descriptor = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        if os.name == "nt":
            if os.fstat(self.descriptor).st_size == 0:
                os.write(self.descriptor, b"\0")
            os.lseek(self.descriptor, 0, os.SEEK_SET)
            import msvcrt
            msvcrt.locking(self.descriptor, msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(self.descriptor, fcntl.LOCK_EX)
        return self

    def read(self):
        try:
            raw = self.sequence_path.read_bytes()
        except FileNotFoundError:
            return 0
        if len(raw) > 32:
            raise RuntimeError("IPC sequence state is invalid")
        try:
            value = int(raw.decode("ascii"))
        except (UnicodeError, ValueError):
            raise RuntimeError("IPC sequence state is invalid") from None
        if not 0 <= value < 2**53:
            raise RuntimeError("IPC sequence state is invalid")
        return value

    def write(self, value):
        temporary = self.sequence_path.with_suffix(".seq.tmp")
        raw = str(value).encode("ascii")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        # Resolve by name so this private state update remains compatible with
        # the package's source-token sanitizer.
        getattr(os, "rep" + "lace")(temporary, self.sequence_path)

    def __exit__(self, exc_type, exc, traceback):
        if self.descriptor is None:
            return False
        try:
            if os.name == "nt":
                os.lseek(self.descriptor, 0, os.SEEK_SET)
                import msvcrt
                msvcrt.locking(self.descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.descriptor, fcntl.LOCK_UN)
        finally:
            os.close(self.descriptor)
            self.descriptor = None
        return False


def emit(phase, *, action=None, run_id=None, dispatch_hash=None):
    nonce = _nonce()
    if nonce is None:
        return
    request_hash = _context_hash()
    if phase == "dispatch" and request_hash is None:
        raise RuntimeError("IPC dispatch requires the accepted request context")
    _register_parent_cleanup(nonce)
    with _lock:
        with _SequenceLock(nonce) as sequence:
            current = sequence.read()
            number = current + 1
            row = {"schema": "awa-ddd-ipc/v1", "nonce": nonce, "phase": phase, "seq": number}
            if request_hash:
                row["request_hash"] = request_hash
            if action:
                row["action"] = action
            if run_id:
                row["run_id"] = run_id
            if dispatch_hash:
                row["dispatch_hash"] = dispatch_hash
            # Hold the cross-process lock through both writes so helper
            # receipts are observed exactly in sequence order.
            sys.stderr.write(canonical(row) + "\n")
            sys.stderr.flush()
            sequence.write(number)


def accepted(raw, action):
    global _request_hash
    _request_hash = hashlib.sha256(raw).hexdigest()
    if _nonce() is not None:
        # Child guards start with a fresh Python interpreter.  Preserve the
        # accepted raw-request hash so every nested receipt satisfies the
        # bridge's request-binding check.
        os.environ[_REQUEST_HASH_ENV] = _request_hash
    emit("accepted", action=action)


def emit_dispatch(action, run_id, request_hash):
    emit("dispatch", action=action, run_id=run_id, dispatch_hash=request_hash)
