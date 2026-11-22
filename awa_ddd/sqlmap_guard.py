"""Run upstream sqlmap with per-wire scope, method, lease and budget guards.

This module is a private launcher.  It replaces ``urllib.request``'s HTTP
handler boundary, where an outbound request is fully formed but no socket has
opened, and adds socket/DNS audit guards for transport that bypasses urllib.
Every permitted request consumes one durable request-slot dispatch before the
original handler runs.  The summary contains digests and counts, never request
headers or bodies.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import socket
import sys
import threading
import urllib.request
from urllib.parse import urlsplit


def _load(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(128 * 1024 + 1)
    if len(raw) > 128 * 1024:
        raise ValueError("guard specification exceeds its byte budget")
    value = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("guard specification must be an object")
    return value


def _request_fact(request):
    method = request.get_method().upper()
    url = request.full_url
    headers = sorted((str(key).lower(), str(value)) for key, value in request.header_items())
    data = request.data if isinstance(request.data, bytes) else b""
    return {
        "url": url,
        "method": method,
        "headers_sha256": hashlib.sha256(
            json.dumps(headers, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")).encode("utf-8")).hexdigest(),
        "body_sha256": hashlib.sha256(data).hexdigest(),
        "body_bytes": len(data),
    }


def main(spec_path):
    from . import execution_coordinator as coordinator
    from .scope import bind_operation, normalize_url, origin, require_scope
    from .store import EngineError, Project, canonical

    spec = _load(spec_path)
    output_path = Path(spec["stdout_path"])
    error_path = Path(spec["stderr_path"])
    summary_path = Path(spec["summary_path"])
    bridge_stderr = sys.stderr
    state = {
        "schema": "awa-sqlmap-guard/v1",
        "complete": False,
        "requests_attempted": 0,
        "writes_attempted": 0,
        "guarded_requests": 0,
        "denied_requests": [],
        "unguarded_socket_attempts": 0,
        "transport": "urllib.do_open+socket_audit",
    }
    local = threading.local()
    state_lock = threading.Lock()

    def deny(reason, message):
        with state_lock:
            if len(state["denied_requests"]) < 100:
                state["denied_requests"].append({"reason": reason, "message": str(message)[:300]})
        raise EngineError(reason, message)

    def audit(event, args):
        if event not in {"socket.connect", "socket.getaddrinfo"}:
            return
        if getattr(local, "permit", 0) > 0:
            return
        with state_lock:
            state["unguarded_socket_attempts"] += 1
        raise PermissionError("sqlmap transport attempted " + event + " outside the request guard")

    sys.addaudithook(audit)
    project = Project(spec["workspace"], spec["project_id"])
    operation = spec["operation"]
    lease = spec["lease"]
    current_operation = project.get("operation", operation["id"])
    if canonical(current_operation) != canonical(operation):
        project.close()
        deny("operation_changed", "SQL operation changed before guarded execution")

    original_do_open = urllib.request.AbstractHTTPHandler.do_open
    sequence = 0
    sequence_lock = threading.Lock()

    def guarded_do_open(handler, http_class, request, **kwargs):
        nonlocal sequence
        try:
            fact = _request_fact(request)
            url = require_scope(project.config, normalize_url(fact["url"]))
            method = fact["method"]
            if method != current_operation["method"]:
                deny("operation_binding", "sqlmap attempted a method outside the registered operation")
            bind_operation(current_operation, url, method)
            write = method not in {"GET", "HEAD", "OPTIONS"}
            if write and (not project.config.get("allow_mutation")
                          or spec["effect"] != "test_resource_write"):
                deny("tool_effect", "sqlmap attempted an unauthorized write")
            if origin(url) != origin(normalize_url(spec["target_url"])):
                deny("tool_target", "sqlmap request origin differs from its reviewed target")
            with sequence_lock:
                sequence += 1
                occurrence = sequence
            request_hash = hashlib.sha256(canonical({
                "unit": "request_slots", "occurrence": occurrence, "request": fact,
            }).encode("utf-8")).hexdigest()
            receipt = coordinator.dispatch(
                project, lease, action="tool.sqlmap", run_id=spec["run_id"],
                request_hash=request_hash, budget=spec["budget_name"],
                max_requests=spec["max_requests"], max_writes=spec["max_writes"],
                effect="test_resource_write" if write else "read_only",
                requests=1, writes=1 if write else 0,
                budget_unit="request_slots",
                emit_ipc=False,
            )
        except EngineError as exc:
            deny(exc.code, str(exc))
        # sqlmap output is redirected to its own artifact.  Dispatch IPC must
        # remain on the inherited bridge stderr.  The fixed single-thread and
        # SQLMap profile keeps this swap inside the guarded dispatch sequence.
        from .ipc import emit_dispatch
        redirected_stderr = sys.stderr
        sys.stderr = bridge_stderr
        try:
            emit_dispatch("tool.sqlmap", spec["run_id"], request_hash)
        finally:
            sys.stderr = redirected_stderr
        with state_lock:
            state["guarded_requests"] += 1
            state["requests_attempted"] += 1
            if write:
                state["writes_attempted"] += 1
        local.permit = int(getattr(local, "permit", 0)) + 1
        try:
            return original_do_open(handler, http_class, request, **kwargs)
        finally:
            local.permit -= 1
        # Unreachable; kept explicit so receipt identity never becomes input.
        raise AssertionError(receipt)

    urllib.request.AbstractHTTPHandler.do_open = guarded_do_open
    # SQLMap can inherit Windows/system proxies.  A proxy would turn one logical
    # target request into traffic to a third party before the HTTP handler guard.
    from .runtime import clean_environment
    environment = clean_environment({"NO_PROXY": "*"})
    os.environ.clear()
    os.environ.update(environment)

    exit_code = 1
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("wb") as stdout, error_path.open("wb") as stderr:
            stdout_stream = io.TextIOWrapper(stdout, encoding="utf-8", errors="replace", write_through=True)
            stderr_stream = io.TextIOWrapper(stderr, encoding="utf-8", errors="replace", write_through=True)
            sys.stdout, sys.stderr = stdout_stream, stderr_stream
            sys.argv = [spec["executable"], *spec["argv"]]
            sys.path.insert(0, str(Path(spec["executable"]).resolve().parent))
            try:
                runpy.run_path(spec["executable"], run_name="__main__")
                exit_code = 0
            except SystemExit as exc:
                exit_code = exc.code if type(exc.code) is int else 1
            except BaseException as exc:
                sys.stderr.write(type(exc).__name__ + ": " + str(exc)[:500] + "\n")
                exit_code = 1
            finally:
                stdout_stream.flush()
                stderr_stream.flush()
    finally:
        sys.stdout, sys.stderr = bridge_stderr, bridge_stderr
        urllib.request.AbstractHTTPHandler.do_open = original_do_open
        state["exit_code"] = exit_code
        # SQLMap output is written to logs.  Emit bridge protocol lines only
        # through the inherited stderr during guard dispatches.
        state["complete"] = not state["denied_requests"] and not state["unguarded_socket_attempts"]
        payload = canonical(state).encode("utf-8")
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        with summary_path.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        project.close()
    return exit_code if state["complete"] else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
