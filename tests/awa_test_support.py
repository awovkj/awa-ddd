"""Shared fixtures for execution-bound tests.

The production browser and sqlmap paths persist one dispatch for the provider
envelope and one dispatch for every guarded wire request.  Unit tests that use
recorded observations or a mocked provider process must reproduce those facts
instead of bypassing the guards.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path


_READ_METHODS = {"GET", "HEAD", "OPTIONS"}


def _canonical(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _request_method(item):
    request = item.get("request", item)
    return str(request.get("method", "GET")).upper()


def local_observation(raw, *, requests=None, writes=None):
    """Return a local browser observation with explicit guard accounting.

    This is for tests that exercise the private ledger boundary directly.
    Tests of ``browser.visit`` should use ``guarded_runtime_result`` so that
    the per-request dispatch receipts are created as well.
    """
    value = deepcopy(raw)
    network = value.get("network") if isinstance(value.get("network"), list) else []
    request_count = len(network)
    write_count = sum(_request_method(item) not in _READ_METHODS for item in network)
    request_count = request_count if requests is None else requests
    write_count = write_count if writes is None else writes
    value.setdefault("requests_attempted", request_count)
    value.setdefault("writes_attempted", write_count)
    value.setdefault("request_budget", max(100, request_count))
    value.setdefault("write_budget", max(write_count, 1 if write_count else 0))
    return value


def record_observation(project, raw, visit_id, source, **kwargs):
    """Record a page visit, adding request-slot facts for local fixtures."""
    from awa_ddd import browser

    if source == "local_playwright":
        raw = local_observation(raw)
    return browser._record_observation(project, raw, visit_id, source, **kwargs)


def _guard_spec(command):
    path = Path(command[-1])
    return json.loads(path.read_text(encoding="utf-8"))


def guarded_runtime_result(project, command, raw, *, returncode=0, stderr=""):
    """Return a CompletedProcess and create one child dispatch per wire request."""
    import subprocess

    from awa_ddd import execution_coordinator

    spec = _guard_spec(command)
    context = spec["guardContext"]
    value = local_observation(raw)
    request_count = value["requests_attempted"]
    write_count = value["writes_attempted"]
    if returncode == 0:
        for index, item in enumerate(value.get("network") or []):
            method = _request_method(item)
            write = method not in _READ_METHODS
            request_hash = hashlib.sha256(
                _canonical(
                    {
                        "unit": "request_slots",
                        "request": item,
                        "occurrence": index + 1,
                    }
                ).encode("utf-8")
            ).hexdigest()
            execution_coordinator.dispatch(
                project,
                context["lease"],
                action="browser.visit",
                run_id=context["run_id"],
                request_hash=request_hash,
                budget=context["budget_name"],
                max_requests=context["max_requests"],
                max_writes=context["max_writes"],
                effect="test_resource_write" if write else "read_only",
                requests=1,
                writes=1 if write else 0,
                budget_unit="request_slots",
                emit_ipc=False,
            )
    return subprocess.CompletedProcess(
        command,
        returncode,
        json.dumps(value, ensure_ascii=False, allow_nan=False),
        stderr,
    )


def guarded_sqlmap_result(
    project,
    command,
    *,
    stdout_text,
    traffic_text,
    returncode=0,
):
    """Emulate the sqlmap launcher's per-request guard and log ownership."""
    from awa_ddd import execution_coordinator

    spec = _guard_spec(command)
    Path(spec["stdout_path"]).write_text(stdout_text, encoding="utf-8")
    Path(spec["stderr_path"]).write_bytes(b"")
    traffic_path = Path(
        spec["argv"][spec["argv"].index("-t") + 1]
    )
    traffic_path.write_text(traffic_text, encoding="utf-8")
    writes = int(spec["effect"] != "read_only")
    requests = max(1, traffic_text.lower().count("http request"))
    writes = writes if requests else 0
    if returncode == 0:
        request_hash = hashlib.sha256(
            _canonical(
                {
                    "unit": "request_slots",
                    "tool": "sqlmap",
                    "run_id": spec["run_id"],
                    "occurrence": 1,
                    "target": spec["target_url"],
                }
            ).encode("utf-8")
        ).hexdigest()
        execution_coordinator.dispatch(
            project,
            spec["lease"],
            action="tool.sqlmap",
            run_id=spec["run_id"],
            request_hash=request_hash,
            budget=spec["budget_name"],
            max_requests=spec["max_requests"],
            max_writes=spec["max_writes"],
            effect=spec["effect"],
            requests=1,
            writes=writes,
            budget_unit="request_slots",
            emit_ipc=False,
        )
    summary = {
        "schema": "awa-sqlmap-guard/v1",
        "complete": returncode == 0,
        "requests_attempted": requests if returncode == 0 else 0,
        "writes_attempted": writes if returncode == 0 else 0,
        "guarded_requests": requests if returncode == 0 else 0,
        "unguarded_socket_attempts": 0,
        "denied_requests": [],
    }
    Path(spec["summary_path"]).write_text(
        _canonical(summary), encoding="utf-8"
    )

    class Process:
        def __init__(self):
            self.returncode = returncode

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            return None

        @property
        def pid(self):
            return 1

    return Process()
