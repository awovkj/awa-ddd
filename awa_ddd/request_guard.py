"""Private per-request slot guard for an owned browser process.

The browser callback invokes this module before ``route.fetch``.  It rechecks
scope and mutation authority in Python, atomically records one request-slot
dispatch, and emits the bridge IPC fact.  It deliberately returns only a small
JSON decision on stdout; tracebacks and IPC remain on stderr.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys


def _load(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("guard input exceeds its byte budget")
    value = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("guard input must be an object")
    return value


def main(spec_path):
    from . import execution_coordinator as coordinator
    from .scope import bind_operation, normalize_url, origin, require_scope
    from .store import EngineError, Project, canonical

    try:
        spec = _load(spec_path)
        project = Project(spec["workspace"], spec["project_id"])
        try:
            request = spec["request"]
            if not isinstance(request, dict):
                raise EngineError("request_guard", "Guard request must be an object")
            url = require_scope(project.config, normalize_url(request.get("url")))
            method = request.get("method")
            if method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
                raise EngineError("request_guard", "Guard request method is unsupported")
            run = project.get("run", spec["run_id"])
            target = normalize_url(spec["target"])
            if run.get("kind") != "browser" or run.get("status") != "running":
                raise EngineError("request_guard", "Browser run is not the current running execution")
            if run.get("target_origin") != origin(target):
                raise EngineError("request_guard", "Browser run target origin changed")
            write = method not in {"GET", "HEAD", "OPTIONS"}
            if write:
                if not project.config.get("allow_mutation") or run.get("allow_write") is not True:
                    raise EngineError("browser_write_not_authorized", "Browser write authority is not current")
                if origin(url) != origin(target):
                    raise EngineError("write_out_of_origin", "Browser write must remain on the visit origin")
                if spec.get("operation") is None:
                    raise EngineError("resource_binding", "Every browser write requires an exact registered operation")
            # Reads remain page/scope-bound unless a caller explicitly requests
            # read binding. Writes always revalidate their immutable operation.
            if spec.get("operation") is not None and (write or spec.get("bind_reads", True)):
                operation = spec["operation"]
                current = project.get("operation", operation["id"])
                if canonical(current) != canonical(operation):
                    raise EngineError("operation_changed", "Browser operation changed during execution")
                params = bind_operation(current, url, method)
            if write:
                from .engine import _resource_binding, operation_signature, resource_signature
                import base64

                resource = spec.get("resource")
                if not isinstance(resource, dict) or not resource.get("id") \
                        or run.get("effect") != "test_resource_write" \
                        or run.get("operation_id") != current["id"] \
                        or run.get("operation_signature") != operation_signature(current) \
                        or run.get("resource_id") != resource["id"]:
                    raise EngineError("resource_binding", "The running browser visit lacks its exact write fixture")
                current_resource = project.get("resource", resource["id"])
                if canonical(current_resource) != canonical(resource) \
                        or current_resource.get("operation_id") != current["id"] \
                        or run.get("resource_signature") != resource_signature(current_resource):
                    raise EngineError("resource_changed", "The browser write fixture changed during execution")
                encoded = request.get("request_body_base64")
                if encoded is None:
                    body = b""
                elif isinstance(encoded, str) and len(encoded) <= 4 * ((1024 * 1024 + 2) // 3):
                    try:
                        body = base64.b64decode(encoded, validate=True)
                    except (ValueError, TypeError):
                        raise EngineError("resource_binding", "Browser write body is not exact base64") from None
                else:
                    raise EngineError("resource_binding", "Browser write body exceeds the guard budget")
                if len(body) > 1024 * 1024 \
                        or request.get("request_body_sha256") not in {None, hashlib.sha256(body).hexdigest()}:
                    raise EngineError("resource_binding", "Browser write body does not match its guarded digest")
                content_type = request.get("content_type") or ""
                if not isinstance(content_type, str) or len(content_type) > 1024:
                    raise EngineError("resource_binding", "Browser write content type is invalid")
                _resource_binding(current_resource, params, url, body, content_type=content_type)
            lease = spec["lease"]
            request_fact = {
                "url": url,
                "method": method,
                "request_body_sha256": request.get("request_body_sha256"),
                "resource_type": request.get("resource_type"),
                "action_index": request.get("action_index"),
                "occurrence": spec["occurrence"],
            }
            request_hash = hashlib.sha256(canonical(
                {"unit": "request_slots", "request": request_fact}).encode("utf-8")).hexdigest()
            receipt = coordinator.dispatch(
                project, lease, action="browser.visit", run_id=spec["run_id"],
                request_hash=request_hash, budget=spec["budget_name"],
                max_requests=spec["max_requests"], max_writes=spec["max_writes"],
                effect="test_resource_write" if write else "read_only",
                requests=1, writes=1 if write else 0,
                budget_unit="request_slots",
            )
            decision = {
                "ok": True,
                "dispatch_id": receipt["id"],
                "requests_remaining": receipt["requests_remaining"],
                "writes_remaining": receipt["writes_remaining"],
            }
            sys.stdout.write(canonical(decision) + "\n")
            sys.stdout.flush()
            return 0
        finally:
            project.close()
    except Exception as exc:
        result = {
            "ok": False,
            "reason": getattr(exc, "code", "request_guard_failed"),
            "message": str(exc)[:500],
        }
        sys.stdout.write(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
        sys.stdout.flush()
        return 2


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
