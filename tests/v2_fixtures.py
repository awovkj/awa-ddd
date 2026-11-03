"""Shared fixtures for AWA-DDD 2.0 regression tests."""
from __future__ import annotations

import base64
import json
import tempfile
from pathlib import Path

from awa_ddd import engine
from awa_ddd.__main__ import dispatch
from awa_ddd.store import Project, now


def workspace(target="http://fixture.invalid", *, allow_mutation=False):
    temporary = tempfile.TemporaryDirectory(prefix="awa-v2-test-")
    root = Path(temporary.name)
    engine.create_project(root, {"project_id": "v2", "target": target,
                                 "scope": [target], "allow_mutation": allow_mutation})
    return temporary, root


def project(root):
    return Project(root, "v2")


def register(project_row, url, method="GET", auth="public", inputs=None, **extra):
    return engine.register_operation(project_row, {
        "url": url, "method": method, "auth": auth, "inputs": inputs or [], **extra})


def observation(url, method, headers, body, timeout, max_bytes, response):
    encoded = json.dumps(response).encode("utf-8")
    sent = body if isinstance(body, bytes) else body.encode("utf-8") if isinstance(body, str) else b""
    return {"request": {"url": url, "method": method, "headers": headers,
                        "body_base64": base64.b64encode(sent).decode("ascii")},
            "response": {"status": 200, "headers": [["content-type", "application/json"]],
                         "length": len(encoded), "body_base64": base64.b64encode(encoded).decode("ascii")},
            "started_at": now(), "completed_at": now(), "complete": True}


class Sequence:
    """Deterministic mocked HTTP transport responses for test.run."""
    def __init__(self, responses, statuses=None):
        self.responses = list(responses)
        self.statuses = list(statuses or [200] * len(self.responses))
        self.calls = 0

    def __call__(self, url, method, headers, body, timeout, max_bytes):
        index = min(self.calls, len(self.responses) - 1)
        self.calls += 1
        payload = observation(url, method, headers, body, timeout, max_bytes, self.responses[index])
        payload["response"]["status"] = self.statuses[index]
        return payload


def start(root, **extra):
    return dispatch(root, "campaign.start", {"project_id": "v2", **extra})
