"""Run three disclosed authorization fixtures through the real assessment API.

Usage: python -X utf8 -B examples/loopback_demo.py --workspace .validation/demo
Only a temporary 127.0.0.1 server receives traffic. Reports and synthetic raw
evidence remain in the required workspace after the server shuts down.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from urllib.parse import urlsplit
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from awa_ddd.__main__ import dispatch
from awa_ddd.store import EngineError


class FixtureHandler(BaseHTTPRequestHandler):
    """An intentionally simple fixture, never a deployable application."""

    def log_message(self, *_args):
        pass

    def do_GET(self):
        with self.server.counter_lock:
            self.server.request_count += 1
        cookie = SimpleCookie()
        cookie.load(self.headers.get("Cookie", ""))
        actor = cookie["demo_actor"].value if "demo_actor" in cookie else None
        actor = actor if actor in {"alice", "bob"} else None
        path = urlsplit(self.path).path
        status, content_type = 200, "application/json"
        if path == "/whoami":
            status = 200 if actor else 401
            body = {"id": actor, "roles": ["user"], "tenant": "demo-tenant"}
        elif path in {f"/{case}/items/owned-1" for case in ("vulnerable", "fixed", "interference")}:
            case = path.split("/")[1]
            if actor == "alice" or (actor == "bob" and case == "vulnerable"):
                body = {"id": "owned-1", "protected_value": "synthetic-owner-only-value"}
            elif actor == "bob" and case == "interference":
                # A generic HTTP 200 login response is not a valid access denial.
                content_type = "text/html; charset=utf-8"
                body = "<!doctype html><title>Demo login</title><p>Please sign in.</p>"
            else:
                status, body = 403, {"error": "owner required"}
        else:
            status, body = 404, {"error": "fixture route not found"}
        raw = (json.dumps(body) if content_type == "application/json" else body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


@contextmanager
def loopback_fixture():
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    server.request_count = 0
    server.counter_lock = threading.Lock()
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server, f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


def demonstrate(workspace, project_id):
    checks, cases, evidence_ids = [], [], []

    def check(name, success):
        checks.append({"name": name, "passed": bool(success)})
        if not success:
            raise RuntimeError("Demo self-check failed: " + name)

    def call(action, **args):
        return dispatch(str(workspace), action, {"project_id": project_id, **args})

    with loopback_fixture() as (server, target):
        created = call("project.create", target=target)
        identity = call("surface.register", operation={"url": target + "/whoami", "method": "GET", "auth": "authenticated"})
        sessions = {}
        for name in ("alice", "bob"):
            call("identity.actor", actor_id=name, subject=name, label=name.title(), roles=["user"], tenant_id="demo-tenant")
            session = call("identity.session", actor_id=name, headers={"Cookie": "demo_actor=" + name})
            verified = call("identity.verify", operation_id=identity["id"], session_id=session["id"],
                            subject_selector="/id", roles_selector="/roles", tenant_selector="/tenant")
            check(name + "_identity_verified", verified["session"]["verified_at"] is not None)
            evidence_ids.append(verified["evidence_id"])
            sessions[name] = session["id"]
        check("same_role_actors_have_distinct_sessions", sessions["alice"] != sessions["bob"])

        for case, expected in (("vulnerable", "confirmed"), ("fixed", "refuted"), ("interference", "inconclusive")):
            operation = call("surface.register", operation={
                "url": target + "/" + case + "/items/{id}", "method": "GET", "auth": "authenticated", "ownership": True,
                "inputs": [{"name": "id", "location": "path", "selector": "id", "consumer": "resource_lookup", "source": "declared"}],
            })
            resource = call("identity.resource", operation_id=operation["id"], owner_actor_id="alice", external_id="owned-1",
                            request_binding={"location": "path", "selector": "id"}, state={"owner": "alice"})
            planned = call("plan.list", limit=500)
            obligation = next(row for row in planned["gaps"] if row["kind"] == "ownership" and row["resource_id"] == resource["id"])
            captures = [call("http.capture", operation_id=operation["id"], resource_id=resource["id"],
                             session_id=sessions[name], url=target + "/" + case + "/items/owned-1") for name in ("alice", "bob")]
            pair_ids = [row["id"] for row in captures]
            evidence_ids.extend(pair_ids)
            decision = call("assessment.evaluate", obligation_id=obligation["id"], evidence_ids=pair_ids,
                            oracle={"type": "authorization", "selector": "/protected_value"})
            check(case + "_expected_outcome", decision["outcome"] == expected)
            cases.append({"case": case, "expected": expected, "actual": decision["outcome"],
                          "operation_id": operation["id"], "obligation_id": obligation["id"],
                          "decision_id": decision["id"], "evidence_ids": pair_ids,
                          "status_codes": [row["status_code"] for row in captures]})
            if decision["outcome"] == "confirmed":
                call("finding.record", decision_id=decision["id"], title="Synthetic cross-account resource access",
                     category="idor", severity="medium", origin="hint_guided",
                     impact="In this disclosed fixture Bob reads a protected value owned by Alice.",
                     remediation="Enforce resource ownership using the authenticated actor before returning data.",
                     limitations=["Disclosed synthetic loopback fixture; not independent discovery or a real target assessment."])

        coverage = call("report.coverage", limit=500)
        check("only_vulnerable_fixture_has_a_current_finding", len(coverage["findings"]) == 1 and coverage["findings"][0]["current"])
        interference_id = cases[-1]["obligation_id"]
        check("interference_remains_open", any(row["id"] == interference_id and row["status"] == "open" for row in coverage["gaps"]))
        for evidence_id in evidence_ids:
            inspected = call("evidence.inspect", evidence_id=evidence_id)
            check("evidence_integrity_" + evidence_id, inspected["integrity"] == "valid")
        report = call("report.build")
        report_summary = json.loads(Path(report["summary"]).read_text(encoding="utf-8"))
        check("report_and_planner_share_coverage", all(report_summary["coverage"][key] == coverage[key]
              for key in ("total", "evaluated", "open", "blocked", "not_applicable", "coverage_ratio", "gaps")))
        check("report_digest_matches", hashlib.sha256(Path(report["report"]).read_bytes()).hexdigest() == report["report_sha256"])
        request_count = server.request_count

    result_path = Path(created["path"]) / "demo-result.json"
    result = {
        "ok": True, "project_id": project_id, "workspace": str(workspace), "target": target, "server_stopped": True,
        "evaluation_kind": "disclosed_loopback_fixture", "cases": cases,
        "metrics": {"fixture_cases": len(cases), "expected_outcomes_matched": len(cases),
                    "confirmed": sum(row["actual"] == "confirmed" for row in cases),
                    "refuted": sum(row["actual"] == "refuted" for row in cases),
                    "inconclusive": sum(row["actual"] == "inconclusive" for row in cases),
                    "requests_sent": request_count, "evidence_records": len(evidence_ids),
                    "self_checks_passed": len(checks), "independent_recall_measured": False},
        "coverage": {key: coverage[key] for key in ("operations", "inputs", "total", "evaluated", "open", "blocked", "coverage_ratio")},
        "artifacts": {"project": created["path"], "report": report["report"], "summary": report["summary"],
                      "result": str(result_path), "report_sha256": report["report_sha256"]},
        "checks": checks,
        "limitations": ["Three disclosed cases exercise authorization decisions; no hidden ground truth or independent recall benchmark.",
                        "Other generated obligations remain open and are visible in the report.",
                        "The fixture server is stopped; repeat execution creates a fresh project and port.",
                        "Evidence and report describe this run; session expiry can later reopen current coverage."],
    }
    result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, help="Retain synthetic evidence and reports in this directory")
    parser.add_argument("--project-id", help="Optional new project ID; existing projects are never overwritten")
    args = parser.parse_args()
    project_id = args.project_id or datetime.now(timezone.utc).strftime("demo-%Y%m%d-%H%M%S-") + uuid4().hex[:8]
    try:
        result = demonstrate(Path(args.workspace).expanduser().resolve(), project_id)
        code = 0
    except KeyboardInterrupt:
        result, code = {"ok": False, "error": {"code": "interrupted", "message": "Demo interrupted; fixture server closed."}}, 130
    except (EngineError, OSError, ValueError, RuntimeError, KeyError, StopIteration) as exc:
        result, code = {"ok": False, "error": {"code": getattr(exc, "code", type(exc).__name__),
                                                "message": str(exc)}, "project_id": project_id}, 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
