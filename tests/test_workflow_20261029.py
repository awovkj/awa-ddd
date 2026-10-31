"""Offline regressions for the second field session's workflow and corrections."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import engine
from awa_ddd.__main__ import dispatch
from awa_ddd.assessment import evaluate, record_finding
from awa_ddd.contracts import CONTRACTS, GROUPS, action_help
from awa_ddd.reporting import build_report, safe_text
from awa_ddd.store import EngineError, Project, now
from awa_ddd import workflow


ROOT = Path(__file__).resolve().parents[1]


def observed(url, method, headers, body, timeout, max_bytes, *, response=None, status=200):
    response = response if response is not None else {"ok": True}
    raw = json.dumps(response, ensure_ascii=False).encode("utf-8")
    sent = body if isinstance(body, bytes) else (body.encode("utf-8") if isinstance(body, str)
                                               else json.dumps(body).encode("utf-8") if body is not None else b"")
    return {"request": {"url": url, "method": method, "headers": headers,
                        "body_base64": base64.b64encode(sent).decode("ascii")},
            "response": {"status": status, "headers": [["content-type", "application/json"]],
                         "length": len(raw), "body_base64": base64.b64encode(raw).decode("ascii")},
            "started_at": now(), "completed_at": now(), "complete": True}


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-workflow-")
        self.addCleanup(self.tmp.cleanup)
        self.base = "http://fixture.invalid"
        engine.create_project(self.tmp.name, {"project_id": "workflow", "target": self.base})
        self.project = Project(self.tmp.name, "workflow")
        self.addCleanup(self.project.close)

    def operation(self, path="/items", **extra):
        return engine.register_operation(self.project, {"url": self.base + path, "method": "GET", "auth": "public", **extra})

    def captured(self, operation, **args):
        with patch.object(engine, "request", side_effect=observed):
            return engine.capture(self.project, {"operation_id": operation["id"], **args})

    def session(self, subject="alice"):
        engine.add_actor(self.project, {"actor_id": subject, "subject": subject, "roles": []})
        session = engine.add_session(self.project, {"actor_id": subject, "headers": {"Cookie": "subject=" + subject}})
        identity = self.operation("/whoami", auth="authenticated")
        with patch.object(engine, "request", side_effect=lambda *args: observed(*args, response={"subject": subject, "roles": []})):
            engine.verify_identity(self.project, {"operation_id": identity["id"], "session_id": session["id"], "subject_selector": "/subject"})
        return self.project.get("session", session["id"])

    def finding(self, *, severity="critical", title="Reviewed fixture"):
        operation = self.operation()
        evidence = self.captured(operation)
        return record_finding(self.project, {"mode": "analyst", "title": title, "category": "Information Disclosure",
            "impact": "A concrete reviewed fixture response", "remediation": "Restrict the fixture response",
            "reviewer": "test reviewer", "reason": "Reviewed the actual fixture capture", "evidence_ids": [evidence["id"]],
            "severity": severity})

    def test_help_catalog_is_complete_and_requires_no_project(self):
        catalog = dispatch(self.tmp.name, "action.help", {})
        self.assertEqual(catalog["action_count"], len(CONTRACTS))
        self.assertEqual(set(CONTRACTS), {action for names in GROUPS.values() for action in names})
        result = action_help({"name": "http.capture"})
        self.assertIn("body_file", result["fields"])
        self.assertIn("effect", result["fields"])
        self.assertTrue(result["fields"]["headers"])
        self.assertEqual(self.project.list("run"), [])

    def test_missing_argument_has_action_specific_help(self):
        with self.assertRaises(EngineError) as caught:
            dispatch(self.tmp.name, "http.capture", {"project_id": "workflow"})
        self.assertEqual(caught.exception.code, "argument_missing")
        self.assertEqual(caught.exception.details["field"], "operation_id")
        self.assertEqual(caught.exception.details["help_input"], {"name": "http.capture"})
        self.assertEqual(self.project.list("run"), [])

    def test_batch_returns_real_ids_and_per_item_errors_without_requests(self):
        hints = [{"url": self.base + "/one", "method": "GET", "auth": "public"},
                 {"url": self.base + "/bad", "method": "GET", "inputs": [{"name": "x", "location": "json"}]},
                 {"url": self.base + "/two", "method": "GET", "auth": "public"}]
        with patch.object(engine, "request") as network:
            result = workflow.register_batch(self.project, {"operations": hints})
        self.assertEqual((result["accepted"], result["rejected"]), (2, 1))
        self.assertEqual(result["results"][1]["error_code"], "input")
        for row in result["results"]:
            if row["status"] == "accepted":
                self.assertIsNotNone(self.project.get("operation", row["operation_id"]))
        network.assert_not_called()
        self.assertEqual(self.project.list("run"), [])

    def test_batch_budget_fails_before_registration(self):
        with self.assertRaises(EngineError):
            workflow.register_batch(self.project, {"operations": [{}] * 51})
        self.assertEqual(self.project.list("operation"), [])

    def test_surface_inventory_and_exact_input_pagination(self):
        operation = self.operation(inputs=[{"name": "f" + str(index), "location": "query", "consumer": "unknown"} for index in range(65)])
        engine.build_plan(self.project)
        result = workflow.inspect_surface(self.project, {"operation_id": operation["id"], "limit": 10})
        self.assertEqual(result["input_total"], 65)
        self.assertEqual(len(result["inputs"]), 10)
        self.assertEqual(result["next_offset"], 10)
        self.assertFalse(workflow.list_surfaces(self.project, {})["registration_is_testing"])

    def test_status_does_not_dump_the_complete_plan(self):
        with self.project.transaction():
            for index in range(220):
                self.operation("/item-" + str(index))
            engine.build_plan(self.project)
        status = workflow.project_status(self.project, {})
        self.assertEqual(status["operations"], 220)
        self.assertNotIn("gaps", status)
        self.assertNotIn("findings", status)
        self.assertLessEqual(len(status["gap_sample"]), 5)
        self.assertLessEqual(len(status["method_coverage"]), 10)
        self.assertLess(len(json.dumps(status).encode("utf-8")), 24 * 1024)

    def test_plan_and_report_coverage_have_identical_pages(self):
        for index in range(35):
            self.operation("/route" + str(index))
        engine.build_plan(self.project)
        args = {"project_id": "workflow", "offset": 3, "limit": 7}
        planned = dispatch(self.tmp.name, "plan.list", args)
        reported = dispatch(self.tmp.name, "report.coverage", args)
        self.assertEqual(planned, reported)
        self.assertEqual(len(planned["gaps"]), 7)
        self.assertEqual(planned["next_offset"], 10)

    def test_plan_build_keeps_integer_count_and_returns_real_obligation_page(self):
        self.operation(inputs=[{"name": "q", "location": "query"}])
        result = dispatch(self.tmp.name, "plan.build", {"project_id": "workflow", "limit": 1})
        self.assertEqual(result["obligations"], 2)
        self.assertEqual(result["obligation_total"], 2)
        self.assertEqual(len(result["obligation_items"]), 1)
        self.assertEqual(result["next_offset"], 1)

    def test_unknown_roles_do_not_make_restricted_comparison_ready(self):
        self.session()
        engine.add_actor(self.project, {"actor_id": "admin", "subject": "admin", "roles": ["admin"]})
        operation = self.operation("/admin", auth="restricted", allowed_roles=["admin"])
        engine.build_plan(self.project)
        result = workflow.next_work(self.project, {"include_blocked": True, "limit": 25})
        row = next(row for row in result["work_items"] if row["operation_id"] == operation["id"] and row.get("actor_id") == "alice")
        self.assertEqual(row["queue_status"], "blocked")
        self.assertIn("server_verified_role_membership", row["missing_prerequisites"])

    def test_next_work_is_offline_and_does_not_close_obligations(self):
        self.operation(inputs=[{"name": "q", "location": "query"}])
        engine.build_plan(self.project)
        before = self.project.list("obligation")
        with patch.object(engine, "request") as network:
            result = workflow.next_work(self.project, {})
        self.assertEqual(result["ready_total"], 1)
        self.assertEqual(result["review_total"], 1)
        self.assertEqual(result["work_items"][0]["suggested_action"], "http.preflight")
        self.assertEqual(before, self.project.list("obligation"))
        network.assert_not_called()

    def test_next_work_with_real_verified_session_is_not_attribute_error(self):
        self.session()
        self.operation("/protected", auth="authenticated")
        engine.build_plan(self.project)
        result = workflow.next_work(self.project, {})
        self.assertGreater(result["ready_total"], 0)

    def test_existing_baseline_can_be_evaluated_after_ttl_expiry(self):
        session = self.session()
        operation = self.operation("/protected", auth="authenticated")
        evidence = self.captured(operation, session_id=session["id"])
        session["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        self.project.put("session", session)
        engine.build_plan(self.project)
        result = workflow.next_work(self.project, {"include_blocked": True, "limit": 25})
        row = next(row for row in result["work_items"] if row["operation_id"] == operation["id"] and row.get("actor_id") == "alice")
        self.assertEqual(row["queue_status"], "ready")
        self.assertEqual(row["suggested_action"], "assessment.evaluate")
        self.assertEqual(row["input_template"]["evidence_ids"], [evidence["id"]])

    def test_bad_baseline_response_is_not_an_evaluation_shortcut(self):
        operation = self.operation()
        with patch.object(engine, "request", side_effect=lambda *args: observed(*args, status=500)):
            engine.capture(self.project, {"operation_id": operation["id"]})
        engine.build_plan(self.project)
        row = workflow.next_work(self.project, {})["work_items"][0]
        self.assertEqual(row["suggested_action"], "http.preflight")

    def test_writes_stay_blocked_without_project_permission(self):
        self.operation(method="POST", inputs=[{"name": "amount", "location": "body", "consumer": "state"}])
        engine.build_plan(self.project)
        result = workflow.next_work(self.project, {})
        self.assertGreater(result["blocked_total"], 0)
        self.assertIn("project_allow_mutation", result["blocked_sample"][0]["missing_prerequisites"])

    def test_preflight_body_file_preserves_bytes_and_creates_no_evidence(self):
        operation = self.operation()
        data = "\u4e2d\u6587\u8bf7\u6c42".encode("utf-8") + b"\x00\xff"
        body_file = Path(self.tmp.name) / "raw-body.bin"
        body_file.write_bytes(data)
        with patch.object(engine, "request") as network:
            result = workflow.capture_preflight(self.project, {"operation_id": operation["id"], "body_file": str(body_file)})
        self.assertEqual(result["body_bytes"], len(data))
        self.assertNotIn("body", result)
        self.assertNotIn("headers", result)
        self.assertEqual(self.project.list("run"), [])
        self.assertEqual(self.project.list("evidence"), [])
        network.assert_not_called()

    def test_evidence_inspect_rechecks_actor_and_not_only_policy(self):
        session = self.session()
        evidence = self.captured(self.operation("/protected", auth="authenticated"), session_id=session["id"])
        engine.add_actor(self.project, {"actor_id": "alice", "subject": "different"})
        result = dispatch(self.tmp.name, "evidence.inspect", {"project_id": "workflow", "evidence_id": evidence["id"]})
        self.assertEqual(result["integrity"], "valid")
        self.assertFalse(result["usable"])
        self.assertFalse(result["usable_for_new_requests"])

    def test_withdrawal_preserves_proof_and_can_be_explicitly_restored(self):
        finding = self.finding()
        decision_before = self.project.get("decision", finding["decision_id"])
        result = workflow.update_finding(self.project, {"finding_id": finding["id"], "status": "withdrawn", "reviewer": "reviewer", "reason": "Retest refuted the impact"})
        self.assertFalse(result["finding"]["current"])
        self.assertTrue(result["finding"]["evidence_current"])
        self.assertEqual(result["finding"]["reason_code"], "finding_withdrawn")
        self.assertEqual(decision_before, self.project.get("decision", finding["decision_id"]))
        restored = workflow.update_finding(self.project, {"finding_id": finding["id"], "status": "active", "reviewer": "reviewer", "reason": "Re-reviewed the original impact"})
        self.assertTrue(restored["finding"]["current"])
        self.assertEqual(len(self.project.list("finding_revision")), 2)

    def test_superseded_critical_does_not_inflate_report(self):
        old = self.finding(severity="critical", title="Old disproved impact")
        new = self.finding(severity="high", title="Narrow verified impact")
        workflow.update_finding(self.project, {"finding_id": old["id"], "status": "superseded", "reviewer": "reviewer",
            "reason": "The original financial impact was disproved", "replacement_finding_id": new["id"]})
        report = build_report(self.project)
        summary = json.loads(Path(report["summary"]).read_text(encoding="utf-8"))
        self.assertEqual(summary["format_version"], 5)
        self.assertEqual(summary["finding_groups"]["current"], 1)
        self.assertEqual(summary["finding_groups"]["historical"], 1)
        self.assertEqual([group["severity"] for group in summary["finding_groups"]["by_severity"]], ["high"])
        text = Path(report["report"]).read_text(encoding="utf-8")
        self.assertIn(new["id"], text)
        self.assertIn("修复建议", text)
        self.assertIn("替代发现", text)

    def test_invalid_replacement_or_proof_rewrite_creates_no_revision(self):
        finding = self.finding()
        for extra in ({"replacement_finding_id": finding["id"]}, {"replacement_finding_id": "F-other-project"}):
            with self.assertRaises(EngineError):
                workflow.update_finding(self.project, {"finding_id": finding["id"], "status": "superseded", "reviewer": "reviewer", "reason": "test", **extra})
        with self.assertRaises(EngineError):
            workflow.update_finding(self.project, {"finding_id": finding["id"], "status": "withdrawn", "reviewer": "reviewer", "reason": "test", "severity": "info"})
        self.assertEqual(self.project.list("finding_revision"), [])

    def test_lifecycle_revisions_are_immutable_and_pages_include_history(self):
        finding = self.finding()
        result = workflow.update_finding(self.project, {"finding_id": finding["id"], "status": "withdrawn", "reviewer": "reviewer", "reason": "retested"})
        with self.assertRaises(EngineError):
            self.project.put("finding_revision", result["revision"])
        result = workflow.findings_page(self.project, {"current": False, "limit": 1})
        self.assertEqual(result["finding_total"], 1)
        self.assertEqual(result["findings"][0]["lifecycle_status"], "withdrawn")

    def test_auth_token_and_basic_are_redacted_from_report_text(self):
        self.assertNotIn("secret123", safe_text('auth_token="secret123"'))
        self.assertNotIn("YWxpY2U6c2VjcmV0", safe_text("Basic YWxpY2U6c2VjcmV0"))

    def test_file_cli_round_trips_unicode_without_shell_json_interpolation(self):
        request = Path(self.tmp.name) / "request.json"
        request.write_text(json.dumps({"action": "identity.actor", "args": {"project_id": "workflow", "actor_id": "unicode",
                           "subject": "subject", "label": "\u4e2d\u6587\u6807\u7b7e", "roles": []}}, ensure_ascii=False), encoding="utf-8")
        # The call operator passes only file paths/options; request content is JSON stdin.
        completed = subprocess.run(["node", str(ROOT / "scripts" / "invoke-request.mjs"), "--workspace", self.tmp.name,
                                    "--request-file", str(request)], cwd=ROOT, capture_output=True, timeout=15)
        result = json.loads(completed.stdout.decode("utf-8"))
        self.assertEqual(completed.returncode, 0, result)
        self.assertEqual(result["data"]["label"], "\u4e2d\u6587\u6807\u7b7e")


if __name__ == "__main__":
    unittest.main()
