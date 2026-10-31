"""Offline report-stage regressions; exporting a snapshot cannot authorize stopping."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import engine
from awa_ddd.reporting import build_report
from awa_ddd.store import EngineError, Project, now


class FinalizationReportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="awa-final-report-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        engine.create_project(self.root, {"project_id": "final-report", "target": "http://fixture.invalid"})
        self.project = Project(self.root, "final-report")
        self.addCleanup(self.project.close)
        engine.register_operation(self.project, {"url": "http://fixture.invalid/items", "method": "GET",
            "auth": "public", "inputs": [{"name": "q", "location": "query", "consumer": "unknown"}]})
        engine.build_plan(self.project)

    def read(self, result):
        return (json.loads(Path(result["summary"]).read_text(encoding="utf-8")),
                json.loads(Path(result["manifest"]).read_text(encoding="utf-8")),
                Path(result["report"]).read_text(encoding="utf-8"))

    def record(self, **extra):
        return {"id": "FINAL-fixture", "checkpoint_id": "CP-fixture", "snapshot_id": "a" * 64,
                "reason": "user_stop", "explanation": "User explicitly ended this isolated fixture.",
                "reviewer": "fixture-reviewer", "completion_status": "partial", "can_claim_complete": False,
                "created_at": "2026-10-30T00:00:00+00:00", "remaining": {"ready_total": 2,
                "review_total": 1, "blocked_total": 0, "unresolved_total": 3}, "frontier_reviewed": False, **extra}

    def explicit_fixture_stop(self):
        from awa_ddd.continuation import checkpoint, finalize
        saved = checkpoint(self.project, {"label": "Explicit isolated fixture stop checkpoint"})
        stopped = finalize(self.project, {"checkpoint_id": saved["checkpoint"]["id"], "reason": "user_stop",
            "explanation": "The fixture user explicitly requests ending this isolated assessment now, with work remaining.",
            "reviewer": "fixture-user"})
        return saved["checkpoint"], stopped["finalization"]

    def tscan_run(self, **extra):
        run = {"id": "RUN-tscan-report", "kind": "external_tool", "adapter": "tscanplus", "action": "query_results",
            "status": "succeeded", "started_at": now(), "scanner_project": "MCP-awa-fixture",
            "instance_id": "fixture-instance", "remote_run_id": "fixture-remote-run", "selected_tool": "query_results",
            "results_complete": False, "returned_rows": 1, "total_rows": 25, "result_limit": 1,
            "remote_execution_state": "unknown", "remote_may_continue": True, "remote_stopped_verified": False,
            "namespace_cleared": False, "declared_flags": {"fresh_project": False},
            "control_endpoint": "http://127.0.0.1:8088/mcp", "context_binding": {"origin": "http://fixture.invalid"},
            "mcp_url": "http://127.0.0.1:8088/mcp", "catalog_sha256": "a" * 64, "table": "urlscan",
            "reported_count": 25, "dispatch_attempted": True, "parser_status": "namespace_echo_missing",
            "response_truncated": None, "unretrieved_results": True, "candidate_count": 1, "new_candidates": 1,
            "duplicate_candidates": 0, "out_of_scope_rows": 0, "unmapped_rows": 0, **extra}
        return self.project.put("run", run)

    def test_real_user_stop_record_exports_final_partial_with_matching_snapshot_and_manifest(self):
        with patch.object(engine, "request") as network:
            saved, stopped = self.explicit_fixture_stop()
            result = build_report(self.project, stage="final", finalization_id=stopped["id"])
        network.assert_not_called()
        summary, manifest, text = self.read(result)
        self.assertEqual("final", result["stage"])
        self.assertEqual("final-partial", result["delivery_status"])
        self.assertEqual("user_stop", stopped["reason"])
        self.assertEqual("caller_declared_external_constraint", stopped["reason_basis"])
        self.assertFalse(stopped["external_constraint_verified"])
        self.assertFalse(stopped["can_claim_complete"])
        self.assertGreater(result["completion"]["open_obligations"], 0)
        self.assertGreater(stopped["remaining"]["ready_total"] + stopped["remaining"]["review_total"], 0)
        self.assertFalse(result["continuation"]["can_claim_complete"])
        self.assertEqual(stopped["id"], result["continuation"]["finalization_id"])
        self.assertEqual(saved["snapshot_id"], stopped["snapshot_id"])
        self.assertEqual(stopped["snapshot_id"], result["continuation"]["snapshot_id"])
        self.assertEqual(stopped, result["finalization"])
        self.assertEqual(stopped, summary["finalization"])
        self.assertEqual(stopped, manifest["finalization"])
        self.assertEqual(result["completion"], summary["coverage"]["completion"])
        self.assertEqual(self.project.get("finalization", stopped["id"]), stopped)
        self.assertIn(stopped["id"], text)
        self.assertIn("\u6700\u7ec8\u90e8\u5206\u4ea4\u4ed8", text)
        self.assertIn("\u8c03\u7528\u65b9\u58f0\u660e", text)
        self.assertNotIn("\u7528\u6237\u660e\u786e\u8981\u6c42\u7ed3\u675f", text)

    def test_new_real_checkpoint_invalidates_final_report_without_material_changes(self):
        from awa_ddd.continuation import checkpoint
        _, stopped = self.explicit_fixture_stop()
        previous = build_report(self.project, stage="final", finalization_id=stopped["id"])
        original = {key: Path(previous[key]).read_bytes() for key in ("report", "summary", "manifest")}
        resumed = checkpoint(self.project, {"label": "Fixture user resumes the assessment"})
        self.assertEqual(stopped["snapshot_id"], resumed["checkpoint"]["snapshot_id"])
        self.assertNotEqual(stopped["checkpoint_id"], resumed["checkpoint"]["id"])
        self.assertTrue(resumed["continuation"]["continue_required"])
        self.assertIsNone(resumed["continuation"]["finalization_id"])
        destination = self.root / "checkpoint-rejected-report"
        with self.assertRaises(EngineError) as caught:
            build_report(self.project, destination, stage="final", finalization_id=stopped["id"])
        self.assertEqual("finalization_stale", caught.exception.code)
        self.assertFalse(destination.exists())
        self.assertEqual(original, {key: Path(previous[key]).read_bytes() for key in original})
        self.assertEqual(stopped, self.project.get("finalization", stopped["id"]))

    def test_real_http_capture_invalidates_final_report_before_any_report_files(self):
        _, stopped = self.explicit_fixture_stop()
        previous = build_report(self.project, stage="final", finalization_id=stopped["id"])
        original = {key: Path(previous[key]).read_bytes() for key in ("report", "summary", "manifest")}
        operation = self.project.list("operation")[0]

        def observed(url, method, headers, body, timeout, max_bytes):
            raw = b'{"ok":true,"revision":"after-stop"}'
            sent = body if isinstance(body, bytes) else body.encode("utf-8") if isinstance(body, str) else \
                json.dumps(body).encode("utf-8") if body is not None else b""
            return {"request": {"url": url, "method": method, "headers": headers,
                "body_base64": base64.b64encode(sent).decode("ascii")}, "response": {"status": 200,
                "headers": [["content-type", "application/json"]], "length": len(raw),
                "body_base64": base64.b64encode(raw).decode("ascii")}, "complete": True,
                "started_at": now(), "completed_at": now()}

        with patch.object(engine, "request", side_effect=observed) as network:
            evidence = engine.capture(self.project, {"operation_id": operation["id"], "effect": "read_only"})
        network.assert_called_once()
        self.assertEqual(evidence, self.project.get("evidence", evidence["id"]))
        current = engine.evaluate_coverage(self.project)["continuation"]
        self.assertNotEqual(stopped["snapshot_id"], current["snapshot_id"])
        self.assertTrue(current["continue_required"])
        destination = self.root / "capture-rejected-report"
        with patch.object(engine, "request") as network:
            with self.assertRaises(EngineError) as caught:
                build_report(self.project, destination, stage="final", finalization_id=stopped["id"])
        network.assert_not_called()
        self.assertEqual("finalization_stale", caught.exception.code)
        self.assertFalse(destination.exists())
        self.assertEqual(original, {key: Path(previous[key]).read_bytes() for key in original})

    def test_artifact_tamper_during_preparation_rejects_real_final_record_before_files(self):
        from awa_ddd import reproduction
        operation = self.project.list("operation")[0]

        def observed(url, method, headers, body, timeout, max_bytes):
            raw = b'{"ok":true,"fixture":"before-tamper"}'
            return {"request": {"url": url, "method": method, "headers": headers, "body_base64": ""},
                "response": {"status": 200, "headers": [["content-type", "application/json"]],
                "length": len(raw), "body_base64": base64.b64encode(raw).decode("ascii")},
                "complete": True, "started_at": now(), "completed_at": now()}

        with patch.object(engine, "request", side_effect=observed):
            evidence = engine.capture(self.project, {"operation_id": operation["id"], "effect": "read_only"})
        artifact = self.project.base / evidence["artifact_path"]
        original_artifact = artifact.read_bytes()
        _, stopped = self.explicit_fixture_stop()
        previous = build_report(self.project, stage="final", finalization_id=stopped["id"])
        original_report = {key: Path(previous[key]).read_bytes() for key in ("report", "summary", "manifest")}
        destination = self.root / "tamper-rejected-report"
        original_prepare = reproduction.prepare_reproduction
        calls = []

        def tamper(project, findings, *, context=None):
            self.assertTrue(project.connection.in_transaction)
            self.assertFalse(destination.exists())
            prepared = original_prepare(project, findings, context=context)
            artifact.write_bytes(original_artifact + b"\n")
            calls.append(True)
            return prepared

        with patch.object(reproduction, "prepare_reproduction", side_effect=tamper), \
                patch.object(engine, "request") as network:
            with self.assertRaises(EngineError) as caught:
                build_report(self.project, destination, stage="final", finalization_id=stopped["id"])
        network.assert_not_called()
        self.assertEqual([True], calls)
        self.assertEqual("finalization_stale", caught.exception.code)
        self.assertFalse(destination.exists())
        self.assertNotEqual(original_artifact, artifact.read_bytes())
        self.assertEqual(original_report, {key: Path(previous[key]).read_bytes() for key in original_report})
        self.assertEqual(stopped, self.project.get("finalization", stopped["id"]))

    def test_default_draft_keeps_partial_coverage_and_requires_continuation(self):
        expected = engine.evaluate_coverage(self.project)
        before = {kind: self.project.list(kind) for kind in ("obligation", "evidence", "run", "decision")}
        with patch.object(engine, "request") as network:
            result = build_report(self.project)
        network.assert_not_called()
        summary, manifest, text = self.read(result)
        self.assertEqual("draft", result["stage"])
        self.assertEqual("draft", result["delivery_status"])
        self.assertTrue(result["continuation"]["continue_required"])
        self.assertEqual(["stage", "completion", "continuation"], list(result)[:3])
        self.assertEqual(expected, summary["coverage"])
        self.assertEqual(expected["completion"], result["completion"])
        self.assertIsNone(result["finalization"])
        self.assertEqual(result["continuation"], summary["continuation"])
        self.assertEqual(summary["continuation"], manifest["continuation"])
        self.assertEqual(summary["stage"], manifest["stage"])
        self.assertIn("plan.checkpoint", text)
        self.assertIn("\u975e\u5b8c\u6210\u51ed\u8bc1", text)
        self.assertEqual(before, {kind: self.project.list(kind) for kind in before})

    def test_final_without_stop_record_fails_before_reproduction_and_files(self):
        destination = self.root / "must-not-exist"
        with patch("awa_ddd.reproduction.prepare_reproduction") as prepare, \
                patch.object(engine, "request") as network:
            with self.assertRaises(EngineError) as caught:
                build_report(self.project, destination, stage="final")
        self.assertEqual("finalization_required", caught.exception.code)
        prepare.assert_not_called()
        network.assert_not_called()
        self.assertFalse(destination.exists())

    def test_invalid_stage_or_draft_stop_reference_fails_before_evaluation(self):
        for stage in (None, True, [], {}, "complete", "DRAFT"):
            with self.subTest(stage=stage), patch.object(engine, "evaluate_coverage") as evaluate:
                with self.assertRaises(EngineError) as caught:
                    build_report(self.project, stage=stage)
                self.assertEqual("report_stage", caught.exception.code)
                evaluate.assert_not_called()
        with patch.object(engine, "evaluate_coverage") as evaluate:
            with self.assertRaises(EngineError) as caught:
                build_report(self.project, finalization_id="FINAL-fixture")
            self.assertEqual("report_stage", caught.exception.code)
            evaluate.assert_not_called()

    def test_finalization_is_validated_in_snapshot_before_material_preparation(self):
        from awa_ddd import continuation, reproduction
        calls = []
        original_prepare = reproduction.prepare_reproduction
        original_control = continuation.control

        def validate(project, identifier, evaluated=None):
            self.assertIs(project, self.project)
            self.assertEqual("FINAL-fixture", identifier)
            self.assertTrue(project.connection.in_transaction)
            self.assertGreater(evaluated["open"], 0)
            if calls:
                self.assertEqual(["validate", "control", "prepare"], [item[0] for item in calls])
                self.assertIsNot(evaluated, calls[0][1])
            calls.append(("validate", evaluated))
            return self.record()

        def control(project, evaluated=None, **context):
            self.assertTrue(project.connection.in_transaction)
            if context:
                return original_control(project, evaluated, **context)
            self.assertIs(evaluated, calls[0][1])
            calls.append(("control", evaluated))
            return {"continue_required": True, "ready_total": 2, "review_total": 1, "blocked_total": 0}

        def prepare(project, findings, *, context=None):
            self.assertTrue(project.connection.in_transaction)
            self.assertEqual(["validate", "control"], [item[0] for item in calls])
            self.assertEqual(self.record(), context["finalization"])
            self.assertTrue(context["continuation"]["continue_required"])
            calls.append(("prepare", None))
            return original_prepare(project, findings, context=context)

        with patch("awa_ddd.continuation.require_finalization", side_effect=validate), \
                patch("awa_ddd.continuation.control", side_effect=control), \
                patch("awa_ddd.reproduction.prepare_reproduction", side_effect=prepare), \
                patch.object(engine, "evaluate_coverage", wraps=engine.evaluate_coverage) as evaluate:
            result = build_report(self.project, stage="final", finalization_id="FINAL-fixture")
        self.assertEqual(2, evaluate.call_count)
        evaluate.assert_called_with(self.project)
        self.assertEqual(["validate", "control", "prepare", "validate"], [item[0] for item in calls])
        summary, manifest, text = self.read(result)
        self.assertEqual("final-partial", result["delivery_status"])
        self.assertEqual(self.record(), summary["finalization"])
        self.assertEqual(summary["finalization"], manifest["finalization"])
        self.assertEqual(summary["completion"], summary["coverage"]["completion"])
        self.assertIn("FINAL-fixture", text)
        self.assertIn("\u6700\u7ec8\u90e8\u5206\u4ea4\u4ed8", text)

    def test_stale_or_continue_required_stop_does_not_publish_or_change_old_snapshot(self):
        first = build_report(self.project)
        previous = {key: Path(first[key]).read_bytes() for key in ("report", "summary", "manifest")}
        parent = Path(first["report"]).parent.parent
        before = set(parent.iterdir())
        for code in ("finalization_stale", "continue_required"):
            with self.subTest(code=code), patch("awa_ddd.continuation.require_finalization",
                    side_effect=EngineError(code, "Fixture stop rejected", {"continuation": {"continue_required": True}})), \
                    patch("awa_ddd.reproduction.prepare_reproduction") as prepare:
                with self.assertRaises(EngineError) as caught:
                    build_report(self.project, parent, stage="final", finalization_id="FINAL-fixture")
                self.assertEqual(code, caught.exception.code)
                prepare.assert_not_called()
            self.assertEqual(before, set(parent.iterdir()))
            self.assertEqual(previous, {key: Path(first[key]).read_bytes() for key in previous})

    def test_final_completed_requires_both_record_permission_and_complete_evaluator(self):
        original = engine.evaluate_coverage(self.project)
        cases = ((True, "partial", "final-partial"), (False, "complete", "final-partial"),
                 (True, "complete", "final-completed"))
        for permitted, status, expected in cases:
            with self.subTest(permitted=permitted, status=status):
                evaluated = copy.deepcopy(original)
                evaluated["completion"]["status"] = status
                record = self.record(can_claim_complete=permitted, completion_status=status,
                    reason="completed" if permitted else "user_stop")
                with patch.object(engine, "evaluate_coverage", return_value=evaluated), \
                        patch("awa_ddd.continuation.control", return_value={"continue_required": False}), \
                        patch("awa_ddd.continuation.require_finalization", return_value=record):
                    result = build_report(self.project, stage="final", finalization_id=record["id"])
                summary, manifest, _ = self.read(result)
                self.assertEqual(expected, result["delivery_status"])
                self.assertEqual(expected, summary["delivery_status"])
                self.assertEqual(expected, manifest["delivery_status"])

    def test_complete_evaluator_does_not_upgrade_default_draft_to_final(self):
        evaluated = engine.evaluate_coverage(self.project)
        evaluated["completion"]["status"] = "complete"
        with patch.object(engine, "evaluate_coverage", return_value=evaluated), \
                patch("awa_ddd.continuation.control", return_value={"continue_required": False}), \
                patch("awa_ddd.continuation.require_finalization") as validate:
            result = build_report(self.project)
        validate.assert_not_called()
        summary, _, text = self.read(result)
        self.assertEqual("draft", result["stage"])
        self.assertEqual("draft", summary["delivery_status"])
        self.assertIn("\u975e\u5b8c\u6210\u51ed\u8bc1", text)

    def test_new_public_stop_metadata_is_redacted_and_manifest_still_verifies(self):
        record = self.record(explanation="Authorization: Bearer PRIVATE-FINALIZATION-SECRET",
            headers={"Cookie": "PRIVATE-FINAL-COOKIE"}, details={"password": "PRIVATE-FINAL-PASSWORD"})
        snapshot = engine.evaluate_coverage(self.project)["continuation"]["snapshot_id"]
        with patch("awa_ddd.continuation.require_finalization", return_value=record), \
                patch("awa_ddd.continuation.control", return_value={"continue_required": True,
                    "snapshot_id": snapshot, "note": "Cookie: sid=PRIVATE-CONTINUATION-COOKIE"}):
            result = build_report(self.project, stage="final", finalization_id=record["id"])
        summary, manifest, _ = self.read(result)
        folder = Path(result["report"]).parent
        exported = json.dumps(result) + "\n" + "\n".join(
            path.read_text(encoding="utf-8") for path in folder.rglob("*") if path.is_file())
        for secret in ("PRIVATE-FINALIZATION-SECRET", "PRIVATE-FINAL-COOKIE", "PRIVATE-FINAL-PASSWORD",
                       "PRIVATE-CONTINUATION-COOKIE"):
            self.assertNotIn(secret, exported)
        self.assertEqual(summary["finalization"], manifest["finalization"])
        for entry in manifest["files"]:
            data = (folder / entry["path"]).read_bytes()
            self.assertEqual(entry["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(entry["size_bytes"], len(data))
        self.assertEqual(result["manifest_sha256"], hashlib.sha256(Path(result["manifest"]).read_bytes()).hexdigest())

    def test_declared_exit_and_blocker_wording_does_not_authenticate_external_facts(self):
        cases = (("user_stop", "caller_declared_external_constraint"),
                 ("budget_exhausted", "caller_declared_external_constraint"),
                 ("authorization_boundary", "caller_declared_external_constraint"),
                 ("blocked", "projected_declared_blockers"))
        for reason, basis in cases:
            with self.subTest(reason=reason):
                flags = {"blocker_facts_verified": False} if reason == "blocked" else {"external_constraint_verified": False}
                record = self.record(reason=reason, reason_basis=basis, **flags)
                with patch("awa_ddd.continuation.require_finalization", return_value=record):
                    result = build_report(self.project, stage="final", finalization_id=record["id"])
                summary, manifest, text = self.read(result)
                self.assertEqual(basis, summary["finalization"]["reason_basis"])
                self.assertEqual(summary["finalization"], manifest["finalization"])
                self.assertIn("\u672a\u72ec\u7acb\u6838\u9a8c", text)
                self.assertIn("\u4e0d\u662f\u4e24\u6b21\u72ec\u7acb\u5b89\u5168\u5b9e\u9a8c", text)
                if reason != "blocked":
                    self.assertIn("\u8c03\u7528\u65b9\u58f0\u660e", text)
                if reason == "budget_exhausted":
                    self.assertIn("\u672a\u72ec\u7acb\u8ba1\u91cf", text)
                self.assertEqual("final-partial", result["delivery_status"])

    def test_tscan_projection_keeps_unknown_partial_metadata_without_confirming_candidates(self):
        from awa_ddd.candidates import store_candidate
        secret = "PRIVATE-TSCAN-MATCH"
        self.tscan_run(**{"pass": "PRIVATE-TSCAN-PASS", "match": secret, "AccessKey": "PRIVATE-TSCAN-AK",
            "SecretKey": "PRIVATE-TSCAN-SK", "metadata_candidates": {"untrusted": secret},
            "limitation": "Scanner result quoted " + secret,
            "context_binding": {"origin": "http://fixture.invalid", "headers": {"Cookie": "PRIVATE-TSCAN-COOKIE"}}})
        store_candidate(self.project, {"kind": "scanner_signal", "name": "Unverified scanner row",
            "url": "http://fixture.invalid/items", "method": "GET", "origin": "imported",
            "source": {"sha256": "b" * 64, "locator": "tscan-fixture#urlscan/1"}})
        with patch("awa_ddd.tscanplus.report_context", return_value={"secret_values": [secret]}) as learn, \
                patch.object(engine, "request") as network:
            result = build_report(self.project)
        learn.assert_called_once_with(self.project)
        network.assert_not_called()
        summary, _, _ = self.read(result)
        row = next(item for item in summary["external_tools"] if item["adapter"] == "tscanplus")
        for field in ("scanner_project", "instance_id", "remote_run_id", "selected_tool", "returned_rows", "total_rows",
                      "result_limit", "remote_execution_state", "remote_may_continue", "remote_stopped_verified",
                      "namespace_cleared", "declared_flags", "control_endpoint", "context_binding", "mcp_url",
                      "catalog_sha256", "table", "reported_count", "dispatch_attempted", "parser_status",
                      "response_truncated", "unretrieved_results", "candidate_count", "new_candidates",
                      "duplicate_candidates", "out_of_scope_rows", "unmapped_rows"):
            self.assertIn(field, row)
        self.assertFalse(row["results_complete"])
        self.assertFalse(row["remote_stopped_verified"])
        self.assertTrue(row["remote_may_continue"])
        self.assertFalse(row["usable_for_confirmation"])
        self.assertEqual("unverified", row["finding_status"])
        self.assertNotIn("metadata_candidates", row)
        self.assertNotIn("headers", row["context_binding"])
        self.assertEqual(1, summary["unverified_candidates"])
        self.assertEqual(0, summary["finding_groups"]["current"])
        self.assertEqual([], self.project.list("finding"))
        folder = Path(result["report"]).parent
        exported = json.dumps(result) + "\n" + "\n".join(path.read_text(encoding="utf-8")
            for path in folder.rglob("*") if path.is_file())
        for value in (secret, "PRIVATE-TSCAN-PASS", "PRIVATE-TSCAN-AK", "PRIVATE-TSCAN-SK", "PRIVATE-TSCAN-COOKIE"):
            self.assertNotIn(value, exported)

    def test_tscan_secret_context_is_learned_before_body_reproduction(self):
        from awa_ddd.assessment import record_finding
        secret = "PRIVATE-TSCAN-CONTEXT-VALUE"
        operation = self.project.list("operation")[0]

        def observed(url, method, headers, body, timeout, max_bytes):
            raw = json.dumps({"note": secret}).encode("utf-8")
            sent = body if isinstance(body, bytes) else body.encode("utf-8") if isinstance(body, str) else \
                json.dumps(body).encode("utf-8") if body is not None else b""
            return {"request": {"url": url, "method": method, "headers": headers,
                "body_base64": base64.b64encode(sent).decode("ascii")}, "response": {"status": 200,
                "headers": [["content-type", "application/json"]], "length": len(raw),
                "body_base64": base64.b64encode(raw).decode("ascii")}, "complete": True,
                "started_at": now(), "completed_at": now()}

        with patch.object(engine, "request", side_effect=observed):
            evidence = engine.capture(self.project, {"operation_id": operation["id"], "body": {"note": secret},
                "headers": {"Content-Type": "application/json"}, "effect": "read_only"})
        record_finding(self.project, {"mode": "analyst", "title": "Reviewed HTTP fixture " + secret,
            "category": "Information Disclosure", "impact": "Independent local capture.", "remediation": "Restrict output.",
            "reviewer": "fixture-reviewer", "reason": "Reviewed independent HTTP fixture.", "evidence_ids": [evidence["id"]]})
        self.tscan_run()
        with patch("awa_ddd.tscanplus.report_context", return_value={"secret_values": [secret]}):
            result = build_report(self.project)
        summary, _, _ = self.read(result)
        self.assertEqual(1, summary["finding_groups"]["current"])
        folder = Path(result["report"]).parent
        exported = json.dumps(result) + "\n" + "\n".join(path.read_text(encoding="utf-8")
            for path in folder.rglob("*") if path.is_file())
        self.assertNotIn(secret, exported)

    def test_stop_explanation_secrets_are_learned_before_reproduction_is_finalized(self):
        from awa_ddd.assessment import record_finding
        secret = "PRIVATE-STOP-CONTEXT-VALUE"
        operation = self.project.list("operation")[0]

        def observed(url, method, headers, body, timeout, max_bytes):
            raw = json.dumps({"note": secret}).encode("utf-8")
            sent = body if isinstance(body, bytes) else body.encode("utf-8") if isinstance(body, str) else \
                json.dumps(body).encode("utf-8") if body is not None else b""
            return {"request": {"url": url, "method": method, "headers": headers,
                "body_base64": base64.b64encode(sent).decode("ascii")}, "response": {"status": 200,
                "headers": [["content-type", "application/json"]], "length": len(raw),
                "body_base64": base64.b64encode(raw).decode("ascii")}, "complete": True,
                "started_at": now(), "completed_at": now()}

        with patch.object(engine, "request", side_effect=observed):
            evidence = engine.capture(self.project, {"operation_id": operation["id"], "body": {"note": secret},
                "headers": {"Content-Type": "application/json"}, "effect": "read_only"})
        record_finding(self.project, {"mode": "analyst", "title": "Fixture result " + secret,
            "category": "Information Disclosure", "impact": "Observed isolated fixture output.",
            "remediation": "Restrict this response.", "reviewer": "fixture-reviewer", "reason": "Reviewed fixture.",
            "evidence_ids": [evidence["id"]]})
        record = self.record(explanation="token=" + secret)
        with patch("awa_ddd.continuation.require_finalization", return_value=record):
            result = build_report(self.project, stage="final", finalization_id=record["id"])
        folder = Path(result["report"]).parent
        exported = json.dumps(result) + "\n" + "\n".join(
            path.read_text(encoding="utf-8") for path in folder.rglob("*") if path.is_file())
        self.assertNotIn(secret, exported)


if __name__ == "__main__":
    unittest.main()
