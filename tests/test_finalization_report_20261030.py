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
                "reason": "completed", "reason_basis": "engine_gate",
                "explanation": "The isolated fixture has passed the strict bounded exhaustion gate.",
                "reviewer": "fixture-reviewer", "completion_status": "complete", "can_claim_complete": True,
                "created_at": "2026-10-30T00:00:00+00:00", "remaining": {"ready_total": 0,
                "review_total": 0, "blocked_total": 0, "unresolved_total": 0}, "frontier_reviewed": True,
                "stop_policy": "exhaustion_only", "stop_policy_version": 1, "automatic_stop_allowed": True, **extra}

    def mock_context(self, record=None):
        """Isolate serializer tests from the real gate, which integration tests exercise."""
        record = record or self.record()
        evaluated = copy.deepcopy(engine.evaluate_coverage(self.project))
        evaluated["completion"]["status"] = "complete"
        evaluated["open"], evaluated["blocked"] = 0, 0
        current = {**evaluated["continuation"], "continue_required": False, "can_finalize": True,
            "can_claim_complete": True, "automatic_stop_allowed": True, "frontier_review_required": False,
            "frontier_rounds": 2, "coverage_status": "complete", "ready_total": 0, "review_total": 0,
            "blocked_total": 0, "actionable_total": 0, "unresolved_total": 0, "snapshot_id": record["snapshot_id"],
            "checkpoint_id": record["checkpoint_id"], "finalization_id": record["id"]}
        evaluated["continuation"] = current
        return evaluated, current

    def completed_fixture_stop(self):
        from awa_ddd import completeness, continuation
        from awa_ddd.assessment import evaluate

        operation = self.project.list("operation")[0]
        engine.declare_consumer(self.project, {"operation_id": operation["id"], "input_location": "query",
            "input_selector": "q", "consumer": "bounded_fixture_input", "test_families": ["generic"]})
        captures = []
        for query, count in (("normal", 1), ("variant", 1), ("sensitivity", 2)):
            def observed(url, method, headers, body, timeout, max_bytes):
                raw = json.dumps({"count": count}).encode("utf-8")
                return {"request": {"url": url, "method": method, "headers": headers, "body_base64": ""},
                    "response": {"status": 200, "headers": [["content-type", "application/json"]],
                        "length": len(raw), "body_base64": base64.b64encode(raw).decode("ascii")},
                    "complete": True, "started_at": now(), "completed_at": now()}
            with patch.object(engine, "request", side_effect=observed):
                captures.append(engine.capture(self.project, {"operation_id": operation["id"],
                    "url": operation["url"] + "?q=" + query, "effect": "read_only"}))
        obligations = {row["kind"]: row for row in self.project.list("obligation") if not row.get("superseded")}
        evaluate(self.project, {"obligation_id": obligations["baseline"]["id"], "evidence_ids": [captures[0]["id"]],
            "oracle": {"type": "baseline", "selector": "/count", "expected": 1}})
        evaluate(self.project, {"obligation_id": obligations["input_test"]["id"],
            "evidence_ids": [row["id"] for row in captures], "oracle": {"type": "semantic_negative",
                "test_family": "generic", "selector": "/count", "baseline_expected": 1, "control_expected": 2}})
        for row in completeness.audit(self.project, {"limit": 100})["checklist"]:
            if row["kind"] == "unassessed_observation":
                continuation.review(self.project, {"checklist_id": row["id"], "status": "reviewed",
                    "reviewer": "fixture-reviewer", "reason": "Reviewed the earlier complete fixture observation offline."})
        references = {"evidence_ids": [captures[0]["id"]]}
        frontier = {"discovery": {"status": "reviewed", "reason": "Reviewed the finite isolated API scope.", **references},
            "pages": {"status": "api_only", "reason": "The finite fixture has no browser surface.", **references},
            "categories": [{"test_family": family, "status": "planned" if family == "generic" else "not_applicable",
                "reason": "The declared isolated fixture contract supports only the modeled generic input.", **references}
                for family in continuation.ALL_FAMILIES]}
        continuation.checkpoint(self.project, {"frontier_review": frontier})
        saved = continuation.checkpoint(self.project, {"frontier_review": frontier})
        stopped = continuation.finalize(self.project, {"checkpoint_id": saved["checkpoint"]["id"], "reason": "completed",
            "explanation": "Actual evaluated controls and evidence-bound frontier reviews exhaust the finite fixture.",
            "reviewer": "fixture-reviewer"})
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

    def test_real_completed_record_exports_final_with_matching_snapshot_and_manifest(self):
        with patch.object(engine, "request") as network:
            saved, stopped = self.completed_fixture_stop()
            result = build_report(self.project, stage="final", finalization_id=stopped["id"])
        network.assert_not_called()
        summary, manifest, text = self.read(result)
        self.assertEqual("final", result["stage"])
        self.assertEqual("final-completed", result["delivery_status"])
        self.assertEqual("completed", stopped["reason"])
        self.assertEqual("engine_gate", stopped["reason_basis"])
        self.assertFalse(stopped["external_constraint_verified"])
        self.assertTrue(stopped["can_claim_complete"])
        self.assertEqual(0, result["completion"]["open_obligations"])
        self.assertEqual(0, stopped["remaining"]["ready_total"] + stopped["remaining"]["review_total"])
        self.assertTrue(result["continuation"]["can_claim_complete"])
        self.assertTrue(result["continuation"]["automatic_stop_allowed"])
        self.assertEqual(stopped["id"], result["continuation"]["finalization_id"])
        self.assertEqual(saved["snapshot_id"], stopped["snapshot_id"])
        self.assertEqual(stopped["snapshot_id"], result["continuation"]["snapshot_id"])
        self.assertEqual(stopped, result["finalization"])
        self.assertEqual(stopped, summary["finalization"])
        self.assertEqual(stopped, manifest["finalization"])
        self.assertEqual(result["completion"], summary["coverage"]["completion"])
        self.assertEqual(self.project.get("finalization", stopped["id"]), stopped)
        self.assertIn(stopped["id"], text)
        self.assertNotIn("final-partial", json.dumps(result))
        self.assertIn("exhaustion_only", text)
        self.assertNotIn("\u7528\u6237\u660e\u786e\u8981\u6c42\u7ed3\u675f", text)

    def test_new_real_checkpoint_invalidates_final_report_without_material_changes(self):
        from awa_ddd.continuation import checkpoint
        _, stopped = self.completed_fixture_stop()
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
        _, stopped = self.completed_fixture_stop()
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
        _, stopped = self.completed_fixture_stop()
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
        from awa_ddd import reproduction
        calls = []
        original_prepare = reproduction.prepare_reproduction
        record = self.record()
        fixture, current = self.mock_context(record)

        def validate(project, identifier, evaluated=None):
            self.assertIs(project, self.project)
            self.assertEqual("FINAL-fixture", identifier)
            self.assertTrue(project.connection.in_transaction)
            self.assertEqual(0, evaluated["open"])
            self.assertEqual("complete", evaluated["completion"]["status"])
            if calls:
                self.assertEqual(["validate", "control", "prepare"], [item[0] for item in calls])
                self.assertIsNot(evaluated, calls[0][1])
            calls.append(("validate", evaluated))
            return record

        def control(project, evaluated=None):
            self.assertTrue(project.connection.in_transaction)
            self.assertIs(evaluated, calls[0][1])
            calls.append(("control", evaluated))
            return current

        def prepare(project, findings, *, context=None):
            self.assertTrue(project.connection.in_transaction)
            self.assertEqual(["validate", "control"], [item[0] for item in calls])
            self.assertEqual(record, context["finalization"])
            self.assertFalse(context["continuation"]["continue_required"])
            calls.append(("prepare", None))
            return original_prepare(project, findings, context=context)

        with patch("awa_ddd.continuation.require_finalization", side_effect=validate), \
                patch("awa_ddd.continuation.control", side_effect=control), \
                patch("awa_ddd.reproduction.prepare_reproduction", side_effect=prepare), \
                patch.object(engine, "evaluate_coverage", side_effect=lambda _project: copy.deepcopy(fixture)) as evaluate:
            result = build_report(self.project, stage="final", finalization_id="FINAL-fixture")
        self.assertEqual(2, evaluate.call_count)
        evaluate.assert_called_with(self.project)
        self.assertEqual(["validate", "control", "prepare", "validate"], [item[0] for item in calls])
        summary, manifest, text = self.read(result)
        self.assertEqual("final-completed", result["delivery_status"])
        self.assertEqual(record, summary["finalization"])
        self.assertEqual(summary["finalization"], manifest["finalization"])
        self.assertEqual(summary["completion"], summary["coverage"]["completion"])
        self.assertIn("FINAL-fixture", text)
        self.assertNotIn("\u6700\u7ec8\u90e8\u5206\u4ea4\u4ed8", text)

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
        cases = ((True, "partial", None), (False, "complete", None), (True, "complete", "final-completed"))
        for permitted, status, expected in cases:
            with self.subTest(permitted=permitted, status=status):
                record = self.record(can_claim_complete=permitted, completion_status=status,
                    reason="completed" if permitted else "user_stop")
                evaluated, current = self.mock_context(record)
                evaluated["completion"]["status"] = status
                with patch.object(engine, "evaluate_coverage", return_value=evaluated), \
                        patch("awa_ddd.continuation.control", return_value=current), \
                        patch("awa_ddd.continuation.require_finalization", return_value=record):
                    if expected is None:
                        with patch("awa_ddd.reproduction.prepare_reproduction") as prepare:
                            with self.assertRaises(EngineError) as caught:
                                build_report(self.project, stage="final", finalization_id=record["id"])
                        self.assertEqual("continue_required", caught.exception.code)
                        prepare.assert_not_called()
                        continue
                    result = build_report(self.project, stage="final", finalization_id=record["id"])
                summary, manifest, _ = self.read(result)
                self.assertEqual(expected, result["delivery_status"])
                self.assertEqual(expected, summary["delivery_status"])
                self.assertEqual(expected, manifest["delivery_status"])

    def test_final_report_defense_rejects_bad_flags_counts_and_bindings_before_preparation(self):
        record = self.record()
        mutations = [("continue_required", True), ("can_finalize", False), ("can_claim_complete", False),
            ("automatic_stop_allowed", "true"), ("frontier_review_required", True), ("frontier_rounds", True),
            ("frontier_rounds", 1), ("ready_total", 1), ("review_total", 1), ("blocked_total", 1),
            ("unresolved_total", 1), ("actionable_total", False), ("ready_total", "0"),
            ("snapshot_id", "different-snapshot"), ("checkpoint_id", "different-checkpoint"),
            ("finalization_id", "different-receipt")]
        for index, (key, value) in enumerate(mutations):
            with self.subTest(key=key, value=value):
                evaluated, current = self.mock_context(record)
                current[key] = value
                destination = self.root / ("bad-control-" + str(index))
                with patch.object(engine, "evaluate_coverage", return_value=evaluated), \
                        patch("awa_ddd.continuation.control", return_value=current), \
                        patch("awa_ddd.continuation.require_finalization", return_value=record), \
                        patch("awa_ddd.reproduction.prepare_reproduction") as prepare:
                    with self.assertRaises(EngineError) as caught:
                        build_report(self.project, destination, stage="final", finalization_id=record["id"])
                self.assertEqual("continue_required", caught.exception.code)
                self.assertTrue(caught.exception.details["continuation"]["continue_required"])
                self.assertFalse(caught.exception.details["continuation"]["automatic_stop_allowed"])
                prepare.assert_not_called()
                self.assertFalse(destination.exists())

    def test_final_report_rechecks_controls_after_preparation_even_if_validator_returns_old_receipt(self):
        from awa_ddd import reproduction
        record = self.record()
        original, current = self.mock_context(record)
        changed = copy.deepcopy(original)
        changed["continuation"]["review_total"] = 1
        destination = self.root / "post-preparation-control-change"
        with patch.object(engine, "evaluate_coverage", side_effect=[original, changed]), \
                patch("awa_ddd.continuation.control", return_value=current), \
                patch("awa_ddd.continuation.require_finalization", return_value=record), \
                patch.object(reproduction, "prepare_reproduction", wraps=reproduction.prepare_reproduction) as prepare:
            with self.assertRaises(EngineError) as caught:
                build_report(self.project, destination, stage="final", finalization_id=record["id"])
        prepare.assert_called_once()
        self.assertEqual("continue_required", caught.exception.code)
        self.assertTrue(caught.exception.details["continuation"]["continue_required"])
        self.assertFalse(destination.exists())

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
        evaluated, current = self.mock_context(record)
        current["note"] = "Cookie: sid=PRIVATE-CONTINUATION-COOKIE"
        with patch.object(engine, "evaluate_coverage", return_value=evaluated), \
                patch("awa_ddd.continuation.require_finalization", return_value=record), \
                patch("awa_ddd.continuation.control", return_value=current):
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

    def test_private_fill_values_cannot_reencode_generated_report_control_enums(self):
        from awa_ddd.store import canonical
        context = {"browser_fill_values": ["complete", "completed", "generic", "exhaustion_only"],
                   "redaction_nonce": "b" * 64}
        self.project.put("run", {"id": "RUN-report-private-context", "kind": "browser", "status": "succeeded",
            "credentials": context, "redaction_context_checked": True, "redaction_context_required": True,
            "redaction_context_available": True,
            "redaction_context_sha256": hashlib.sha256(canonical(context).encode("utf-8")).hexdigest()})
        record = self.record(explanation="A private quoted fill value completed is not a stop condition.")
        evaluated, current = self.mock_context(record)
        with patch.object(engine, "evaluate_coverage", return_value=evaluated), \
                patch("awa_ddd.continuation.require_finalization", return_value=record), \
                patch("awa_ddd.continuation.control", return_value=current):
            result = build_report(self.project, stage="final", finalization_id=record["id"])
        summary, manifest, _ = self.read(result)
        self.assertEqual("complete", summary["completion"]["status"])
        self.assertEqual("exhaustion_only", summary["continuation"]["stop_policy"])
        self.assertEqual("completed", summary["finalization"]["reason"])
        self.assertEqual("final-completed", summary["delivery_status"])
        self.assertEqual(summary["continuation"], manifest["continuation"])
        self.assertNotIn("private quoted fill value completed", summary["finalization"]["explanation"])
        self.assertNotIn(context["redaction_nonce"], json.dumps(summary))

    def test_declared_exit_cannot_be_final_even_if_validation_returns_it(self):
        cases = (("user_stop", "caller_declared_external_constraint"),
                 ("budget_exhausted", "caller_declared_external_constraint"),
                 ("authorization_boundary", "caller_declared_external_constraint"),
                 ("blocked", "projected_declared_blockers"))
        for reason, basis in cases:
            with self.subTest(reason=reason):
                flags = {"blocker_facts_verified": False} if reason == "blocked" else {"external_constraint_verified": False}
                record = self.record(reason=reason, reason_basis=basis, **flags)
                destination = self.root / ("forbidden-" + reason)
                with patch("awa_ddd.continuation.require_finalization", return_value=record), \
                        patch("awa_ddd.reproduction.prepare_reproduction") as prepare:
                    with self.assertRaises(EngineError) as caught:
                        build_report(self.project, destination, stage="final", finalization_id=record["id"])
                self.assertEqual("continue_required", caught.exception.code)
                prepare.assert_not_called()
                self.assertFalse(destination.exists())

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
        learn.assert_any_call(self.project)
        self.assertEqual(2, learn.call_count)
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
        evaluated, current = self.mock_context(record)
        with patch.object(engine, "evaluate_coverage", return_value=evaluated), \
                patch("awa_ddd.continuation.require_finalization", return_value=record), \
                patch("awa_ddd.continuation.control", return_value=current):
            result = build_report(self.project, stage="final", finalization_id=record["id"])
        folder = Path(result["report"]).parent
        exported = json.dumps(result) + "\n" + "\n".join(
            path.read_text(encoding="utf-8") for path in folder.rglob("*") if path.is_file())
        self.assertNotIn(secret, exported)


class CredentialHeaderContextTests(unittest.TestCase):
    def test_multiline_set_cookie_learns_each_cookie_not_only_the_first_header(self):
        from awa_ddd.reproduction import Redactor, _learn_header
        redactor = Redactor()
        raw = "first=SYNTHETIC-FIRST-COOKIE; Path=/; HttpOnly\nsecond=SYNTHETIC-SECOND-COOKIE; Path=/; Secure"
        _learn_header(redactor, "Set-Cookie", raw)
        public = redactor.prose("Runtime quoted SYNTHETIC-FIRST-COOKIE and SYNTHETIC-SECOND-COOKIE")
        self.assertNotIn("SYNTHETIC-FIRST-COOKIE", public)
        self.assertNotIn("SYNTHETIC-SECOND-COOKIE", public)
        self.assertEqual(raw, "first=SYNTHETIC-FIRST-COOKIE; Path=/; HttpOnly\nsecond=SYNTHETIC-SECOND-COOKIE; Path=/; Secure")

    def test_quoted_cookie_value_is_private_when_runtime_echoes_its_unquoted_value(self):
        from awa_ddd.reproduction import Redactor, _learn_header
        for name, raw in (("Cookie", 'session="SYNTHETIC-QUOTED-COOKIE"; other=SYNTHETIC-OTHER-COOKIE'),
                          ("Set-Cookie", 'session="SYNTHETIC-QUOTED-COOKIE"; Path=/')):
            with self.subTest(name=name):
                redactor = Redactor()
                _learn_header(redactor, name, raw)
                self.assertNotIn("SYNTHETIC-QUOTED-COOKIE", redactor.prose("Runtime quoted SYNTHETIC-QUOTED-COOKIE"))


class ReportPublicationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="awa-report-publish-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.parent = self.root / "reports"
        self.staging = self.parent / ".report-owned"
        self.destination = self.parent / "new-batch"
        self.staging.mkdir(parents=True)
        (self.staging / "report.md").write_text("owned fixture report", encoding="utf-8")

    @staticmethod
    def sharing_error(code=5):
        error = PermissionError("Synthetic Windows staging share contention")
        error.winerror = code
        return error

    def test_transient_windows_share_failure_retries_only_atomic_owned_publish(self):
        from awa_ddd import reporting
        rename = reporting.os.rename
        calls = []

        def publish(source, target):
            calls.append((source, target))
            if len(calls) == 1:
                raise self.sharing_error()
            return rename(source, target)

        with patch.object(reporting.os, "rename", side_effect=publish), patch.object(reporting.time, "sleep") as sleep:
            reporting._publish_report(self.staging, self.destination, self.parent)
        sleep.assert_called_once_with(0.025)
        self.assertEqual([(self.staging, self.destination)] * 2, calls)
        self.assertFalse(self.staging.exists())
        self.assertEqual("owned fixture report", (self.destination / "report.md").read_text(encoding="utf-8"))

    def test_permanent_share_failure_never_publishes_or_claims_success(self):
        from awa_ddd import reporting
        with patch.object(reporting.os, "rename", side_effect=self.sharing_error(32)) as rename, \
                patch.object(reporting.time, "sleep") as sleep:
            with self.assertRaises(PermissionError):
                reporting._publish_report(self.staging, self.destination, self.parent)
        self.assertEqual(4, rename.call_count)
        self.assertEqual([0.025, 0.075, 0.15], [call.args[0] for call in sleep.call_args_list])
        self.assertFalse(self.destination.exists())
        self.assertTrue((self.staging / "report.md").exists())

    def test_non_windows_permission_errors_are_not_retried(self):
        from awa_ddd import reporting
        error = PermissionError("Permanent fixture permission failure")
        with patch.object(reporting.os, "rename", side_effect=error) as rename, patch.object(reporting.time, "sleep") as sleep:
            with self.assertRaises(PermissionError):
                reporting._publish_report(self.staging, self.destination, self.parent)
        rename.assert_called_once()
        sleep.assert_not_called()
        self.assertFalse(self.destination.exists())

    def test_existing_destination_is_never_replaced(self):
        from awa_ddd import reporting
        self.destination.mkdir()
        original = self.destination / "existing.md"
        original.write_text("keep existing report", encoding="utf-8")
        with patch.object(reporting.os, "rename") as rename:
            with self.assertRaises(FileExistsError):
                reporting._publish_report(self.staging, self.destination, self.parent)
        rename.assert_not_called()
        self.assertEqual("keep existing report", original.read_text(encoding="utf-8"))

    def test_escape_is_rejected_before_move_or_retry(self):
        from awa_ddd import reporting
        with patch.object(reporting.os, "rename") as rename, patch.object(reporting.time, "sleep") as sleep:
            with self.assertRaises(ValueError):
                reporting._publish_report(self.staging, self.root / "outside-parent", self.parent)
        rename.assert_not_called()
        sleep.assert_not_called()
        self.assertTrue((self.staging / "report.md").exists())


if __name__ == "__main__":
    unittest.main()
