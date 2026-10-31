"""Real store/evaluator integration for snapshots and untrusted legacy imports."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from awa_ddd.engine import build_plan, create_project, evaluate_coverage, register_operation
from awa_ddd.importers import import_pentest
from awa_ddd.reporting import build_report, coverage, safe_metadata, safe_text
from awa_ddd.store import Project


class ReportingImportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="awa-report-import-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.workspace = self.root / "workspace"
        create_project(self.workspace, {"project_id": "audit", "target": "https://example.invalid/app/"})
        self.project = Project(self.workspace, "audit")
        self.addCleanup(self.project.close)

    def operation(self):
        return register_operation(self.project, {
            "url": "https://example.invalid/app/orders", "method": "POST", "auth": "unknown",
            "inputs": [{"name": "ownerId", "location": "body", "selector": "/order/ownerId",
                        "consumer": "unknown", "source": "declared"}],
            "sources": [{"path": "fixture.openapi.json", "sha256": "a" * 64,
                         "locator": "/paths/orders", "trust": "declared"}],
        })

    def legacy(self, *, endpoints=None, findings=None):
        source = self.root / "legacy"
        source.mkdir(exist_ok=True)
        documents = {
            "config.json": {"target": "https://example.invalid/app/", "test_accounts": [
                {"password": "PRIVATE-CONFIG-PASSWORD", "cookie": "PRIVATE-CONFIG-COOKIE"}]},
            "inventory.json": {"endpoints": endpoints if endpoints is not None else [{
                "url_id": "U1", "url": "/app/orders?access_token=PRIVATE-URL-TOKEN", "method": "POST",
                "params_enumerated": True, "test_status": "tested", "params": [
                    {"name": "ownerId", "in": "body", "selector": "/order/ownerId", "sample": "PRIVATE-INPUT-SAMPLE",
                     "sinks": ["authorization"], "check_status": "tested"}]}]},
            "findings.json": {"findings": findings if findings is not None else [{
                "finding_id": "F1", "url_id": "U1", "name": "Historical authorization issue", "category": "idor",
                "severity": "high", "status": "confirmed", "origin": "forward", "evidence_refs": ["E-OLD"],
                "request": {"headers": {"Authorization": "Bearer PRIVATE-AUTH-HEADER"}},
                "response": {"body_preview": "PRIVATE-RESPONSE-BODY"}}]},
            "sessions.json": {"sessions": [{"cookie": "PRIVATE-SESSION-COOKIE"}]},
        }
        for name, doc in documents.items():
            (source / name).write_text(json.dumps(doc), encoding="utf-8")
        return source

    def test_coverage_calls_single_evaluator_and_does_not_mutate_state(self):
        self.operation()
        build_plan(self.project)
        before = self.project.list("obligation")
        expected = evaluate_coverage(self.project)
        with patch("awa_ddd.engine.evaluate_coverage", wraps=evaluate_coverage) as evaluate:
            self.assertEqual(coverage(self.project), expected)
            evaluate.assert_called_once_with(self.project)
        self.assertEqual(self.project.list("obligation"), before)

    def test_snapshot_preserves_real_open_and_blocked_gaps(self):
        self.operation()
        build_plan(self.project)
        obligations = self.project.list("obligation")
        self.assertGreater(len(obligations), 1)
        blocked = dict(obligations[0], status="blocked", reason="Missing a valid test actor")
        self.project.put("obligation", blocked)
        expected = evaluate_coverage(self.project)
        result = build_report(self.project)
        summary = json.loads(Path(result["summary"]).read_text(encoding="utf-8"))
        report = Path(result["report"]).read_text(encoding="utf-8")
        self.assertEqual(summary["coverage"], expected)
        self.assertEqual(summary["coverage"]["blocked"], 1)
        self.assertIn("Missing a valid test actor", report)
        self.assertIn("declared", report)
        self.assertEqual(result["report_sha256"], hashlib.sha256(Path(result["report"]).read_bytes()).hexdigest())
        self.assertEqual(result["summary_sha256"], hashlib.sha256(Path(result["summary"]).read_bytes()).hexdigest())

    def test_stale_finding_is_explicitly_historical(self):
        operation = self.operation()
        self.project.put("finding", {"id": "F-old", "title": "Historical result", "status": "confirmed",
            "category": "idor", "operation_id": operation["id"], "decision_id": "D-missing", "evidence_ids": []})
        result = build_report(self.project)
        summary = json.loads(Path(result["summary"]).read_text(encoding="utf-8"))
        self.assertFalse(summary["coverage"]["findings"][0]["current"])
        self.assertIn("历史 / 当前不可验证发现", Path(result["report"]).read_text(encoding="utf-8"))

    def test_public_outputs_exclude_credentials_bodies_and_url_query_values(self):
        operation = self.operation()
        self.project.put("session", {"id": "S-private", "headers": {"Cookie": "PRIVATE-SESSION-SECRET"}})
        self.project.put("obligation", {"id": "OB-private", "operation_id": operation["id"], "kind": "consumer",
            "status": "open", "reason": "Review https://example.invalid/app/orders?token=PRIVATE-QUERY-SECRET",
            "headers": {"Authorization": "PRIVATE-HEADER-SECRET"},
            "response": {"body": "PRIVATE-BODY-SECRET"}, "details": {"password": "PRIVATE-PASSWORD-SECRET"}})
        self.project.put("finding", {"id": "F-private", "title": "Authorization: Bearer PRIVATE-TITLE-SECRET",
            "decision_id": "missing", "status": "confirmed", "request_headers": {"X-Api-Key": "PRIVATE-KEY-SECRET"}})
        result = build_report(self.project)
        exported = Path(result["summary"]).read_text(encoding="utf-8") + Path(result["report"]).read_text(encoding="utf-8")
        for value in ("PRIVATE-SESSION-SECRET", "PRIVATE-QUERY-SECRET", "PRIVATE-HEADER-SECRET", "PRIVATE-BODY-SECRET",
                      "PRIVATE-PASSWORD-SECRET", "PRIVATE-TITLE-SECRET", "PRIVATE-KEY-SECRET"):
            self.assertNotIn(value, exported)
        self.assertIn("OB-private", exported)

    def test_snapshots_are_unique_and_keep_previous_bytes(self):
        self.operation()
        first = build_report(self.project)
        original = Path(first["report"]).read_bytes()
        build_plan(self.project)
        second = build_report(self.project)
        self.assertNotEqual(first["report"], second["report"])
        self.assertEqual(Path(first["report"]).read_bytes(), original)

    def test_nested_metadata_secret_keys_are_case_and_separator_independent(self):
        metadata = {"reason": "An unresolved input", "details": {
            "accessToken": "PRIVATE-ACCESS", "requestHeaders": {"X-Key": "PRIVATE-HEADER"},
            "storageState": {"cookies": ["PRIVATE-COOKIE"]}, "clientSecret": "PRIVATE-CLIENT",
            "idToken": "PRIVATE-ID", "privateKey": "PRIVATE-KEY", "input_count": 2,
        }}
        result = safe_metadata(metadata)
        self.assertEqual(result, {"reason": "An unresolved input", "details": {"input_count": 2}})

    def test_text_redacts_quoted_assignments_and_complete_cookie_headers(self):
        cases = [
            '{"password": "PRIVATE-PASSWORD", "id": 12}',
            "{'accessToken': 'PRIVATE-ACCESS', 'id': 12}",
            'Cookie: tracking=PUBLIC; session=PRIVATE-SESSION; jwt=PRIVATE-JWT',
            '{"Cookie": "tracking=PUBLIC; session=PRIVATE-SESSION", "id": 12}',
            "token=PRIVATE-TOKEN; status=review",
            'clientSecret: "PRIVATE-CLIENT,also-private"',
        ]
        for value in cases:
            with self.subTest(value=value):
                self.assertNotIn("PRIVATE-", safe_text(value))

    def test_json_credentials_in_report_reasons_are_removed(self):
        operation = self.operation()
        self.project.put("obligation", {"id": "OB-json", "operation_id": operation["id"],
            "kind": "consumer", "status": "open", "reason": '{"password": "PRIVATE-JSON"}',
            "details": {"accessToken": "PRIVATE-CAMEL"}})
        result = build_report(self.project)
        for name in ("report", "summary"):
            self.assertNotIn("PRIVATE-", Path(result[name]).read_text(encoding="utf-8"))

    def test_import_is_read_only_and_does_not_inherit_verification(self):
        source = self.legacy()
        original = {p.name: p.read_bytes() for p in source.iterdir()}
        result = import_pentest(self.project, source)
        self.assertEqual(result["operations_imported"], 1)
        self.assertEqual(result["candidates_created"], 1)
        self.assertFalse(result["verification_inherited"])
        self.assertEqual({p.name: p.read_bytes() for p in source.iterdir()}, original)
        self.assertEqual(self.project.list("finding"), [])
        self.assertEqual(self.project.list("decision"), [])
        self.assertEqual(self.project.list("evidence"), [])
        self.assertEqual(self.project.list("session"), [])
        candidate = self.project.list("candidate")[0]
        self.assertEqual(candidate["status"], "unverified")
        self.assertEqual(candidate["legacy_status"], "confirmed")
        self.assertEqual(candidate["origin"], "imported")
        self.assertEqual(candidate["legacy_origin"], "forward")
        self.assertEqual(candidate["source"]["sha256"], hashlib.sha256(original["findings.json"]).hexdigest())
        build_plan(self.project)
        current = evaluate_coverage(self.project)
        self.assertEqual(current["evaluated"], 0)
        self.assertGreater(current["open"], 0)
        normalized = json.dumps({k: self.project.list(k) for k in ("candidate", "operation", "session", "finding", "decision")})
        self.assertNotIn("PRIVATE-", normalized)

    def test_import_keeps_parameter_locators_and_legacy_mapping(self):
        result = import_pentest(self.project, self.legacy())
        operation = self.project.list("operation")[0]
        self.assertEqual(result["operation_mapping"], {"U1": operation["id"]})
        self.assertEqual(operation["url"], "https://example.invalid/app/orders")
        owner = next(row for row in operation["inputs"] if row["name"] == "ownerId")
        self.assertEqual(owner["selector"], "/order/ownerId")
        self.assertEqual(owner["consumer"], "unknown")
        self.assertEqual(owner["source"], "declared")
        self.assertEqual(self.project.list("candidate")[0]["operation_id"], operation["id"])

    def test_repeated_import_does_not_duplicate_candidates_or_operations(self):
        source = self.legacy()
        import_pentest(self.project, source)
        second = import_pentest(self.project, source)
        self.assertEqual(second["candidates_created"], 0)
        self.assertEqual(len(self.project.list("candidate")), 1)
        self.assertEqual(len(self.project.list("operation")), 1)

    def test_missing_or_duplicate_legacy_ids_never_bind_findings(self):
        source = self.legacy(endpoints=[
            {"url": "/app/no-id", "method": "GET"},
            {"url_id": "U-duplicate", "url": "/app/one", "method": "GET"},
            {"url_id": "U-duplicate", "url": "/app/two", "method": "GET"},
        ], findings=[
            {"finding_id": "F-no-id", "title": "Missing legacy link"},
            {"finding_id": "F-ambiguous", "url_id": "U-duplicate", "title": "Ambiguous legacy link"},
        ])
        result = import_pentest(self.project, source)
        self.assertEqual(result["operations_imported"], 3)
        self.assertEqual(result["operation_mapping"], {})
        self.assertEqual(result["ambiguous_legacy_ids"], ["U-duplicate"])
        self.assertEqual(result["unmapped_findings"], 2)
        for candidate in self.project.list("candidate"):
            self.assertNotIn("operation_id", candidate)
            self.assertTrue(any("manual mapping" in item for item in candidate["limitations"]))

    def test_import_retains_named_operations_and_content_types(self):
        source = self.legacy(endpoints=[
            {"url_id": "U-one", "url": "/app/graphql", "method": "POST", "protocol": "graphql",
             "operation_name": "GetOrder", "content_type": "application/json"},
            {"url_id": "U-two", "url": "/app/graphql", "method": "POST", "protocol": "graphql",
             "operation_name": "ListOrders", "content_type": "application/json"},
            {"url_id": "U-three", "url": "/app/graphql", "method": "POST",
             "content_type": "application/graphql"},
        ], findings=[])
        result = import_pentest(self.project, source)
        self.assertEqual(result["operations_imported"], 3)
        operations = self.project.list("operation")
        self.assertEqual({op["operation_name"] for op in operations}, {"GetOrder", "ListOrders", ""})
        self.assertEqual({op["content_type"] for op in operations}, {"application/json", "application/graphql"})

    def test_failed_import_rolls_back_operations_candidates_and_events(self):
        existing = self.operation()
        source = self.legacy()
        before_events = self.project.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        real_event = self.project.event

        def fail_final_event(kind, payload):
            if kind == "legacy.imported":
                raise RuntimeError("Synthetic failure before import commit")
            return real_event(kind, payload)

        with patch.object(self.project, "event", side_effect=fail_final_event), self.assertRaises(RuntimeError):
            import_pentest(self.project, source)
        self.assertEqual(self.project.list("operation"), [existing])
        self.assertEqual(self.project.list("candidate"), [])
        self.assertEqual(self.project.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0], before_events)

    def test_rejected_registration_cannot_leave_a_partial_operation(self):
        source = self.legacy(findings=[])

        def partial_registration(project, hint):
            register_operation(project, hint)
            raise ValueError("Synthetic rejection after a partial write")

        with patch("awa_ddd.engine.register_operation", side_effect=partial_registration):
            result = import_pentest(self.project, source)
        self.assertEqual(result["operations_imported"], 0)
        self.assertEqual(len(result["skipped_operations"]), 1)
        self.assertEqual(self.project.list("operation"), [])

    def test_import_preserves_reviewed_destination_policy_and_consumers(self):
        original = register_operation(self.project, {
            "url": "https://example.invalid/app/orders", "method": "POST", "auth": "restricted",
            "allowed_roles": ["manager"], "ownership": True,
            "inputs": [{"name": "ownerId", "location": "body", "selector": "/order/ownerId",
                        "consumer": "authorization", "source": "observed"}],
        })
        import_pentest(self.project, self.legacy())
        current = self.project.get("operation", original["id"])
        self.assertEqual(current["auth"], "restricted")
        self.assertEqual(current["allowed_roles"], ["manager"])
        self.assertTrue(current["ownership"])
        owner = next(row for row in current["inputs"] if row["name"] == "ownerId")
        self.assertEqual(owner["source"], "observed")
        self.assertEqual(owner["consumer"], "authorization")

    def test_out_of_scope_operation_is_skipped_without_leaking_query(self):
        source = self.legacy(endpoints=[{"url_id": "U-out", "url": "https://outside.invalid/private?token=PRIVATE-OUTSIDE",
                                        "method": "GET", "params": []}], findings=[])
        result = import_pentest(self.project, source)
        self.assertEqual(result["operations_imported"], 0)
        self.assertEqual(len(result["skipped_operations"]), 1)
        self.assertNotIn("PRIVATE-OUTSIDE", json.dumps(result))

    def test_invalid_findings_structure_fails_before_destination_mutation(self):
        source = self.legacy()
        (source / "findings.json").write_text('{"findings":"invalid"}', encoding="utf-8")
        with self.assertRaises(ValueError):
            import_pentest(self.project, source)
        self.assertEqual(self.project.list("operation"), [])

    def test_byte_budget_is_enforced_before_import(self):
        source = self.legacy()
        with patch("awa_ddd.importers.MAX_DOCUMENT_BYTES", 8), self.assertRaises(ValueError):
            import_pentest(self.project, source)
        self.assertEqual(self.project.list("operation"), [])

    def test_source_cannot_overlap_destination(self):
        with self.assertRaisesRegex(ValueError, "overlap"):
            import_pentest(self.project, self.project.base)
        with self.assertRaisesRegex(ValueError, "overlap"):
            import_pentest(self.project, self.workspace)

    def test_symlink_legacy_document_is_rejected(self):
        source = self.legacy()
        outside = self.root / "other-inventory.json"
        (source / "inventory.json").replace(outside)
        try:
            (source / "inventory.json").symlink_to(outside)
        except OSError as exc:
            self.skipTest("Symlink creation is unavailable: " + type(exc).__name__)
        with self.assertRaisesRegex(ValueError, "symlink"):
            import_pentest(self.project, source)
        self.assertEqual(self.project.list("operation"), [])

    def test_report_directory_symlink_is_rejected(self):
        outside = self.root / "outside-reports"
        outside.mkdir()
        try:
            (self.project.base / "reports").symlink_to(outside, target_is_directory=True)
        except OSError as exc:
            self.skipTest("Symlink creation is unavailable: " + type(exc).__name__)
        with self.assertRaisesRegex(ValueError, "symlink"):
            build_report(self.project)
        self.assertEqual(list(outside.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
