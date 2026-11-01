"""Strict disk-summary projections with genuine ledger/file controls and mock traffic."""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shlex
import unittest
from unittest.mock import patch
from urllib.parse import quote

from awa_ddd import browser, engine, reproduction
from awa_ddd.assessment import evaluate, record_finding
from awa_ddd.__main__ import dispatch
from awa_ddd.publication import publish_report_summary
from awa_ddd.reporting import build_report
from awa_ddd.store import EngineError, canonical


class ReportSummaryPublicationTests(unittest.TestCase):
    def setUp(self):
        from test_report_reproduction_20261030 import ReportReproductionTests

        self.fixture = ReportReproductionTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root, self.project, self.base = self.fixture.root, self.fixture.project, self.fixture.base
        guard = patch.object(engine, "request", side_effect=AssertionError("No target traffic is permitted"))
        self.network = guard.start()
        self.addCleanup(guard.stop)
        self.serial = 0

    def tearDown(self):
        self.network.assert_not_called()

    def fill(self, value="12", *, missing=False):
        self.serial += 1
        url = self.base + "/context"
        action = {"type": "fill", "selector": "#private", "ok": True, "finalUrl": url}
        if not missing:
            action["value"] = value
        raw = {"url": url, "finalUrl": url, "status": 200, "signals": {"forms": 1}, "title": str(value),
               "network": [{"url": url, "method": "GET", "status": 200}], "actions": [action]}
        path = self.root / ("context-" + str(self.serial) + ".json")
        path.write_text(canonical(raw), encoding="utf-8")
        return browser.import_observation(self.project, {"path": str(path)})

    def report(self):
        result = build_report(self.project)
        folder = Path(result["report"]).parent
        summary = json.loads(Path(result["summary"]).read_text(encoding="utf-8"))
        manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
        for entry in manifest["files"]:
            material = (folder / entry["path"]).read_bytes()
            self.assertEqual(entry["sha256"], hashlib.sha256(material).hexdigest())
            self.assertEqual(entry["size_bytes"], len(material))
        return result, folder, summary, manifest

    def recorded(self, *, body=None, sources=None):
        operation = self.fixture.operation("/items", sources=sources or [])
        evidence = self.fixture.capture(operation, response={"content": "business-result"},
                                        url=operation["url"] + "?q=normal", body=body,
                                        headers={"Content-Type": "application/json"} if body is not None else {})
        finding = self.fixture.finding([evidence["id"]])
        return operation, evidence, finding

    def raw_summary(self, findings=()):
        evaluated = engine.evaluate_coverage(self.project)
        prepared = reproduction.prepare_reproduction(self.project, list(findings))
        return {"format_version": 5, "language": "zh-CN", "stage": "draft", "delivery_status": "draft",
                "coverage": evaluated, "completion": evaluated["completion"], "continuation": evaluated["continuation"],
                "finalization": None, "operation_metadata": self.project.list("operation"),
                "reproduction": prepared["finding_details"],
                "artifacts": [{"path": path, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
                              for path, data in prepared["files"].items()]}, prepared

    def test_source_numbers_are_private_while_twelve_real_operations_remain_typed(self):
        self.fill("12")
        for number in range(12):
            self.fixture.operation("/route-" + str(number), sources=[{"metadata": {"business_count": 12, "input_count": 12,
                "floating": 12.0, "values": [12, 12.0], "continuation": {"ready_total": 12}}}])
        engine.build_plan(self.project)
        _, _, summary, _ = self.report()
        self.assertEqual(12, summary["coverage"]["operations"])
        self.assertEqual(12, summary["coverage"]["obligations"])
        self.assertIs(type(summary["coverage"]["operations"]), int)
        for operation in summary["operation_metadata"]:
            self.assertIs(type(operation["input_count"]), int)
            metadata = operation["sources"][0]["metadata"]
            self.assertTrue(all(isinstance(metadata[key], str) for key in ("business_count", "input_count", "floating")))
            self.assertTrue(all(isinstance(value, str) for value in metadata["values"]))
            self.assertIsInstance(metadata["continuation"]["ready_total"], str)

    def test_body_numbers_and_leading_zero_aliases_do_not_escape_into_files_or_excerpts(self):
        self.fill("000012")
        _, evidence, finding = self.recorded(body={"integer": 12, "floating": 12.0, "literal": "000012"})
        original = (self.project.base / evidence["artifact_path"]).read_bytes()
        _, folder, summary, _ = self.report()
        step = summary["reproduction"][finding["id"]]["steps"][0]
        body = json.loads((folder / step["body_file"]).read_text(encoding="utf-8"))
        self.assertTrue(all(isinstance(value, str) and "AWA_" in value for value in body.values()))
        self.assertNotIn("000012", step["request_body_excerpt"])
        self.assertEqual(original, (self.project.base / evidence["artifact_path"]).read_bytes())

    def test_curl_query_and_generated_file_tokens_survive_a_pin_collision(self):
        self.fill("12")
        original_id = self.project.id
        mint = lambda prefix: prefix + "-" + "a" * 30 + "12" if prefix in {"E", "F", "D"} else original_id(prefix)
        with patch.object(self.project, "id", side_effect=mint):
            operation, evidence, finding = self.recorded(body={"note": "ordinary-body"})
        _, folder, summary, _ = self.report()
        detail = summary["reproduction"][finding["id"]]
        step = detail["steps"][0]
        arguments = shlex.split(step["curl"]["posix"])
        self.assertEqual(operation["url"] + "?q=normal", arguments[arguments.index("--url") + 1])
        self.assertEqual("@" + step["body_file"], arguments[arguments.index("--data-binary") + 1])
        self.assertIn(step["body_file"], step["curl"]["powershell"])
        self.assertTrue((folder / step["body_file"]).is_file())
        self.assertTrue(detail["available"])
        self.assertTrue(step["request_template_available"])
        self.assertEqual(evidence["id"], step["evidence_id"])
        self.assertEqual(evidence["sha256"], step["source_sha256"])

    def test_prepared_placeholder_labels_keep_the_assignment_name_without_reslotting(self):
        operation = self.fixture.operation()
        evidence = self.fixture.capture(operation, response={"password": "synthetic-private-actuator", "content": "business-result"})
        finding = self.fixture.finding([evidence["id"]], impact="Actuator password=synthetic-private-actuator; rotate the credential.")
        _, _, summary, _ = self.report()
        impact = next(row for row in summary["coverage"]["findings"] if row["id"] == finding["id"])["impact"]
        self.assertIn("password=<AWA_", impact)
        self.assertNotIn("synthetic-private-actuator", canonical(summary))

    def test_forbidden_source_keys_are_removed_before_private_key_names_are_scrubbed(self):
        self.fill("body")
        operation = self.fixture.operation(sources=[{"body": {"independent": "synthetic-sensitive-unrelated-payload"}}])
        summary, prepared = self.raw_summary()
        public = publish_report_summary(self.project, summary, extra_secrets=prepared["redactor"].values, files=prepared["files"])
        self.assertNotIn("synthetic-sensitive-unrelated-payload", canonical(public))
        self.assertEqual({"body": {"independent": "synthetic-sensitive-unrelated-payload"}}, self.project.get("operation", operation["id"])["sources"][0])

    def test_proof_source_numbers_and_caller_selected_uuid_handles_are_not_restored(self):
        self.fill("12")
        actor_id = "ACT-" + "b" * 32
        engine.add_actor(self.project, {"actor_id": actor_id, "subject": "fixture-principal"})
        engine.add_session(self.project, {"actor_id": actor_id, "headers": {"Authorization": "Bearer " + actor_id}})
        _, evidence, finding = self.recorded()
        changed = deepcopy(finding)
        changed["proof"] = {"actor_id": actor_id, "recovered_value": {"count": 12},
                            "source": {"actor_id": actor_id, "ready_total": 12}}
        self.project.put("finding", changed)
        _, _, summary, _ = self.report()
        proof = summary["coverage"]["findings"][0]["proof"]
        self.assertNotIn(actor_id, canonical(summary))
        self.assertIsInstance(proof["recovered_value"]["count"], str)
        self.assertIsInstance(proof["source"]["ready_total"], str)
        self.assertEqual(changed, self.project.get("finding", finding["id"]))
        self.project.read_artifact(evidence)

    def test_unknown_hashes_do_not_gain_material_digest_exemptions(self):
        self.fill("12")
        fake = "a" * 30 + "12" + "b" * 32
        _, _, finding = self.recorded(sources=[{"metadata": {"sha256": fake, "arbitrary_digest": fake}}])
        _, _, summary, manifest = self.report()
        self.assertNotIn(fake, canonical(summary))
        self.assertTrue(summary["reproduction"][finding["id"]]["available"])
        self.assertTrue(all(type(row["size_bytes"]) is int for row in summary["artifacts"]))
        self.assertTrue(all(type(row["size_bytes"]) is int for row in manifest["files"]))

    def test_generated_input_signature_survives_without_restoring_a_source_copy(self):
        operation = self.fixture.operation(inputs=[{"name": "q", "location": "query", "consumer": "business_input"}])
        engine.build_plan(self.project)
        obligation = next(row for row in self.project.list("obligation") if row["kind"] == "input_test")
        signature = obligation["input_signature"]
        self.fill(signature)
        changed = deepcopy(operation)
        changed["sources"] = [{"metadata": {"input_signature": signature}}]
        self.project.put("operation", changed)
        _, _, summary, _ = self.report()
        gap = next(row for row in summary["coverage"]["gaps"] if row["id"] == obligation["id"])
        self.assertEqual(signature, gap["input_signature"])
        self.assertNotIn(signature, canonical(summary["operation_metadata"][0]["sources"]))

    def test_exact_evidence_finding_and_material_digest_credentials_do_not_destroy_bound_references(self):
        _, evidence, finding = self.recorded(body={"note": "ordinary-body"})
        for secret in (evidence["id"], finding["id"], evidence["sha256"]):
            self.fill(secret)
        _, folder, summary, _ = self.report()
        step = summary["reproduction"][finding["id"]]["steps"][0]
        self.assertEqual(evidence["id"], step["evidence_id"])
        self.assertEqual(evidence["sha256"], step["source_sha256"])
        self.assertTrue((folder / step["request_file"]).is_file())
        self.assertTrue((folder / step["body_file"]).is_file())
        arguments = shlex.split(step["curl"]["posix"])
        self.assertEqual("@" + step["body_file"], arguments[arguments.index("--data-binary") + 1])

    def test_untrusted_original_commands_are_not_restored_as_generated_curl(self):
        self.fill("12")
        _, _, finding = self.recorded(body={"note": "ordinary-body"})
        current = engine.evaluate_coverage(self.project)["findings"]
        summary, prepared = self.raw_summary(current)
        summary["reproduction"][finding["id"]]["steps"][0]["curl"] = {"posix": "unsafe invented command", "powershell": "unsafe invented command"}
        original = deepcopy(summary)
        public = publish_report_summary(self.project, summary, extra_secrets=prepared["redactor"].values, files=prepared["files"])
        step = public["reproduction"][finding["id"]]["steps"][0]
        self.assertNotIn("unsafe invented command", canonical(step["curl"]))
        self.assertEqual("curl", shlex.split(step["curl"]["posix"])[0])
        self.assertEqual(original, summary)

    def test_legacy_unavailable_context_exports_only_metadata_with_no_private_request_files(self):
        secret = "synthetic-unknown-legacy-token"
        self.fill(secret, missing=True)
        operation = self.fixture.operation()
        evidence = self.fixture.capture(operation, response={"content": "business-result"}, url=operation["url"] + "?q=" + secret)
        finding = self.fixture.finding([evidence["id"]])
        _, folder, summary, manifest = self.report()
        self.assertTrue(summary["reproduction_metadata_only"])
        detail = summary["reproduction"][finding["id"]]
        self.assertTrue(detail["metadata_only"])
        self.assertFalse(detail["available"])
        self.assertEqual([evidence["id"]], detail["evidence_ids"])
        self.assertEqual([], summary["artifacts"])
        self.assertFalse((folder / "reproduction").exists())
        self.assertTrue(summary["continuation"]["continue_required"])
        self.assertEqual({"report.md", "summary.json"}, {row["path"] for row in manifest["files"]})
        self.assertNotIn(secret, b"\n".join(path.read_bytes() for path in folder.rglob("*") if path.is_file()).decode("utf-8"))

    def test_sqlmap_request_reference_and_profile_are_rebuilt_from_safe_bound_material(self):
        self.fill("12")
        operation = self.fixture.operation("/products", inputs=[{"name": "sort", "location": "query", "consumer": "sql_order_by"}])
        engine.build_plan(self.project)
        obligation = next(row for row in self.project.list("obligation") if row["kind"] == "input_test")
        values = ["price", "extractvalue(1,concat(0x7e,database(),0x7e))", "extractvalue(1,concat(0x7e,12345,0x7e))"]
        replies = [{"items": [{"name": "normal"}]}, {"error": "~shop_fixture~"}, {"error": "no database metadata"}]
        evidence = [self.fixture.capture(operation, response=response, url=operation["url"] + "?sort=" + quote(value, safe=""))
                    for value, response in zip(values, replies)]
        decision = evaluate(self.project, {"obligation_id": obligation["id"], "evidence_ids": [row["id"] for row in evidence],
            "oracle": {"type": "error_channel", "metadata_type": "database", "expected_value": "shop_fixture", "response_pattern": r"~(?P<value>[^~]+)~"}})
        finding = record_finding(self.project, {"decision_id": decision["id"], "title": "Bound SQL fixture", "category": "SQL Injection",
                                              "impact": "Recorded metadata", "remediation": "Allowlist the sort expression"})
        _, folder, summary, _ = self.report()
        sqlmap = summary["reproduction"][finding["id"]]["sqlmap"]
        arguments = shlex.split(sqlmap["commands"]["posix"])
        self.assertEqual("sort", arguments[arguments.index("-p") + 1])
        self.assertEqual(sqlmap["request_file"], arguments[arguments.index("-r") + 1])
        self.assertTrue((folder / sqlmap["request_file"]).is_file())
        self.assertIn("--technique=BEU", arguments)
        self.assertNotIn("--dump", arguments)
        self.assertTrue(sqlmap["manual_only"])
        self.assertFalse(sqlmap["executed_by_report"])

    def test_a_rejected_artifact_binding_cannot_be_published_as_a_file(self):
        summary, prepared = self.raw_summary()
        original = deepcopy(summary)
        with self.assertRaises(EngineError) as caught:
            publish_report_summary(self.project, summary, files={"../escape.http": b"must-not-write"})
        self.assertEqual("publication_failed", caught.exception.code)
        self.assertEqual(original, summary)
        self.assertEqual({}, prepared["files"])

    def test_codeword_and_numeric_secrets_do_not_corrupt_draft_delivery_controls(self):
        self.fixture.operation()
        engine.build_plan(self.project)
        for value in ("draft", "partial", "continue", "1", "000012"):
            with self.subTest(value=value):
                self.fill(value)
                _, _, summary, manifest = self.report()
                self.assertEqual("draft", summary["stage"])
                self.assertEqual("draft", summary["delivery_status"])
                self.assertEqual(summary["completion"], manifest["completion"])
                self.assertIs(type(summary["coverage"]["operations"]), int)
                self.assertIs(summary["continuation"]["continue_required"], True)
                self.assertIs(summary["continuation"]["automatic_stop_allowed"], False)

    def test_real_final_delivery_keeps_the_current_gate_and_manifest_controls(self):
        from test_finalization_report_20261030 import FinalizationReportTests

        fixture = FinalizationReportTests()
        fixture.setUp()
        try:
            actor = engine.add_actor(fixture.project, {"subject": "fixture-report-principal"})
            engine.add_session(fixture.project, {"actor_id": actor["id"], "headers": {"Authorization": "Bearer completed"}})
            _, stop = fixture.completed_fixture_stop()
            result = build_report(fixture.project, stage="final", finalization_id=stop["id"])
            summary, manifest, _ = fixture.read(result)
            self.assertEqual("final-completed", summary["delivery_status"])
            self.assertEqual("completed", summary["finalization"]["reason"])
            self.assertTrue(summary["continuation"]["automatic_stop_allowed"])
            self.assertFalse(summary["continuation"]["continue_required"])
            self.assertEqual(summary["finalization"], manifest["finalization"])
            self.assertEqual(result["continuation"], manifest["continuation"])
        finally:
            fixture.doCleanups()


if __name__ == "__main__":
    unittest.main()
