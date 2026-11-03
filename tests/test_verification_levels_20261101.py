"""Report assurance comes from current proof, never scores or caller-selected labels."""
from __future__ import annotations

import json
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.parse import quote

from awa_ddd import browser, engine
from awa_ddd.__main__ import dispatch
from awa_ddd.assessment import evaluate, record_finding
from awa_ddd.store import EngineError


class VerificationLevelTests(unittest.TestCase):
    def setUp(self):
        from test_report_reproduction_20261030 import ReportReproductionTests

        self.fixture = ReportReproductionTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.project, self.root, self.base = self.fixture.project, self.fixture.root, self.fixture.base

    def extraction(self):
        operation = self.fixture.operation("/extract", inputs=[{
            "name": "xml", "location": "query", "consumer": "xml_parser", "test_families": ["xxe"]}])
        engine.build_plan(self.project)
        item = next(item for item in self.project.list("obligation")
                    if item["operation_id"] == operation["id"] and item["kind"] == "input_test")
        values = ['<!DOCTYPE doc [<!ENTITY sample SYSTEM "file:///fixture/canary.txt">]><doc>&sample;</doc>',
                  "<doc>normal</doc>"]
        controls = [self.fixture.capture(operation, response={"data": {"preview": value}},
            url=operation["url"] + "?xml=" + quote(body, safe=""))
            for body, value in zip(values, ("FIXTURE-CANARY", "normal"))]
        decision = evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": [row["id"] for row in controls],
            "oracle": {"type": "extraction", "test_family": "xxe", "selector": "/data/preview", "expect": "^FIXTURE-CANARY$",
                       "expected_value": "FIXTURE-CANARY", "source_reference": "file:///fixture/canary.txt"}})
        finding = record_finding(self.project, {"title": "Typed fixture extraction", "category": "XXE",
            "impact": "Bounded canary read", "remediation": "Disable external entities", "decision_id": decision["id"],
            "verification_level": "hint_only"})
        return finding, controls

    def report(self):
        with patch.object(engine, "request", side_effect=AssertionError("Reports must not send target requests")):
            return self.fixture.report()

    def test_typed_proof_and_untyped_analyst_are_separate_and_immutable(self):
        typed, controls = self.extraction()
        manual = self.fixture.finding([controls[1]["id"]], title="Code interpretation only",
                                      verification_level="runtime_verified")
        original = {row["id"]: row for row in self.project.list("finding")}
        _, _, summary, text = self.report()
        levels = {row["id"]: row["verification_level"] for row in summary["coverage"]["findings"]}
        self.assertEqual("runtime_verified", levels[typed["id"]])
        self.assertEqual("analyst_review", levels[manual["id"]])
        self.assertEqual(1, summary["verification_assurance"]["runtime_verified"])
        self.assertEqual(1, summary["verification_assurance"]["analyst_review"])
        self.assertIn("运行时证实", text)
        self.assertIn("非 typed 运行时证实", text)
        self.assertEqual(original, {row["id"]: row for row in self.project.list("finding")})

    def test_answer_keys_and_code_sinks_never_add_runtime_findings(self):
        definition = self.root / "fixture-definition.json"
        definition.write_text(json.dumps({"version": "fixture-v1", "maxScore": 400, "vulns": [
            ["/user/login", [["password", "POST"]], "RCE", 200],
            ["/products", [["order", "GET"]], "SQL注入", 200]]}), encoding="utf-8")
        script = self.root / "fixture-client.js"
        script.write_text("const name = row.shop_name; card.innerHTML = name;", encoding="utf-8")
        with patch.object(engine, "request", side_effect=AssertionError("Offline discovery must not send requests")):
            for path, format in ((definition, "assessment_hints"), (script, "javascript")):
                dispatch(self.root, "surface.import", {"project_id": "repro", "path": str(path), "format": format, "base_url": self.base})
        _, _, summary, text = self.report()
        assurance = summary["verification_assurance"]
        self.assertEqual(0, assurance["runtime_verified"])
        self.assertEqual(0, assurance["analyst_review"])
        self.assertEqual(2, assurance["hint_only"])
        self.assertEqual(1, assurance["code_hint"])
        self.assertFalse(assurance["hints_count_as_findings"])
        self.assertEqual(0, summary["finding_groups"]["current"])
        self.assertEqual([], self.project.list("decision"))
        self.assertIn("代码级提示 1", text)

    def test_stale_runtime_material_moves_to_history_without_a_runtime_count(self):
        finding, controls = self.extraction()
        original = self.project.get("finding", finding["id"])
        artifact = self.project.base / controls[0]["artifact_path"]
        artifact.write_bytes(artifact.read_bytes() + b" ")
        _, _, summary, _ = self.report()
        self.assertEqual(0, summary["verification_assurance"]["runtime_verified"])
        self.assertEqual(1, summary["verification_assurance"]["historical"])
        self.assertEqual("historical", summary["coverage"]["findings"][0]["verification_level"])
        self.assertEqual(original, self.project.get("finding", finding["id"]))

    def test_analyst_sql_with_real_accepted_metadata_retains_runtime_assurance(self):
        operation = self.fixture.operation("/sql", inputs=[{"name": "q", "location": "query", "consumer": "sql_like"}])
        engine.build_plan(self.project)
        item = next(item for item in self.project.list("obligation")
                    if item["operation_id"] == operation["id"] and item["kind"] == "input_test")
        values = ["normal", "extractvalue(1,concat(database()))", "extractvalue(1,12345)"]
        responses = [{"count": 1}, {"error": "~shop_fixture~"}, {"error": "no database metadata"}]
        ids = [self.fixture.capture(operation, response=response, url=operation["url"] + "?q=" + quote(value, safe=""))["id"]
               for value, response in zip(values, responses)]
        decision = evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": ids,
            "oracle": {"type": "error_channel", "metadata_type": "database", "expected_value": "shop_fixture",
                       "response_pattern": r"~(?P<value>[^~]+)~"}})
        finding = self.fixture.finding(ids, category="SQL Injection", proof_decision_id=decision["id"])
        _, _, summary, _ = self.report()
        row = next(row for row in summary["coverage"]["findings"] if row["id"] == finding["id"])
        self.assertEqual("analyst", row["mode"])
        self.assertEqual("runtime_verified", row["verification_level"])

    def test_secret_collisions_preserve_typed_assurance_but_required_context_fails_closed(self):
        finding, _ = self.extraction()
        for number, value in enumerate(("0", "runtime_verified", "true")):
            url = self.base + "/context"
            raw = {"url": url, "finalUrl": url, "status": 200, "signals": {"forms": 1},
                   "network": [{"url": url, "method": "GET", "status": 200}],
                   "actions": [{"type": "fill", "selector": "#private", "ok": True, "value": value, "finalUrl": url}]}
            source = self.root / ("context-" + str(number) + ".json")
            source.write_text(json.dumps(raw), encoding="utf-8")
            browser.import_observation(self.project, {"path": str(source)})
        result, _, summary, _ = self.report()
        assurance = summary["verification_assurance"]
        self.assertIs(type(assurance["runtime_verified"]), int)
        self.assertEqual(1, assurance["runtime_verified"])
        self.assertIs(assurance["hints_count_as_findings"], False)
        row = next(row for row in summary["coverage"]["findings"] if row["id"] == finding["id"])
        self.assertEqual("runtime_verified", row["verification_level"])
        self.assertEqual(assurance, result["verification_assurance"])
        reports = self.project.base / "reports"
        published = {str(path.relative_to(reports)): path.read_bytes()
                     for path in reports.rglob("*") if path.is_file()}
        for visit in self.project.list("page_visit"):
            changed = dict(visit)
            changed.pop("credentials", None)
            self.project.put("page_visit", changed)
        with self.assertRaises(EngineError) as caught:
            self.report()
        self.assertEqual("browser_redaction_context", caught.exception.code)
        self.assertEqual(published, {str(path.relative_to(reports)): path.read_bytes()
                                    for path in reports.rglob("*") if path.is_file()})

    def test_legacy_unavailable_context_retains_typed_assurance_in_metadata_only_report(self):
        self.extraction()
        url = self.base + "/legacy-context"
        raw = {"url": url, "finalUrl": url, "status": 200, "signals": {"forms": 1},
               "network": [{"url": url, "method": "GET", "status": 200}],
               "actions": [{"type": "fill", "selector": "#private", "ok": True, "finalUrl": url}]}
        source = self.root / "legacy-context.json"
        source.write_text(json.dumps(raw), encoding="utf-8")
        browser.import_observation(self.project, {"path": str(source)})
        _, _, unavailable, _ = self.report()
        self.assertTrue(unavailable["reproduction_metadata_only"])
        self.assertEqual(1, unavailable["verification_assurance"]["runtime_verified"])
        self.assertFalse(unavailable["verification_assurance"]["runtime_level_implies_full_coverage"])


if __name__ == "__main__":
    unittest.main()
