"""Answer keys select hypotheses; no score, validator response or static hint is proof."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import engine
from awa_ddd.__main__ import dispatch
from awa_ddd.discovery import discover
from awa_ddd.store import EngineError, Project


class AssessmentHintTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="awa-hint-import-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "definition.json"
        self.base = "http://fixture.invalid"

    def document(self, value):
        self.source.write_text(value if isinstance(value, str) else json.dumps(value, ensure_ascii=False), encoding="utf-8")
        return self.source

    def native(self):
        return {"version": "fixture-v1", "maxScore": 500, "vulns": [
            ["/search?access_token=SYNTHETIC_SECRET", [["keyword", "GET"]], "SQL注入", 180],
            ["/orders/{order_no}", [["order_no", "PATH"]], "越权访问", 160],
            ["/upload", [["file", "FILES"], ["filename", "POST"]], "文件上传", 160],
        ]}

    def normalized(self, **entry):
        return {"schema_version": 1, "source_kind": "validator_export", "entries": [
            {"url": "/search", "method": "GET", "test_family": "sql_injection",
             "inputs": [{"name": "q", "location": "query"}], "result": "valid", **entry}]}

    def test_actual_native_shape_imports_only_minimized_priority_clues(self):
        source = self.document(self.native())
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        result = discover(source, "assessment_hints", self.base)
        self.assertEqual([], result["operations"])
        self.assertEqual(3, len(result["candidates"]))
        self.assertNotIn("SYNTHETIC_SECRET", json.dumps(result))
        for hint in result["candidates"]:
            self.assertEqual("answer_key_hint", hint["kind"])
            self.assertEqual("hint_only", hint["verification_level"])
            self.assertTrue(hint["independent_evidence_required"])
            self.assertFalse(hint["usable_for_confirmation"])
            self.assertFalse(hint["requestable"])
            self.assertIsNone(hint["method"])
            self.assertTrue(hint["method_requires_binding"])
            self.assertNotIn("score", hint)
        first = result["candidates"][0]
        self.assertEqual({"keyword", "access_token"}, {item["name"] for item in first["inputs"]})
        self.assertEqual("unknown", first["inputs"][0]["consumer"])
        self.assertEqual(before, hashlib.sha256(source.read_bytes()).hexdigest())

    def test_validator_results_never_become_verdicts_or_exclusions(self):
        for status in ("hint", "valid", "type_error", "param_error", "unregistered"):
            with self.subTest(status=status):
                result = discover(self.document(self.normalized(result=status)), "assessment_hints", self.base)
                self.assertEqual([], result["operations"])
                candidate = result["candidates"][0]
                self.assertEqual(status, candidate["validator_result"])
                self.assertEqual("hint_only", candidate["verification_level"])
                self.assertFalse(candidate["usable_for_confirmation"])

    def test_rce_label_does_not_guess_a_single_injection_mechanism(self):
        native = {"version": "1", "maxScore": 200, "vulns": [["/promo", [["label", "POST"]], "RCE", 200]]}
        row = discover(self.document(native), "assessment_hints", self.base)["candidates"][0]
        self.assertEqual({"command_injection", "template_injection", "deserialization"}, set(row["suggested_test_families"]))
        self.assertIsNone(row["method"])

    def test_unknown_type_and_score_mismatch_stay_explicit_review(self):
        native = {"version": "1", "maxScore": 999, "vulns": [["/unknown", [], "custom fixture rule", 1]]}
        result = discover(self.document(native), "assessment_hints", self.base)
        self.assertEqual([], result["candidates"][0]["suggested_test_families"])
        codes = {row["code"] for row in result["limitations"]}
        self.assertIn("assessment_hint_family_requires_review", codes)
        self.assertIn("assessment_hint_score_mismatch", codes)
        self.assertNotIn("custom fixture rule", json.dumps(result))

    def test_invalid_entries_are_visible_without_importing_secrets_or_code(self):
        doc = self.normalized(method="RUN", instructions="execute SYNTHETIC_SECRET", score=6000)
        result = discover(self.document(doc), "assessment_hints", self.base)
        self.assertEqual([], result["candidates"])
        self.assertIn("invalid_assessment_hint", {row["code"] for row in result["limitations"]})
        self.assertNotIn("SYNTHETIC_SECRET", json.dumps(result))

    def test_document_shape_and_ambiguous_parameter_aliases_fail_closed(self):
        for doc in ([], {"schema_version": True, "source_kind": "validator_export", "entries": []},
                    {"schema_version": 1, "source_kind": [], "entries": []},
                    {"version": "1", "maxScore": True, "vulns": []},
                    {**self.native(), "entries": []}):
            with self.subTest(doc=doc), self.assertRaises(ValueError):
                discover(self.document(doc), "assessment_hints", self.base)
        result = discover(self.document(self.normalized(params=[["q", "GET"]])), "assessment_hints", self.base)
        self.assertEqual([], result["candidates"])

    def test_all_discovery_json_is_strict_before_hints_are_created(self):
        for raw in ('{"schema_version":1,"schema_version":1}', '{"schema_version":NaN}',
                    '{"schema_version":1,"entries":"\\ud800"}', '{"schema_version":1e999}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                discover(self.document(raw), "assessment_hints", self.base)

    def test_real_dispatch_is_offline_idempotent_and_cannot_confirm_from_the_key(self):
        engine.create_project(self.root, {"project_id": "hints", "target": self.base})
        source = self.document(self.native())
        args = {"project_id": "hints", "format": "assessment_hints", "path": str(source), "base_url": self.base}
        with patch.object(engine, "request", side_effect=AssertionError("hint import must not send requests")):
            first = dispatch(self.root, "surface.import", args)
            again = dispatch(self.root, "surface.import", args)
        self.assertEqual([], first["operation_ids"])
        self.assertEqual(3, first["candidates"])
        self.assertEqual(0, again["candidates"])
        with Project(self.root, "hints") as project:
            for kind in ("operation", "evidence", "decision", "finding", "run"):
                self.assertEqual([], project.list(kind))
            candidate = project.list("candidate")[0]
        with self.assertRaises(EngineError):
            dispatch(self.root, "finding.record", {"project_id": "hints", "title": "score-only claim",
                "category": "sql_injection", "impact": "unproven", "remediation": "review", "decision_id": candidate["id"]})
        status = dispatch(self.root, "plan.audit", {"project_id": "hints"})
        self.assertEqual(3, status["completion"]["unresolved_candidates"])
        self.assertFalse(status["continuation"]["can_claim_complete"])


if __name__ == "__main__":
    unittest.main()
