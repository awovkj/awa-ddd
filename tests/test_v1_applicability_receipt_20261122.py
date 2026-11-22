"""V1 evidence-backed N/A receipts terminate only on exact, current material."""
from __future__ import annotations

import hashlib
import json
import unittest

import test_continuation_20261030 as fixtures
from awa_ddd import applicability, completeness, engine
from awa_ddd.store import EngineError, canonical


class V1ApplicabilityReceiptTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ContinuationTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.project = self.fixture.project
        self.sql_operation = self.fixture.register("/sql", inputs=[{
            "name": "q",
            "location": "query",
            "consumer": "sql_query",
            "test_families": ["sql_injection"],
        }])
        self.item = next(
            row for row in self.project.list("obligation")
            if not row.get("superseded")
            and row.get("operation_id") == self.sql_operation["id"]
            and row.get("kind") == "input_test"
            and row.get("test_family") == "sql_injection")

    def material(self):
        bindings = applicability.binding(self.project, self.item)
        deployment = "fixture-build-20261122"
        manifest = {
            "schema": applicability.SCHEMA,
            "deployment_id": deployment,
            "bindings": bindings,
            "sql_query_execution_enabled": False,
        }
        raw = json.dumps(
            manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        path = self.fixture.root / "deployment-manifest.json"
        path.write_bytes(raw)
        evidence = self.fixture.capture(operation=self.sql_operation, response={
            "deployment_id": deployment,
            "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        })
        proof = {
            "type": "deployment_manifest",
            "path": str(path),
            "build_evidence_id": evidence["id"],
            "build_selector": "/deployment_id",
            "deployment_id": deployment,
            "manifest_sha256_selector": "/manifest_sha256",
            "predicate_selector": "/sql_query_execution_enabled",
            "reviewer": "fixture-reviewer",
            "reason": "The exact deployed build disables this SQL execution path.",
        }
        return evidence, path, proof

    def exclude(self, evidence, proof):
        return engine.disposition(self.project, {
            "obligation_id": self.item["id"],
            "status": "not_applicable",
            "basis": "business_fact",
            "evidence_ids": [evidence["id"]],
            "applicability_proof": proof,
            "reason": "The deployed manifest makes this exact mechanism inapplicable.",
        })

    def frontier(self, evidence=None):
        review = self.fixture.frontier(evidence)
        planned = {
            row["test_family"] for row in self.project.list("obligation")
            if not row.get("superseded")
            and row.get("kind") in {"input_test", "access", "ownership"}
        }
        for row in review["categories"]:
            if row["test_family"] in planned:
                row["status"] = "planned"
        return review

    def test_current_receipt_closes_na_review_without_counting_as_tested(self):
        evidence, _, proof = self.material()
        item = self.exclude(evidence, proof)
        receipt = self.project.get(
            "applicability_receipt", item["applicability_receipt_id"])

        self.assertRegex(receipt["id"], r"^AR-[0-9a-f]{64}$")
        self.assertEqual("AR-" + hashlib.sha256(canonical({
            key: value for key, value in receipt.items()
            if key not in {"id", "created_at"}
        }).encode("utf-8")).hexdigest(), receipt["id"])
        self.assertEqual(self.item["id"], receipt["subject_id"])
        self.assertIs(False, receipt["machine_proof"])
        self.assertIs(False, receipt["counts_as_tested"])
        audit = completeness.audit(self.project, {"limit": 100})
        self.assertEqual(0, audit["continuation"]["applicability_review_total"])
        self.assertFalse(any(
            row.get("kind") == "unverified_applicability"
            and row.get("obligation_id") == self.item["id"]
            for row in audit["checklist"]))
        self.assertEqual(0, audit["security_coverage"]["evaluated"])

    def test_manifest_byte_change_reopens_the_original_obligation(self):
        evidence, path, proof = self.material()
        item = self.exclude(evidence, proof)
        receipt = self.project.get(
            "applicability_receipt", item["applicability_receipt_id"])
        material = self.project.get("material", receipt["material_id"])
        stored = self.project.base / material["artifact_path"]
        stored.write_bytes(stored.read_bytes() + b" ")

        audit = completeness.audit(self.project, {"limit": 100})
        self.assertEqual(0, audit["continuation"]["applicability_review_total"])
        row = next(
            row for row in audit["checklist"]
            if row.get("kind") == "obligation"
            and row.get("obligation_id") == self.item["id"])
        self.assertEqual("exclusion_evidence_invalid", row["reason_code"])

    def test_arbitrary_true_or_missing_predicate_cannot_create_receipt(self):
        evidence, path, proof = self.material()
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["sql_query_execution_enabled"] = True
        path.write_text(json.dumps(manifest), encoding="utf-8")
        evidence = self.fixture.capture(operation=self.sql_operation, response={
            "deployment_id": proof["deployment_id"],
            "manifest_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        })
        proof["build_evidence_id"] = evidence["id"]
        before = self.project.list("applicability_receipt")
        with self.assertRaises(EngineError) as caught:
            self.exclude(evidence, proof)
        self.assertEqual("applicability_predicate", caught.exception.code)
        self.assertEqual(before, self.project.list("applicability_receipt"))

    def test_na_typed_tests_and_two_current_frontiers_finalize_together(self):
        material_evidence, _, proof = self.material()
        excluded = self.exclude(material_evidence, proof)
        sql_baseline = next(
            row for row in self.project.list("obligation")
            if not row.get("superseded")
            and row.get("operation_id") == self.sql_operation["id"]
            and row.get("kind") == "baseline")
        fixtures.evaluate(self.project, {
            "obligation_id": sql_baseline["id"],
            "evidence_ids": [material_evidence["id"]],
            "oracle": {
                "type": "baseline",
                "selector": "/deployment_id",
                "expected": proof["deployment_id"],
            },
        })
        self.fixture.close_generic()
        self.fixture.operation = self.fixture.register(
            "/typed",
            inputs=[{
                "name": "q",
                "location": "query",
                "consumer": "business_input",
                "test_families": ["generic"],
            }],
        )
        self.fixture.close_generic()

        first = self.fixture.checkpoint(self.frontier())
        second = self.fixture.checkpoint(
            self.frontier(self.fixture.variant_evidence))
        self.assertNotEqual(
            first["frontier_receipt_id"], second["frontier_receipt_id"])
        self.assertEqual(2, second["continuation"]["frontier_rounds"])
        self.assertTrue(
            second["continuation"]["can_finalize"],
            json.dumps(second["continuation"], indent=2, sort_keys=True),
        )

        audit = completeness.audit(self.project, {"limit": 100})
        self.assertEqual(0, audit["continuation"]["applicability_review_total"])
        self.assertGreaterEqual(
            audit["security_coverage"]["evaluated"], 1)
        receipt = self.project.get(
            "applicability_receipt", excluded["applicability_receipt_id"])
        self.assertIs(False, receipt["counts_as_tested"])
        self.assertIs(False, receipt["machine_proof"])

        finalized = self.fixture.finish(second)
        self.assertFalse(finalized["continuation"]["continue_required"])
        self.assertTrue(finalized["continuation"]["can_claim_complete"])
        self.assertEqual("engine_gate", finalized["finalization"]["reason_basis"])


if __name__ == "__main__":
    unittest.main()
