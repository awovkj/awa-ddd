"""Typed V2 N/A acceptance, deployment binding and expiry regressions."""
from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import v2_fixtures as fx
from awa_ddd import engine
from awa_ddd.domain.receipt import evaluate_receipt
from awa_ddd.domain.repository import Repository
from awa_ddd.planning import coverage
from awa_ddd.store import EngineError


class ApplicabilityTests(unittest.TestCase):
    def setUp(self):
        self.temporary, self.root = fx.workspace()
        self.addCleanup(self.temporary.cleanup)
        row = fx.project(self.root)
        self.operation = fx.register(
            row,
            "http://fixture.invalid/render",
            "GET",
            "public",
            [{
                "name": "label",
                "location": "query",
                "selector": "label",
                "schema_branch": "render:label",
                "consumer": "template_engine",
                "test_families": ["template_injection"],
            }],
        )
        row.close()
        self.campaign = fx.start(self.root)["campaign"]["id"]
        row = fx.project(self.root)
        repository = Repository(row)
        hypotheses = repository.list_campaign(
            "hypothesis", self.campaign, limit=None)[0]
        self.hypothesis = next(
            item for item in hypotheses
            if item.get("family") == "template_injection")
        universe = repository.get("universe", self.hypothesis["universe_id"])
        operation = next(
            item for item in universe["operations"]
            if item["operation_id"] == self.operation["id"])
        input_row = next(
            item for item in operation["inputs"]
            if item["input_key"] == self.hypothesis["input_key"])
        self.bindings = {
            "operation_id": operation["operation_id"],
            "operation_signature": operation["operation_signature"],
            "input_location": input_row["location"],
            "input_selector": input_row["selector"],
            "schema_branch": input_row["schema_branch"],
            "test_family": self.hypothesis["family"],
        }
        row.close()

    def _manifest(self, *, predicate=False, suffix="one"):
        path = self.root.parent / (
            self.root.name + "-applicability-" + suffix + ".json")
        path.write_text(json.dumps({
            "schema": "awa-applicability/v1",
            "bindings": self.bindings,
            "deployment_id": "build-1",
            "predicate": {"feature_enabled": predicate},
        }, separators=(",", ":")), encoding="utf-8")
        self.addCleanup(lambda: path.exists() and path.unlink())
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def _capture_build(self, *, build="build-1", digest=None, missing=False):
        response = {
            "deployment": {"build": build},
            "manifest_sha256": None if missing else digest,
            "predicate": {"feature_enabled": False},
        }
        row = fx.project(self.root)
        with patch(
                "awa_ddd.engine.request",
                side_effect=fx.Sequence([response])):
            evidence = engine.capture(row, {
                "operation_id": self.operation["id"],
                "url": self.operation["url"] + "?label=vendor-neutral",
                "idempotency_key": "applicability-build-" + build + str(
                    len(row.list("evidence"))),
            })
        verified, _artifact = engine.verify_current_evidence(row, evidence["id"])
        row.close()
        return verified

    def _proof(self, path, evidence, **changes):
        proof = {
            "type": "deployment_manifest",
            "path": str(path),
            "build_evidence_id": evidence["id"],
            "build_selector": "/deployment/build",
            "deployment_id": "build-1",
            "manifest_sha256_selector": "/manifest_sha256",
            "predicate_selector": "/predicate/feature_enabled",
            "reviewer": "reviewer-1",
            "reason": "The exact deployed manifest disables this input branch.",
        }
        proof.update(changes)
        return proof

    def _dispose(self, proof):
        return fx.dispatch(self.root, "review.disposition", {
            "project_id": "v2",
            "campaign_id": self.campaign,
            "hypothesis_id": self.hypothesis["id"],
            "status": "not_applicable",
            "reason": proof.get("reason"),
            "proof": proof,
        })

    def test_normal_response_and_arbitrary_predicate_are_not_exclusions(self):
        row = fx.project(self.root)
        with patch(
                "awa_ddd.engine.request",
                side_effect=fx.Sequence([{
                    "status": "ok",
                    "build": "build-1",
                    "feature_enabled": False,
                }])):
            evidence = engine.capture(row, {
                "operation_id": self.operation["id"],
                "url": self.operation["url"] + "?label=ordinary",
            })
        row.close()
        with self.assertRaises(EngineError):
            fx.dispatch(self.root, "review.disposition", {
                "project_id": "v2",
                "campaign_id": self.campaign,
                "hypothesis_id": self.hypothesis["id"],
                "status": "not_applicable",
                "predicate": {
                    "operator": "equals",
                    "subject": "response.feature_enabled",
                    "expected": False,
                },
                "verifier": {
                    "type": "normal_http",
                    "id": evidence["id"],
                    "version": "1",
                },
                "evidence_ids": [evidence["id"]],
            })
        row = fx.project(self.root)
        repository = Repository(row)
        hypothesis = repository.get("hypothesis", self.hypothesis["id"])
        self.assertNotEqual("not_applicable", hypothesis["status"])
        self.assertEqual([], repository.list_campaign(
            "applicability_receipt", self.campaign, limit=None)[0])
        row.close()

    def test_exact_sha_and_build_bound_manifest_creates_only_v2_receipt(self):
        path, digest = self._manifest()
        evidence = self._capture_build(digest=digest)
        result = self._dispose(self._proof(path, evidence))
        self.assertEqual("not_applicable", result["hypothesis"]["status"])
        row = fx.project(self.root)
        repository = Repository(row)
        receipt = repository.get(
            "applicability_receipt",
            result["hypothesis"]["applicability_receipt_id"])
        self.assertEqual("applicability", receipt["kind"])
        self.assertEqual(self.bindings, receipt["bindings"])
        self.assertEqual(digest, receipt["manifest_material"]["material_sha256"])
        evaluation = evaluate_receipt(row, receipt)
        self.assertTrue(evaluation["current"], json.dumps(evaluation))
        self.assertEqual(1, len(row.list("material")))
        self.assertEqual([], row.list("applicability_receipt"))
        row.close()

    def test_missing_manifest_digest_is_rejected_without_receipt(self):
        path, _digest = self._manifest()
        evidence = self._capture_build(missing=True)
        with self.assertRaises(EngineError) as caught:
            self._dispose(self._proof(path, evidence))
        self.assertEqual(
            "applicability_material", caught.exception.code)
        row = fx.project(self.root)
        self.assertEqual([], row.list("v2_applicability_receipt"))
        row.close()

    def test_new_deployment_observation_expires_accepted_receipt(self):
        path, digest = self._manifest()
        first = self._capture_build(digest=digest)
        accepted = self._dispose(self._proof(path, first))
        self._capture_build(build="build-2")
        row = fx.project(self.root)
        receipt = Repository(row).get(
            "applicability_receipt", accepted["applicability_receipt"]["id"])
        evaluation = evaluate_receipt(row, receipt)
        self.assertFalse(evaluation["current"])
        matrix = coverage.compute(row, self.campaign)
        reopened = next(
            item for item in matrix["consumer_matrix"]
            if item["input_key"] == self.hypothesis["input_key"])
        self.assertIsNotNone(reopened)
        self.assertGreaterEqual(
            matrix["receipt_summary"]["applicability_reopened"], 1)
        row.close()

    def test_manifest_byte_change_expires_accepted_receipt(self):
        path, digest = self._manifest()
        evidence = self._capture_build(digest=digest)
        accepted = self._dispose(self._proof(path, evidence))
        row = fx.project(self.root)
        receipt = Repository(row).get(
            "applicability_receipt", accepted["applicability_receipt"]["id"])
        material = row.get("material", receipt["manifest_material"]["material_id"])
        stored_path = row.base / material["artifact_path"]
        stored_path.write_bytes(b"{}")
        self.assertFalse(evaluate_receipt(row, receipt)["current"])
        row.close()


if __name__ == "__main__":
    unittest.main()
