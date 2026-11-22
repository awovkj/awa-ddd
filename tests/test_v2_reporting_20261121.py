"""V2 reporting shares completion authority and never crosses campaign scope."""
from __future__ import annotations

import json
import importlib
from pathlib import Path
import unittest
from unittest.mock import patch

import v2_fixtures as fx
from awa_ddd.completion import CompletionEvaluator
from awa_ddd.domain.campaign import delivery_acceptance
from awa_ddd.domain.repository import Repository
from awa_ddd.store import EngineError

reporting_matrix = importlib.import_module("awa_ddd.reporting.matrix")


class V2ReportingTests(unittest.TestCase):
    def setUp(self):
        self.temporary, self.root = fx.workspace()
        self.addCleanup(self.temporary.cleanup)
        project = fx.project(self.root)
        fx.register(
            project,
            "http://fixture.invalid/render",
            "GET",
            "public",
            [{
                "name": "label",
                "location": "query",
                "selector": "label",
                "consumer": "template_engine",
                "test_families": ["template_injection"],
            }],
        )
        project.close()
        self.campaign_id = fx.start(self.root)["campaign"]["id"]

    def _artifact_text(self, handle, limit):
        chunks = []
        offset = 0
        while True:
            page = fx.dispatch(self.root, "report.artifact", {
                "project_id": "v2",
                "handle": handle,
                "offset": offset,
                "limit": limit,
            })
            self.assertEqual(offset, page["offset"])
            self.assertEqual(limit, page["limit"])
            self.assertEqual(
                page["next_offset"],
                None if page["complete"]
                else offset + len(page["content"]),
            )
            chunks.append(page["content"])
            if page["complete"]:
                return "".join(chunks), page
            self.assertIsNotNone(page["next_offset"])
            self.assertGreater(page["next_offset"], offset)
            offset = page["next_offset"]

    def _foreign_finding(self):
        project = fx.project(self.root)
        Repository(project).add(
            "finding",
            {
                "id": "FOREIGN-FINDING",
                "campaign_id": "CAM-FOREIGN",
                "hypothesis_id": "H-FOREIGN",
                "proof_receipt_id": "PRC-FOREIGN",
                "status": "confirmed",
                "current": True,
                "title": "foreign token=SHOULD-NEVER-APPEAR",
                "mode": "machine",
                "severity": "critical",
                "evidence_ids": ["E-FOREIGN"],
            },
            immutable=False,
        )
        project.close()

    def _final_delivery_fixture(self, *, acceptance_campaign=None):
        campaign_id = self.campaign_id
        checkpoint_id = "CP2-CURRENT"
        frontier_ids = ["FRC-" + "a" * 64, "FRC-" + "b" * 64]
        decision = CompletionEvaluator.evaluate(
            model="v2",
            subject_id=campaign_id,
            has_scope=True,
            coverage_complete=True,
            counts={
                "ready": 0,
                "review": 0,
                "blocked": 0,
                "unresolved": 0,
                "effect_unknown": 0,
            },
            frontier_current=True,
            source_complete=True,
            checkpoint_current=True,
            finalized=True,
            next_action="report.build",
        )
        campaign = {
            "id": campaign_id,
            "state": "completed",
            "delivery": {
                "reason": "completed",
                "exhausted_authority": True,
                "checkpoint_id": checkpoint_id,
                "completion_decision_id": decision["id"],
            },
        }
        acceptance_campaign = (
            acceptance_campaign
            or {
                "id": campaign_id,
                "state": "active",
                "delivery": None,
            }
        )
        acceptance = delivery_acceptance(
            acceptance_campaign,
            reason="completed",
            explanation="The current synthetic campaign facts are complete.",
            checkpoint_id=checkpoint_id,
            completion_decision=decision,
            remaining=[],
        )
        campaign["delivery"]["acceptance_id"] = acceptance["id"]
        continuation = {
            "completion_decision": decision,
            "checkpoint_id": checkpoint_id,
            "frontier_receipt_ids": frontier_ids,
            "frontier_review_required": False,
            "frontier_rounds": 2,
        }
        checkpoints = [{
            "id": checkpoint_id,
            "campaign_id": campaign_id,
            "frontier_receipt_ids": frontier_ids,
        }]
        frontiers = [
            (
                {
                    "id": frontier_ids[index],
                    "campaign_id": campaign_id,
                    "material": {"round_sha256": marker * 64},
                },
                {"current": True},
            )
            for index, marker in enumerate(("c", "d"))
        ]
        return campaign, continuation, acceptance, checkpoints, frontiers

    def _require_final_fixture(
            self, campaign, continuation, acceptance, checkpoints, frontiers):
        class FixtureRepository:
            def __init__(self, _project):
                pass

            def get(self, kind, identity, required=False):
                if kind == "completion_acceptance" \
                        and acceptance is not None \
                        and identity == acceptance.get("id"):
                    return acceptance
                if required:
                    raise EngineError("not_found", "Unknown fixture record")
                return None

            def list_campaign(self, kind, campaign_id, limit=None):
                if kind == "checkpoint":
                    return checkpoints, len(checkpoints)
                if kind == "completion_acceptance":
                    return (
                        [acceptance] if acceptance is not None else []
                    ), int(acceptance is not None)
                return [], 0

        project = fx.project(self.root)
        try:
            with patch.object(
                    reporting_matrix, "Repository", FixtureRepository), \
                    patch.object(
                        reporting_matrix,
                        "current_receipts",
                        return_value=frontiers,
                    ):
                return reporting_matrix._require_completed_campaign_delivery(
                    project, campaign, continuation)
        finally:
            project.close()

    def test_matrix_uses_one_completion_authority_and_campaign_scope(self):
        self._foreign_finding()
        result = fx.dispatch(self.root, "report.matrix", {
            "project_id": "v2",
            "campaign_id": self.campaign_id,
        })
        self.assertEqual(
            result["completion_decision"],
            result["continuation"]["completion_decision"],
        )
        self.assertEqual("awa-completion/v1", result["completion_decision"]["schema"])
        self.assertEqual([], result["findings"])
        self.assertEqual(0, result["finding_summary"]["current_total"])

    def test_draft_report_is_redacted_and_staged_as_one_immutable_batch(self):
        self._foreign_finding()
        output = self.root / "projects" / "v2" / "reports"
        result = fx.dispatch(self.root, "report.build", {
            "project_id": "v2",
            "campaign_id": self.campaign_id,
            "stage": "draft",
            "output_dir": str(output),
        })
        self.assertEqual("draft", result["stage"])
        self.assertTrue(result["report"].startswith("artifact://reports/"))
        self.assertNotIn(str(self.root), json.dumps(result))
        report, report_page = self._artifact_text(result["report"], 4000)
        matrix_text, _ = self._artifact_text(result["matrix"], 8000)
        manifest_text, _ = self._artifact_text(result["manifest"], 8000)
        manifest = json.loads(manifest_text)
        self.assertNotIn("SHOULD-NEVER-APPEAR", report)
        self.assertNotIn("SHOULD-NEVER-APPEAR", matrix_text)
        self.assertEqual(result["checkpoint_id"], manifest["checkpoint_id"])
        self.assertEqual(
            result["completion_decision"]["id"],
            manifest["completion_decision"]["id"],
        )
        self.assertEqual(2, len(manifest["files"]))
        self.assertEqual(result["report_sha256"], report_page["sha256"])
        self.assertTrue(report_page["complete"])
        self.assertIsNone(report_page["next_offset"])

    def test_publication_failure_leaves_no_partial_batch(self):
        project = fx.project(self.root)
        output = self.root / "failed-reports"
        try:
            with patch(
                    "awa_ddd.reporting_legacy._publish_report",
                    side_effect=RuntimeError("forced publish failure"),
            ):
                with self.assertRaisesRegex(
                        RuntimeError, "forced publish failure"):
                    reporting_matrix.build_v2_report(
                        project,
                        output,
                        stage="draft",
                        campaign_id=self.campaign_id,
                    )
        finally:
            project.close()
        self.assertTrue(output.is_dir())
        self.assertEqual([], list(output.iterdir()))

    def test_final_report_rejects_state_without_shared_current_decision(self):
        project = fx.project(self.root)
        repository = Repository(project)
        campaign = repository.get("campaign", self.campaign_id)
        campaign["state"] = "completed"
        campaign["delivery"] = {
            "reason": "completed",
            "exhausted_authority": True,
            "checkpoint_id": "CP2-NOT-CURRENT",
            "completion_decision_id": "CD-NOT-CURRENT",
        }
        repository.save("campaign", campaign)
        project.close()
        with self.assertRaises(EngineError) as caught:
            fx.dispatch(self.root, "report.build", {
                "project_id": "v2",
                "campaign_id": self.campaign_id,
                "stage": "final",
            })
        self.assertEqual("v2_report_final", caught.exception.code)

    def test_cda_is_content_addressed_and_rejects_missing_tampered_or_foreign(self):
        campaign, continuation, acceptance, checkpoints, frontiers = (
            self._final_delivery_fixture()
        )
        self.assertEqual(
            acceptance,
            self._require_final_fixture(
                campaign, continuation, acceptance, checkpoints, frontiers),
        )

        missing_campaign = {
            **campaign,
            "delivery": {
                **campaign["delivery"],
                "acceptance_id": None,
            },
        }
        tampered = {
            **acceptance,
            "completion_decision": {
                **acceptance["completion_decision"],
                "finalized": False,
            },
        }
        foreign_campaign = {
            "id": "CAM-FOREIGN-CDA",
            "state": "active",
            "delivery": None,
        }
        _, _, foreign, _, _ = self._final_delivery_fixture(
            acceptance_campaign=foreign_campaign)
        foreign_campaign_state = {
            **campaign,
            "delivery": {
                **campaign["delivery"],
                "acceptance_id": foreign["id"],
            },
        }
        cases = (
            ("missing", missing_campaign, None),
            ("tampered", campaign, tampered),
            ("foreign", foreign_campaign_state, foreign),
        )
        for name, selected_campaign, selected_acceptance in cases:
            with self.subTest(name=name):
                with self.assertRaises(EngineError) as caught:
                    self._require_final_fixture(
                        selected_campaign,
                        continuation,
                        selected_acceptance,
                        checkpoints,
                        frontiers,
                    )
                self.assertEqual("v2_report_final", caught.exception.code)


if __name__ == "__main__":
    unittest.main()
