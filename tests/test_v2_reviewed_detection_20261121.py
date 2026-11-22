"""Reviewed detection must be derived from request controls and readbacks."""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode

import v2_fixtures as fx
from awa_ddd import engine, publication
from awa_ddd.domain.hypothesis import transition
from awa_ddd.domain.repository import Repository
from awa_ddd.execution import review_engine
from awa_ddd.planning import coverage
from awa_ddd.store import EngineError


class ReviewedDetectionAcceptanceTests(unittest.TestCase):
    def _project(self):
        temporary, root = fx.workspace()
        self.addCleanup(temporary.cleanup)
        project = fx.project(root)
        operation = fx.register(
            project,
            "http://fixture.invalid/render",
            "GET",
            "public",
            [{
                "name": "expr",
                "location": "query",
                "selector": "expr",
                "consumer": "template_engine",
                "test_families": ["template_injection"],
            }],
        )
        project.close()
        started = fx.start(root)
        campaign_id = started["campaign"]["id"]
        project = fx.project(root)
        self.addCleanup(project.close)
        repository = Repository(project)
        campaign = repository.get("campaign", campaign_id)
        hypothesis = next(
            row for row in repository.list_campaign(
                "hypothesis", campaign_id, limit=None)[0]
            if row.get("family") == "template_injection")
        if hypothesis.get("status") != "running":
            transition(
                hypothesis, "running",
                reason="bound reviewed evidence run")
            repository.save("hypothesis", hypothesis)
        values = ("plain", "{{9*9}}", "negative")
        responses = (
            {"rendered": "plain"},
            {"rendered": 81},
            {"rendered": "negative"},
        )
        evidence = []
        with patch(
                "awa_ddd.engine.request",
                side_effect=fx.Sequence(list(responses))):
            for value in values:
                url = operation["url"] + "?" + urlencode({"expr": value})
                evidence.append(engine.capture(project, {
                    "operation_id": operation["id"],
                    "url": url,
                    "idempotency_key": "review-control-" + value,
                }))
        run = {
            "id": project.id("RUN2"),
            "campaign_id": campaign_id,
            "hypothesis_id": hypothesis["id"],
            "recipe_id": None,
            "status": "evaluated",
            "evidence_ids": [row["id"] for row in evidence],
            "mode": "test",
            "evaluation": {"outcome": "inconclusive"},
            "outcome": "inconclusive",
            "effect": {"kind": "read_only", "unknown": False},
        }
        repository.add("run", run, immutable=False)
        spec = {
            "schema": "awa-reviewed-detection/v1",
            "profile": "unexpected_expression_evaluation",
            "evidence_ids": run["evidence_ids"],
            "selector": "/rendered",
            "expression": "{{9*9}}",
            "reviewer": "review-agent",
            "reason": "The bounded arithmetic canary was evaluated by the server template engine.",
        }
        args = {
            "campaign_id": campaign_id,
            "hypothesis_id": hypothesis["id"],
            "run_id": run["id"],
            "evidence_ids": run["evidence_ids"],
            "reviewer": {
                "type": "agent_recorded",
                "id": "review-agent",
                "source": "fixture-review",
            },
            "reason": spec["reason"],
            "title": "Template expression evaluation",
        }
        return temporary, root, project, campaign, hypothesis, args, spec

    def test_missing_typed_spec_cannot_turn_successful_http_into_finding(self):
        _temporary, _root, project, _campaign, hypothesis, args, _spec = self._project()
        with self.assertRaises(EngineError) as caught:
            review_engine.accept(project, args)
        self.assertEqual("reviewed_proof", caught.exception.code)
        self.assertEqual([], project.list("v2_review"))
        self.assertEqual([], project.list("v2_review_proof_receipt"))
        self.assertEqual([], project.list("v2_finding"))
        current = Repository(project).get("hypothesis", hypothesis["id"])
        self.assertEqual("running", current["status"])
        project.close()

    def test_top_level_reviewed_proof_creates_receipts_only_after_validation(self):
        _temporary, _root, project, campaign, hypothesis, args, spec = self._project()
        result = review_engine.accept(project, {
            **args,
            "reviewed_proof": spec,
        })
        self.assertTrue(result["detection"])
        self.assertFalse(result["machine_proof"])
        self.assertFalse(result["reviewer_independent"])
        self.assertEqual(
            spec["reason"], result["review"]["reason"])
        self.assertEqual(
            "agent_recorded",
            result["review_proof_receipt"]["reviewer_assurance"])
        receipt = Repository(project).get(
            "proof_receipt", result["proof_receipt"]["id"])
        self.assertEqual(
            result["review_proof_receipt"]["id"],
            receipt["review_proof_receipt_id"])
        self.assertEqual(
            receipt["material"]["evidence_ids"],
            spec["evidence_ids"],
        )
        finding = Repository(project).get(
            "finding", result["finding"]["id"])
        self.assertEqual(
            result["review_proof_receipt"]["id"],
            finding["review_proof_receipt_id"])
        current = Repository(project).get("hypothesis", hypothesis["id"])
        self.assertEqual("supported", current["status"])
        matrix = coverage.compute(project, campaign["id"])
        self.assertEqual(1, matrix["finding_summary"]["reviewed"])
        project.close()

    def test_embedded_verification_spec_is_supported_and_human_claim_is_rejected(self):
        _temporary, _root, project, _campaign, _hypothesis, args, spec = self._project()
        with self.assertRaises(EngineError) as caught:
            review_engine.accept(project, {
                **args,
                "reviewer": {
                    "type": "human_independent",
                    "id": "review-agent",
                    "source": "self-declared",
                },
                "verification": {"spec": spec},
            })
        self.assertEqual("reviewed_reviewer", caught.exception.code)
        self.assertEqual([], project.list("v2_review"))
        project.close()

        _temporary2, _root2, project2, _campaign2, _hypothesis2, args2, spec2 = self._project()
        result = review_engine.accept(project2, {
            **args2,
            "verification": {"spec": spec2},
        })
        self.assertFalse(result["machine_proof"])
        project2.close()

    def test_evidence_byte_change_expires_reviewed_finding(self):
        _temporary, _root, project, campaign, _hypothesis, args, spec = self._project()
        result = review_engine.accept(project, {
            **args,
            "reviewed_proof": spec,
        })
        evidence = project.get("evidence", spec["evidence_ids"][1])
        Path(project.base, evidence["artifact_path"]).write_bytes(
            Path(project.base, evidence["artifact_path"]).read_bytes() + b" ")
        matrix = coverage.compute(project, campaign["id"])
        self.assertGreaterEqual(
            matrix["finding_summary"]["expired_or_invalid_total"], 1)
        from awa_ddd.domain.receipt import evaluate_receipt
        self.assertFalse(evaluate_receipt(
            project, result["proof_receipt"])["current"])
        project.close()

    def test_public_projection_binds_reviewed_receipt_without_machine_proof(self):
        _temporary, _root, project, _campaign, _hypothesis, args, spec = self._project()
        result = review_engine.accept(project, {
            **args,
            "reviewed_proof": spec,
        })
        receipt_id = result["review_proof_receipt"]["id"]
        review_receipt = result["review_proof_receipt"]
        proof = {
            key: review_receipt[key]
            for key in (
                "schema",
                "profile",
                "proof_scope",
                "not_proven",
                "reviewer_assurance",
                "machine_proof",
            )
        }
        context = publication.PublicationContext(project)
        self.assertRegex(receipt_id, r"^RPR-[a-f0-9]{64}$")
        self.assertTrue(context.bound_handle(
            "review_proof_receipt", receipt_id))
        self.assertFalse(context.bound_handle(
            "review_proof_receipt", "RPR-" + "a" * 32))

        decision_id = project.id("D")
        finding_id = project.id("F")
        decision = {
            "id": decision_id,
            "outcome": "confirmed",
            "mode": "analyst",
            "evidence_ids": spec["evidence_ids"],
            "oracle": {"type": "reviewed_detection"},
            "proof": proof,
            "review_proof_receipt_id": receipt_id,
            "reviewer_assurance": "agent_recorded",
        }
        project.put("decision", decision)
        finding = {
            "id": finding_id,
            "title": "Template expression evaluation",
            "category": "template_injection",
            "impact": "A bounded arithmetic expression was evaluated.",
            "remediation": "Treat template source as data.",
            "limitations": list(result["finding"].get("limitations") or []),
            "severity": "high",
            "decision_id": decision_id,
            "evidence_ids": spec["evidence_ids"],
            "mode": "analyst",
            "origin": "independent",
            "status": "confirmed",
            "confirmed_scope": "unexpected_expression_evaluation",
            "review_proof_receipt_id": receipt_id,
            "reviewer_assurance": "agent_recorded",
            "proof": proof,
        }
        project.put("finding", finding)
        public = publication.publish(project, "finding.record", finding)
        self.assertEqual(receipt_id, public["review_proof_receipt_id"])
        self.assertEqual(
            "agent_recorded", public["reviewer_assurance"])
        self.assertEqual(
            "unexpected_expression_evaluation",
            public["confirmed_scope"])
        self.assertIs(False, public["proof"]["machine_proof"])
        public_decision = publication.publish(
            project, "assessment.evaluate", decision)
        self.assertEqual(
            receipt_id, public_decision["review_proof_receipt_id"])
        self.assertEqual(
            "reviewed_detection", public_decision["oracle"]["type"])
        project.close()

    def _add_collision_sessions(self, project, references):
        actor = engine.add_actor(
            project,
            {"subject": "fixture-secret-collision"},
        )
        for value in references:
            engine.add_session(project, {
                "actor_id": actor["id"],
                "headers": {"Authorization": "Bearer " + value},
            })

    def test_structured_ids_survive_credential_byte_collisions(self):
        _temporary, _root, project, campaign, hypothesis, args, spec = self._project()
        result = review_engine.accept(project, {
            **args,
            "reviewed_proof": spec,
        })
        recipe = {
            "id": project.id("REC"),
            "campaign_id": campaign["id"],
            "universe_id": hypothesis["universe_id"],
            "hypothesis_id": hypothesis["id"],
            "family": hypothesis["family"],
            "revision": 1,
            "spec_hash": "0" * 64,
        }
        project.put("v2_recipe", recipe, create_only=True)
        references = (
            campaign["id"],
            hypothesis["id"],
            recipe["id"],
            result["proof_receipt"]["run_id"],
            result["proof_receipt"]["review_id"],
            result["proof_receipt"]["id"],
            result["review_proof_receipt"]["id"],
            result["finding"]["id"],
            result["proof_receipt"]["receipt_hash"],
            "accepted",
            hypothesis["family"],
            result["review_proof_receipt"]["bindings"]["operation_signature"],
        )
        self._add_collision_sessions(project, references)

        public = publication.publish(project, "review.finding", result)
        self.assertEqual(
            hypothesis["id"], public["review"]["hypothesis_id"])
        self.assertEqual(
            campaign["id"], public["proof_receipt"]["campaign_id"])
        self.assertEqual(
            result["proof_receipt"]["run_id"],
            public["proof_receipt"]["run_id"],
        )
        self.assertEqual(
            result["proof_receipt"]["review_id"],
            public["proof_receipt"]["review_id"],
        )
        self.assertEqual(
            result["proof_receipt"]["receipt_hash"],
            public["proof_receipt"]["receipt_hash"],
        )
        self.assertEqual("accepted", public["proof_receipt"]["decision"])
        self.assertEqual(
            hypothesis["family"],
            public["review_proof_receipt"]["bindings"]["test_family"],
        )
        self.assertEqual(
            result["review_proof_receipt"]["bindings"]["operation_signature"],
            public["review_proof_receipt"]["bindings"]["operation_signature"],
        )
        self.assertEqual(
            result["finding"]["id"],
            public["finding"]["id"],
        )
        self.assertEqual(
            result["proof_receipt"]["id"],
            public["finding"]["proof_receipt_id"],
        )
        self.assertEqual(
            result["review_proof_receipt"]["id"],
            public["finding"]["review_proof_receipt_id"],
        )

        run = Repository(project).get(
            "run",
            result["proof_receipt"]["run_id"],
        )
        inspected = publication.publish(project, "test.inspect", {
            "private_capsule_available": False,
            "control_count": 0,
            "recipe": recipe,
            "run": run,
        })
        for section, values in (
            ("recipe", (
                recipe["id"],
                recipe["campaign_id"],
                recipe["universe_id"],
                recipe["hypothesis_id"],
            )),
            ("run", (
                run["id"],
                run["campaign_id"],
                run["hypothesis_id"],
            )),
        ):
            for key, expected in zip(
                    ("id", "campaign_id", "universe_id", "hypothesis_id")
                    if section == "recipe"
                    else ("id", "campaign_id", "hypothesis_id"),
                    values):
                self.assertEqual(expected, inspected[section][key])
        project.close()

    def test_unavailable_context_keeps_references_but_not_prose(self):
        _temporary, _root, project, _campaign, _hypothesis, args, spec = self._project()
        result = review_engine.accept(project, {
            **args,
            "reviewed_proof": spec,
        })
        result["finding"]["title"] = "private prose title"
        references = (
            result["proof_receipt"]["campaign_id"],
            result["proof_receipt"]["hypothesis_id"],
            result["proof_receipt"]["run_id"],
            result["proof_receipt"]["review_id"],
            result["proof_receipt"]["id"],
            result["review_proof_receipt"]["id"],
        )
        self._add_collision_sessions(project, references)
        with patch(
                "awa_ddd.browser.learn_redaction_context",
                return_value={
                    "page_visit_ids": ["PV-unavailable"],
                    "run_ids": [],
                }):
            public = publication.publish(
                project, "review.finding", result)

        self.assertEqual(
            "unavailable", public["redaction_context_status"])
        self.assertEqual(
            references[2], public["proof_receipt"]["run_id"])
        self.assertEqual(
            references[4], public["finding"]["proof_receipt_id"])
        self.assertEqual(
            references[5],
            public["finding"]["review_proof_receipt_id"],
        )
        self.assertEqual(
            result["proof_receipt"]["receipt_hash"],
            public["proof_receipt"]["receipt_hash"],
        )
        self.assertEqual("accepted", public["proof_receipt"]["decision"])
        self.assertEqual(
            "[content omitted: project redaction context unavailable]",
            public["finding"]["title"],
        )
        project.close()

    def test_union_objects_and_literal_zero_restore_without_text_fallback(self):
        _temporary, _root, project, _campaign, _hypothesis, _args, _spec = self._project()
        secret = "union-prose-secret"
        actor = engine.add_actor(
            project, {"subject": "fixture-union-secret"})
        engine.add_session(project, {
            "actor_id": actor["id"],
            "headers": {"Authorization": "Bearer " + secret},
        })
        union = publication.publish(project, "tool.inspect", {
            "private_capsule_available": False,
            "control_count": 0,
            "selected_tool": {
                "name": "http_request",
                "description": secret,
                "inputSchema": {
                    "type": "object",
                    "default": secret,
                    "nested": {"value": secret, "count": 2},
                },
                "annotations": {"note": secret, "count": 2},
                "unknown_field": secret,
            },
        })
        selected = union["selected_tool"]
        self.assertNotIn("unknown_field", selected)
        self.assertNotIn(secret, json.dumps(selected))
        self.assertNotEqual(secret, selected["description"])
        self.assertEqual(2, selected["inputSchema"]["nested"]["count"])
        self.assertEqual(2, selected["annotations"]["count"])

        snapshot = publication.publish(project, "recon.snapshot", {
            "imported": {
                "kind": "routes",
                "added": 2,
                "route_total": 3,
                "unresolved_total": 1,
                "catch_all_total": 0,
                "limitations": [secret],
                "requests_sent": 0,
                "unknown_field": secret,
            },
            "requests_sent": 0,
            "notice": secret,
        })
        self.assertEqual("routes", snapshot["imported"]["kind"])
        self.assertEqual(0, snapshot["imported"]["requests_sent"])
        self.assertEqual(2, snapshot["imported"]["added"])
        self.assertNotIn("unknown_field", snapshot["imported"])
        self.assertNotIn(secret, json.dumps(snapshot))

        with patch(
                "awa_ddd.browser.learn_redaction_context",
                return_value={
                    "page_visit_ids": ["PV-unavailable"],
                    "run_ids": [],
                }):
            unavailable = publication.publish(
                project, "recon.snapshot", {
                    "imported": {
                        "kind": "routes",
                        "added": 2,
                        "route_total": 3,
                        "unresolved_total": 1,
                        "catch_all_total": 0,
                        "limitations": [secret],
                        "requests_sent": 0,
                        "unknown_field": secret,
                    },
                    "requests_sent": 0,
                    "notice": secret,
                })
            unavailable_tool = publication.publish(
                project, "tool.inspect", {
                    "selected_tool": {
                        "name": "http_request",
                        "description": secret,
                        "inputSchema": {"default": secret},
                        "annotations": {"note": secret},
                        "unknown_field": secret,
                    },
                })
        self.assertEqual(2, unavailable["imported"]["added"])
        self.assertEqual(3, unavailable["imported"]["route_total"])
        self.assertEqual(1, unavailable["imported"]["unresolved_total"])
        self.assertEqual(0, unavailable["imported"]["requests_sent"])
        self.assertNotIn("unknown_field", unavailable["imported"])
        self.assertNotIn(secret, json.dumps(unavailable))
        self.assertNotIn(
            "unknown_field", unavailable_tool["selected_tool"])
        self.assertEqual(
            {}, unavailable_tool["selected_tool"]["inputSchema"])
        self.assertNotIn(secret, json.dumps(unavailable_tool))

        engine.add_session(project, {
            "actor_id": engine.add_actor(
                project, {"subject": "fixture-zero-secret"})["id"],
            "headers": {"X-Offline-Count": "0"},
            "credential_header_names": ["X-Offline-Count"],
        })
        context = publication.PublicationContext(project)
        context.unavailable = {
            "page_visit_ids": ["PV-unavailable"],
            "run_ids": [],
        }
        zero_schema = publication._Closed({
            "requests_sent": publication._Rule("0"),
            "requests_replayed": publication._Rule("0"),
        })
        public_zero = context.metadata({
            "requests_sent": 0,
            "requests_replayed": 0,
        }, schema=zero_schema)
        self.assertEqual(0, public_zero["requests_sent"])
        self.assertEqual(0, public_zero["requests_replayed"])
        self.assertFalse(context._typed(False, publication._Rule("0")))
        self.assertFalse(context._typed(1, publication._Rule("0")))
        self.assertFalse(context._typed("0", publication._Rule("0")))
        self.assertFalse(context._typed(None, publication._Rule("0")))
        project.close()

    def test_forged_and_unknown_ledger_handles_are_never_control_data(self):
        _temporary, _root, project, _campaign, _hypothesis, _args, _spec = self._project()
        context = publication.PublicationContext(project)
        forged = (
            ("run", "RUN2-" + "a" * 24),
            ("proof_receipt", "PRC-" + "a" * 24),
            ("review_proof_receipt", "RPR-" + "a" * 32),
            ("review_proof_receipt", "RPR-" + "a" * 64),
            ("frontier_receipt", "FRC-" + "a" * 32),
            ("frontier_receipt", "FRC-" + "a" * 64),
            ("completion_acceptance", "CA-" + "a" * 32),
            ("completion_acceptance", "CA-" + "a" * 64),
        )
        for kind, value in forged:
            self.assertFalse(context.bound_handle(kind, value))
        project.close()


if __name__ == "__main__":
    unittest.main()
