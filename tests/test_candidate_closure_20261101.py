"""Offline, source-bound discovery closure; declarations never erase real work."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import unittest
from unittest.mock import patch

import test_continuation_20261030 as fixtures
from awa_ddd import candidates, completeness, discovery, engine
from awa_ddd.__main__ import dispatch
from awa_ddd.reporting import build_report, public_integrity_metadata, safe_metadata
from awa_ddd.store import EngineError, Project, canonical, now


class CandidateClosureTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ContinuationTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.project = self.fixture.project
        self.index = 0

    def candidate(self, **changes):
        self.index += 1
        row = {"kind": "operation_hint", "url": self.fixture.operation["url"], "method": "GET",
               "protocol": "http", "inputs": deepcopy(self.fixture.operation["inputs"]),
               "source": {"path": "local-fixture.js", "sha256": "a" * 64,
                          "locator": "line:" + str(self.index)}}
        row.update(changes)
        identity, _ = candidates.store_candidate(self.project, row)
        return self.project.get("candidate", identity)

    def dismiss(self, candidate, **changes):
        return dispatch(self.fixture.root, "candidate.dismiss", {"project_id": "continuation",
                        "candidate_id": candidate["id"], "reason": "Reviewed this local fixture source.", **changes})

    def audit(self):
        with patch.object(engine, "request") as network:
            result = completeness.audit(self.project, {"limit": 100})
        network.assert_not_called()
        self.assertEqual(0, result["requests_sent"])
        return result

    def state(self):
        return {table: [tuple(row) for row in self.project.connection.execute("SELECT * FROM " + table + " ORDER BY 1,2")]
                for table in ("entities", "events", "metadata")}

    def rejection(self, candidate, **args):
        before = self.state()
        with patch.object(engine, "request") as network, self.assertRaises(EngineError) as caught:
            self.dismiss(candidate, **args)
        network.assert_not_called()
        self.assertEqual("candidate_closure", caught.exception.code)
        self.assertEqual(before, self.state())

    def completed(self):
        self.fixture.checkpoint(self.fixture.frontier())
        return self.fixture.finish(self.fixture.checkpoint(self.fixture.frontier()))

    def outside_source(self):
        source = self.fixture.root / "outside-scope.openapi.json"
        source.write_text(json.dumps({"openapi": "3.0.3", "info": {"title": "Owned offline source", "version": "1"},
                          "servers": [{"url": "https://outside-fixture.invalid"}],
                          "paths": {"/one": {"get": {"responses": {"200": {"description": "ok"}}}},
                                    "/two": {"get": {"responses": {"200": {"description": "ok"}}}}}}), encoding="utf-8")
        return source, {"project_id": "continuation", "path": str(source), "format": "openapi"}

    def test_reason_only_real_dynamic_import_remains_review_and_rejects_completion(self):
        self.fixture.close_generic()
        source = self.fixture.root / "dynamic-request.js"
        source.write_text("const url = '/api/items/' + id; fetch(url);\n", encoding="utf-8")
        with patch.object(engine, "request") as network:
            result = dispatch(self.fixture.root, "surface.import", {"project_id": "continuation",
                              "path": str(source), "format": "javascript"})
        network.assert_not_called()
        self.assertEqual([], result["operation_ids"])
        self.assertEqual(1, result["candidates"])
        candidate = self.project.list("candidate")[0]
        evidence_before = self.project.list("evidence")
        self.dismiss(candidate)
        dismissed = self.project.get("candidate", candidate["id"])
        audit = self.audit()
        self.assertEqual("dismissed", dismissed["status"])
        self.assertEqual(1, audit["completion"]["unresolved_candidates"])
        self.assertEqual(1, audit["continuation"]["review_total"])
        row = next(item for item in audit["checklist"] if item.get("candidate_id") == candidate["id"])
        self.assertEqual("open", row["status"])
        self.assertEqual("candidate.reopen", row["suggested_action"])
        self.assertEqual("candidate_dismissal_unverified", row["reason_code"])
        self.assertFalse(row["administrative_review_allowed"])
        self.fixture.checkpoint(self.fixture.frontier())
        checkpoint = self.fixture.checkpoint(self.fixture.frontier())
        with self.assertRaises(EngineError) as caught:
            self.fixture.finish(checkpoint)
        self.assertEqual("continue_required", caught.exception.code)
        self.assertEqual([], self.project.list("finalization"))
        self.assertEqual(evidence_before, self.project.list("evidence"))
        self.assertEqual(dismissed, self.project.get("candidate", candidate["id"]))
        for status in ("reviewed", "blocked"):
            with self.subTest(status=status), self.assertRaises(EngineError) as caught:
                self.fixture.review(row, status=status)
            self.assertEqual("closure_review", caught.exception.code)
        reopened = dispatch(self.fixture.root, "candidate.reopen", {"project_id": "continuation", **row["input_template"]})
        self.assertEqual("unverified", reopened["status"])
        self.assertEqual(1, self.audit()["completion"]["unresolved_candidates"])

    def test_current_exact_source_duplicate_with_typed_security_coverage_can_close(self):
        self.fixture.close_generic()
        candidate = self.candidate()
        before = self.project.list("evidence"), self.project.list("decision")
        public = self.dismiss(candidate, basis="duplicate_operation", operation_id=self.fixture.operation["id"])
        self.assertEqual("duplicate_operation", public["candidate_closure"]["basis"])
        self.assertNotIn("candidate_closure_context", public)
        stored = self.project.get("candidate", candidate["id"])
        self.assertIn("candidate_closure_context", stored)
        self.assertTrue(candidates.dismissal_valid(self.project, stored, engine.evaluate_coverage(self.project)))
        self.assertEqual(0, self.audit()["completion"]["unresolved_candidates"])
        final = self.completed()
        self.assertTrue(final["continuation"]["automatic_stop_allowed"])
        self.assertEqual(before, (self.project.list("evidence"), self.project.list("decision")))

    def test_unstarted_or_normal_baseline_only_work_cannot_prove_duplicate(self):
        candidate = self.candidate()
        self.rejection(candidate, basis="duplicate_operation", operation_id=self.fixture.operation["id"])
        evidence = self.fixture.capture()
        self.fixture.baseline(evidence)
        self.rejection(candidate, basis="duplicate_operation", operation_id=self.fixture.operation["id"])

    def test_an_operation_with_no_security_plan_is_not_a_duplicate_completion(self):
        operation = self.fixture.register("/baseline-only")
        evidence = self.fixture.capture(operation)
        obligation = next(item for item in self.project.list("obligation") if item["operation_id"] == operation["id"])
        from awa_ddd.assessment import evaluate

        evaluate(self.project, {"obligation_id": obligation["id"], "evidence_ids": [evidence["id"]],
                              "oracle": {"type": "baseline", "selector": "/count", "expected": 1}})
        candidate = self.candidate(url=operation["url"], inputs=[])
        self.rejection(candidate, basis="duplicate_operation", operation_id=operation["id"])

    def test_duplicate_requires_the_actual_method_protocol_path_and_binding(self):
        self.fixture.close_generic()
        changes = ({"method": None}, {"method": "POST"}, {"method": ["GET"]},
                   {"url": self.fixture.base + "/other"}, {"url": self.fixture.operation["url"] + "?q=one"},
                   {"url": self.fixture.base + "/{unknown}"}, {"protocol": "graphql", "operation_name": "Other"},
                   {"content_type": "application/xml"}, {"auth": "restricted", "allowed_roles": ["admin"]},
                   {"ownership": True}, {"url_redacted": True}, {"native_input_requires_binding": True})
        for change in changes:
            with self.subTest(change=change):
                self.rejection(self.candidate(**change), basis="duplicate_operation", operation_id=self.fixture.operation["id"])

    def test_duplicate_cannot_hide_an_input_sink_family_or_schema_branch(self):
        self.fixture.close_generic()
        entry = deepcopy(self.fixture.operation["inputs"][0])
        changes = ({"selector": "other"}, {"location": "body"}, {"consumer": "sql"},
                   {"test_families": ["xss"]}, {"schema_branch": "alternate"},
                   {"schema_type": "object"}, {"required": True})
        for change in changes:
            with self.subTest(change=change):
                self.rejection(self.candidate(inputs=[{**entry, **change}]), basis="duplicate_operation",
                               operation_id=self.fixture.operation["id"])

    def test_duplicate_schema_booleans_cannot_be_replaced_by_numbers(self):
        entry = {**self.fixture.operation["inputs"][0], "required": False}
        self.fixture.operation = engine.register_operation(self.project, {"url": self.fixture.operation["url"],
            "method": "GET", "auth": "public", "inputs": [entry]})
        engine.build_plan(self.project)
        self.fixture.close_generic()
        changed = {**self.fixture.operation["inputs"][0], "required": 0}
        self.rejection(self.candidate(inputs=[changed]), basis="duplicate_operation", operation_id=self.fixture.operation["id"])

    def test_scanner_findings_metadata_and_dynamic_sources_are_not_endpoint_duplicates(self):
        self.fixture.close_generic()
        for kind in ("tool_signal", "tool_metadata", "sarif_finding", "tscanplus_route", "dynamic_request"):
            with self.subTest(kind=kind):
                self.rejection(self.candidate(kind=kind), basis="duplicate_operation", operation_id=self.fixture.operation["id"])

    def test_verified_declared_scope_exclusion_is_offline_and_does_not_expand_scope(self):
        self.fixture.close_generic()
        config = deepcopy(self.project.config)
        candidate = self.candidate(url="https://outside-fixture.invalid/items", inputs=[])
        public = self.dismiss(candidate, basis="outside_scope")
        self.assertEqual("outside_scope", public["candidate_closure"]["basis"])
        self.assertEqual(config, self.project.config)
        self.assertEqual(0, self.audit()["completion"]["unresolved_candidates"])
        self.assertTrue(self.completed()["continuation"]["automatic_stop_allowed"])

    def test_mutable_exclude_does_not_turn_an_in_scope_clue_into_verified_exhaustion(self):
        self.fixture.close_generic()
        candidate = self.candidate()
        self.rejection(candidate, basis="outside_scope")
        engine.update_project(self.project, {"exclude": [self.fixture.operation["url"]]})
        self.rejection(candidate, basis="outside_scope")
        self.dismiss(candidate)
        self.assertEqual(1, self.audit()["completion"]["unresolved_candidates"])

    def test_lossy_har_query_cannot_manufacture_outside_scope_proof(self):
        from awa_ddd.scope import require_scope

        authorized_url = self.fixture.base + "/items?tenant=fixture-one"
        engine.create_project(self.fixture.root, {"project_id": "query-candidate", "target": authorized_url})
        source = self.fixture.root / "query-scope.har.json"
        source.write_text(json.dumps({"log": {"entries": [{
            "request": {"url": authorized_url, "method": "GET", "headers": [], "queryString": []},
            "response": {"status": 200, "headers": [], "content": {"mimeType": "application/json", "text": "{}"}},
        }]}}), encoding="utf-8")
        with Project(self.fixture.root, "query-candidate") as project, patch.object(engine, "request") as network:
            self.assertEqual(authorized_url, require_scope(project.config, authorized_url))
            imported = dispatch(self.fixture.root, "surface.import", {"project_id": "query-candidate",
                                "path": str(source), "format": "har"})
            self.assertEqual(1, imported["candidates"])
            candidate = project.list("candidate")[0]
            self.assertNotIn("fixture-one", json.dumps(candidate))
            before = project.get("candidate", candidate["id"])
            with self.assertRaises(EngineError) as caught:
                dispatch(self.fixture.root, "candidate.dismiss", {"project_id": "query-candidate", "candidate_id": candidate["id"],
                         "reason": "A query-free locator is not actual exclusion evidence.", "basis": "outside_scope"})
            self.assertEqual("candidate_closure", caught.exception.code)
            self.assertEqual(before, project.get("candidate", candidate["id"]))
            self.assertEqual(1, completeness.audit(project, {"limit": 100})["completion"]["unresolved_candidates"])
        network.assert_not_called()

    def test_nested_private_locator_flags_cannot_establish_exclusion(self):
        for flag in ("url_redacted", "native_input_requires_binding"):
            candidate = self.candidate(url=None, hint={"url": "https://outside-fixture.invalid/items", "method": "GET", flag: True})
            self.rejection(candidate, basis="outside_scope")

    def test_scope_expansion_reopens_a_verified_exclusion_without_rewriting_it(self):
        self.fixture.close_generic()
        candidate = self.candidate(url="https://outside-fixture.invalid/items", inputs=[])
        self.dismiss(candidate, basis="outside_scope")
        stored = self.project.get("candidate", candidate["id"])
        config = deepcopy(self.project.config)
        config["scope"].append("https://outside-fixture.invalid")
        self.project.set_config(config)
        self.assertEqual(1, self.audit()["completion"]["unresolved_candidates"])
        self.assertEqual(stored, self.project.get("candidate", candidate["id"]))

    def test_private_invalid_or_dynamic_locators_cannot_prove_scope_exclusion(self):
        for change in ({"url": "[private URL omitted]", "url_redacted": True}, {"url": "/unknown"},
                       {"url": "https://outside-fixture.invalid/{unknown}"}, {"url": None},
                       {"url": "https://outside-fixture.invalid/items", "url_redacted": True}):
            with self.subTest(change=change):
                self.rejection(self.candidate(**change), basis="outside_scope")

    def test_damaged_duplicate_evidence_reopens_review_and_invalidates_final_report(self):
        self.fixture.close_generic()
        candidate = self.candidate()
        self.dismiss(candidate, basis="duplicate_operation", operation_id=self.fixture.operation["id"])
        final = self.completed()
        stored = self.project.get("candidate", candidate["id"])
        evidence = self.project.list("evidence")[-1]
        (self.project.base / evidence["artifact_path"]).write_bytes(b"changed owned fixture artifact")
        audit = self.audit()
        self.assertEqual(1, audit["completion"]["unresolved_candidates"])
        self.assertTrue(audit["continuation"]["continue_required"])
        self.assertFalse(audit["continuation"]["automatic_stop_allowed"])
        destination = self.fixture.root / "invalid-final"
        with patch("awa_ddd.reproduction.prepare_reproduction") as prepare, self.assertRaises(EngineError):
            build_report(self.project, destination, stage="final", finalization_id=final["finalization"]["id"])
        prepare.assert_not_called()
        self.assertFalse(destination.exists())
        self.assertEqual(stored, self.project.get("candidate", candidate["id"]))

    def test_changed_source_context_reopens_review_and_reimport_preserves_history(self):
        candidate = self.candidate(url="https://outside-fixture.invalid/items", inputs=[])
        self.dismiss(candidate, basis="outside_scope")
        stored = self.project.get("candidate", candidate["id"])
        repeated = deepcopy(candidate)
        repeated["sources"] = [{"path": "extra-local-source.js", "sha256": "b" * 64, "locator": "line:2"}]
        identity, created = candidates.store_candidate(self.project, repeated)
        self.assertEqual(candidate["id"], identity)
        self.assertFalse(created)
        updated = self.project.get("candidate", identity)
        self.assertEqual("dismissed", updated["status"])
        self.assertEqual(stored["candidate_closure_context"], updated["candidate_closure_context"])
        self.assertEqual(1, self.audit()["completion"]["unresolved_candidates"])
        self.dismiss(updated, basis="outside_scope")
        self.assertEqual(0, self.audit()["completion"]["unresolved_candidates"])

    def test_imported_closure_receipts_are_not_trusted_or_copied(self):
        forged = self.candidate(url="https://outside-fixture.invalid/items", inputs=[], status="dismissed",
                                candidate_closure={"version": 1, "basis": "outside_scope"},
                                candidate_closure_context={"forged": True})
        self.assertNotIn("candidate_closure", forged)
        self.assertNotIn("candidate_closure_context", forged)
        self.assertEqual(1, self.audit()["completion"]["unresolved_candidates"])

    def test_malformed_legacy_receipts_never_poison_offline_audit(self):
        candidate = self.candidate(url="https://outside-fixture.invalid/items", inputs=[])
        self.dismiss(candidate, basis="outside_scope")
        stored = self.project.get("candidate", candidate["id"])
        for closure in (None, [], {"version": True, "basis": "outside_scope"},
                        {"version": 1, "basis": []}, {"version": 1, "basis": "unknown"},
                        {"version": 1, "basis": "outside_scope", "force": True},
                        {"version": 1, "basis": "duplicate_operation", "operation_id": {}}):
            with self.subTest(closure=closure):
                changed = {**stored, "candidate_closure": closure}
                self.project.put("candidate", changed)
                self.assertEqual(1, self.audit()["completion"]["unresolved_candidates"])
                self.assertEqual(changed, self.project.get("candidate", candidate["id"]))

    def test_private_closure_source_context_uses_exact_json_types(self):
        candidate = self.candidate(url="https://outside-fixture.invalid/items", inputs=[{"name": "q", "location": "query", "required": False}])
        self.dismiss(candidate, basis="outside_scope")
        stored = self.project.get("candidate", candidate["id"])
        changed = deepcopy(stored)
        changed["inputs"][0]["required"] = 0
        self.project.put("candidate", changed)
        self.assertEqual(1, self.audit()["completion"]["unresolved_candidates"])
        self.assertEqual(changed, self.project.get("candidate", candidate["id"]))

    def test_unverified_dismiss_reopen_cycles_do_not_count_as_closure_progress(self):
        self.fixture.close_generic()
        candidate = self.candidate(kind="dynamic_request", url=None)
        first = self.fixture.checkpoint()
        self.dismiss(candidate)
        second = self.fixture.checkpoint()
        candidates.reopen_candidate(self.project, {"candidate_id": candidate["id"], "reason": "Continue inspecting its real source."})
        third = self.fixture.checkpoint()
        self.assertEqual(first["continuation"]["progress_id"], second["continuation"]["progress_id"])
        self.assertEqual(first["continuation"]["progress_id"], third["continuation"]["progress_id"])
        self.assertGreaterEqual(third["continuation"]["no_progress_rounds"], 2)

    def test_invalid_basis_and_extra_authority_fields_fail_without_mutation(self):
        candidate = self.candidate()
        for args in ({"basis": "caller_review"}, {"basis": []}, {"basis": "duplicate_operation"},
                     {"operation_id": self.fixture.operation["id"]},
                     {"basis": "outside_scope", "operation_id": self.fixture.operation["id"]}):
            with self.subTest(args=args):
                self.rejection(candidate, **args)
        with self.assertRaises(EngineError) as caught:
            self.dismiss(candidate, force=True)
        self.assertEqual("arguments", caught.exception.code)

    def test_public_views_never_publish_private_source_context(self):
        candidate = self.candidate(url="https://outside-fixture.invalid/items", inputs=[])
        self.dismiss(candidate, basis="outside_scope")
        stored = self.project.get("candidate", candidate["id"])
        public = dispatch(self.fixture.root, "candidate.inspect", {"project_id": "continuation", "candidate_id": candidate["id"]})
        self.assertNotIn("candidate_closure_context", public["candidate"])
        self.assertNotIn("candidate_closure_context", public_integrity_metadata(stored))
        self.assertNotIn("candidate_closure_context", safe_metadata(stored))
        candidates.reopen_candidate(self.project, {"candidate_id": candidate["id"], "reason": "Reinspect this source."})
        reopened = self.project.get("candidate", candidate["id"])
        self.assertNotIn("candidate_closure_context", reopened)
        self.assertNotIn("candidate_closure", reopened)

    def test_draft_candidate_count_uses_current_exhaustion_review_not_raw_labels(self):
        self.fixture.close_generic()
        candidate = self.candidate(kind="dynamic_request", url=None)
        self.dismiss(candidate)
        with patch.object(engine, "request") as network:
            report = build_report(self.project)
        network.assert_not_called()
        from pathlib import Path

        summary = json.loads(Path(report["summary"]).read_text(encoding="utf-8"))
        self.assertEqual(1, summary["unverified_candidates"])
        self.assertEqual(1, summary["completion"]["unresolved_candidates"])
        self.assertEqual(1, summary["continuation"]["review_total"])
        self.assertEqual("draft", report["stage"])
        self.assertTrue(report["continuation"]["continue_required"])

    def test_rejected_import_hints_keep_distinct_source_bound_candidate_ids(self):
        _, args = self.outside_source()
        with patch.object(engine, "request") as network:
            imported = dispatch(self.fixture.root, "surface.import", args)
            repeated = dispatch(self.fixture.root, "surface.import", args)
        network.assert_not_called()
        self.assertEqual([], imported["operation_ids"])
        self.assertEqual(2, imported["candidates"])
        self.assertEqual(0, repeated["candidates"])
        records = self.project.list("candidate")
        self.assertEqual(2, len(records))
        self.assertEqual(2, len({record["id"] for record in records}))
        self.assertEqual({"https://outside-fixture.invalid/one", "https://outside-fixture.invalid/two"},
                         {record["hint"]["url"] for record in records})
        for record in records:
            self.dismiss(record, basis="outside_scope")
        self.assertEqual(0, self.audit()["completion"]["unresolved_candidates"])

    def test_legacy_rejection_id_preserves_the_exact_hint_and_recovers_a_missing_sibling(self):
        source, args = self.outside_source()
        hint = discovery.discover(source, "openapi")["operations"][0]
        legacy_id = "C-" + hashlib.sha256(canonical([None, None, "operation_hint", None, None, None, None, None]).encode()).hexdigest()[:24]
        legacy = {"id": legacy_id, "kind": "operation_hint", "hint": hint, "status": "dismissed",
                  "reason": "Original fixture declaration remains history.", "created_at": now(), "updated_at": now()}
        self.project.put("candidate", legacy, create_only=True)
        with patch.object(engine, "request") as network:
            imported = dispatch(self.fixture.root, "surface.import", args)
            repeated = dispatch(self.fixture.root, "surface.import", args)
        network.assert_not_called()
        self.assertEqual(1, imported["candidates"])
        self.assertEqual(0, repeated["candidates"])
        self.assertEqual(2, len(self.project.list("candidate")))
        retained = self.project.get("candidate", legacy_id)
        for key in ("id", "kind", "hint", "status", "reason", "created_at"):
            self.assertEqual(legacy[key], retained[key])
        sibling = next(record for record in self.project.list("candidate") if record["id"] != legacy_id)
        self.assertNotEqual(hint["url"], sibling["hint"]["url"])
        self.assertEqual(2, self.audit()["completion"]["unresolved_candidates"])


if __name__ == "__main__":
    unittest.main()
