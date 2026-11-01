"""Caller exclusions and reduced plans cannot manufacture automatic exhaustion."""
from __future__ import annotations

import copy
import hashlib
import unittest
from unittest.mock import patch
from urllib.parse import quote

import test_continuation_20261030 as fixtures
from awa_ddd import completeness, continuation, engine, workflow
from awa_ddd.assessment import evaluate, record_finding
from awa_ddd.reporting import build_report
from awa_ddd.store import EngineError, Project, canonical, now


class ApplicabilityStopTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ContinuationTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.project = self.fixture.project

    def database_state(self):
        return {table: [tuple(row) for row in self.project.connection.execute(f"SELECT * FROM {table} ORDER BY 1,2")]
                for table in ("entities", "events", "metadata")}

    def exclude(self, item, evidence):
        return engine.disposition(self.project, {"obligation_id": item["id"], "status": "not_applicable",
            "basis": "business_fact", "evidence_ids": [evidence["id"]],
            "reason": "The caller asserts that the whole obligation is inapplicable based on this normal observation."})

    def archive_unused(self):
        for row in completeness.audit(self.project, {"limit": 100})["checklist"]:
            if row["kind"] == "unassessed_observation":
                self.fixture.review(row)

    def assert_not_exhausted(self, *, applicability=None, reduction=None):
        result = completeness.audit(self.project, {"limit": 100})
        self.assertEqual("partial", result["completion"]["status"])
        self.assertTrue(result["continuation"]["continue_required"])
        self.assertFalse(result["continuation"]["can_finalize"])
        self.assertFalse(result["continuation"]["automatic_stop_allowed"])
        self.assertFalse(result["continuation"]["can_claim_complete"])
        for field, expected in (("applicability_review_total", applicability), ("scope_reduction_review_total", reduction)):
            if expected is not None:
                self.assertEqual(expected, result["completion"][field])
                self.assertEqual(expected, result["continuation"][field])
        return result

    def assert_no_final_stop(self, checkpoint):
        before = self.database_state()
        with patch.object(engine, "request") as network, self.assertRaises(EngineError) as caught:
            self.fixture.finish(checkpoint)
        network.assert_not_called()
        self.assertEqual("continue_required", caught.exception.code)
        self.assertTrue(caught.exception.details["continuation"]["continue_required"])
        self.assertEqual(before, self.database_state())
        self.assertEqual([], self.project.list("finalization"))

    def complete_frontier(self, *, families=("generic",), evidence=None):
        frontier = self.fixture.frontier(evidence)
        for row in frontier["categories"]:
            if row["test_family"] in families:
                row["status"] = "planned"
        self.fixture.checkpoint(frontier)
        return self.fixture.checkpoint(frontier)

    def current_input(self, operation=None, family="generic"):
        operation = operation or self.fixture.operation
        return next(item for item in self.project.list("obligation") if not item.get("superseded")
                    and item["operation_id"] == operation["id"] and item.get("kind") == "input_test"
                    and item.get("test_family", "generic") == family)

    def declare(self, families, *, consumer="business_input"):
        return engine.declare_consumer(self.project, {"operation_id": self.fixture.operation["id"],
            "input_location": "query", "input_selector": "q", "consumer": consumer, "test_families": families})

    def close_current_generic(self, operation=None):
        operation = operation or self.fixture.operation
        captures = [self.fixture.capture(operation=operation, url=operation["url"] + "?q=" + value,
            response={"count": count}) for value, count in (("normal", 1), ("variant", 1), ("sensitivity", 2))]
        baseline = next(item for item in self.project.list("obligation") if not item.get("superseded")
                        and item["operation_id"] == operation["id"] and item.get("kind") == "baseline")
        evaluate(self.project, {"obligation_id": baseline["id"], "evidence_ids": [captures[0]["id"]],
            "oracle": {"type": "baseline", "selector": "/count", "expected": 1}})
        evaluate(self.project, {"obligation_id": self.current_input(operation)["id"],
            "evidence_ids": [row["id"] for row in captures], "oracle": {"type": "semantic_negative",
                "test_family": "generic", "selector": "/count", "baseline_expected": 1, "control_expected": 2}})
        self.fixture.baseline_evidence = captures[0]
        return captures[0]

    def close_current_sql(self):
        operation = self.project.get("operation", self.fixture.operation["id"])
        observations = (("normal-sql", {"count": 1}),
                        ("1 UNION SELECT database()", {"count": 1, "db": "fixture_database"}),
                        ("1 UNION SELECT database() WHERE 1=2", {"count": 1}))
        captures = [self.fixture.capture(operation=operation, url=operation["url"] + "?q=" + quote(value, safe=""),
            response=response) for value, response in observations]
        decision = evaluate(self.project, {"obligation_id": self.current_input(operation, "sql_injection")["id"],
            "evidence_ids": [row["id"] for row in captures], "oracle": {"type": "sql_metadata",
                "test_family": "sql_injection", "metadata_type": "database", "expected_value": "fixture_database", "selector": "/db",
                "baseline_selector": "/count", "baseline_expected": 1}})
        self.assertEqual("confirmed", decision["outcome"])
        record_finding(self.project, {"mode": "machine", "decision_id": decision["id"],
            "title": "Isolated fixture metadata proof", "category": "SQL Injection", "severity": "medium",
            "impact": "Only the modeled fixture database name.", "remediation": "Bind this modeled input."})

    def test_all_na_obligations_and_one_normal_capture_cannot_complete(self):
        evidence = self.fixture.capture(url=self.fixture.operation["url"] + "?q=normal")
        excluded = [self.exclude(item, evidence) for item in self.project.list("obligation")]
        self.archive_unused()
        before = self.database_state()
        with patch.object(engine, "request") as network:
            audit = self.assert_not_exhausted(applicability=2, reduction=0)
            next_work = workflow.next_work(self.project, {"limit": 1})
        network.assert_not_called()
        self.assertEqual(before, self.database_state())
        self.assertEqual(0, audit["security_coverage"]["evaluated"])
        self.assertEqual(0, len(self.project.list("decision")))
        self.assertEqual(2, audit["continuation"]["review_total"])
        self.assertEqual(2, audit["continuation"]["unresolved_total"])
        self.assertEqual([], next_work["work_items"])
        self.assertEqual(2, next_work["review_followup_total"])
        self.assertEqual({item["id"] for item in excluded},
            {row["obligation_id"] for row in audit["checklist"] if row["kind"] == "unverified_applicability"})
        for item in excluded:
            self.assertEqual(item, self.project.get("obligation", item["id"]))
        self.assert_no_final_stop(self.complete_frontier(evidence=evidence))

    def test_one_tested_generic_does_not_cover_an_excluded_sql_obligation(self):
        normal = self.fixture.close_generic()
        operation = self.fixture.register("/sql", inputs=[{"name": "q", "location": "query",
            "consumer": "sql_like", "test_families": ["sql_injection"]}])
        evidence = self.fixture.capture(operation=operation, url=operation["url"] + "?q=normal")
        baseline = next(row for row in self.project.list("obligation") if row["operation_id"] == operation["id"]
                        and row["kind"] == "baseline" and not row.get("superseded"))
        evaluate(self.project, {"obligation_id": baseline["id"], "evidence_ids": [evidence["id"]],
            "oracle": {"type": "baseline", "selector": "/count", "expected": 1}})
        self.exclude(self.current_input(operation, "sql_injection"), evidence)
        audit = self.assert_not_exhausted(applicability=1)
        self.assertEqual(1, audit["security_coverage"]["evaluated"])
        self.assertTrue(any(row.get("test_family") == "sql_injection" and row["kind"] == "unverified_applicability"
                            for row in audit["checklist"]))
        self.assert_no_final_stop(self.complete_frontier(families=("generic", "sql_injection"), evidence=normal))

    def test_a_na_baseline_is_also_a_nonadministrative_review_gap(self):
        evidence = self.fixture.close_generic()
        self.exclude(self.fixture.obligation("baseline"), evidence)
        audit = self.assert_not_exhausted(applicability=1)
        row = next(row for row in audit["checklist"] if row["kind"] == "unverified_applicability")
        self.assertEqual("baseline", row["obligation_kind"])
        self.assert_no_final_stop(self.complete_frontier())

    def test_all_setup_access_and_ownership_na_kinds_remain_visible(self):
        engine.add_actor(self.project, {"actor_id": "owner", "subject": "owner", "roles": ["user"]})
        engine.add_actor(self.project, {"actor_id": "other", "subject": "other", "roles": ["user"]})
        unknown = self.fixture.register("/unknown", auth="unknown")
        restricted = self.fixture.register("/restricted", auth="restricted", allowed_roles=["admin"])
        setup = self.fixture.register("/ownership-setup", ownership=True)
        owned = self.fixture.register("/owned", ownership=True)
        resource = engine.add_resource(self.project, {"operation_id": owned["id"], "owner_actor_id": "owner",
            "external_id": "7", "request_binding": {"location": "query", "selector": "id"}})
        review = self.fixture.register("/review", inputs=[{"name": "q", "location": "query"}])
        engine.build_plan(self.project)
        evidence = {operation["id"]: self.fixture.capture(operation=operation,
            **({"url": operation["url"] + "?id=7", "resource_id": resource["id"]} if operation["id"] == owned["id"] else {}))
            for operation in (unknown, restricted, setup, owned, review)}
        selected = []
        kinds = {"auth_review", "access", "identity_setup", "ownership_setup", "ownership", "input_review"}
        for item in self.project.list("obligation"):
            if not item.get("superseded") and item["operation_id"] in evidence and item["kind"] in kinds:
                selected.append(self.exclude(item, evidence[item["operation_id"]]))
        self.assertEqual(kinds, {item["kind"] for item in selected})
        audit = self.assert_not_exhausted(applicability=len(selected))
        rows = [row for row in audit["checklist"] if row["kind"] == "unverified_applicability"]
        self.assertEqual({item["id"] for item in selected}, {row["obligation_id"] for row in rows})
        self.assertTrue(all(row["administrative_review_allowed"] is False for row in rows))

    def test_plan_review_cannot_archive_block_or_reopen_applicability_gaps(self):
        evidence = self.fixture.capture()
        self.exclude(self.current_input(), evidence)
        row = next(row for row in completeness.audit(self.project, {"limit": 100})["checklist"]
                   if row["kind"] == "unverified_applicability")
        for status in ("reviewed", "blocked", "reopen"):
            before = self.database_state()
            with self.subTest(status=status), self.assertRaises(EngineError) as caught:
                self.fixture.review(row, status, evidence_ids=[evidence["id"]])
            self.assertEqual("closure_review", caught.exception.code)
            self.assertEqual(before, self.database_state())
        self.assert_not_exhausted(applicability=1)

    def test_na_source_failure_reopens_the_original_gap_without_double_counting(self):
        evidence = self.fixture.capture()
        items = [self.exclude(item, evidence) for item in self.project.list("obligation")]
        artifact = self.project.base / evidence["artifact_path"]
        original = artifact.read_bytes()
        artifact.write_bytes(original + b" ")
        audit = self.assert_not_exhausted(applicability=0)
        rows = [row for row in audit["checklist"] if row["kind"] == "obligation"]
        self.assertEqual({item["id"] for item in items}, {row["obligation_id"] for row in rows})
        self.assertTrue(all(row["reason_code"] == "exclusion_evidence_invalid" for row in rows))
        self.assertFalse(any(row["kind"] == "unverified_applicability" for row in audit["checklist"]))
        artifact.write_bytes(original)
        self.assert_not_exhausted(applicability=2)

    def test_legacy_na_records_are_not_rewritten_by_loading_or_audit(self):
        evidence = self.fixture.capture()
        for item in self.project.list("obligation"):
            self.exclude(item, evidence)
        before = self.database_state()
        with Project(self.fixture.root, "continuation") as loaded, patch.object(engine, "request") as network:
            result = completeness.audit(loaded, {"limit": 100})
        network.assert_not_called()
        self.assertEqual("partial", result["completion"]["status"])
        self.assertEqual(2, result["continuation"]["applicability_review_total"])
        self.assertEqual(before, self.database_state())

    def test_false_legacy_completed_na_receipt_cannot_publish_final_files(self):
        evidence = self.fixture.capture()
        for item in self.project.list("obligation"):
            self.exclude(item, evidence)
        self.archive_unused()
        saved = self.complete_frontier(evidence=evidence)
        stop = {"id": self.project.id("FN"), "checkpoint_id": saved["checkpoint"]["id"],
            "snapshot_id": saved["continuation"]["snapshot_id"], "reason": "completed", "reason_basis": "engine_gate",
            "can_claim_complete": True, "completion_status": "complete", "frontier_reviewed": True,
            "explanation": "Historical caller declarations are not typed proof.", "reviewer": "historical-fixture",
            "created_at": now(), "remaining": {key: 0 for key in ("ready_total", "review_total", "blocked_total", "unresolved_total")}}
        self.project.put("finalization", stop)
        before = self.database_state()
        destination = self.fixture.root / "forbidden-na-final"
        with patch.object(engine, "request") as network, patch("awa_ddd.reproduction.prepare_reproduction") as prepare:
            with self.assertRaises(EngineError) as caught:
                build_report(self.project, destination, stage="final", finalization_id=stop["id"])
            network.assert_not_called()
            prepare.assert_not_called()
        self.assertEqual("finalization_policy", caught.exception.code)
        self.assertFalse(destination.exists())
        self.assertEqual(before, self.database_state())
        self.assertEqual(stop, self.project.get("finalization", stop["id"]))

    def test_reopening_na_and_real_typed_tests_allow_completed_exhaustion(self):
        evidence = self.fixture.capture()
        items = [self.exclude(item, evidence) for item in self.project.list("obligation")]
        self.archive_unused()
        for item in items:
            engine.disposition(self.project, {"obligation_id": item["id"], "status": "open",
                "reason": "Restore the obligation for actual typed testing."})
        self.assert_not_exhausted(applicability=0)
        self.fixture.close_generic()
        saved = self.complete_frontier()
        with patch.object(engine, "request") as network:
            stopped = self.fixture.finish(saved)
            report = build_report(self.project, stage="final", finalization_id=stopped["finalization"]["id"])
        network.assert_not_called()
        self.assertEqual("final-completed", report["delivery_status"])
        self.assertEqual(0, report["continuation"]["applicability_review_total"])
        self.assertEqual(0, report["continuation"]["scope_reduction_review_total"])

    def test_deleting_an_unfinished_family_does_not_restore_exhaustion(self):
        self.fixture.close_generic()
        self.declare(["generic", "sql_injection"])
        removed = self.current_input(family="sql_injection")
        self.declare(["generic"])
        audit = self.assert_not_exhausted(applicability=0, reduction=1)
        rows = [row for row in audit["checklist"] if row["kind"] == "scope_reduction"]
        self.assertEqual("sql_injection", rows[0]["test_family"])
        self.assertEqual([removed["id"]], rows[0]["source_obligation_ids"])
        self.assertTrue(self.project.get("obligation", removed["id"])["superseded"])
        self.assertEqual("open", self.project.get("obligation", removed["id"])["status"])
        self.assert_no_final_stop(self.complete_frontier())

    def test_explicit_reregistration_cannot_remove_an_unfinished_family(self):
        self.fixture.close_generic()
        self.declare(["generic", "sql_injection"])
        engine.register_operation(self.project, {"url": self.fixture.operation["url"], "method": "GET", "auth": "public",
            "inputs": [{"name": "q", "location": "query", "consumer": "business_input", "test_families": ["generic"]}]})
        engine.build_plan(self.project)
        self.assert_not_exhausted(reduction=1)

    def test_each_removed_family_has_its_own_scope_gap(self):
        self.fixture.close_generic()
        self.declare(["generic", "sql_injection", "xss"])
        self.declare(["generic"])
        audit = self.assert_not_exhausted(reduction=2)
        self.assertEqual({"sql_injection", "xss"}, {row["test_family"] for row in audit["checklist"] if row["kind"] == "scope_reduction"})

    def test_scope_gaps_cannot_be_administratively_archived_or_blocked(self):
        self.fixture.close_generic()
        self.declare(["generic", "sql_injection"])
        self.declare(["generic"])
        row = next(row for row in completeness.audit(self.project, {"limit": 100})["checklist"] if row["kind"] == "scope_reduction")
        for status in ("reviewed", "blocked", "reopen"):
            before = self.database_state()
            with self.subTest(status=status), self.assertRaises(EngineError) as caught:
                self.fixture.review(row, status)
            self.assertEqual("closure_review", caught.exception.code)
            self.assertEqual(before, self.database_state())
        self.assert_not_exhausted(reduction=1)

    def test_restoring_a_family_creates_real_work_not_stop_permission(self):
        self.fixture.close_generic()
        self.declare(["generic", "sql_injection"])
        self.declare(["generic"])
        self.declare(["generic", "sql_injection"])
        self.assertEqual("open", self.current_input(family="sql_injection")["status"])
        audit = self.assert_not_exhausted(reduction=0)
        self.assertGreater(audit["continuation"]["actionable_total"], 0)
        evidence = self.fixture.capture(url=self.fixture.operation["url"] + "?q=normal")
        self.exclude(self.current_input(family="sql_injection"), evidence)
        self.assert_not_exhausted(applicability=1, reduction=0)

    def test_restored_families_and_actual_typed_proofs_can_complete(self):
        self.fixture.close_generic()
        self.declare(["generic", "sql_injection"])
        self.declare(["generic"])
        self.declare(["generic", "sql_injection"])
        self.close_current_generic()
        self.close_current_sql()
        self.archive_unused()
        saved = self.complete_frontier(families=("generic", "sql_injection"))
        self.assertEqual(0, saved["continuation"]["scope_reduction_review_total"])
        self.assertEqual(0, saved["continuation"]["applicability_review_total"])
        self.assertTrue(saved["continuation"]["can_finalize"])
        stopped = self.fixture.finish(saved)
        self.assertTrue(stopped["continuation"]["automatic_stop_allowed"])

    def test_equivalent_current_obligations_do_not_duplicate_old_signatures(self):
        self.declare(["generic", "sql_injection"])
        engine.register_operation(self.project, {"url": self.fixture.operation["url"], "method": "GET", "auth": "public",
            "inputs": [{"name": "q", "location": "query", "consumer": "business_input", "source": "new-source",
                        "test_families": ["generic", "sql_injection"]}]})
        engine.build_plan(self.project)
        audit = self.assert_not_exhausted(reduction=0)
        self.assertFalse(any(row["kind"] == "scope_reduction" for row in audit["checklist"]))

    def test_an_actually_closed_removed_family_is_not_an_unfinished_scope_gap(self):
        self.fixture.close_generic()
        self.declare(["generic", "business_logic"])
        captures = [self.fixture.capture(url=self.fixture.operation["url"] + "?q=" + value, response={"count": count})
                    for value, count in (("normal-business", 1), ("variant-business", 1), ("sensitive-business", 2))]
        item = self.current_input(family="business_logic")
        evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": [row["id"] for row in captures],
            "oracle": {"type": "semantic_negative", "test_family": "business_logic", "selector": "/count",
                       "baseline_expected": 1, "control_expected": 2}})
        self.declare(["generic"])
        audit = completeness.audit(self.project, {"limit": 100})
        self.assertEqual(0, audit["continuation"]["scope_reduction_review_total"])
        self.assertTrue(self.project.get("obligation", item["id"])["superseded"])

    def test_a_fake_evaluated_label_does_not_verify_a_removed_family(self):
        self.declare(["generic", "sql_injection"])
        item = self.current_input(family="sql_injection")
        self.project.put("obligation", {**item, "status": "evaluated", "decision_id": "missing-typed-decision"})
        self.declare(["generic"])
        self.assert_not_exhausted(reduction=1)

    def test_multiple_old_signatures_for_one_removed_family_are_deduplicated(self):
        self.declare(["generic", "sql_injection"])
        engine.register_operation(self.project, {"url": self.fixture.operation["url"], "method": "GET", "auth": "public",
            "inputs": [{"name": "q", "location": "query", "consumer": "business_input", "source": "later-source",
                        "test_families": ["generic", "sql_injection"]}]})
        engine.build_plan(self.project)
        self.declare(["generic"])
        audit = self.assert_not_exhausted(reduction=1)
        row = next(row for row in audit["checklist"] if row["kind"] == "scope_reduction")
        self.assertEqual(2, len(row["source_obligation_ids"]))

    def test_removed_inputs_and_schema_branches_are_independent_scope_gaps(self):
        operation = self.fixture.register("/branches", inputs=[
            {"name": "q", "location": "query", "consumer": "sql_like", "test_families": ["sql_injection"], "schema_branch": "one"},
            {"name": "q", "location": "query", "consumer": "sql_like", "test_families": ["sql_injection"], "schema_branch": "two"},
            {"name": "other", "location": "query", "consumer": "sql_like", "test_families": ["sql_injection"]}])
        changed = self.project.get("operation", operation["id"])
        changed["inputs"] = []
        self.project.put("operation", changed)
        engine.build_plan(self.project)
        audit = self.assert_not_exhausted(reduction=3)
        keys = {(row["input_selector"], row.get("schema_branch")) for row in audit["checklist"] if row["kind"] == "scope_reduction"}
        self.assertEqual({("q", "one"), ("q", "two"), ("other", None)}, keys)

    def test_restricted_to_public_keeps_the_untested_access_boundary(self):
        self.fixture.close_generic()
        engine.register_operation(self.project, {"url": self.fixture.operation["url"], "method": "GET",
            "auth": "restricted", "allowed_roles": ["admin"]})
        engine.build_plan(self.project)
        engine.register_operation(self.project, {"url": self.fixture.operation["url"], "method": "GET", "auth": "public", "allowed_roles": []})
        engine.build_plan(self.project)
        audit = self.assert_not_exhausted(reduction=1)
        self.assertTrue(any(row["kind"] == "scope_reduction" and row["obligation_kind"] == "access" for row in audit["checklist"]))
        self.assert_no_final_stop(self.complete_frontier())

    def test_ownership_false_cannot_hide_a_specific_untested_fixture_boundary(self):
        self.fixture.close_generic()
        for subject in ("owner", "other"):
            engine.add_actor(self.project, {"actor_id": subject, "subject": subject, "roles": ["user"]})
        engine.register_operation(self.project, {"url": self.fixture.operation["url"], "method": "GET", "auth": "public", "ownership": True})
        resource = engine.add_resource(self.project, {"operation_id": self.fixture.operation["id"], "owner_actor_id": "owner",
            "external_id": "7", "request_binding": {"location": "query", "selector": "q"}})
        engine.build_plan(self.project)
        engine.register_operation(self.project, {"url": self.fixture.operation["url"], "method": "GET", "auth": "public", "ownership": False})
        engine.build_plan(self.project)
        audit = self.assert_not_exhausted(reduction=1)
        row = next(row for row in audit["checklist"] if row["kind"] == "scope_reduction")
        self.assertEqual("ownership", row["obligation_kind"])
        self.assertEqual(resource["id"], row["resource_id"])
        self.assertEqual("other", row["actor_id"])
        self.assert_no_final_stop(self.complete_frontier())

    def test_first_unknown_policy_declaration_does_not_invent_removed_access_tests(self):
        operation = self.fixture.register("/first-unknown", auth="unknown")
        engine.register_operation(self.project, {"url": operation["url"], "method": "GET", "auth": "public"})
        engine.build_plan(self.project)
        audit = self.assert_not_exhausted(reduction=0)
        self.assertTrue(any(row["operation_id"] == operation["id"] and self.project.get("obligation", row["obligation_id"])["kind"] == "baseline"
                            for row in audit["checklist"] if row["kind"] == "obligation"))

    def test_first_unknown_to_authenticated_still_requires_its_new_tests_not_scope_gaps(self):
        engine.add_actor(self.project, {"actor_id": "alice", "subject": "alice", "roles": []})
        operation = self.fixture.register("/first-authenticated", auth="unknown")
        engine.register_operation(self.project, {"url": operation["url"], "method": "GET", "auth": "authenticated"})
        engine.build_plan(self.project)
        self.assert_not_exhausted(reduction=0)
        current = [item for item in self.project.list("obligation") if item["operation_id"] == operation["id"] and not item.get("superseded")]
        self.assertTrue(any(item["kind"] == "baseline" and item.get("actor_id") == "alice" for item in current))
        self.assertTrue(any(item["kind"] == "access" and item.get("actor_id") is None for item in current))

    def test_known_policy_cannot_be_laundered_through_unknown_then_public(self):
        engine.add_actor(self.project, {"actor_id": "alice", "subject": "alice", "roles": []})
        operation = self.fixture.register("/policy-laundering", auth="unknown")
        for auth in ("authenticated", "unknown", "public"):
            engine.register_operation(self.project, {"url": operation["url"], "method": "GET", "auth": auth})
            engine.build_plan(self.project)
        audit = self.assert_not_exhausted()
        self.assertGreater(audit["continuation"]["scope_reduction_review_total"], 0)
        self.assertTrue(any(row["kind"] == "scope_reduction" and row["obligation_kind"] == "access" for row in audit["checklist"]))

    def test_legacy_html_to_generic_drift_preserves_the_original_scope_family(self):
        operation = self.fixture.register("/legacy-html", inputs=[{"name": "q", "location": "query", "consumer": "html_render"}])
        old = next(item for item in self.project.list("obligation") if item["operation_id"] == operation["id"]
                   and item["kind"] == "input_test" and not item.get("superseded"))
        self.assertNotIn("test_family", old)
        self.assertEqual("xss", old["scope_family"])
        self.assertEqual("xss", old["consumer_family"])
        engine.declare_consumer(self.project, {"operation_id": operation["id"], "input_location": "query",
            "input_selector": "q", "consumer": "business_input"})
        audit = self.assert_not_exhausted(reduction=1)
        row = next(row for row in audit["checklist"] if row["kind"] == "scope_reduction")
        self.assertEqual("xss", row["test_family"])
        self.assertEqual("xss", self.project.get("obligation", old["id"])["scope_family"])

    def test_legacy_missing_snapshot_and_changed_signature_cannot_guess_past_family(self):
        operation = self.fixture.register("/old-html", inputs=[{"name": "q", "location": "query", "consumer": "html_render"}])
        old = next(item for item in self.project.list("obligation") if item["operation_id"] == operation["id"]
                   and item["kind"] == "input_test" and not item.get("superseded"))
        legacy = {key: value for key, value in old.items() if key not in {"scope_family", "consumer_family"}}
        self.project.put("obligation", legacy)
        engine.declare_consumer(self.project, {"operation_id": operation["id"], "input_location": "query",
            "input_selector": "q", "consumer": "business_input"})
        before = self.database_state()
        audit = self.assert_not_exhausted(reduction=1)
        self.assertEqual(before, self.database_state())
        saved = self.project.get("obligation", old["id"])
        self.assertNotIn("scope_family", saved)
        self.assertNotIn("consumer_family", saved)
        row = next(row for row in audit["checklist"] if row["kind"] == "scope_reduction")
        self.assertNotIn("test_family", row)

    def test_generic_does_not_omit_a_concrete_sql_or_html_requirement(self):
        for consumer, family in (("sql_like", "sql_injection"), ("html_render", "xss")):
            operation = self.fixture.register("/required-" + family, inputs=[{"name": "q", "location": "query",
                "consumer": consumer, "test_families": ["generic"]}])
            self.close_current_generic(operation)
            current = self.project.get("operation", operation["id"])
            self.assertEqual(["generic"], current["inputs"][0]["test_families"])
        audit = self.assert_not_exhausted(reduction=2)
        rows = [row for row in audit["checklist"] if row["kind"] == "consumer_family_required"]
        self.assertEqual({"sql_injection", "xss"}, {row["test_family"] for row in rows})
        for row in rows:
            before = self.database_state()
            with self.assertRaises(EngineError) as caught:
                self.fixture.review(row, "reviewed")
            self.assertEqual("closure_review", caught.exception.code)
            self.assertEqual(before, self.database_state())

    def test_relabelling_a_generic_only_concrete_consumer_does_not_launder_its_requirement(self):
        self.declare(["generic"], consumer="html_render")
        self.close_current_generic()
        self.assert_not_exhausted(reduction=1)
        self.declare(["generic"], consumer="business_input")
        self.close_current_generic()
        self.archive_unused()
        audit = self.assert_not_exhausted(reduction=1)
        row = next(row for row in audit["checklist"] if row["kind"] == "scope_reduction")
        self.assertEqual("xss", row["test_family"])
        self.assert_no_final_stop(self.complete_frontier())

    def test_current_missing_family_and_old_same_requirement_are_not_double_counted(self):
        operation = self.fixture.register("/missing-sql", inputs=[{"name": "q", "location": "query",
            "consumer": "sql_like", "source": "first", "test_families": ["generic"]}])
        engine.register_operation(self.project, {"url": operation["url"], "method": "GET", "auth": "public",
            "inputs": [{"name": "q", "location": "query", "consumer": "sql_like", "source": "second",
                        "test_families": ["generic"]}]})
        engine.build_plan(self.project)
        audit = self.assert_not_exhausted(reduction=1)
        self.assertEqual(1, len([row for row in audit["checklist"] if row["kind"] == "consumer_family_required"]))
        self.assertFalse(any(row["kind"] == "scope_reduction" for row in audit["checklist"]))

    def test_same_concrete_family_signature_change_is_not_a_reduction(self):
        operation = self.fixture.register("/same-html", inputs=[{"name": "q", "location": "query",
            "consumer": "html_render", "source": "first", "test_families": ["xss"]}])
        engine.register_operation(self.project, {"url": operation["url"], "method": "GET", "auth": "public",
            "inputs": [{"name": "q", "location": "query", "consumer": "html_render", "source": "second",
                        "test_families": ["xss"]}]})
        engine.build_plan(self.project)
        self.assert_not_exhausted(reduction=0)

    def test_names_do_not_create_concrete_consumer_requirements(self):
        self.fixture.register("/names", inputs=[{"name": "sql_html_url", "location": "query", "consumer": "business_input",
            "test_families": ["generic"]}])
        audit = self.assert_not_exhausted(reduction=0)
        self.assertFalse(any(row["kind"] == "consumer_family_required" for row in audit["checklist"]))

    def test_first_unknown_consumer_trace_creates_required_work_not_old_scope_loss(self):
        operation = self.fixture.register("/unknown-consumer", inputs=[{"name": "q", "location": "query"}])
        engine.declare_consumer(self.project, {"operation_id": operation["id"], "input_location": "query",
            "input_selector": "q", "consumer": "html_render", "test_families": ["xss"]})
        self.assert_not_exhausted(reduction=0)

    def test_superseded_disposition_is_rejected_without_timestamp_drift(self):
        operation = self.fixture.register("/stale-unknown", auth="unknown")
        old = next(item for item in self.project.list("obligation") if item["operation_id"] == operation["id"]
                   and item["kind"] == "auth_review")
        engine.register_operation(self.project, {"url": operation["url"], "method": "GET", "auth": "public"})
        engine.build_plan(self.project)
        saved = self.project.get("obligation", old["id"])
        self.assertTrue(saved["superseded_at"])
        before = self.database_state()
        with self.assertRaises(EngineError) as caught:
            engine.disposition(self.project, {"obligation_id": old["id"], "status": "open", "reason": "A delayed stale queue ID."})
        self.assertEqual("obligation_superseded", caught.exception.code)
        self.assertEqual("plan.next", caught.exception.details["next_action"])
        self.assertEqual(before, self.database_state())
        engine.build_plan(self.project)
        self.assertEqual(saved["superseded_at"], self.project.get("obligation", old["id"])["superseded_at"])
        self.assert_not_exhausted(reduction=0)

    def test_private_fill_redaction_context_protects_checkpoint_prose_not_machine_codes(self):
        context = {"browser_fill_values": ["42", "generic", "completed"], "redaction_nonce": "a" * 64}
        self.project.put("run", {"id": self.project.id("RUN"), "kind": "browser", "status": "succeeded",
            "credentials": context, "redaction_context_required": True, "redaction_context_checked": True,
            "redaction_context_available": True, "redaction_context_sha256": hashlib.sha256(canonical(context).encode("utf-8")).hexdigest(),
            "started_at": now(), "finished_at": now()})
        result = self.fixture.checkpoint(label="The private unlabelled PIN is 42.")
        self.assertNotIn("42", result["checkpoint"]["label"])
        self.assertEqual("exhaustion_only", result["continuation"]["stop_policy"])
        self.assertIs(result["continuation"]["continue_required"], True)

    def test_missing_required_redaction_context_fails_before_checkpoint_write(self):
        self.project.put("run", {"id": self.project.id("RUN"), "kind": "browser", "status": "succeeded",
            "redaction_context_required": True, "started_at": now(), "finished_at": now()})
        before = self.database_state()
        with self.assertRaises(EngineError) as caught:
            self.fixture.checkpoint(label="No incomplete context may publish content.")
        self.assertEqual("browser_redaction_context", caught.exception.code)
        self.assertEqual(before, self.database_state())

    def test_zero_review_counter_schema_extensions_do_not_stale_closed_material(self):
        self.fixture.close_generic()
        evaluated = engine.evaluate_coverage(self.project)
        inventory = completeness._inventory(self.project, evaluated)
        completion = copy.deepcopy(evaluated["completion"])
        self.assertEqual(0, completion.pop("applicability_review_total"))
        self.assertEqual(0, completion.pop("scope_reduction_review_total"))
        legacy = continuation._state(self.project, evaluated, inventory, completion)
        current = continuation._state(self.project, evaluated, inventory, evaluated["completion"])
        self.assertEqual(legacy["snapshot_id"], current["snapshot_id"])


if __name__ == "__main__":
    unittest.main()
