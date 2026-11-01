"""A denial status cannot hide selected business data or ambiguous JSON evidence."""
from __future__ import annotations

from copy import deepcopy
import json
import unittest
from unittest.mock import patch

import test_security_boundaries_20261031 as access_fixtures
import test_state_transition_20261030 as owner_fixtures
from awa_ddd import assessment, engine
from awa_ddd.store import EngineError, canonical


class _DenialStatusCases:
    def setup_fixture(self, fixture_type):
        guard = patch.object(engine, "request", side_effect=AssertionError("Unexpected target I/O"))
        self.network = guard.start()
        self.addCleanup(guard.stop)
        self.fixture = fixture_type()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.project = self.fixture.project

    def tearDown(self):
        self.network.assert_not_called()

    def body(self, value=None):
        return {"record": {"secret": self.marker if value is None else value, "balance": 0}}

    def capture(self, allowed, body, status=200, *, media="application/json"):
        raw = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")

        def response(*args):
            artifact = access_fixtures.observed_response(*args, response=raw)
            artifact["response"].update(status=status, headers=[["content-type", media]])
            return artifact

        with patch.object(engine, "request", side_effect=response):
            return engine.capture(self.project, {"operation_id": self.operation["id"],
                "session_id": self.sessions["allowed" if allowed else "variant"], **self.bindings})

    def arguments(self, baseline, variant, **oracle):
        return {"obligation_id": self.item["id"], "evidence_ids": [baseline["id"], variant["id"]],
                "oracle": {"type": "authorization", "selector": "/record/secret", **oracle}}

    def assert_no_closure(self, args, code):
        before = {kind: canonical(self.project.list(kind)) for kind in ("decision", "obligation", "evidence", "run")}
        with self.assertRaises(EngineError) as caught:
            assessment.evaluate(self.project, args)
        self.assertEqual(code, caught.exception.code)
        for kind, snapshot in before.items():
            self.assertEqual(snapshot, canonical(self.project.list(kind)), kind)
        self.assertEqual("open", self.project.get("obligation", self.item["id"])["status"])

    def legacy(self, args):
        # Mint a real decision under only the prior denial-body gate; all request,
        # principal, role, fixture, signature, and event checks remain active.
        with patch.object(assessment, "_authorization_denial_has_data", return_value=False):
            result = assessment.evaluate(self.project, args)
        self.assertEqual("refuted", result["outcome"])
        return result

    def assert_legacy_reopens(self, legacy, code):
        private = deepcopy(self.project.get("decision", legacy["id"]))
        obligation = deepcopy(self.project.get("obligation", self.item["id"]))
        before = {kind: canonical(self.project.list(kind)) for kind in ("decision", "obligation", "evidence", "run")}
        with self.assertRaises(EngineError) as caught:
            assessment.validate_confirmation(self.project, private)
        self.assertEqual(code, caught.exception.code)
        with self.assertRaises(EngineError) as caught:
            engine._decision_valid(self.project, private)
        self.assertEqual(code, caught.exception.code)
        evaluated = engine.evaluate_coverage(self.project)
        gap = next(row for row in evaluated["gaps"] if row["id"] == self.item["id"])
        self.assertEqual("evidence_invalid", gap["reason_code"])
        for kind, snapshot in before.items():
            self.assertEqual(snapshot, canonical(self.project.list(kind)), kind)
        self.assertEqual(private, self.project.get("decision", legacy["id"]))
        self.assertEqual(obligation, self.project.get("obligation", self.item["id"]))

    def test_same_selected_protected_value_on_401_and_403_never_refutes(self):
        for status in (401, 403):
            with self.subTest(status=status):
                baseline = self.capture(True, self.body())
                variant = self.capture(False, self.body(), status)
                self.assert_no_closure(self.arguments(baseline, variant), "authorization_response")

    def test_other_selected_business_data_and_zero_are_not_denial_only_responses(self):
        for value in ("different-private-record", 0, {"name": "private fixture record", "balance": 0}, [self.marker, 0]):
            with self.subTest(value=value):
                baseline = self.capture(True, self.body())
                variant = self.capture(False, self.body(value), 403)
                self.assert_no_closure(self.arguments(baseline, variant), "authorization_response")

    def test_true_plain_forbidden_is_valid_even_with_the_legacy_json_header(self):
        baseline = self.capture(True, self.body())
        for status, body in ((401, b"Unauthorized"), (403, b"Forbidden"), (403, b"Access denied."), (403, b"")):
            with self.subTest(status=status, body=body):
                variant = self.capture(False, body, status)
                decision = assessment.evaluate(self.project, self.arguments(baseline, variant))
                self.assertEqual("refuted", decision["outcome"])
                assessment.validate_confirmation(self.project, decision)
                engine._decision_valid(self.project, self.project.get("decision", decision["id"]))

    def test_json_metadata_only_denial_or_missing_selected_data_still_refutes(self):
        baseline = self.capture(True, self.body())
        for body in ({"error": "denied", "status": 403}, {"record": {}}, {"record": {"secret": None}},
                     {"record": {"secret": []}}, {"record": {"secret": {"ok": False, "message": "denied"}}},
                     {"record": {"secret": "\u65e0\u6743\u9650"}}):
            with self.subTest(body=body):
                variant = self.capture(False, body, 403)
                decision = assessment.evaluate(self.project, self.arguments(baseline, variant))
                self.assertEqual("refuted", decision["outcome"])
                engine._decision_valid(self.project, self.project.get("decision", decision["id"]))

    def test_ambiguous_or_malformed_structured_denial_json_is_not_field_absence(self):
        baseline = self.capture(True, self.body())
        for raw in (b'{"record":{"secret":"first","secret":"second"}}',
                    b'{"error":"denied","unused":{"x":1,"x":2}}', b'{"error":"denied","unused":NaN}',
                    b'{"error":"denied","unused":Infinity}', b'{"error":"denied","unused":"\\ud800"}',
                    b'{"error":"denied","unused":"\xff"}', b'{"record":', b'"Forbidden', b'Forbidden {"record":1}'):
            with self.subTest(raw=raw):
                variant = self.capture(False, raw, 403)
                self.assert_no_closure(self.arguments(baseline, variant), "response_json")

    def test_structured_json_is_checked_despite_a_non_json_content_type(self):
        baseline = self.capture(True, self.body())
        variant = self.capture(False, self.body(), 403, media="text/plain")
        self.assert_no_closure(self.arguments(baseline, variant), "authorization_response")
        malformed = self.capture(False, b'{"error":"denied","x":NaN}', 403, media="text/plain")
        self.assert_no_closure(self.arguments(baseline, malformed), "response_json")

    def test_a_selected_zero_baseline_and_denial_value_are_still_protected(self):
        baseline = self.capture(True, self.body(0))
        variant = self.capture(False, self.body(0), 403)
        self.assert_no_closure(self.arguments(baseline, variant), "authorization_response")

    def test_opted_in_404_cannot_hide_the_selected_business_value(self):
        baseline = self.capture(True, self.body())
        variant = self.capture(False, self.body(), 404)
        self.assert_no_closure(self.arguments(baseline, variant, deny_statuses=[401, 403, 404]), "authorization_response")

    def test_legacy_status_only_refutation_reopens_without_rewriting_history(self):
        baseline = self.capture(True, self.body())
        variant = self.capture(False, self.body(), 403)
        self.assert_legacy_reopens(self.legacy(self.arguments(baseline, variant)), "authorization_proof")

    def test_legacy_structured_parse_failure_refutation_is_rechecked(self):
        baseline = self.capture(True, self.body())
        variant = self.capture(False, b'{"error":"denied","unused":NaN}', 403)
        self.assert_legacy_reopens(self.legacy(self.arguments(baseline, variant)), "response_json")

    def test_existing_same_value_200_disclosure_confirmation_remains_valid(self):
        for value in (self.marker, 0, "\u771f\u5b9e\u7684\u79c1\u6709\u8bb0\u5f55"):
            with self.subTest(value=value):
                baseline = self.capture(True, self.body(value))
                variant = self.capture(False, self.body(value))
                decision = assessment.evaluate(self.project, self.arguments(baseline, variant))
                self.assertEqual("confirmed", decision["outcome"])
                engine._decision_valid(self.project, self.project.get("decision", decision["id"]))


class AccessDenialStatusTests(_DenialStatusCases, unittest.TestCase):
    def setUp(self):
        self.setup_fixture(access_fixtures.AuthorizationProtectedDataTests)
        self.operation, self.item = self.fixture.operation, self.fixture.item
        self.sessions = {"allowed": self.fixture.sessions["admin"]["id"], "variant": self.fixture.sessions["user"]["id"]}
        self.bindings = {}
        self.marker = "synthetic-status-body-private-record"


class OwnershipDenialStatusTests(_DenialStatusCases, unittest.TestCase):
    def setUp(self):
        self.setup_fixture(owner_fixtures.StateTransitionTests)
        self.operation = engine.register_operation(self.project, {
            "url": self.fixture.base + "/private-records/{record_id}", "method": "GET", "auth": "authenticated", "ownership": True,
            "inputs": [{"name": "record_id", "location": "path", "consumer": "resource_reference"}]})
        resource = engine.add_resource(self.project, {"operation_id": self.operation["id"], "owner_actor_id": "alice", "external_id": "7",
            "request_binding": {"location": "path", "selector": "record_id"}})
        engine.build_plan(self.project)
        self.item = next(row for row in self.project.list("obligation")
                         if row["operation_id"] == self.operation["id"] and row["kind"] == "ownership" and row.get("actor_id") == "bob"
                         and row.get("resource_id") == resource["id"] and not row.get("superseded"))
        self.sessions = {"allowed": self.fixture.sessions["alice"], "variant": self.fixture.sessions["bob"]}
        self.bindings = {"url": self.fixture.base + "/private-records/7", "resource_id": resource["id"]}
        self.marker = "synthetic-owner-private-record"


if __name__ == "__main__":
    unittest.main()
