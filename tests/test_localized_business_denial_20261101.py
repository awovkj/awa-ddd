"""Localized control messages never establish disclosure, state, or sensitivity proof."""
from __future__ import annotations

import base64
from copy import deepcopy
import json
import math
import re
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

import test_continuation_20261030 as continuation_fixtures
import test_legacy_review_gate_20261101 as review_fixtures
import test_state_transition_20261030 as state_fixtures
import test_workflow_readiness_20261029 as access_fixtures
from awa_ddd import assessment, engine, transport
from awa_ddd.store import EngineError


DENIED = "\u65e0\u6743\u9650"
INSUFFICIENT = "\u6743\u9650\u4e0d\u8db3"
ACK = "\u64cd\u4f5c\u6210\u529f"
BUSINESS = "\u5ba2\u6237\u5f20\u4e09\u7684\u8ba2\u5355\u8d44\u6599"
OLD_METADATA_VALUES = frozenset("ok success succeeded failed error denied forbidden unauthorized true false notfound permissiondenied authenticationrequired".split())


def legacy_business_state(value, *, protected=False):
    if isinstance(value, dict):
        return any(not transport.control_metadata_field(key) and legacy_business_state(child, protected=protected)
                   for key, child in value.items())
    if isinstance(value, list):
        return any(legacy_business_state(child, protected=protected) for child in value)
    if isinstance(value, str):
        return bool(value.strip()) and re.sub(r"[^a-z0-9]", "", value.casefold()) not in OLD_METADATA_VALUES
    return type(value) in ({int, float} if protected else {bool, int, float})


class ControlMessageTests(unittest.TestCase):
    def test_common_chinese_and_english_denials_and_acknowledgements_are_control_values(self):
        messages = (DENIED, "\u65e0 \u6743 \u9650\uff01", "\u3010\u65e0\u6743\u9650\u3011",
                    DENIED + "\uff1a\u8bf7\u8054\u7cfb\u7ba1\u7406\u5458\u3002",
                    "\u60a8\u6ca1\u6709\u6743\u9650\u8bbf\u95ee\u6b64\u8d44\u6e90\u3002",
                    "\u62b1\u6b49\uff0c\u60a8\u6ca1\u6709\u6743\u9650\u67e5\u770b\u8be5\u8ba2\u5355\u3002",
                    "\u65e0\u6743\u8bbf\u95ee\u8be5\u8d44\u6e90\u3002", INSUFFICIENT + "\uff0c\u8bf7\u8054\u7cfb\u7ba1\u7406\u5458\u3002",
                    "\u8bbf\u95ee\u88ab\u62d2\u7edd\uff1b\u7f3a\u5c11\u8bfb\u53d6\u6743\u9650\u3002",
                    "\u62d2\u7edd\u8bbf\u95ee\uff01", "\u672a\u6388\u6743\uff1a\u4f1a\u8bdd\u65e0\u6548\u3002",
                    "\u63d0\u793a\uff1a\u65e0\u6743\u9650", "\u7cfb\u7edf\u63d0\u793a\uff1a\u62b1\u6b49\uff0c\u60a8\u6ca1\u6709\u6743\u9650\u8bbf\u95ee\u3002",
                    "\u672a\u767b\u5f55\uff0c\u8bf7\u5148\u767b\u5f55\u3002", "\u8bf7\u5148\u767b\u5f55\u540e\u518d\u64cd\u4f5c\u3002",
                    "\u7121\u6b0a\u9650", "\u6b0a\u9650\u4e0d\u8db3\uff0c\u8acb\u5148\u767b\u9304\u3002",
                    "Permission denied: missing privilege.", "ACCESS DENIED. Contact the administrator.",
                    "PERMISSION_DENIED: missing privilege.", "Access-denied; no privileges.", "Not-Authorized: missing role.",
                    "Authentication_required (login needed)",
                    "Unauthorized (token expired)", "403 Forbidden: missing role.", "HTTP 401 Unauthorized",
                    "Authentication failed \u2014 expired session.", "You do not have permission to view this record.",
                    "You don't have permission to access this record.", "Not authorized for this operation.",
                    "Insufficient privileges: admin required.", "Please log in first.", "OK: request accepted.",
                    "Success! Changes saved.", "Request succeeded: synthetic request receipt.", "Operation completed successfully.",
                    "Saved successfully.", "Error: protected data is unavailable.", "Failed (missing fixture)",
                    "\u6210\u529f", ACK + "\uff1a\u5df2\u4fdd\u5b58\u3002", "\u8bf7\u6c42\u6210\u529f\uff0c\u6682\u65e0\u6570\u636e\u3002",
                    "\u67e5\u8be2\u6210\u529f", "\u9519\u8bef\uff1a\u6743\u9650\u4e0d\u8db3\u3002",
                    "\u8ba4\u8bc1\u5931\u8d25\uff1a\u767b\u5f55\u4fe1\u606f\u5931\u6548\u3002")
        for value in messages:
            with self.subTest(value=value):
                self.assertTrue(transport.control_metadata_value(value))
                for selected in (value, [value], {"data": value}, {"data": [{"payload": value}]}):
                    self.assertFalse(transport.has_business_state(selected))
                    self.assertFalse(assessment._protected_business_data(selected))

    def test_non_ascii_business_text_and_nearby_words_are_preserved(self):
        values = (BUSINESS, "\u8ba2\u5355\u72b6\u6001\uff1a\u5df2\u652f\u4ed8", "\u6743\u9650\u7ba1\u7406\u65b9\u6848",
                  "\u6210\u529f\u7684\u8ba2\u5355", "\u9519\u8bef\u66f4\u6b63\u7f16\u7801", "OK\u8ba2\u5355",
                  "success\u6848\u4f8b", "error\u4fee\u590d\u8bb0\u5f55", "caf\u00e9", "\U0001f680",
                  "success story", "error correction report", "paid", "approved", "completed")
        for value in values:
            with self.subTest(value=value):
                self.assertFalse(transport.control_metadata_value(value))
                self.assertTrue(transport.has_business_state(value))
                self.assertTrue(assessment._protected_business_data({"record": value}))
        self.assertFalse(transport.json_equal("caf\u00e9", "cafe"))

    def test_control_field_punctuation_preserves_unicode_instead_of_erasing_it(self):
        for field in ("Status_Code", "HTTP-Status", "\u72b6\u6001\uff1a", "\u6d88\u606f\uff01", "\u9519\u8bef\u3002"):
            with self.subTest(field=field):
                self.assertTrue(transport.control_metadata_field(field))
                self.assertFalse(transport.has_business_state({field: BUSINESS}))
                self.assertFalse(assessment._protected_business_data({field: BUSINESS}))
        for field in ("\u72b6\u6001\u8f6c\u6362\u8bb0\u5f55", "\u540d\u79f0", "business_status", "state"):
            with self.subTest(field=field):
                self.assertFalse(transport.control_metadata_field(field))

    def test_typed_boolean_zero_large_integer_and_domain_state_rules_do_not_change(self):
        for value in (False, True, 0, -0.0, 2**1024, {"enabled": False, "balance": 0}, {"state": "paid"}, {"state": BUSINESS}):
            with self.subTest(value=value):
                self.assertTrue(transport.has_business_state(value))
        self.assertFalse(assessment._protected_business_data(True))
        self.assertFalse(assessment._protected_business_data(False))
        self.assertTrue(assessment._protected_business_data(0))
        self.assertTrue(assessment._protected_business_data(2**1024))
        for value in (None, "", {}, [], math.nan, math.inf, "\ud800"):
            with self.subTest(value=repr(value)):
                self.assertFalse(transport.has_business_state(value))

    def test_signal_selector_gate_is_finite_and_preserves_unicode_field_names(self):
        for field in ("ok", "success", "successful", "authenticated", "authorized", "allowed", "denied",
                      "isAuthenticated", "is_authorized", "isAllowed", "isDenied", "is_success", "\u6210\u529f",
                      "\u662f\u5426\u6210\u529f", "\uff33\uff35\uff23\uff23\uff25\uff33\uff33"):
            with self.subTest(field=field):
                self.assertTrue(transport.control_signal_field(field))
                self.assertTrue(transport.control_signal_selector("/response/" + field))
                self.assertFalse(transport.has_business_state({field: True}))
        for field in ("data", "status", "code", "state", "enabled", "is_active", "is_paid",
                      "successful_orders", "success\u8bb0\u5f55", "\u6210\u529f\u6b21\u6570", "\u72b6\u6001"):
            with self.subTest(field=field):
                self.assertFalse(transport.control_signal_field(field))
                self.assertFalse(transport.control_signal_selector("/response/" + field))
        self.assertFalse(transport.control_signal_selector("success"))
        self.assertFalse(transport.control_signal_selector(None))


class OfflineFixtureTests(unittest.TestCase):
    def setUp(self):
        guard = patch.object(engine, "request", side_effect=AssertionError("Unexpected target I/O"))
        self.network = guard.start()
        self.addCleanup(guard.stop)

    def tearDown(self):
        self.network.assert_not_called()

    def fixture(self, fixture_type):
        fixture = fixture_type()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        return fixture

    def assert_legacy_reopens(self, project, item, legacy, code):
        stored = deepcopy(project.get("decision", legacy["id"]))
        with self.assertRaises(EngineError) as caught:
            engine._decision_valid(project, stored)
        self.assertEqual(code, caught.exception.code)
        evaluated = engine.evaluate_coverage(project)
        gap = next(row for row in evaluated["gaps"] if row["id"] == item["id"])
        self.assertEqual("evidence_invalid", gap["reason_code"])
        self.assertEqual(stored, project.get("decision", stored["id"]))


class LocalizedAuthorizationTests(OfflineFixtureTests):
    def setUp(self):
        super().setUp()
        self.access = self.fixture(access_fixtures.WorkflowReadinessTests)
        self.project = self.access.project
        self.session = self.access.session("admin", roles=("admin",))
        self.operation = self.access.operation("/localized-denial", auth="restricted", allowed_roles=["admin"])
        engine.build_plan(self.project)
        self.item = next(row for row in self.project.list("obligation")
                         if row["operation_id"] == self.operation["id"] and row["kind"] == "access" and row.get("actor_id") is None)

    def controls(self, baseline_value, variant_value=None):
        variant_value = baseline_value if variant_value is None else variant_value
        captures = []
        for value, args in ((baseline_value, {"session_id": self.session["id"]}), (variant_value, {})):
            with patch.object(engine, "request", side_effect=lambda *args, value=value: access_fixtures.observation(*args, response={"data": value})):
                captures.append(engine.capture(self.project, {"operation_id": self.operation["id"], **args}))
        return {"obligation_id": self.item["id"], "evidence_ids": [row["id"] for row in captures],
                "oracle": {"type": "authorization", "selector": "/data"}}

    def test_real_verified_admin_and_anonymous_localized_denial_never_confirm(self):
        for value in (DENIED, {"record": DENIED}, [DENIED], "\u60a8\u6ca1\u6709\u6743\u9650\u8bbf\u95ee\u6b64\u8d44\u6e90\u3002",
                      "Permission denied: missing privilege.", ACK, "Request succeeded: receipt only."):
            with self.subTest(value=value):
                args = self.controls(value)
                before = self.project.list("decision")
                with self.assertRaises(EngineError) as caught:
                    assessment.evaluate(self.project, args)
                self.assertEqual("protected_value", caught.exception.code)
                self.assertEqual(before, self.project.list("decision"))
                self.assertEqual("open", self.project.get("obligation", self.item["id"])["status"])

    def test_generic_variant_denial_is_not_a_successful_disclosure_or_a_status_refutation(self):
        args = self.controls(BUSINESS, DENIED)
        with self.assertRaises(EngineError) as caught:
            assessment.evaluate(self.project, args)
        self.assertEqual("protected_value", caught.exception.code)
        self.assertFalse(self.project.list("decision"))

    def test_legacy_localized_confirmation_and_finding_reopen_without_losing_history(self):
        args = self.controls(DENIED)
        with patch.object(assessment, "_protected_business_data", side_effect=lambda value: legacy_business_state(value, protected=True)):
            legacy = assessment.evaluate(self.project, args)
            finding = assessment.record_finding(self.project, {"decision_id": legacy["id"], "title": "Legacy localized fixture claim",
                "category": "Access Control", "impact": "Synthetic fixture claim", "remediation": "Inspect actual business data"})
        self.assertEqual("confirmed", legacy["outcome"])
        private_finding = deepcopy(self.project.get("finding", finding["id"]))
        self.assert_legacy_reopens(self.project, self.item, legacy, "protected_value")
        evaluated = engine.evaluate_coverage(self.project)
        self.assertFalse(next(row for row in evaluated["findings"] if row["id"] == finding["id"])["current"])
        self.assertEqual(private_finding, self.project.get("finding", finding["id"]))

    def test_real_unicode_data_zero_and_large_integer_disclosures_remain_valid(self):
        for value in (BUSINESS, {"\u540d\u79f0": "\u5f20\u4e09"}, 0, 2**1024):
            with self.subTest(value=value):
                decision = assessment.evaluate(self.project, self.controls(value))
                self.assertEqual("confirmed", decision["outcome"])
                engine._decision_valid(self.project, self.project.get("decision", decision["id"]))


class LocalizedSensitivityAndStateTests(OfflineFixtureTests):
    def setUp(self):
        super().setUp()
        self.controls_fixture = self.fixture(continuation_fixtures.ContinuationTests)
        self.project = self.controls_fixture.project

    def semantic(self, values, field="data"):
        fixture = self.controls_fixture
        captures = [fixture.capture(url=fixture.operation["url"] + "?q=" + name, response={field: value})
                    for name, value in zip(("normal", "variant", "sensitive"), values)]
        item = fixture.obligation("input_test")
        return item, {"obligation_id": item["id"], "evidence_ids": [row["id"] for row in captures],
                      "oracle": {"type": "semantic_negative", "test_family": "generic", "selector": "/" + field,
                                 "baseline_expected": values[0], "control_expected": values[2]}}

    def state_invariant(self, old, new, field="state"):
        fixture = self.controls_fixture
        engine.add_actor(self.project, {"actor_id": "state-owner", "subject": "state-owner"})
        operation = fixture.register("/localized-state", method="POST", content_type="application/json", inputs=[
            {"name": "id", "location": "body", "selector": "/id", "consumer": "resource_reference"},
            {"name": "action", "location": "body", "selector": "/action", "consumer": "business_state", "test_families": ["business_logic"]}])
        resource = engine.add_resource(self.project, {"operation_id": operation["id"], "owner_actor_id": "state-owner", "external_id": "7",
                                                     "request_binding": {"location": "body", "selector": "/id"}})
        captures = [fixture.capture(operation, resource_id=resource["id"], effect="test_resource_write",
                    body=json.dumps({"id": "7", "action": action}), headers={"Content-Type": "application/json"},
                    response={field: value})
                    for action, value in (("inspect", old), ("mutate", ACK), ("inspect", new))]
        item = next(row for row in self.project.list("obligation")
                    if row["operation_id"] == operation["id"] and row.get("input_selector") == "/action" and not row.get("superseded"))
        return item, {"obligation_id": item["id"], "evidence_ids": [row["id"] for row in captures],
                      "oracle": {"type": "state_invariant", "test_family": "business_logic", "selector": "/" + field,
                                 "before_expected": old, "forbidden_after": new}}

    def test_denial_and_acknowledgement_sensitivity_controls_never_refute(self):
        for values in ((DENIED, DENIED, INSUFFICIENT), (ACK, ACK, "\u8bf7\u6c42\u6210\u529f"),
                       (BUSINESS, DENIED, "\u53e6\u4e00\u6761\u771f\u5b9e\u8ba2\u5355")):
            with self.subTest(values=values):
                item, args = self.semantic(values)
                before = self.project.list("decision")
                with self.assertRaises(EngineError) as caught:
                    assessment.evaluate(self.project, args)
                self.assertEqual("control_invalid", caught.exception.code)
                self.assertEqual(before, self.project.list("decision"))
                self.assertEqual("open", self.project.get("obligation", item["id"])["status"])

    def test_legacy_false_semantic_refutation_reopens(self):
        item, args = self.semantic((DENIED, DENIED, INSUFFICIENT))
        with patch.object(assessment, "has_business_state", side_effect=legacy_business_state):
            legacy = assessment.evaluate(self.project, args)
        self.assertEqual("refuted", legacy["outcome"])
        self.assert_legacy_reopens(self.project, item, legacy, "control_invalid")

    def test_pure_success_and_authorization_flags_never_refute_on_any_value_type(self):
        controls = [(field, False, True) for field in ("ok", "success", "successful", "authenticated", "authorized", "allowed", "denied",
                    "isAuthenticated", "is_authorized", "isAllowed", "\u6210\u529f", "\u662f\u5426\u6210\u529f",
                    "\uff33\uff35\uff23\uff23\uff25\uff33\uff33")]
        controls += [("ok", 0, 1), ("ok", "pending", "paid")]
        for field, normal, sensitive in controls:
            with self.subTest(field=field, normal=normal, sensitive=sensitive):
                item, args = self.semantic((normal, normal, sensitive), field)
                before = self.project.list("decision")
                with self.assertRaises(EngineError) as caught:
                    assessment.evaluate(self.project, args)
                self.assertEqual("control_invalid", caught.exception.code)
                self.assertEqual(before, self.project.list("decision"))
                self.assertEqual("open", self.project.get("obligation", item["id"])["status"])

    def test_legacy_boolean_response_flag_refutation_reopens(self):
        item, args = self.semantic((False, False, True), "ok")
        with patch.object(assessment, "control_signal_selector", return_value=False):
            legacy = assessment.evaluate(self.project, args)
        self.assertEqual("refuted", legacy["outcome"])
        self.assert_legacy_reopens(self.project, item, legacy, "control_invalid")

    def test_status_code_data_and_named_boolean_business_sensitivity_remain_valid(self):
        for field, normal, sensitive in (("status", "paid", "refunded"), ("code", 1, 2), ("data", False, True),
                                         ("is_active", False, True), ("\u72b6\u6001", "\u5df2\u652f\u4ed8", "\u5df2\u9000\u6b3e")):
            with self.subTest(field=field):
                _, args = self.semantic((normal, normal, sensitive), field)
                result = assessment.evaluate(self.project, args)
                self.assertEqual("refuted", result["outcome"])
                engine._decision_valid(self.project, self.project.get("decision", result["id"]))

    def test_genuine_unicode_boolean_zero_and_large_integer_sensitivity_stays_valid(self):
        for normal, sensitive in ((BUSINESS, "\u53e6\u4e00\u6761\u8ba2\u5355"), (False, True), (0, 2**1024), ("paid", "refunded")):
            with self.subTest(normal=normal, sensitive=sensitive):
                _, args = self.semantic((normal, normal, sensitive))
                result = assessment.evaluate(self.project, args)
                self.assertEqual("refuted", result["outcome"])
                engine._decision_valid(self.project, self.project.get("decision", result["id"]))

    def test_denial_or_acknowledgement_state_invariant_readbacks_never_confirm(self):
        for old, new in ((DENIED, INSUFFICIENT), ("pending", DENIED), ("pending", ACK)):
            with self.subTest(old=old, new=new):
                item, args = self.state_invariant(old, new)
                before = self.project.list("decision")
                with self.assertRaises(EngineError) as caught:
                    assessment.evaluate(self.project, args)
                self.assertEqual("control_invalid", caught.exception.code)
                self.assertEqual(before, self.project.list("decision"))
                self.assertEqual("open", self.project.get("obligation", item["id"])["status"])

    def test_legacy_denial_state_invariant_reopens(self):
        item, args = self.state_invariant("pending", DENIED)
        with patch.object(assessment, "has_business_state", side_effect=legacy_business_state):
            legacy = assessment.evaluate(self.project, args)
        self.assertEqual("confirmed", legacy["outcome"])
        self.assert_legacy_reopens(self.project, item, legacy, "control_invalid")

    def test_pure_boolean_numeric_and_string_response_flags_are_not_state_invariants(self):
        for field, old, new in (("ok", False, True), ("success", 0, 1), ("isAuthorized", "pending", "paid"), ("\u6210\u529f", False, True)):
            with self.subTest(field=field):
                _, args = self.state_invariant(old, new, field)
                before = self.project.list("decision")
                with self.assertRaises(EngineError) as caught:
                    assessment.evaluate(self.project, args)
                self.assertEqual("control_invalid", caught.exception.code)
                self.assertEqual(before, self.project.list("decision"))

    def test_legacy_boolean_response_flag_state_invariant_reopens(self):
        item, args = self.state_invariant(False, True, "ok")
        with patch.object(assessment, "control_signal_selector", return_value=False):
            legacy = assessment.evaluate(self.project, args)
        self.assertEqual("confirmed", legacy["outcome"])
        self.assert_legacy_reopens(self.project, item, legacy, "control_invalid")

    def test_status_code_data_and_named_boolean_business_states_remain_valid(self):
        for field, old, new in (("status", "paid", "refunded"), ("code", 1, 2), ("data", False, True),
                                ("is_active", False, True), ("\u72b6\u6001", "\u5df2\u652f\u4ed8", "\u5df2\u9000\u6b3e")):
            with self.subTest(field=field):
                _, args = self.state_invariant(old, new, field)
                result = assessment.evaluate(self.project, args)
                self.assertEqual("confirmed", result["outcome"])
                engine._decision_valid(self.project, self.project.get("decision", result["id"]))

    def test_real_unicode_boolean_and_large_integer_state_invariants_remain_valid(self):
        for old, new in (("paid", "\u5df2\u9000\u6b3e"), (False, True), (0, 2**1024)):
            with self.subTest(old=old, new=new):
                _, args = self.state_invariant(old, new)
                result = assessment.evaluate(self.project, args)
                self.assertEqual("confirmed", result["outcome"])
                engine._decision_valid(self.project, self.project.get("decision", result["id"]))

    def test_normal_baseline_assertion_is_not_changed_into_a_security_proof_gate(self):
        fixture = self.controls_fixture
        evidence = fixture.capture(response={"data": DENIED})
        result = assessment.evaluate(self.project, {"obligation_id": fixture.obligation("baseline")["id"],
            "evidence_ids": [evidence["id"]], "oracle": {"type": "baseline", "selector": "/data", "expected": DENIED}})
        self.assertEqual("refuted", result["outcome"])
        self.assertEqual("open", self.project.get("obligation", fixture.obligation("input_test")["id"])["status"])


class LocalizedScenarioReadbackTests(OfflineFixtureTests):
    def setUp(self):
        super().setUp()
        self.state = self.fixture(state_fixtures.StateTransitionTests)
        self.project = self.state.project

    def scenario_states(self, old, new, field="state"):
        original = self.state.observed
        readbacks = iter((old, new))

        def observed(url, method, headers, body, timeout, max_bytes):
            artifact = original(url, method, headers, body, timeout, max_bytes)
            if method == "GET" and urlsplit(url).path == "/profile":
                response = json.loads(base64.b64decode(artifact["response"]["body_base64"]))
                response[field] = next(readbacks)
                raw = json.dumps(response, ensure_ascii=False).encode("utf-8")
                artifact["response"].update(body_base64=base64.b64encode(raw).decode("ascii"), length=len(raw))
            return artifact

        with patch.object(self.state, "observed", side_effect=observed):
            run = self.state.scenario()
        oracle = self.state.oracle(run, selector="/" + field, before_expected=old, forbidden_after=new)
        oracle.pop("max_delta")
        return {"obligation_id": self.state.item["id"], "evidence_ids": run["evidence_ids"], "oracle": oracle}

    def test_scenario_denial_and_acknowledgement_are_not_business_readbacks(self):
        for old, new in ((DENIED, INSUFFICIENT), ("paid", DENIED), ("paid", ACK)):
            with self.subTest(old=old, new=new):
                args = self.scenario_states(old, new)
                before = self.project.list("decision")
                with self.assertRaises(EngineError) as caught:
                    assessment.evaluate(self.project, args)
                self.assertEqual("state_readback", caught.exception.code)
                self.assertEqual(before, self.project.list("decision"))

    def test_legacy_scenario_denial_confirmation_reopens(self):
        args = self.scenario_states("paid", DENIED)
        with patch.object(assessment, "has_business_state", side_effect=legacy_business_state):
            legacy = assessment.evaluate(self.project, args)
        self.assertEqual("confirmed", legacy["outcome"])
        self.assert_legacy_reopens(self.project, self.state.item, legacy, "state_readback")

    def test_scenario_pure_authorization_and_success_flag_readbacks_are_rejected(self):
        for field, old, new in (("allowed", False, True), ("authenticated", 0, 1), ("isAuthorized", "pending", "paid"),
                                ("\u6210\u529f", False, True)):
            with self.subTest(field=field):
                args = self.scenario_states(old, new, field)
                before = self.project.list("decision")
                with self.assertRaises(EngineError) as caught:
                    assessment.evaluate(self.project, args)
                self.assertEqual("state_selector", caught.exception.code)
                self.assertEqual(before, self.project.list("decision"))

    def test_legacy_scenario_authorization_flag_confirmation_reopens(self):
        args = self.scenario_states(False, True, "allowed")
        with patch.object(assessment, "control_signal_selector", return_value=False):
            legacy = assessment.evaluate(self.project, args)
        self.assertEqual("confirmed", legacy["outcome"])
        self.assert_legacy_reopens(self.project, self.state.item, legacy, "state_selector")

    def test_scenario_domain_status_data_and_named_boolean_readbacks_remain_valid(self):
        for field, old, new in (("status", "paid", "refunded"), ("data", False, True), ("is_active", False, True)):
            with self.subTest(field=field):
                result = assessment.evaluate(self.project, self.scenario_states(old, new, field))
                self.assertEqual("confirmed", result["outcome"])
                engine._decision_valid(self.project, self.project.get("decision", result["id"]))

    def test_real_unicode_boolean_zero_and_large_integer_scenario_states_remain_valid(self):
        for old, new in (("paid", "\u5df2\u9000\u6b3e"), (False, True), (0, 2**1024)):
            with self.subTest(old=old, new=new):
                result = assessment.evaluate(self.project, self.scenario_states(old, new))
                self.assertEqual("confirmed", result["outcome"])
                engine._decision_valid(self.project, self.project.get("decision", result["id"]))


class LocalizedClosureReadbackTests(OfflineFixtureTests):
    def setUp(self):
        super().setUp()
        self.review = self.fixture(review_fixtures.LegacyReviewGateTests)
        self.project = self.review.project

    def readback(self, value):
        source, run, resource, read = self.review.write_and_read(response={"state": value})
        row = self.review.fixture.checklist("unreconciled_run", run["id"])
        binding = self.review.binding(source, resource, selector="/state", expected=value)
        return run, read, row, binding

    def test_localized_denial_and_ack_readbacks_cannot_archive_uncertain_writes(self):
        for value in (DENIED, INSUFFICIENT, ACK, [DENIED, ACK], {"data": DENIED}, "Permission denied: missing role."):
            with self.subTest(value=value):
                _, read, row, binding = self.readback(value)
                before = self.project.list("closure_review")
                with self.assertRaises(EngineError) as caught:
                    self.review.review(row, evidence_ids=[read["id"]], readback_bindings=[binding])
                self.assertEqual("reconciliation_evidence", caught.exception.code)
                self.assertEqual(before, self.project.list("closure_review"))

    def test_engine_minted_legacy_denial_readback_receipt_is_revalidated_as_pending(self):
        run, read, row, binding = self.readback(DENIED)
        with patch.object(transport, "has_business_state", side_effect=legacy_business_state):
            receipt = self.review.review(row, evidence_ids=[read["id"]], readback_bindings=[binding])
        private = self.project.get("closure_review", receipt["review"]["id"])
        self.review.assert_legacy_write_retained(run, private)

    def test_real_unicode_domain_boolean_zero_and_large_integer_readbacks_remain_valid(self):
        for value in (BUSINESS, "paid", False, 0, 2**1024, {"balance": 0, "enabled": True, "state": BUSINESS}):
            with self.subTest(value=value):
                run, read, row, binding = self.readback(value)
                receipt = self.review.review(row, evidence_ids=[read["id"]], readback_bindings=[binding])
                private = deepcopy(self.project.get("closure_review", receipt["review"]["id"]))
                audit = self.review.audit()
                self.assertFalse(any(item.get("run_id") == run["id"] for item in audit["checklist"]))
                self.assertEqual(private, self.project.get("closure_review", private["id"]))
                self.assertEqual("failed", self.project.get("run", run["id"])["status"])


if __name__ == "__main__":
    unittest.main()
