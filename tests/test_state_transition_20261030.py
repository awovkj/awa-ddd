"""Offline, scenario-owned state transition proof and association regressions."""
from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from awa_ddd import engine
from awa_ddd.assessment import evaluate, record_finding
from awa_ddd.scenario import run_scenario
from awa_ddd.store import EngineError, Project, now


class StateTransitionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-state-transition-")
        self.addCleanup(self.tmp.cleanup)
        self.base = "http://fixture.invalid"
        engine.create_project(self.tmp.name, {"project_id": "state", "target": self.base, "allow_mutation": True})
        self.project = Project(self.tmp.name, "state")
        self.addCleanup(self.project.close)
        self.balance, self.write_success, self.subject_override = 900, True, None
        self.identity = engine.register_operation(self.project, {"url": self.base + "/whoami", "method": "GET", "auth": "authenticated"})
        self.read = engine.register_operation(self.project, {"url": self.base + "/profile", "method": "GET", "auth": "authenticated", "state_scope": "actor"})
        self.action = engine.register_operation(self.project, {"url": self.base + "/orders/{order_no}/refund", "method": "POST", "auth": "authenticated",
            "inputs": [{"name": "order_no", "location": "path", "consumer": "unknown"},
                       {"name": "amount", "location": "body", "consumer": "refund_amount", "test_families": ["business_logic"]}]})
        self.sessions = {}
        for subject in ("alice", "bob"):
            engine.add_actor(self.project, {"actor_id": subject, "subject": subject, "roles": ["user"], "tenant_id": "tenant"})
            session = engine.add_session(self.project, {"actor_id": subject, "headers": {"Cookie": "SID=" + subject}})
            with patch.object(engine, "request", side_effect=self.observed):
                engine.verify_identity(self.project, {"operation_id": self.identity["id"], "session_id": session["id"],
                                                       "subject_selector": "/subject", "roles_selector": "/roles", "tenant_selector": "/tenant"})
            self.sessions[subject] = session["id"]
        self.resource = engine.add_resource(self.project, {"operation_id": self.action["id"], "owner_actor_id": "alice", "external_id": "ORDER-1",
                                                           "request_binding": {"location": "path", "selector": "order_no"}})
        engine.build_plan(self.project)
        self.item = next(row for row in self.project.list("obligation") if row.get("test_family") == "business_logic" and not row.get("superseded"))

    def observed(self, url, method, headers, body, timeout, max_bytes):
        started = now()
        subject = headers.get("cookie", "SID=alice").partition("=")[2]
        if isinstance(body, (dict, list)):
            sent = json.dumps(body, separators=(",", ":")).encode()
            headers = {**headers, "content-type": "application/json"}
        else:
            sent = body if isinstance(body, bytes) else body.encode() if isinstance(body, str) else b""
        if method == "POST":
            amount = json.loads(sent)["amount"]
            if self.write_success:
                self.balance += amount
            response = {"success": self.write_success, "amount": amount}
        elif urlsplit(url).path == "/whoami":
            response = {"subject": subject, "roles": ["user"], "tenant": "tenant"}
        else:
            response = {"subject": self.subject_override or subject, "balance": self.balance, "success": True}
        raw = json.dumps(response, separators=(",", ":")).encode()
        return {"request": {"url": url, "method": method, "headers": headers, "body_base64": base64.b64encode(sent).decode()},
                "response": {"status": 200, "headers": [], "body_base64": base64.b64encode(raw).decode(), "length": len(raw)},
                "complete": True, "started_at": started, "completed_at": now()}

    def steps(self, amount=999999, *, reader=None, reader_resource=None, after_session=None, after_headers=None):
        reader = reader or self.read
        before = {"id": "before", "operation_id": reader["id"], "session_id": self.sessions["alice"]}
        after = {**before, "id": "after"}
        if reader_resource:
            before.update(resource_id=reader_resource["id"], url=reader["url"].replace("{order_no}", reader_resource["external_id"]))
            after.update(resource_id=reader_resource["id"], url=before["url"])
        if after_session:
            after["session_id"] = after_session
        if after_headers:
            after["headers"] = after_headers
        action = {"id": "action", "operation_id": self.action["id"], "url": self.base + "/orders/ORDER-1/refund",
                  "session_id": self.sessions["alice"], "resource_id": self.resource["id"], "effect": "test_resource_write", "body": {"amount": amount}}
        return [before, action, after]

    def scenario(self, steps=None):
        with patch.object(engine, "request", side_effect=self.observed):
            return run_scenario(self.project, {"scenario": {"steps": steps or self.steps()}})

    def oracle(self, run, **extra):
        return {"type": "state_transition", "test_family": "business_logic", "scenario_run_id": run["id"],
                "before_step_id": "before", "action_step_id": "action", "after_step_id": "after", "selector": "/balance",
                "before_expected": 900, "action_input_expected": 999999, "action_success_selector": "/success", "action_success_expected": True,
                "readback_scope": {"type": "actor", "subject_selector": "/subject", "relation": "The refund credits the acting account's balance"},
                "max_delta": 100, **extra}

    def decide(self, run, **extra):
        return evaluate(self.project, {"obligation_id": self.item["id"], "evidence_ids": run["evidence_ids"], "oracle": self.oracle(run, **extra)})

    def test_refund_cross_operation_chain_confirms_and_revalidates_a_finding(self):
        run = self.scenario()
        decision = self.decide(run)
        self.assertEqual(decision["outcome"], "confirmed")
        self.assertEqual(decision["proof"]["scope"], "bounded_state_transition")
        self.assertEqual(decision["proof"]["after_value"], 1000899)
        finding = record_finding(self.project, {"decision_id": decision["id"], "title": "fixture over-refund", "category": "Business Logic Flaw",
                                               "impact": "fixture", "remediation": "fixture"})
        self.assertEqual(finding["status"], "confirmed")
        self.assertEqual(engine.evaluate_coverage(self.project)["evaluated"], 1)

    def test_unrelated_cross_operation_evidence_does_not_relax_the_old_oracle(self):
        run = self.scenario()
        with self.assertRaises(EngineError) as error:
            evaluate(self.project, {"obligation_id": self.item["id"], "evidence_ids": run["evidence_ids"],
                                   "oracle": {"type": "state_invariant", "test_family": "business_logic", "selector": "/balance", "before_expected": 900, "max_delta": 100}})
        self.assertEqual(error.exception.code, "evidence_binding")

    def test_no_violation_remains_inconclusive_not_refuted(self):
        run = self.scenario(self.steps(50))
        decision = self.decide(run, action_input_expected=50)
        self.assertEqual(decision["outcome"], "inconclusive")
        self.assertEqual(self.project.get("obligation", self.item["id"])["status"], "open")

    def test_false_business_success_is_rejected_even_when_http_and_scenario_succeeded(self):
        self.write_success = False
        run = self.scenario()
        self.assertEqual(run["status"], "succeeded")
        with self.assertRaises(EngineError) as error:
            self.decide(run)
        self.assertEqual(error.exception.code, "state_action_success")

    def test_changed_identity_or_read_headers_cannot_join_the_chain(self):
        for steps, code in ((self.steps(after_session=self.sessions["bob"]), "control_identity"),
                            (self.steps(after_headers={"X-Business": "different"}), "state_readback")):
            self.balance = 900
            run = self.scenario(steps)
            with self.assertRaises(EngineError) as error:
                self.decide(run)
            self.assertEqual(error.exception.code, code)

    def test_fake_completed_scenario_cannot_relabel_real_captures(self):
        run = self.scenario()
        fake = deepcopy(run)
        fake["id"] = "SC-fake"
        self.project.put("run", fake)
        self.project.event("scenario.completed", {"run_id": fake["id"], "steps": 3})
        with self.assertRaises(EngineError) as error:
            self.decide(fake)
        self.assertEqual(error.exception.code, "state_scenario")

    def test_wrong_evidence_order_or_nonconsecutive_checkpoints_are_rejected(self):
        run = self.scenario()
        reversed_ids = deepcopy(run)
        reversed_ids["evidence_ids"] = list(reversed(run["evidence_ids"]))
        with self.assertRaises(EngineError) as error:
            self.decide(reversed_ids)
        self.assertEqual(error.exception.code, "state_scenario")
        self.balance = 900
        steps = self.steps()
        steps.insert(2, {"id": "intervening", "operation_id": self.identity["id"], "session_id": self.sessions["alice"]})
        run = self.scenario(steps)
        with self.assertRaises(EngineError) as error:
            self.decide(run)
        self.assertEqual(error.exception.code, "state_order")

    def test_concurrent_action_is_not_a_sequential_state_proof(self):
        steps = self.steps()
        steps[1]["concurrent"] = 2
        run = self.scenario(steps)
        with self.assertRaises(EngineError) as error:
            self.decide(run)
        self.assertEqual(error.exception.code, "state_scenario")

    def test_missing_actor_scope_or_wrong_server_subject_is_rejected(self):
        reader = engine.register_operation(self.project, {"url": self.base + "/plain-profile", "method": "GET", "auth": "authenticated"})
        run = self.scenario(self.steps(reader=reader))
        with self.assertRaises(EngineError) as error:
            self.decide(run)
        self.assertEqual(error.exception.code, "state_scope")
        self.balance, self.subject_override = 900, "someone-else"
        run = self.scenario()
        with self.assertRaises(EngineError) as error:
            self.decide(run)
        self.assertEqual(error.exception.code, "state_scope")

    def test_resource_readbacks_require_real_matching_request_binding(self):
        reader = engine.register_operation(self.project, {"url": self.base + "/orders/{order_no}", "method": "GET", "auth": "authenticated",
                                                          "inputs": [{"name": "order_no", "location": "path", "consumer": "unknown"}]})
        for identifier, expected in (("ORDER-1", "confirmed"), ("UNRELATED-ORDER", "state_scope")):
            self.balance = 900
            resource = engine.add_resource(self.project, {"operation_id": reader["id"], "owner_actor_id": "alice", "external_id": identifier,
                                                           "request_binding": {"location": "path", "selector": "order_no"}})
            run = self.scenario(self.steps(reader=reader, reader_resource=resource))
            scope = {"type": "resource", "resource_id": resource["id"], "relation": "Read the same test order affected by the refund"}
            if expected == "confirmed":
                self.assertEqual(self.decide(run, readback_scope=scope)["outcome"], expected)
            else:
                with self.assertRaises(EngineError) as error:
                    self.decide(run, readback_scope=scope)
                self.assertEqual(error.exception.code, expected)

    def test_mutated_fixture_and_wrong_action_input_cannot_relabel_the_proof(self):
        run = self.scenario()
        with self.assertRaises(EngineError) as error:
            self.decide(run, action_input_expected=1)
        self.assertEqual(error.exception.code, "state_input")
        engine.add_resource(self.project, {"resource_id": self.resource["id"], "operation_id": self.action["id"], "owner_actor_id": "alice", "external_id": "CHANGED",
                                           "request_binding": {"location": "path", "selector": "order_no"}})
        with self.assertRaises(EngineError) as error:
            self.decide(run)
        self.assertEqual(error.exception.code, "resource_changed")

    def test_finite_invariants_and_business_selectors_are_required(self):
        run = self.scenario()
        for maximum in (True, -1, "NaN", "Infinity"):
            with self.assertRaises(EngineError) as error:
                self.decide(run, max_delta=maximum)
            self.assertEqual(error.exception.code, "numeric_invariant")
        with self.assertRaises(EngineError) as error:
            self.decide(run, selector="/success", before_expected=True)
        self.assertEqual(error.exception.code, "state_selector")

    def test_expired_ttl_does_not_erase_an_intact_captured_state_proof(self):
        run = self.scenario()
        session = self.project.get("session", self.sessions["alice"])
        session["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        self.project.put("session", session)
        self.assertEqual(self.decide(run)["outcome"], "confirmed")

    def test_forbidden_after_is_a_finite_bounded_state_not_an_absence_claim(self):
        run = self.scenario(self.steps(100))
        oracle = self.oracle(run, action_input_expected=100, forbidden_after=1000)
        oracle.pop("max_delta")
        decision = evaluate(self.project, {"obligation_id": self.item["id"], "evidence_ids": run["evidence_ids"], "oracle": oracle})
        self.assertEqual(decision["outcome"], "confirmed")
        for value in ({"status": "approved"}, "NaN", 900):
            modified = {**oracle, "forbidden_after": value}
            if value == "NaN":
                # A scalar string state cannot match a numeric readback; it is not a violation.
                self.assertEqual(evaluate(self.project, {"obligation_id": self.item["id"], "evidence_ids": run["evidence_ids"], "oracle": modified})["outcome"], "inconclusive")
            else:
                with self.assertRaises(EngineError):
                    evaluate(self.project, {"obligation_id": self.item["id"], "evidence_ids": run["evidence_ids"], "oracle": modified})

    def test_malformed_scenario_metadata_is_rejected_without_uncaught_type_errors(self):
        run = self.scenario()
        for field, value in (("preflight", True), ("checkpoints", [None, None, None]),
                             ("checkpoints", [{"step_id": [], "evidence_id": "E-none", "status": "verified"}] * 3)):
            fake = deepcopy(run)
            fake["id"] = "SC-malformed-" + field + str(type(value).__name__)
            fake[field] = value
            self.project.put("run", fake)
            with self.assertRaises(EngineError) as error:
                self.decide(fake)
            self.assertEqual(error.exception.code, "state_scenario")
        with self.assertRaises(EngineError) as error:
            self.decide(run, before_step_id=["before"])
        self.assertEqual(error.exception.code, "state_scenario")


if __name__ == "__main__":
    unittest.main()
