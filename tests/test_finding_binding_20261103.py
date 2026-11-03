"""Offline proof reuse, immutable finding replacement and failure atomicity."""
from __future__ import annotations

import base64
from copy import deepcopy
import json
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

from awa_ddd import browser, completeness, engine, workflow
from awa_ddd.assessment import evaluate, record_finding
from awa_ddd.finding_binding import bind_finding
from awa_ddd.scenario import run_scenario
from awa_ddd.store import EngineError, Project, now


class FindingBindingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="awa-finding-binding-")
        self.addCleanup(temporary.cleanup)
        self.base = "http://fixture.invalid"
        engine.create_project(temporary.name, {"project_id": "binding", "target": self.base, "allow_mutation": True})
        self.project = Project(temporary.name, "binding")
        self.addCleanup(self.project.close)
        self.operation = engine.register_operation(self.project, {
            "url": self.base + "/preview", "method": "GET", "auth": "public",
            "inputs": [{"name": "url", "location": "query", "consumer": "outbound_http", "test_families": ["ssrf"]}],
        })
        engine.build_plan(self.project)

    def observed(self, url, method, headers, body, timeout, max_bytes, *, response=None):
        started = now()
        sent = body if isinstance(body, bytes) else body.encode("utf-8") if isinstance(body, str) else b""
        raw = json.dumps(response if response is not None else {"value": "ordinary"}).encode("utf-8")
        return {"request": {"url": url, "method": method, "headers": headers, "body_base64": base64.b64encode(sent).decode("ascii")},
                "response": {"status": 200, "headers": [["content-type", "application/json"]], "length": len(raw),
                             "body_base64": base64.b64encode(raw).decode("ascii")},
                "complete": True, "started_at": started, "completed_at": now()}

    def capture(self, value="ordinary", *, operation=None, response=None, **extra):
        operation = operation or self.operation
        with patch.object(engine, "request", side_effect=lambda *args: self.observed(*args, response=response)):
            return engine.capture(self.project, {"operation_id": operation["id"],
                "url": operation["url"] + "?" + urlencode({operation["inputs"][0]["name"]: value}) if operation["inputs"] else operation["url"],
                **extra})

    def proof(self):
        source = "http://canary.invalid/bounded-fixture"
        captures = [self.capture(source, response={"value": "CANARY-2048-FIXTURE"}),
                    self.capture("http://ordinary.invalid/bounded-fixture")]
        item = next(row for row in self.project.list("obligation") if row.get("test_family") == "ssrf" and not row.get("superseded"))
        decision = evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": [row["id"] for row in captures],
            "oracle": {"type": "extraction", "test_family": "ssrf", "selector": "/value", "expect": "^CANARY-2048-FIXTURE$",
                       "expected_value": "CANARY-2048-FIXTURE", "source_reference": source}})
        self.assertEqual("confirmed", decision["outcome"])
        return decision, captures, item

    def analyst_args(self, ids, *, category="SSRF", **extra):
        return {"mode": "analyst", "title": "Bounded URL recovery", "category": category, "impact": "One fixture source recovered",
                "remediation": "Constrain the actual fetch destination", "severity": "high", "origin": "hint_guided",
                "limitations": ["Only the recorded source and its negative control were observed."],
                "reviewer": "fixture reviewer", "reason": "Reviewed the original captures", "evidence_ids": ids, **extra}

    def original(self, captures, **extra):
        return record_finding(self.project, self.analyst_args([row["id"] for row in captures], **extra))

    def arguments(self, original, proof):
        return {"finding_id": original["id"], "decision_id": proof["id"], "reviewer": "fixture reviewer",
                "reason": "Bind only the existing source controls to their independently evaluated proof"}

    def snapshot(self):
        return ([tuple(row) for row in self.project.connection.execute("SELECT * FROM entities ORDER BY kind,id")],
                [tuple(row) for row in self.project.connection.execute("SELECT * FROM events ORDER BY seq")])

    def rejects(self, action, args, code=None):
        before = self.snapshot()
        with patch.object(engine, "request") as network:
            with self.assertRaises(EngineError) as caught:
                action(self.project, args)
        network.assert_not_called()
        if code:
            self.assertEqual(code, caught.exception.code)
        self.assertEqual(before, self.snapshot())

    def test_analyst_reuses_current_typed_proof_without_changing_its_decision_or_obligation(self):
        proof, captures, item = self.proof()
        before = deepcopy((self.project.get("decision", proof["id"]), self.project.get("obligation", item["id"])))
        with patch.object(engine, "request") as network:
            finding = record_finding(self.project, self.analyst_args(proof["evidence_ids"], proof_decision_id=proof["id"]))
            audit = completeness.audit(self.project, {})
        network.assert_not_called()
        decision = self.project.get("decision", finding["decision_id"])
        self.assertEqual("analyst", finding["mode"])
        self.assertEqual(proof["id"], decision["proof_decision_id"])
        self.assertEqual(proof["oracle"], decision["oracle"])
        self.assertEqual(proof["proof"], decision["proof"])
        self.assertEqual(item["id"], decision["obligation_id"])
        self.assertEqual(0, audit["completion"]["unlinked_analyst_findings"])
        self.assertEqual(before, (self.project.get("decision", proof["id"]), self.project.get("obligation", item["id"])))

    def test_analyst_wrong_family_unknown_category_and_conflicting_proof_ids_fail_atomically(self):
        proof, captures, _ = self.proof()
        for category in ("XXE", "Information Disclosure", "信息泄露"):
            self.rejects(record_finding, self.analyst_args(proof["evidence_ids"], category=category,
                         proof_decision_id=proof["id"]), "oracle_family")
        self.rejects(record_finding, self.analyst_args(proof["evidence_ids"], proof_decision_id=proof["id"],
                     decision_id="D-different"), "finding_decision")

    def test_analyst_requires_the_exact_typed_evidence_set_and_order(self):
        proof, _, _ = self.proof()
        for ids in (proof["evidence_ids"][:1], list(reversed(proof["evidence_ids"])), [proof["evidence_ids"][0]] * 2):
            self.rejects(record_finding, self.analyst_args(ids, proof_decision_id=proof["id"]), "evidence_binding")

    def test_analyst_text_and_refuted_baselines_cannot_be_reused_as_positive_proof(self):
        proof, captures, _ = self.proof()
        original = self.original(captures)
        self.rejects(record_finding, self.analyst_args(proof["evidence_ids"], proof_decision_id=original["decision_id"]), "finding_proof")
        baseline = next(row for row in self.project.list("obligation") if row["operation_id"] == self.operation["id"] and row["kind"] == "baseline")
        normal = evaluate(self.project, {"obligation_id": baseline["id"], "evidence_ids": [captures[1]["id"]],
            "oracle": {"type": "baseline", "selector": "/value", "expected": "ordinary"}})
        self.rejects(record_finding, self.analyst_args(normal["evidence_ids"], proof_decision_id=normal["id"]), "finding_proof")
        forged = {**normal, "id": self.project.id("D"), "outcome": "confirmed"}
        self.project.put("decision", forged)
        baseline.update(status="evaluated", decision_id=forged["id"])
        self.project.put("obligation", baseline)
        self.rejects(record_finding, self.analyst_args(forged["evidence_ids"], proof_decision_id=forged["id"]), "finding_proof")

    def test_stale_replaced_and_removed_obligations_cannot_supply_proof(self):
        proof, captures, item = self.proof()
        newer = evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": proof["evidence_ids"], "oracle": proof["oracle"]})
        self.rejects(record_finding, self.analyst_args(proof["evidence_ids"], proof_decision_id=proof["id"]), "finding_proof_current")
        changed = self.project.get("obligation", item["id"])
        changed["superseded"] = True
        self.project.put("obligation", changed)
        self.rejects(record_finding, self.analyst_args(newer["evidence_ids"], proof_decision_id=newer["id"]), "finding_proof_current")

    def test_binding_appends_a_typed_finding_and_preserves_old_proof_with_a_lifecycle_revision(self):
        proof, captures, item = self.proof()
        extra = self.capture("http://another-ordinary.invalid/bounded-fixture")
        original = self.original(captures + [extra])
        old_decision = deepcopy(self.project.get("decision", original["decision_id"]))
        typed_decision = deepcopy(self.project.get("decision", proof["id"]))
        with patch.object(engine, "request") as network:
            result = bind_finding(self.project, self.arguments(original, proof))
            audit = completeness.audit(self.project, {})
        network.assert_not_called()
        replacement = result["finding"]
        self.assertNotEqual(original["id"], replacement["id"])
        for field in ("title", "category", "impact", "remediation", "severity", "origin", "limitations"):
            self.assertEqual(original[field], replacement[field])
        self.assertEqual("machine", replacement["mode"])
        self.assertEqual(proof["id"], replacement["decision_id"])
        self.assertEqual(proof["evidence_ids"], replacement["evidence_ids"])
        preserved = self.project.get("finding", original["id"])
        for field, value in original.items():
            self.assertEqual(value, preserved[field])
        self.assertEqual("superseded", preserved["lifecycle_status"])
        self.assertEqual(replacement["id"], preserved["replacement_finding_id"])
        self.assertEqual(old_decision, self.project.get("decision", original["decision_id"]))
        self.assertEqual(typed_decision, self.project.get("decision", proof["id"]))
        self.assertEqual(proof["id"], self.project.get("obligation", item["id"])["decision_id"])
        self.assertEqual(1, len(self.project.list("finding_revision")))
        self.assertEqual(0, audit["completion"]["unlinked_analyst_findings"])
        self.assertEqual(0, result["requests_sent"])
        self.assertTrue(result["original_proof_preserved"])
        self.rejects(bind_finding, self.arguments(original, proof), "finding_binding_lifecycle")

    def test_binding_rejects_missing_controls_and_unrelated_original_operations(self):
        proof, captures, _ = self.proof()
        incomplete = self.original(captures[:1])
        self.rejects(bind_finding, self.arguments(incomplete, proof), "evidence_binding")
        other = engine.register_operation(self.project, {"url": self.base + "/other", "method": "GET", "auth": "public"})
        extra = self.capture(operation=other)
        unrelated = self.original(captures + [extra])
        self.rejects(bind_finding, self.arguments(unrelated, proof), "evidence_binding")

    def test_binding_never_guesses_a_category_or_accepts_another_analyst_label_as_proof(self):
        proof, captures, _ = self.proof()
        for category in ("XXE", "Information Disclosure", "信息泄露"):
            original = self.original(captures, category=category)
            self.rejects(bind_finding, self.arguments(original, proof), "oracle_family")
        original = self.original(captures)
        analyst_proof = self.project.get("decision", original["decision_id"])
        self.rejects(bind_finding, self.arguments(original, analyst_proof), "finding_proof")

    def test_binding_rejects_a_real_but_no_longer_current_proof(self):
        proof, captures, item = self.proof()
        original = self.original(captures)
        evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": proof["evidence_ids"], "oracle": proof["oracle"]})
        self.rejects(bind_finding, self.arguments(original, proof), "finding_proof_current")

    def test_binding_rejects_withdrawn_already_bound_and_already_published_proof(self):
        proof, captures, _ = self.proof()
        withdrawn = self.original(captures)
        workflow.update_finding(self.project, {"finding_id": withdrawn["id"], "status": "withdrawn", "reviewer": "fixture", "reason": "fixture withdrawal"})
        self.rejects(bind_finding, self.arguments(withdrawn, proof), "finding_binding_lifecycle")
        original = self.original(captures)
        already_bound = record_finding(self.project, self.analyst_args(proof["evidence_ids"], proof_decision_id=proof["id"]))
        self.rejects(bind_finding, self.arguments(already_bound, proof), "finding_binding_duplicate")
        self.rejects(bind_finding, self.arguments(original, proof), "finding_binding_duplicate")

    def test_binding_rejects_changed_original_support_even_when_selected_proof_is_intact(self):
        proof, captures, _ = self.proof()
        extra = self.capture("http://extra-ordinary.invalid/bounded-fixture")
        original = self.original(captures + [extra])
        artifact = self.project.base / extra["artifact_path"]
        artifact.write_bytes(artifact.read_bytes() + b" ")
        self.rejects(bind_finding, self.arguments(original, proof), "evidence_changed")

    def test_binding_failure_after_new_finding_creation_rolls_back_entities_and_events(self):
        proof, captures, _ = self.proof()
        original = self.original(captures)
        with patch.object(workflow, "update_finding", side_effect=EngineError("fixture_failure", "Injected lifecycle failure")):
            self.rejects(bind_finding, self.arguments(original, proof), "fixture_failure")

    def test_binding_arguments_are_bounded_and_cannot_change_original_report_fields(self):
        proof, captures, _ = self.proof()
        original = self.original(captures)
        for extra in ({"category": "XXE"}, {"reviewer": ""}, {"reason": "x" * 4001}, {"decision_id": None}):
            self.rejects(bind_finding, {**self.arguments(original, proof), **extra}, "finding_binding")

    def test_existing_unbound_xss_runtime_uses_its_existing_runtime_binding_entry(self):
        marker = "AWA-XSS-0011223344556677"
        operation = engine.register_operation(self.project, {"url": self.base + "/render", "method": "GET", "auth": "public",
            "inputs": [{"name": "content", "location": "query", "consumer": "html_render", "test_families": ["xss"]}]})
        engine.build_plan(self.project)
        attack = self.capture("<img src=x onerror=alert('" + marker + "')>", operation=operation)
        url = self.project.read_artifact(attack)["request"]["url"]
        visit = browser._record_observation(self.project, {"url": url, "finalUrl": url, "status": 200, "signals": {"forms": 1},
            "dialogs": [{"type": "alert", "message": marker, "action_index": None}],
            "network": [{"url": url, "method": "GET", "type": "document", "status": 200, "request_headers": {}}]},
            self.project.id("PV"), "local_playwright")
        original = self.original([attack], category="XSS", runtime_visit_id=visit["id"], consumer_url=url, runtime_marker=marker)
        proof, _, _ = self.proof()
        self.rejects(bind_finding, self.arguments(original, proof), "finding_binding_channel")

    def actor(self, name, roles):
        engine.add_actor(self.project, {"actor_id": name, "subject": name, "roles": roles})
        session = engine.add_session(self.project, {"actor_id": name, "headers": {"Cookie": "SID=" + name}})
        identity = engine.register_operation(self.project, {"url": self.base + "/identity", "method": "GET", "auth": "authenticated"})
        with patch.object(engine, "request", side_effect=lambda *args: self.observed(*args, response={"subject": name, "roles": roles})):
            engine.verify_identity(self.project, {"operation_id": identity["id"], "session_id": session["id"],
                "subject_selector": "/subject", "roles_selector": "/roles"})
        return self.project.get("session", session["id"])

    def test_authorization_proof_reuse_accepts_a_concrete_chinese_category_without_a_proof_object(self):
        sessions = [self.actor("owner", ["admin"]), self.actor("viewer", ["user"])]
        operation = engine.register_operation(self.project, {"url": self.base + "/protected", "method": "GET",
            "auth": "restricted", "allowed_roles": ["admin"]})
        engine.build_plan(self.project)
        captures = [self.capture(operation=operation, session_id=session["id"], response={"data": {"record": "protected-fixture"}})
                    for session in sessions]
        item = next(row for row in self.project.list("obligation") if row["operation_id"] == operation["id"]
                    and row["kind"] == "access" and row.get("actor_id") == "viewer" and not row.get("superseded"))
        proof = evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": [row["id"] for row in captures],
            "oracle": {"type": "authorization", "selector": "/data/record"}})
        self.assertNotIn("proof", proof)
        finding = record_finding(self.project, self.analyst_args(proof["evidence_ids"], category="越权访问", proof_decision_id=proof["id"]))
        self.assertEqual(proof["id"], self.project.get("decision", finding["decision_id"])["proof_decision_id"])
        self.assertEqual(0, completeness.audit(self.project, {})["completion"]["unlinked_analyst_findings"])

    def state_proof(self):
        session = self.actor("alice", ["user"])
        read = engine.register_operation(self.project, {"url": self.base + "/profile", "method": "GET",
            "auth": "authenticated", "state_scope": "actor"})
        action = engine.register_operation(self.project, {"url": self.base + "/orders/{order_no}/refund", "method": "POST",
            "auth": "authenticated", "inputs": [{"name": "order_no", "location": "path"},
                {"name": "amount", "location": "body", "consumer": "refund_amount", "test_families": ["business_logic"]}]})
        resource = engine.add_resource(self.project, {"operation_id": action["id"], "owner_actor_id": "alice", "external_id": "ORDER-1",
            "request_binding": {"location": "path", "selector": "order_no"}})
        engine.build_plan(self.project)
        balance = [100]

        def response(url, method, headers, body, timeout, max_bytes):
            if isinstance(body, dict):
                body = json.dumps(body).encode("utf-8")
                headers = {**headers, "content-type": "application/json"}
            if method == "POST":
                amount = json.loads(body)["amount"]
                balance[0] += amount
                value = {"success": True, "amount": amount}
            else:
                value = {"subject": "alice", "balance": balance[0]}
            return self.observed(url, method, headers, body, timeout, max_bytes, response=value)

        with patch.object(engine, "request", side_effect=response):
            run = run_scenario(self.project, {"scenario": {"steps": [
                {"id": "before", "operation_id": read["id"], "session_id": session["id"]},
                {"id": "action", "operation_id": action["id"], "url": self.base + "/orders/ORDER-1/refund",
                 "session_id": session["id"], "resource_id": resource["id"], "effect": "test_resource_write", "body": {"amount": 500}},
                {"id": "after", "operation_id": read["id"], "session_id": session["id"]},
            ]}})
        item = next(row for row in self.project.list("obligation") if row.get("test_family") == "business_logic" and not row.get("superseded"))
        proof = evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": run["evidence_ids"], "oracle": {
            "type": "state_transition", "test_family": "business_logic", "scenario_run_id": run["id"],
            "before_step_id": "before", "action_step_id": "action", "after_step_id": "after", "selector": "/balance",
            "before_expected": 100, "action_input_expected": 500, "action_success_selector": "/success", "action_success_expected": True,
            "max_delta": 100, "readback_scope": {"type": "actor", "subject_selector": "/subject", "relation": "The fixture refund credits the acting account"}}})
        self.assertEqual("confirmed", proof["outcome"])
        return proof, [self.project.get("evidence", identity) for identity in proof["evidence_ids"]], run

    def test_genuine_cross_operation_state_readbacks_bind_only_the_verified_scenario(self):
        proof, captures, _ = self.state_proof()
        original = self.original(captures, category="交易篡改")
        with patch.object(engine, "request") as network:
            result = bind_finding(self.project, self.arguments(original, proof))
        network.assert_not_called()
        self.assertEqual(proof["evidence_ids"], result["finding"]["evidence_ids"])
        self.assertEqual("superseded", self.project.get("finding", original["id"])["lifecycle_status"])

    def test_changed_state_scenario_checkpoint_cannot_bind_a_saved_manual_claim(self):
        proof, captures, run = self.state_proof()
        original = self.original(captures, category="业务逻辑")
        changed = deepcopy(run)
        changed["checkpoints"][1]["status"] = "failed"
        self.project.put("run", changed)
        self.rejects(bind_finding, self.arguments(original, proof), "state_scenario")


if __name__ == "__main__":
    unittest.main()
