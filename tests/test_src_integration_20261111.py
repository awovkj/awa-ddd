"""Discovery-mode execution boundaries and offline exchange proof provenance."""
from __future__ import annotations

import base64
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

from awa_ddd import browser, engine, external, integration, scenario, tscanplus
from awa_ddd.__main__ import dispatch
from awa_ddd.assessment import evaluate
from awa_ddd.store import EngineError, Project, canonical, now


class SrcIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="awa-src-integration-")
        self.addCleanup(temporary.cleanup)
        self.workspace = temporary.name
        self.base = "http://fixture.invalid"
        engine.create_project(self.workspace, {"project_id": "src-project", "target": self.base,
                                              "assessment_mode": "src", "exclude": [self.base + "/excluded"]})
        self.project = Project(self.workspace, "src-project")
        self.addCleanup(self.project.close)
        self.operation = engine.register_operation(self.project, {
            "url": self.base + "/preview", "method": "GET", "auth": "public",
            "inputs": [{"name": "url", "location": "query", "consumer": "outbound_http", "test_families": ["ssrf"]}],
        })
        engine.build_plan(self.project)

    def invoke(self, action, **args):
        return dispatch(self.workspace, action, {"project_id": "src-project", **args})

    def rejects(self, function, code, *args, **kwargs):
        with self.assertRaises(EngineError) as raised:
            function(*args, **kwargs)
        self.assertEqual(code, raised.exception.code)
        return raised.exception

    def observed(self, url, method, headers, body, timeout, max_bytes, *, response=None):
        sent = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode() if isinstance(body, (dict, list)) else (body or "").encode() if isinstance(body, str) else body or b""
        raw = json.dumps(response or {"value": "ordinary-value"}, ensure_ascii=False).encode()
        return {"request": {"url": url, "method": method, "headers": headers,
                            "body_base64": base64.b64encode(sent).decode("ascii")},
                "response": {"status": 200, "headers": [["content-type", "application/json"]],
                             "length": len(raw), "body_base64": base64.b64encode(raw).decode("ascii")},
                "complete": True, "started_at": now(), "completed_at": now()}

    def capture(self, value="ordinary", *, operation=None, response=None, **args):
        operation = operation or self.operation
        with patch.object(engine, "request", side_effect=lambda *sent: self.observed(*sent, response=response)):
            return engine.capture(self.project, {"operation_id": operation["id"],
                "url": operation["url"] + "?" + urlencode({"url": value}), **args})

    def proof(self):
        source = "http://canary.invalid/bounded-fixture"
        captures = [self.capture(source, response={"value": "CANARY-2048-FIXTURE"}, idempotency_key="known-proof"),
                    self.capture("http://ordinary.invalid/bounded-fixture")]
        item = next(row for row in self.project.list("obligation") if row.get("test_family") == "ssrf" and not row.get("superseded"))
        decision = evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": [row["id"] for row in captures],
            "oracle": {"type": "extraction", "test_family": "ssrf", "selector": "/value", "expect": "^CANARY-2048-FIXTURE$",
                       "expected_value": "CANARY-2048-FIXTURE", "source_reference": source}})
        self.assertEqual("confirmed", decision["outcome"])
        return decision, captures

    def exchange(self, **changes):
        value = {"schema": integration.SCHEMA, "engagement": {"id": "rt-fixture", "name": "靶标示例", "mode": "src"},
                 "candidates": [{"external_id": "vuln-1", "url": self.operation["url"], "method": "GET",
                                 "title": "External SSRF candidate", "category": "ssrf", "severity": "high",
                                 "source_status": "confirmed", "evidence_refs": ["http-1"]}],
                 "http_evidence": [{"external_id": "http-1", "url": self.operation["url"], "method": "GET",
                                    "status_code": 200, "sha256": "a" * 64, "hash_scope": "metadata"}]}
        value.update(changes)
        return value

    def import_candidate(self, exchange=None):
        result = self.invoke("integration.import", exchange=exchange or self.exchange())
        return result, result["candidates"][0]["candidate_id"]

    def test_mode_is_persistent_and_immutable_even_through_direct_store(self):
        self.assertEqual("src", self.invoke("project.status")["config"]["assessment_mode"])
        self.rejects(self.invoke, "assessment_mode_immutable", "project.update", assessment_mode="assessment")
        self.rejects(self.invoke, "src_write_denied", "project.update", allow_mutation=True)
        self.rejects(self.project.set_config, "assessment_mode_immutable", {**self.project.config, "assessment_mode": "assessment"})
        self.rejects(self.project.set_config, "src_write_denied", {**self.project.config, "allow_mutation": True})
        with Project(self.workspace, "src-project") as reopened:
            self.assertEqual("src", reopened.config["assessment_mode"])
            self.assertFalse(reopened.config["allow_mutation"])
        self.rejects(engine.create_project, "src_write_denied", self.workspace,
                     {"project_id": "invalid", "target": self.base, "assessment_mode": "src", "allow_mutation": True})
        self.assertFalse((Path(self.workspace) / "projects" / "invalid").exists())

    def test_legacy_project_defaults_to_assessment_and_src_transport_does_not_widen_it(self):
        engine.create_project(self.workspace, {"project_id": "legacy", "target": self.base})
        with Project(self.workspace, "legacy") as legacy:
            config = legacy.config
            config.pop("assessment_mode")
            legacy.connection.execute("UPDATE metadata SET value=? WHERE key='config'", (canonical(config),))
            legacy.connection.commit()
            self.assertEqual("assessment", legacy.config["assessment_mode"])
            self.rejects(engine.update_project, "assessment_mode_immutable", legacy, {"assessment_mode": "src"})
        with patch.object(engine, "request") as target:
            for action in ("project.status", "http.capture", "tool.sqlmap", "scenario.run"):
                self.rejects(dispatch, "assessment_mode_mismatch", self.workspace, action,
                             {"project_id": "legacy", "required_assessment_mode": "src"})
            target.assert_not_called()

    def test_active_adapter_and_scenario_guards_run_before_executables_or_parsing(self):
        with patch.object(external, "_configured_executable") as executable, \
                patch.object(scenario, "_steps") as steps, patch.object(tscanplus, "_settings") as settings:
            for function in (external.sqlmap_run, external.yakit_replay, scenario.run_scenario, tscanplus.request_run):
                self.rejects(function, "src_action_denied", self.project, {})
            for action in ("tool.sqlmap", "tool.yakit_replay", "tool.tscanplus_request", "scenario.run", "test.run_external", "test.run_scenario"):
                self.rejects(self.invoke, "src_action_denied", action)
            executable.assert_not_called()
            steps.assert_not_called()
            settings.assert_not_called()

    def test_src_denies_writes_and_browser_interactions_before_target_dispatch(self):
        write = engine.register_operation(self.project, {"url": self.base + "/write", "method": "POST", "auth": "public"})
        with patch.object(engine, "request") as request, patch.object(browser, "probe") as probe:
            self.rejects(engine.capture, "src_write_denied", self.project, {"operation_id": write["id"], "effect": "test_resource_write"})
            self.rejects(engine.capture, "src_write_denied", self.project, {"operation_id": self.operation["id"], "effect": "test_resource_write"})
            self.rejects(browser.visit, "src_write_denied", self.project, {"url": self.base, "allow_write": True})
            self.rejects(browser.visit, "src_action_denied", self.project, {"url": self.base, "actions": [{"type": "click", "selector": "#submit"}]})
            request.assert_not_called()
            probe.assert_not_called()

    def test_src_caps_http_capture_and_keeps_unrelated_operations_available(self):
        with patch.object(engine, "request", side_effect=self.observed) as request:
            engine.capture(self.project, {"operation_id": self.operation["id"], "timeout": 60, "max_bytes": 4 * 1024 * 1024})
            self.assertEqual((15, 65536), request.call_args.args[-2:])
        result = self.invoke("plan.next", include_blocked=True)
        self.assertTrue(any(row["operation_id"] == self.operation["id"] for row in result["work_items"]))

    def test_direct_proof_freezes_operation_but_allows_cached_receipt_and_offline_review(self):
        decision, captures = self.proof()
        self.assertEqual(1, len(self.project.list("src_stop")))
        with patch.object(engine, "request") as request:
            self.rejects(engine.capture, "stopped_at_evidence", self.project, {"operation_id": self.operation["id"]})
            self.rejects(engine.capture, "stopped_at_evidence", self.project, {"operation_id": self.operation["id"], "idempotency_key": "new-proof"})
            cached = engine.capture(self.project, {"operation_id": self.operation["id"],
                "url": self.operation["url"] + "?" + urlencode({"url": "http://canary.invalid/bounded-fixture"}), "idempotency_key": "known-proof"})
            self.assertEqual(captures[0]["id"], cached["id"])
            request.assert_not_called()
        viewed = self.invoke("evidence.inspect", evidence_id=captures[0]["id"])
        self.assertTrue(viewed["usable"])
        prepared = self.invoke("assessment.prepare", operation_id=self.operation["id"])
        self.assertTrue(all(row["execution_blocked"] for row in prepared["items"]))
        self.assertTrue(all(row["suggested_action"] == "evidence.inspect" for row in prepared["items"]))
        status = self.invoke("project.status")
        self.assertEqual(decision["id"], status["assessment_policy"]["stopped_operations"][0]["decision_id"])
        other = engine.register_operation(self.project, {"url": self.base + "/other", "method": "GET", "auth": "public"})
        with patch.object(engine, "request", side_effect=self.observed):
            self.assertTrue(engine.capture(self.project, {"operation_id": other["id"]})["complete"])

    def test_changing_content_type_or_corrupting_evidence_cannot_reopen_src_execution(self):
        _, captures = self.proof()
        replacement = engine.register_operation(self.project, {"url": self.operation["url"], "method": "GET", "auth": "public", "content_type": "text/plain"})
        self.rejects(engine.capture, "stopped_at_evidence", self.project, {"operation_id": replacement["id"]})
        (self.project.base / captures[0]["artifact_path"]).write_text("{}", encoding="utf-8")
        self.rejects(engine.capture, "stopped_at_evidence", self.project, {"operation_id": self.operation["id"]})
        self.rejects(browser.visit, "stopped_at_evidence", self.project, {"url": self.operation["url"]})

    def test_registering_a_concrete_url_cannot_escape_a_stopped_operation_template(self):
        template = engine.register_operation(self.project, {"url": self.base + "/bound/{id}", "method": "GET", "auth": "public",
            "inputs": [{"name": "url", "location": "query", "consumer": "outbound_http", "test_families": ["ssrf"]}]})
        engine.build_plan(self.project)
        source = "http://canary.invalid/bounded-fixture"
        captures = []
        for value, response in ((source, {"value": "CANARY-2048-FIXTURE"}),
                                ("http://ordinary.invalid/bounded-fixture", {"value": "ordinary"})):
            with patch.object(engine, "request", side_effect=lambda *args: self.observed(*args, response=response)):
                captures.append(engine.capture(self.project, {"operation_id": template["id"],
                    "url": self.base + "/bound/one?" + urlencode({"url": value})}))
        item = next(row for row in self.project.list("obligation") if row.get("operation_id") == template["id"] and row.get("test_family") == "ssrf" and not row.get("superseded"))
        evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": [row["id"] for row in captures],
            "oracle": {"type": "extraction", "test_family": "ssrf", "selector": "/value", "expect": "^CANARY-2048-FIXTURE$",
                       "expected_value": "CANARY-2048-FIXTURE", "source_reference": source}})
        concrete = engine.register_operation(self.project, {"url": self.base + "/bound/one", "method": "GET", "auth": "public"})
        with patch.object(engine, "request") as target:
            self.rejects(engine.capture, "stopped_at_evidence", self.project, {"operation_id": concrete["id"]})
            self.rejects(browser.visit, "stopped_at_evidence", self.project, {"url": self.base + "/bound/two"})
            target.assert_not_called()

    def test_import_is_offline_candidate_only_idempotent_and_does_not_change_link_status(self):
        with patch.object(engine, "request") as request:
            first, candidate_id = self.import_candidate()
            self.assertEqual({"candidates": 1, "created": 1, "reused": 0, "http_metadata": 1}, first["counts"])
            self.assertEqual([], self.project.list("evidence"))
            self.assertEqual([], self.project.list("decision"))
            self.assertEqual([], self.project.list("finding"))
            self.invoke("candidate.link", candidate_id=candidate_id, operation_id=self.operation["id"], input_location="query", input_selector="url")
            repeated, repeated_id = self.import_candidate()
            self.assertEqual(candidate_id, repeated_id)
            self.assertEqual(0, repeated["counts"]["created"])
            self.assertEqual("linked", self.project.get("candidate", candidate_id)["status"])
            exported = self.invoke("integration.export", import_id=first["import_id"])
            self.assertFalse(exported["candidates"][0]["usable_for_confirmation"])
            self.assertEqual([], exported["candidates"][0]["decisions"])
            request.assert_not_called()

    def test_scope_exclude_shape_and_budgets_fail_before_partial_import(self):
        for url in ("http://outside.invalid/preview", self.base + "/excluded", self.base + "/excluded/child"):
            exchange = self.exchange()
            exchange["candidates"].append({**exchange["candidates"][0], "external_id": "vuln-2", "url": url})
            self.rejects(self.invoke, "out_of_scope", "integration.import", exchange=exchange)
            self.assertEqual([], self.project.list("candidate"))
            self.assertEqual([], self.project.list("integration_import"))
        oversized = self.exchange(candidates=[{**self.exchange()["candidates"][0], "external_id": "vuln-" + str(index)} for index in range(201)])
        self.rejects(self.invoke, "integration_budget", "integration.import", exchange=oversized)
        self.rejects(self.invoke, "integration_schema", "integration.import", exchange={"schema": "unknown"})
        exchange = self.exchange()
        exchange["unused"] = "x" * (2 * 1024 * 1024)
        self.rejects(self.invoke, "integration_budget", "integration.import", exchange=exchange)

    def test_import_discards_raw_http_and_redacts_secret_reuse_in_prose_and_query(self):
        secret = "SRC-SYNTHETIC-SECRET-946813"
        exchange = self.exchange()
        exchange["candidates"][0]["title"] += " " + secret
        exchange["candidates"][0]["url"] += "?access_token=" + secret
        exchange["http_evidence"][0]["url"] += "?token=" + secret
        exchange["http_evidence"][0]["request"] = "GET /preview HTTP/1.1\r\nAuthorization: Bearer " + secret + "\r\nCookie: session=" + secret + "\r\n\r\n"
        exchange["http_evidence"][0]["response"] = {"headers": {"Set-Cookie": "session=" + secret}, "body": "private raw body"}
        result, candidate_id = self.import_candidate(exchange)
        serialized = canonical(self.invoke("integration.export", import_id=result["import_id"]))
        stored = canonical(self.project.list("candidate") + self.project.list("integration_import"))
        for material in (serialized, stored):
            self.assertNotIn(secret, material)
            self.assertNotIn("private raw body", material)
            self.assertNotIn("Authorization: Bearer", material)
        candidate = self.project.get("candidate", candidate_id)
        self.assertEqual(self.operation["url"], candidate["url"])
        self.assertEqual("metadata", candidate["external_http_metadata"][0]["hash_scope"])
        self.assertFalse(candidate["external_http_metadata"][0]["raw_material_included"])
        self.assertEqual("unverified", candidate["status"])

    def test_identifier_collisions_and_duplicate_handles_cannot_hide_provenance(self):
        exchange = self.exchange()
        exchange["candidates"].append(deepcopy(exchange["candidates"][0]))
        self.rejects(self.invoke, "integration_shape", "integration.import", exchange=exchange)
        exchange = self.exchange()
        exchange["password"] = "vuln-1"
        self.rejects(self.invoke, "integration_redaction", "integration.import", exchange=exchange)
        self.assertEqual([], self.project.list("candidate"))

    def test_changed_external_locator_conflict_rolls_back_all_new_candidates(self):
        first, _ = self.import_candidate()
        exchange = self.exchange()
        exchange["candidates"][0]["url"] = self.base + "/changed"
        exchange["candidates"].insert(0, {**exchange["candidates"][0], "external_id": "new-id", "url": self.base + "/new"})
        self.rejects(self.invoke, "integration_identity_conflict", "integration.import", exchange=exchange)
        self.assertEqual(1, len(self.project.list("candidate")))
        self.assertEqual(1, len(self.project.list("integration_import")))
        self.assertEqual(first["import_id"], self.project.list("integration_import")[0]["id"])

    def test_export_needs_exact_input_link_and_current_typed_local_proof(self):
        exchange = self.exchange()
        scanner_title = "Scanner claims unrestricted command execution"
        exchange["candidates"][0].update(title=scanner_title, severity="critical")
        result, candidate_id = self.import_candidate(exchange)
        self.invoke("candidate.link", candidate_id=candidate_id, operation_id=self.operation["id"])
        decision, captures = self.proof()
        secret = "LOCAL-FINDING-TITLE-SECRET-518649"
        engine.add_actor(self.project, {"actor_id": "title-context", "subject": "fixture-title-user"})
        engine.add_session(self.project, {"actor_id": "title-context", "headers": {"Authorization": "Bearer " + secret}})
        local_title = "Bounded SSRF canary recovery: " + secret
        finding = self.invoke("finding.record", decision_id=decision["id"], mode="machine", category="ssrf",
                              title=local_title, severity="medium", impact="A controlled fixture marker was recovered",
                              remediation="Constrain the outbound destination")
        with patch.object(engine, "request") as request:
            unbound = self.invoke("integration.export", import_id=result["import_id"])["candidates"][0]
            proof = next(row for row in unbound["decisions"] if row["decision_id"] == decision["id"])
            self.assertTrue(proof["validated"])
            self.assertFalse(proof["usable_for_confirmation"])
            self.assertEqual("input_binding_required", proof["reason"])
            self.invoke("candidate.link", candidate_id=candidate_id, operation_id=self.operation["id"], input_location="query", input_selector="url")
            bound = self.invoke("integration.export", import_id=result["import_id"])["candidates"][0]
            self.assertTrue(bound["usable_for_confirmation"])
            proof = next(row for row in bound["decisions"] if row["decision_id"] == decision["id"])
            self.assertEqual("machine", proof["mode"])
            self.assertEqual("extraction", proof["oracle_type"])
            self.assertEqual([row["id"] for row in captures], proof["evidence_ids"])
            self.assertEqual([row["sha256"] for row in captures], [row["sha256"] for row in proof["evidence_hashes"]])
            actual_finding = next(row for row in bound["findings"] if row["finding_id"] == finding["id"])
            self.assertEqual("machine", actual_finding["mode"])
            self.assertEqual("medium", actual_finding["severity"])
            self.assertTrue(actual_finding["title"].startswith("Bounded SSRF canary recovery:"))
            self.assertNotIn(secret, actual_finding["title"])
            self.assertNotEqual(scanner_title, actual_finding["title"])
            self.assertEqual(scanner_title, bound["title"])
            self.assertEqual("critical", bound["severity"])
            internal = integration.export_exchange(self.project, {"import_id": result["import_id"]})
            self.assertNotIn(secret, internal["candidates"][0]["findings"][0]["title"])
            request.assert_not_called()
        (self.project.base / captures[0]["artifact_path"]).write_text("{}", encoding="utf-8")
        stale = self.invoke("integration.export", import_id=result["import_id"])["candidates"][0]
        self.assertFalse(stale["usable_for_confirmation"])
        self.assertFalse(next(row for row in stale["decisions"] if row["decision_id"] == decision["id"])["current"])

    def test_same_endpoint_different_vulnerability_family_does_not_confirm_imported_claim(self):
        exchange = self.exchange()
        exchange["candidates"][0]["category"] = "xss"
        result, candidate_id = self.import_candidate(exchange)
        self.invoke("candidate.link", candidate_id=candidate_id, operation_id=self.operation["id"], input_location="query", input_selector="url")
        self.proof()
        row = self.invoke("integration.export", import_id=result["import_id"])["candidates"][0]
        self.assertFalse(row["usable_for_confirmation"])
        self.assertTrue(all(not proof["usable_for_confirmation"] for proof in row["decisions"]))

    def test_transport_guard_is_removed_before_exact_argument_handlers(self):
        result, candidate_id = self.import_candidate()
        linked = self.invoke("candidate.link", candidate_id=candidate_id, operation_id=self.operation["id"], required_assessment_mode="src")
        self.assertEqual("linked", linked["status"])
        inspected = self.invoke("assessment.prepare", operation_id=self.operation["id"], required_assessment_mode="src")
        self.assertEqual(0, inspected["requests_sent"])

    def test_v2_direct_run_stops_at_proof_and_export_recomputes_its_frozen_controls(self):
        engine.create_project(self.workspace, {"project_id": "src-v2", "target": self.base, "assessment_mode": "src"})
        with Project(self.workspace, "src-v2") as project:
            operation = engine.register_operation(project, {
                "url": self.base + "/render", "method": "GET", "auth": "public",
                "inputs": [{"name": "label", "location": "query", "consumer": "template_engine",
                            "test_families": ["template_injection"]}],
            })
        def invoke(action, **args):
            return dispatch(self.workspace, action, {"project_id": "src-v2", **args})
        started = invoke("campaign.start")
        next_page = invoke("campaign.next", limit=1)
        recipe_id = next_page["recipes"][0]["recipe"]["id"]
        responses = [{"value": "AWA-NORMAL"}, {"value": "49"}, {"value": "AWA-NORMAL-2"}]
        calls = []
        def transport(*args):
            calls.append(args)
            return self.observed(*args, response=responses[len(calls) - 1])
        with patch.object(engine, "request", side_effect=transport):
            result = invoke("test.run", campaign_id=started["campaign"]["id"], recipe_id=recipe_id, idempotency_key="v2-first")
        self.assertEqual("supported", result["outcome"])
        self.assertEqual(3, len(calls))
        exchange = self.exchange()
        exchange["candidates"][0].update(url=operation["url"], category="template_injection")
        exchange["http_evidence"][0]["url"] = operation["url"]
        imported = invoke("integration.import", exchange=exchange)
        candidate_id = imported["candidates"][0]["candidate_id"]
        invoke("candidate.link", candidate_id=candidate_id, operation_id=operation["id"])
        unbound = invoke("integration.export", import_id=imported["import_id"])["candidates"][0]
        self.assertFalse(unbound["usable_for_confirmation"])
        invoke("candidate.link", candidate_id=candidate_id, operation_id=operation["id"], input_location="query", input_selector="label")
        bound = invoke("integration.export", import_id=imported["import_id"])["candidates"][0]
        self.assertTrue(bound["usable_for_confirmation"])
        self.assertEqual(result["finding"]["decision_id"], bound["decisions"][0]["decision_id"])
        self.assertEqual("unexpected_expression_evaluation", bound["decisions"][0]["oracle_type"])
        self.assertEqual(result["finding"]["title"], bound["findings"][0]["title"])
        self.assertEqual(result["finding"]["severity"], bound["findings"][0]["severity"])
        with patch.object(engine, "request") as target:
            self.rejects(invoke, "stopped_at_evidence", "test.run", campaign_id=started["campaign"]["id"],
                         recipe_id=recipe_id, idempotency_key="v2-second")
            target.assert_not_called()
        with Project(self.workspace, "src-v2") as project:
            original_operation = project.get("operation", operation["id"])
            changed = deepcopy(original_operation)
            changed["inputs"][0]["consumer"] = "changed_sink"
            project.put("operation", changed)
        changed_binding = invoke("integration.export", import_id=imported["import_id"])["candidates"][0]
        self.assertFalse(changed_binding["usable_for_confirmation"])
        with Project(self.workspace, "src-v2") as project:
            project.put("operation", original_operation)
            evidence = project.list("evidence")[0]
            (project.base / evidence["artifact_path"]).write_text("{}", encoding="utf-8")
        stale = invoke("integration.export", import_id=imported["import_id"])["candidates"][0]
        self.assertFalse(stale["usable_for_confirmation"])


if __name__ == "__main__":
    unittest.main()
