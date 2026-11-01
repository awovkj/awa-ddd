"""Synthetic project-publication regressions; no historical target traffic."""
from __future__ import annotations

import ast
import base64
from copy import deepcopy
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import quote

from awa_ddd import __main__ as entry, browser, engine, publication
from awa_ddd.store import EngineError, Project, canonical, now


ROOT = Path(__file__).resolve().parents[1]


def observed(response):
    def request(url, method, headers, body, timeout, max_bytes):
        raw = canonical(response).encode("utf-8")
        sent = body if isinstance(body, bytes) else body.encode("utf-8") if isinstance(body, str) else b""
        return {"request": {"url": url, "method": method, "headers": headers,
                            "body_base64": base64.b64encode(sent).decode("ascii")},
                "response": {"status": 200, "headers": [["content-type", "application/json"]],
                             "length": len(raw), "body_base64": base64.b64encode(raw).decode("ascii")},
                "complete": True, "started_at": now(), "completed_at": now()}
    return request


class ProjectPublicationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="awa-publication-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.base = "http://fixture.invalid"
        engine.create_project(self.root, {"project_id": "publication", "target": self.base})
        self.project = Project(self.root, "publication")
        self.addCleanup(self.project.close)
        guard = patch.object(engine, "request", side_effect=AssertionError("Unexpected fixture traffic"))
        self.network = guard.start()
        self.addCleanup(guard.stop)
        self.serial = 0

    def call(self, action, **args):
        return entry.dispatch(self.root, action, {"project_id": "publication", **args})

    def register(self, path="/items", **fields):
        public = self.call("surface.register", url=self.base + path, method="GET", auth="public", **fields)
        return self.project.get("operation", public["id"])

    def credential(self, value, *, actor_id=None, session_id=None, cookie=False):
        actor = self.call("identity.actor", subject="fixture-principal", **({"actor_id": actor_id} if actor_id else {}))
        created = self.call("identity.session", actor_id=actor_id or actor["id"],
                            headers={"Cookie": "pin=" + value} if cookie else {"Authorization": "Bearer " + value},
                            **({"session_id": session_id} if session_id else {}))
        return self.project.get("session", session_id or created["id"])

    def browser_context(self, value="private-fill", *, missing=False):
        self.serial += 1
        url = self.base + "/page"
        action = {"type": "fill", "selector": "#fixture", "ok": True, "finalUrl": url}
        if not missing:
            action["value"] = value
        raw = {"url": url, "finalUrl": url, "status": 200, "signals": {"forms": 1}, "title": str(value),
               "network": [{"url": url, "method": "GET", "status": 200}], "actions": [action]}
        source = self.root / ("browser-" + str(self.serial) + ".json")
        source.write_text(canonical(raw), encoding="utf-8")
        public = self.call("browser.import_mcp", path=str(source))
        return self.project.get("page_visit", public["id"])

    def corrupt_context(self, record, project=None):
        changed = deepcopy(record)
        changed.pop("credentials", None)
        (project or self.project).put("page_visit", changed)

    def snapshot(self):
        return {table: [tuple(row) for row in self.project.connection.execute("SELECT * FROM " + table + " ORDER BY 1,2")]
                for table in ("entities", "events", "metadata")}

    def assert_private_locator(self, row, key="url"):
        self.assertEqual("[locator omitted: protected project context]", row[key])
        self.assertTrue(row[key + "_redacted"])
        self.assertTrue(row["locator_requires_binding"])
        self.assertTrue(row["native_input_requires_binding"])
        self.assertFalse(row["requestable"])

    def test_session_bearer_is_private_in_surface_views_without_changing_the_source(self):
        secret = "synthetic-publication-session-secret"
        self.credential(secret)
        public = self.call("surface.register", url=self.base + "/opaque/" + secret, method="GET", auth="public",
            inputs=[{"name": secret, "selector": secret, "location": "query", "consumer": secret}],
            sources=[{"path": str(self.root / (secret + ".js")), "annotation": secret, "metadata": {secret: secret}}])
        original = deepcopy(self.project.get("operation", public["id"]))
        listed = self.call("surface.list")
        inspected = self.call("surface.inspect", operation_id=public["id"])
        for row in (public, listed, inspected):
            self.assertNotIn(secret, canonical(row))
        self.assert_private_locator(public)
        self.assert_private_locator(listed["operations"][0])
        self.assert_private_locator(inspected["operation"])
        self.assertEqual(original, self.project.get("operation", public["id"]))
        self.assertEqual(self.base + "/opaque/" + secret, original["url"])
        self.network.assert_not_called()

    def test_project_plan_and_method_views_scrub_path_metadata_not_only_continuation(self):
        secret = "synthetic-plan-path-secret"
        self.credential(secret)
        operation = self.register("/route/" + secret)
        for action in ("project.status", "plan.next", "plan.list", "plan.build", "plan.audit", "report.coverage"):
            with self.subTest(action=action):
                public = self.call(action)
                self.assertNotIn(secret, canonical(public))
                self.assertTrue(public["continuation"]["continue_required"])
                self.assertFalse(public["continuation"]["automatic_stop_allowed"])
                self.assertIs(type(public["continuation"]["ready_total"]), int)
                self.assertEqual("partial", public["completion"]["status"])
                for method in public.get("method_coverage", []):
                    self.assertTrue(method["path_shape_redacted"])
                    self.assertFalse(method["requestable"])
        queued = self.call("plan.next")["work_items"][0]
        self.assert_private_locator(queued)
        self.assertEqual(operation["id"], queued["operation_id"])
        self.network.assert_not_called()

    def test_http_preflight_is_private_and_makes_no_claim_or_request(self):
        secret = "synthetic-preflight-private-path"
        self.credential(secret)
        operation = self.register("/opaque/" + secret)
        before = self.snapshot()
        result = self.call("http.preflight", operation_id=operation["id"])
        self.assert_private_locator(result)
        self.assertNotIn(secret, canonical(result))
        self.assertEqual(0, result["requests_sent"])
        self.assertTrue(result["ready"])
        self.assertIsNone(result["existing_run_id"])
        self.assertEqual(before, self.snapshot())
        self.network.assert_not_called()

    def test_short_credential_is_removed_even_inside_innocent_source_annotations(self):
        self.credential("12", cookie=True)
        public = self.call("surface.register", url=self.base + "/before12after", method="GET", auth="public",
            sources=[{"note": "before12after", "hint": {"arbitrary_id": "before12after"}}])
        self.assertNotIn("before12after", canonical(public))
        self.assert_private_locator(public)
        self.assertEqual(public["id"], self.call("surface.list")["operations"][0]["id"])

    def test_percent_encoded_and_lowercase_escaped_path_aliases_are_not_requestable(self):
        secret = "synthetic+publication%secret"
        self.credential(secret)
        for rounds in (1, 2, 4):
            encoded = secret
            for _ in range(rounds):
                encoded = quote(encoded, safe="")
            encoded = re.sub(r"%[0-9A-Fa-f]{2}", lambda match: match.group().lower(), encoded)
            public = self.call("surface.register", url=self.base + "/encoded/" + encoded, method="GET", auth="public")
            self.assert_private_locator(public)
            self.assertNotIn(encoded, canonical(public))
            self.assertEqual(self.base + "/encoded/" + encoded, self.project.get("operation", public["id"])["url"])

    def test_deep_encodings_of_known_credentials_are_private_in_surfaces_candidates_and_sources(self):
        from awa_ddd.candidates import store_candidate

        secret = "synthetic+deep%publication-secret"
        self.credential(secret)
        for rounds in (6, 10):
            encoded = secret
            for _ in range(rounds):
                encoded = quote(encoded, safe="")
            source = {"locator": "fixture#" + encoded, "annotation": encoded}
            public = self.call("surface.register", url=self.base + "/" + encoded, method="GET", auth="public", sources=[source])
            self.assert_private_locator(public)
            self.assert_private_locator(public["sources"][0], "locator")
            self.assertNotIn(encoded, canonical(public))
            self.assertEqual(source, self.project.get("operation", public["id"])["sources"][0])
            identity, _ = store_candidate(self.project, {"kind": "operation_hint", "url": self.base + "/candidate/" + encoded,
                                                        "method": "unknown", "source": source})
            candidate = self.call("candidate.inspect", candidate_id=identity)["candidate"]
            self.assertIn(candidate["url"], {"[locator omitted: protected project context]", "[candidate locator omitted: protected context]"})
            self.assertTrue(candidate["url_redacted"])
            self.assertTrue(candidate["locator_requires_binding"])
            self.assertTrue(candidate["native_input_requires_binding"])
            self.assertFalse(candidate["requestable"])
            self.assertNotIn(encoded, canonical(candidate))
            self.assertEqual(self.base + "/candidate/" + encoded, self.project.get("candidate", identity)["url"])
        self.network.assert_not_called()

    def test_deep_secret_encoding_is_not_retained_in_public_engine_error_prose_or_details(self):
        secret = "synthetic+deep%error-secret"
        self.credential(secret)
        operation = self.register()
        for rounds in (6, 10):
            encoded = secret
            for _ in range(rounds):
                encoded = quote(encoded, safe="")
            error = EngineError("invalid_input", "Fixture annotation " + encoded,
                                {"locator": self.base + "/" + encoded, "reason": encoded})
            with patch.object(engine, "preflight_capture", side_effect=error), self.assertRaises(EngineError) as caught:
                self.call("http.capture", operation_id=operation["id"])
            self.assertEqual("invalid_input", caught.exception.code)
            self.assertNotIn(encoded, str(caught.exception) + canonical(caught.exception.details))
            self.assert_private_locator(caught.exception.details, "locator")
            self.assertNotIn("run_id", caught.exception.details)
        self.network.assert_not_called()

    def test_caller_flag_order_cannot_reenable_redacted_candidate_or_source_locators(self):
        from awa_ddd.candidates import store_candidate

        secret = "synthetic+caller%flag-secret"
        self.credential(secret)
        encoded = secret
        for _ in range(10):
            encoded = quote(encoded, safe="")
        weakening = {"url_redacted": False, "locator_redacted": False, "requestable": True,
                     "native_input_requires_binding": False, "locator_requires_binding": False}
        source = {"locator": "fixture#" + encoded, **weakening}
        public = self.call("surface.register", url=self.base + "/normal", method="GET", auth="public", sources=[source])
        self.assert_private_locator(public["sources"][0], "locator")
        self.assertEqual(source, self.project.get("operation", public["id"])["sources"][0])
        identity, _ = store_candidate(self.project, {"kind": "operation_hint", "url": self.base + "/" + encoded,
                                                    "method": "unknown", "source": {"locator": "fixture#source"}, **weakening})
        for candidate in (self.call("candidate.list")["candidates"][0], self.call("candidate.inspect", candidate_id=identity)["candidate"]):
            self.assertNotIn(encoded, canonical(candidate))
            self.assertTrue(candidate["url_redacted"])
            self.assertTrue(candidate["locator_requires_binding"])
            self.assertTrue(candidate["native_input_requires_binding"])
            self.assertFalse(candidate["requestable"])
        self.assertTrue(self.project.get("candidate", identity)["requestable"])
        self.network.assert_not_called()

    def test_caller_error_flags_cannot_override_generated_private_locator_controls(self):
        secret = "synthetic+error%flag-secret"
        self.credential(secret)
        operation = self.register()
        encoded = secret
        for _ in range(6):
            encoded = quote(encoded, safe="")
        details = {"locator": self.base + "/" + encoded, "locator_redacted": False, "requestable": True,
                   "native_input_requires_binding": False, "locator_requires_binding": False}
        with patch.object(engine, "preflight_capture", side_effect=EngineError("invalid_input", "Fixture rejected", details)), \
                self.assertRaises(EngineError) as caught:
            self.call("http.capture", operation_id=operation["id"])
        self.assert_private_locator(caught.exception.details, "locator")
        self.assertNotIn("run_id", caught.exception.details)
        self.network.assert_not_called()

    def test_numeric_private_source_counts_are_not_restored_as_engine_controls(self):
        self.credential("000042")
        public = self.call("surface.register", url=self.base + "/numeric", method="GET", auth="public",
            inputs=[{"name": "q", "location": "query", "array_template": [42, 42.0]}],
            sources=[{"metadata": {"ready_total": 42, "arbitrary_count": 42.0,
                                    "continuation": {"ready_total": 42, "state": "000042"}}}])
        metadata = public["sources"][0]["metadata"]
        self.assertIsInstance(metadata["ready_total"], str)
        self.assertIsInstance(metadata["arbitrary_count"], str)
        self.assertIsInstance(metadata["continuation"]["ready_total"], str)
        self.assertTrue(all(isinstance(value, str) for value in public["inputs"][0]["array_template"]))
        self.assertIs(type(self.call("surface.list")["operation_total"]), int)
        self.assertEqual([42, 42.0], self.project.get("operation", public["id"])["inputs"][0]["array_template"])

    def test_browser_fill_context_protects_other_project_actions(self):
        self.browser_context("23")
        public = self.call("surface.register", url=self.base + "/before23after", method="GET", auth="public")
        self.assert_private_locator(public)
        self.assertNotIn("before23after", canonical(self.call("project.status")))
        self.assertNotIn("credentials", canonical(public))
        self.network.assert_not_called()

    def test_boolean_fill_value_is_private_in_source_data_but_control_flags_stay_typed(self):
        self.browser_context(True)
        public = self.call("surface.register", url=self.base + "/boolean", method="GET", auth="public", ownership=True,
                           sources=[{"metadata": {"ordinary": True}}])
        self.assertIs(public["ownership"], True)
        self.assertIsInstance(public["sources"][0]["metadata"]["ordinary"], str)
        self.assertIs(self.project.get("operation", public["id"])["sources"][0]["metadata"]["ordinary"], True)

    def test_intact_scanner_artifact_is_a_private_seed_not_a_source_mutation(self):
        secret = "synthetic-scanner-publication-secret"
        run = {"id": Project.id("RUN"), "kind": "external_tool", "adapter": "tscanplus", "action": "project_summary",
               "status": "succeeded", "started_at": now()}
        document = {"execution": deepcopy(run), "result": {"password": secret}}
        path, digest = self.project.artifact(Project.id("TA"), document)
        self.project.put("run", {**run, "artifact_path": path, "sha256": digest})
        before = (self.project.base / path).read_bytes()
        public = self.call("surface.register", url=self.base + "/scanner/" + secret, method="GET", auth="public")
        self.assert_private_locator(public)
        self.assertNotIn(secret, canonical(public))
        self.assertEqual(before, (self.project.base / path).read_bytes())
        self.network.assert_not_called()

    def test_legacy_unavailable_context_omits_prose_without_corrupting_plan_controls(self):
        unknown = "synthetic-unknown-legacy-private-value"
        self.browser_context(unknown, missing=True)
        public = self.call("surface.register", url=self.base + "/" + unknown, method="GET", auth="public",
                           sources=[{"free": unknown, "numeric": 42, "nested": {unknown: unknown}}])
        self.assertNotIn(unknown, canonical(public))
        self.assertEqual("unavailable", public["redaction_context_status"])
        self.assert_private_locator(public)
        planned = self.call("plan.next")
        self.assertEqual("unavailable", planned["redaction_context_status"])
        self.assertIs(type(planned["queue_total"]), int)
        self.assertTrue(planned["continuation"]["continue_required"])
        self.assertFalse(planned["continuation"]["automatic_stop_allowed"])
        self.assertEqual("partial", planned["completion"]["status"])
        self.network.assert_not_called()

    def test_required_context_invalid_before_dispatch_blocks_every_execution_handler(self):
        operation = self.register()
        record = self.browser_context()
        self.corrupt_context(record)
        cases = [("http.capture", {"operation_id": operation["id"]}),
                 ("identity.verify", {"operation_id": operation["id"], "session_id": "unavailable", "subject_selector": "/id"}),
                 ("scenario.run", {"scenario": {"steps": [{"id": "one", "operation_id": operation["id"]}]}}),
                 ("browser.visit", {"url": operation["url"]}), ("browser.probe", {}),
                 ("tool.probe", {"adapter": "tscanplus"}), ("tool.sqlmap", {"operation_id": operation["id"], "effect": "read_only"})]
        before = self.snapshot()
        with patch.object(entry, "_project_dispatch", side_effect=AssertionError("Execution reached the handler")) as handler:
            for action, args in cases:
                with self.subTest(action=action), self.assertRaises(EngineError) as caught:
                    self.call(action, **args)
                self.assertEqual("browser_redaction_context", caught.exception.code)
                self.assertNotIn("run_id", caught.exception.details)
                self.assertFalse(caught.exception.details["automatic_replay_allowed"])
        handler.assert_not_called()
        self.network.assert_not_called()
        self.assertEqual(before, self.snapshot())

    def test_offline_mutation_publication_failure_rolls_back_entities_events_and_mint_metadata(self):
        before = self.snapshot()
        with patch.object(publication, "publish", side_effect=EngineError("browser_redaction_context", "private annotation")):
            with self.assertRaises(EngineError) as caught:
                self.call("identity.actor", subject="fixture-new-principal")
        self.assertEqual(before, self.snapshot())
        self.assertNotIn("run_id", caught.exception.details)
        self.assertNotIn("private annotation", str(caught.exception))
        self.network.assert_not_called()

    def test_offline_context_invalidation_rolls_back_the_actual_mutation(self):
        record = self.browser_context("offline-private-context")
        original = entry._project_dispatch
        before = self.snapshot()

        def mutate(project, action, args):
            result = original(project, action, args)
            self.corrupt_context(record, project)
            return result

        with patch.object(entry, "_project_dispatch", side_effect=mutate), self.assertRaises(EngineError) as caught:
            self.call("surface.register", url=self.base + "/new", method="GET", auth="public")
        self.assertEqual("browser_redaction_context", caught.exception.code)
        self.assertEqual(before, self.snapshot())

    def test_context_invalidation_after_capture_keeps_the_real_outcome_and_evidence(self):
        secret = "after-dispatch-private-context"
        operation = self.register()
        record = self.browser_context(secret)
        response = observed({"ok": True, "opaque": secret})

        def dispatching(*args):
            self.corrupt_context(record)
            return response(*args)

        self.network.side_effect = dispatching
        with self.assertRaises(EngineError) as caught:
            self.call("http.capture", operation_id=operation["id"])
        self.assertEqual(1, self.network.call_count)
        self.assertEqual("browser_redaction_context", caught.exception.code)
        run = self.project.get("run", caught.exception.details["run_id"])
        self.assertEqual("succeeded", run["status"])
        self.assertTrue(caught.exception.details["outcome_persisted"])
        self.assertEqual("run.inspect", caught.exception.details["next_action"])
        self.assertFalse(caught.exception.details["automatic_replay_allowed"])
        self.assertNotIn(secret, str(caught.exception) + canonical(caught.exception.details))
        evidence = self.project.get("evidence", run["evidence_id"])
        self.assertEqual(secret, json.loads(base64.b64decode(self.project.read_artifact(evidence)["response"]["body_base64"]))["opaque"])

    def test_context_invalidation_after_scenario_keeps_parent_and_all_child_runs(self):
        operation = self.register()
        record = self.browser_context("scenario-private-context")
        response = observed({"ok": True})

        def dispatching(*args):
            self.corrupt_context(record)
            return response(*args)

        self.network.side_effect = dispatching
        spec = {"steps": [{"id": "one", "operation_id": operation["id"]}, {"id": "two", "operation_id": operation["id"]}]}
        with self.assertRaises(EngineError) as caught:
            self.call("scenario.run", scenario=spec)
        identity = caught.exception.details["run_id"]
        self.assertTrue(identity.startswith("SC-"))
        parent = self.project.get("run", identity)
        self.assertEqual("succeeded", parent["status"])
        self.assertEqual(2, len(parent["evidence_ids"]))
        self.assertEqual(3, len(self.project.list("run")))
        self.assertEqual(2, self.network.call_count)
        for evidence_id in parent["evidence_ids"]:
            self.project.read_artifact(self.project.get("evidence", evidence_id))

    def test_static_step_ids_are_private_in_run_preflight_inspection_and_error_prose(self):
        secret = "synthetic-static-step-private-token"
        self.credential(secret)
        operation = self.register()
        spec = {"steps": [{"id": secret, "operation_id": operation["id"], "assertions": [{"selector": "/ok", "equals": False}]}]}
        checked = self.call("scenario.preflight", scenario=spec)
        self.assertNotIn(secret, canonical(checked))
        self.network.side_effect = observed({"ok": True})
        with self.assertRaises(EngineError) as caught:
            self.call("scenario.run", scenario=spec)
        self.assertEqual("scenario_assertion", caught.exception.code)
        identity = caught.exception.details["run_id"]
        self.assertNotIn(secret, str(caught.exception) + canonical(caught.exception.details))
        inspected = self.call("run.inspect", run_id=identity)
        self.assertNotIn(secret, canonical(inspected))
        self.assertEqual(secret, self.project.get("run", identity)["checkpoints"][0]["step_id"])
        self.assertEqual(1, self.network.call_count)

    def test_target_extracted_variables_remain_private_and_are_not_added_to_the_result(self):
        secret = "synthetic-extracted-variable-secret"
        self.credential(secret)
        seed, consumer = self.register("/seed"), self.register("/consume/{code}")
        self.network.side_effect = observed({"ok": True, "opaque": secret})
        result = self.call("scenario.run", scenario={"steps": [
            {"id": "seed", "operation_id": seed["id"], "extract": {"opaque": "/opaque"}},
            {"id": "consumer", "operation_id": consumer["id"], "url": self.base + "/consume/${seed.opaque}"}]})
        inspected = self.call("run.inspect", run_id=result["id"])
        for value in (result, inspected):
            self.assertNotIn(secret, canonical(value))
            self.assertNotIn("variables", value)
        self.assertEqual(2, self.network.call_count)
        self.assertIn(secret, self.network.call_args_list[1].args[0])

    def test_static_step_id_cannot_borrow_a_real_generated_run_handle_exception(self):
        operation = self.register()
        self.network.side_effect = observed({"ok": True})
        first = self.call("http.capture", operation_id=operation["id"])
        secret = first["run_id"]
        self.credential(secret)
        result = self.call("scenario.run", scenario={"steps": [{"id": secret, "operation_id": operation["id"]}]})
        self.assertNotEqual(secret, result["checkpoints"][0]["step_id"])
        self.assertEqual(secret, self.project.get("run", result["id"])["checkpoints"][0]["step_id"])

    def test_identity_assertion_failure_reports_the_actual_post_capture_run(self):
        identity = self.register("/whoami")
        session = self.credential("synthetic-subject-check-secret")
        self.network.side_effect = observed({"id": "other-principal"})
        with self.assertRaises(EngineError) as caught:
            self.call("identity.verify", operation_id=identity["id"], session_id=session["id"], subject_selector="/id")
        self.assertEqual("identity_mismatch", caught.exception.code)
        run = self.project.get("run", caught.exception.details["run_id"])
        self.assertEqual("succeeded", run["status"])
        self.assertTrue(caught.exception.details["outcome_persisted"])
        self.assertEqual(1, self.network.call_count)

    def test_publication_failure_uses_claim_provenance_not_an_unrelated_run_id(self):
        operation = self.register()
        foreign = {"id": Project.id("RUN"), "kind": "http", "operation_id": operation["id"], "status": "failed", "started_at": now()}
        self.project.put("run", foreign)
        self.network.side_effect = observed({"ok": True})
        error = EngineError("browser_redaction_context", "untrusted private error", {"run_id": foreign["id"]})
        with patch.object(publication, "publish", side_effect=error), self.assertRaises(EngineError) as caught:
            self.call("http.capture", operation_id=operation["id"])
        self.assertNotEqual(foreign["id"], caught.exception.details["run_id"])
        self.assertEqual("succeeded", self.project.get("run", caught.exception.details["run_id"])["status"])
        self.assertEqual(1, self.network.call_count)
        self.assertNotIn("untrusted private error", str(caught.exception))

    def test_failure_before_claim_does_not_borrow_an_unrelated_concurrent_run(self):
        operation = self.register()

        def fail(project, action, args):
            foreign = {"id": Project.id("RUN"), "kind": "http", "operation_id": operation["id"], "status": "failed", "started_at": now()}
            self.project.put("run", foreign)
            raise EngineError("invalid_input", "Fixture rejected before its own claim", {"run_id": foreign["id"]})

        with patch.object(entry, "_project_dispatch", side_effect=fail), self.assertRaises(EngineError) as caught:
            self.call("http.capture", operation_id=operation["id"])
        self.assertNotIn("run_id", caught.exception.details)
        self.assertEqual(1, len(self.project.list("run")))
        self.network.assert_not_called()

    def test_generated_local_handles_survive_later_views_without_restoring_the_label(self):
        actor = self.call("identity.actor", subject="fixture-local-principal")
        secret = actor["id"]
        self.call("identity.session", actor_id=secret, headers={"Authorization": "Bearer " + secret})
        updated = self.call("identity.actor", actor_id=secret, label=secret)
        status = self.call("project.status")
        self.assertEqual(secret, updated["id"])
        self.assertNotEqual(secret, updated["label"])
        self.assertEqual(secret, status["actors"][0]["id"])
        self.assertNotIn(secret, status["actors"][0]["label"])

    def test_caller_selected_uuid_shaped_ids_cannot_claim_generated_handle_provenance(self):
        secret = "ACT-" + "a" * 32
        self.credential(secret, actor_id=secret)
        public = self.call("identity.actor", actor_id=secret, label=secret)
        self.assertNotEqual(secret, public["id"])
        self.assertNotIn(secret, canonical(self.call("project.status")))
        self.assertEqual(secret, self.project.get("actor", secret)["id"])

    def test_engine_artifact_handles_paths_and_digests_survive_a_numeric_credential(self):
        self.credential("1")
        operation = self.register()
        self.network.side_effect = observed({"ok": True})
        public = self.call("http.capture", operation_id=operation["id"])
        raw = self.project.get("evidence", public["id"])
        before = (self.project.base / raw["artifact_path"]).read_bytes()
        inspected = self.call("evidence.inspect", evidence_id=raw["id"])
        for field in ("id", "run_id", "artifact_path", "sha256", "operation_id", "operation_signature"):
            self.assertEqual(raw[field], public[field])
            self.assertEqual(raw[field], inspected[field])
        self.assertEqual("valid", inspected["integrity"])
        self.assertEqual(before, (self.project.base / raw["artifact_path"]).read_bytes())

    def test_sanitized_browser_locators_are_not_reinterpreted_as_original_urls(self):
        secret = "synthetic-browser-opaque-secret"
        self.credential(secret)
        url = self.base + "/" + secret
        source = self.root / "opaque-browser.json"
        source.write_text(canonical({"url": url, "finalUrl": url, "status": 200, "signals": {"forms": 1},
                                     "network": [{"url": url, "method": "GET", "status": 200}]}), encoding="utf-8")
        public = self.call("browser.import_mcp", path=str(source))
        self.assertNotIn(secret, canonical(public))
        self.assertIn("<AWA_", public["url"])
        self.assertTrue(public["url_redacted"])
        self.assertTrue(public["locator_requires_binding"])
        self.assertIs(type(public["network_count"]), int)

    def test_other_projects_and_global_actions_do_not_load_historical_private_context(self):
        secret = "synthetic-other-project-private-context"
        record = self.browser_context(secret)
        self.corrupt_context(record)
        engine.create_project(self.root, {"project_id": "other", "target": self.base})
        result = entry.dispatch(self.root, "surface.register", {"project_id": "other", "url": self.base + "/" + secret,
                                                                 "method": "GET", "auth": "public"})
        self.assertEqual(self.base + "/" + secret, result["url"])
        with patch.object(publication, "PublicationContext", side_effect=AssertionError("Global action loaded a project context")), \
                patch("awa_ddd.runtime.probe", return_value={"runtime": "fixture"}):
            self.assertEqual(1, entry.dispatch(self.root, "action.help", {})["contract_version"])
            self.assertIn("publication", entry.dispatch(self.root, "project.list", {})["projects"])
            self.assertEqual({"runtime": "fixture"}, entry.dispatch(self.root, "runtime.probe", {}))
            self.assertEqual("fresh", entry.dispatch(self.root, "project.create", {"project_id": "fresh", "target": self.base})["project_id"])

    def test_cli_engine_error_message_and_details_use_the_current_project_seed(self):
        secret = "synthetic-cli-private-step"
        self.credential(secret)
        request = {"action": "scenario.preflight", "args": {"project_id": "publication", "scenario": {"steps": [{"id": secret}]}}}
        result = subprocess.run([sys.executable, "-X", "utf8", "-m", "awa_ddd", "--workspace", str(self.root)],
                                input=canonical(request).encode("utf-8"), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                cwd=ROOT, timeout=30, check=False)
        response = json.loads(result.stdout)
        self.assertEqual(2, result.returncode)
        self.assertFalse(response["ok"])
        self.assertEqual("scenario_shape", response["error"]["code"])
        self.assertNotIn(secret, result.stdout.decode("utf-8"))
        self.assertNotIn("run_id", response["error"]["details"])
        self.network.assert_not_called()

    def test_all_static_engine_codes_are_in_the_closed_public_error_schema(self):
        codes = set()

        def literals(node):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return {node.value} if node.value else set()
            if isinstance(node, ast.IfExp):
                return literals(node.body) | literals(node.orelse)
            if isinstance(node, ast.BoolOp):
                return set().union(*(literals(value) for value in node.values))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr" and len(node.args) > 2:
                return literals(node.args[2])
            return set()

        for source in (ROOT / "awa_ddd").glob("*.py"):
            for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id == "EngineError" and node.args:
                        codes.update(literals(node.args[0]))
                    if isinstance(node.func, ast.Name) and node.func.id == "getattr" and len(node.args) > 2 \
                            and isinstance(node.args[1], ast.Constant) and node.args[1].value == "code":
                        codes.update(literals(node.args[2]))
                    for keyword in node.keywords:
                        if keyword.arg == "error_code":
                            codes.update(literals(keyword.value))
                elif isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "code" for target in node.targets):
                    codes.update(literals(node.value))
        self.assertEqual(set(), codes - publication._ERROR_CODES)


class FinalReportPublicationTests(unittest.TestCase):
    def test_real_exhaustion_gate_and_final_delivery_codes_survive_a_credential_codeword(self):
        from test_finalization_report_20261030 import FinalizationReportTests

        fixture = FinalizationReportTests()
        fixture.setUp()
        try:
            actor = engine.add_actor(fixture.project, {"subject": "fixture-report-principal"})
            engine.add_session(fixture.project, {"actor_id": actor["id"], "headers": {"Authorization": "Bearer completed"}})
            checkpoint, stopped = fixture.completed_fixture_stop()
            result = entry.dispatch(fixture.root, "report.build", {"project_id": "final-report", "stage": "final", "finalization_id": stopped["id"]})
            summary, manifest, _ = fixture.read(result)
            self.assertEqual("final-completed", result["delivery_status"])
            self.assertEqual(summary["delivery_status"], result["delivery_status"])
            self.assertEqual(manifest["delivery_status"], result["delivery_status"])
            self.assertEqual("completed", result["finalization"]["reason"])
            self.assertEqual(stopped["id"], result["continuation"]["finalization_id"])
            self.assertEqual(checkpoint["snapshot_id"], result["continuation"]["snapshot_id"])
            self.assertTrue(result["continuation"]["automatic_stop_allowed"])
            self.assertFalse(result["continuation"]["continue_required"])
            self.assertEqual("complete", result["completion"]["status"])
            self.assertEqual(result["finalization"], summary["finalization"])
            self.assertEqual(result["finalization"], manifest["finalization"])
        finally:
            fixture.doCleanups()


if __name__ == "__main__":
    unittest.main()
