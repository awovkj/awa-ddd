"""Offline browser tool-choice policy; planning never starts Playwright or HTTP."""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import browser, browser_policy, engine, workflow
from awa_ddd.store import Project
import test_analyst_binding_20261030 as runtime_fixtures


SUMMARY_FIELDS = {"required_total", "assisted_total", "call_needed_total", "invoke_now_total",
                  "blocked_total", "native_unsupported_total", "followup_total", "task_total"}
NATIVE_FIELDS = {"url", "session_id", "allow_write"}


@contextmanager
def runtime_fixture():
    fixture = runtime_fixtures.AnalystBindingTests()
    fixture.setUp()
    try:
        yield fixture
    finally:
        fixture.doCleanups()


class BrowserPolicyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="awa-browser-policy-")
        self.addCleanup(temporary.cleanup)
        self.base, self.other = "http://fixture.invalid", "http://other.invalid"
        engine.create_project(temporary.name, {"project_id": "policy", "target": self.base,
            "scope": [self.base, self.other], "exclude": [self.base + "/excluded"]})
        self.project = Project(temporary.name, "policy")
        self.addCleanup(self.project.close)

    def operation(self, path="/api", family="generic", consumer="business_input", name="q", **changes):
        return engine.register_operation(self.project, {"url": self.base + path, "method": "GET", "auth": "public",
            "inputs": [{"name": name, "location": "query", "consumer": consumer, "test_families": [family]}], **changes})

    def gap(self, operation, family):
        entry = operation["inputs"][0]
        return {"kind": "input_test", "obligation_kind": "input_test", "operation_id": operation["id"],
                "test_family": family, "input_location": entry["location"], "input_selector": entry["selector"],
                "schema_branch": entry.get("schema_branch"), "status": "open"}

    def state(self, project):
        return ([tuple(row) for row in project.connection.execute("SELECT * FROM entities ORDER BY kind,id")],
                [tuple(row) for row in project.connection.execute("SELECT * FROM events ORDER BY seq")],
                deepcopy(project.config))

    def offline(self, action, *, project=None):
        project = project or self.project
        before = self.state(project)
        with ExitStack() as stack:
            forbidden = [stack.enter_context(patch.object(engine, "request", side_effect=AssertionError("Planner requested HTTP"))),
                         stack.enter_context(patch.object(browser, "probe", side_effect=AssertionError("Planner probed a browser"))),
                         stack.enter_context(patch.object(browser, "visit", side_effect=AssertionError("Planner visited a browser"))),
                         stack.enter_context(patch("subprocess.run", side_effect=AssertionError("Planner launched subprocess.run"))),
                         stack.enter_context(patch("subprocess.Popen", side_effect=AssertionError("Planner launched subprocess.Popen")))]
            result = action()
        for operation in forbidden:
            operation.assert_not_called()
        self.assertEqual(self.state(project), before)
        return result

    def planned(self, **arguments):
        engine.build_plan(self.project)
        return self.offline(lambda: workflow.next_work(self.project, {"include_blocked": True, **arguments}))

    def work_row(self, result, operation, family):
        return next(row for row in result["work_items"] if row.get("operation_id") == operation["id"]
                    and row.get("test_family") == family and row.get("obligation_kind") == "input_test")

    def assert_policy(self, policy, requirement):
        self.assertEqual(policy["requirement"], requirement)
        self.assertEqual(policy["must_call_playwright"], requirement != "not_needed")
        self.assertIsInstance(policy["reason_codes"], list)
        self.assertTrue(all(isinstance(reason, str) for reason in policy["reason_codes"]))
        self.assertIsInstance(policy["unsupported_by_native"], list)
        self.assertTrue(all(isinstance(reason, str) for reason in policy["unsupported_by_native"]))
        self.assertIs(type(policy["native_supported"]), bool)

    def assert_handoff(self, policy, requirement):
        self.assert_policy(policy, requirement)
        if requirement == "not_needed":
            self.assertIsNone(policy["preferred_provider"])
            self.assertEqual(policy["native_fallback"], [])
        else:
            self.assertEqual(policy["preferred_provider"], "host_playwright_mcp")
            self.assertEqual(policy["native_fallback"], ["browser.probe", "browser.visit"])
        native = policy.get("native_visit_input")
        if native is not None:
            self.assertIsInstance(native, dict)
            self.assertLessEqual(set(native), NATIVE_FIELDS)
            self.assertIs(native["allow_write"], False)
            self.assertIsInstance(native["url"], str)

    def linked_page(self, operation, *, api=None):
        page = browser.register_page(self.project, {"url": self.base + "/ui"})
        browser.register_function(self.project, {"page_id": page["id"], "name": "Search", "trigger": "button#search",
            "apis": [{"operation_id": operation["id"]} if api is None else api]})
        return self.project.get("page", page["id"])

    def controls(self, fixture, *, session=None, actor=None):
        operation = fixture.operation(auth="authenticated" if session else "public")
        engine.build_plan(fixture.project)
        extra = {"session_id": session["id"]} if session else {}
        captures = [fixture.capture(operation, value, **extra) for value in ("normal", fixture.payload)]
        item = next(item for item in fixture.project.list("obligation") if item.get("kind") == "input_test"
                    and item["operation_id"] == operation["id"] and item.get("test_family") == "xss")
        url = fixture.project.read_artifact(captures[1])["request"]["url"]
        return operation, item, captures, url

    def fixture_row(self, fixture, operation):
        result = self.offline(lambda: workflow.next_work(fixture.project, {"include_blocked": True, "limit": 25}),
                              project=fixture.project)
        return self.work_row(result, operation, "xss")

    def test_explicit_xss_requires_browser_without_a_machine_confirmation_adapter(self):
        operation = self.operation(family="xss", consumer="html_render")
        entry, gap = operation["inputs"][0], self.gap(operation, "xss")
        policy = self.offline(lambda: browser_policy.classify(operation, gap=gap, entry=entry))
        self.assert_policy(policy, "required")
        self.assertIs(policy["proof_requires_browser"], True)
        row = self.work_row(self.planned(), operation, "xss")
        self.assert_handoff(row["browser_testing"], "required")
        self.assertIs(row["positive_machine_adapter"], False)
        self.assertEqual(row["proof_channels"], ["analyst_runtime"])

    def test_declared_browser_consumers_require_playwright_without_new_test_families(self):
        for consumer in ("innerHTML", "client_route", "client_state", "postmessage_receiver", "csrf_flow",
                         "cors_policy", "cookie_attributes", "clickjacking", "oauth_redirect"):
            with self.subTest(consumer=consumer):
                operation = self.operation("/" + consumer.lower(), consumer=consumer)
                policy = self.offline(lambda: browser_policy.classify(operation, gap=self.gap(operation, "generic"),
                                                                      entry=operation["inputs"][0]))
                self.assert_policy(policy, "required")
                self.assertIs(policy["proof_requires_browser"], True)
                self.assertEqual(operation["inputs"][0]["test_families"], ["generic"])

    def test_field_names_and_untrusted_policy_hints_do_not_declare_browser_dependencies(self):
        for name in ("q", "html", "postmessage", "csrf", "oauth"):
            with self.subTest(name=name):
                operation = self.operation("/" + name, consumer="unknown", name=name)
                entry = operation["inputs"][0]
                policy = self.offline(lambda: browser_policy.classify(operation, gap=self.gap(operation, "generic"), entry=entry))
                self.assert_policy(policy, "not_needed")
                self.assertIs(policy["proof_requires_browser"], False)

    def test_output_policy_hints_cannot_downgrade_explicit_xss(self):
        operation = self.operation(family="xss", consumer="html_render")
        entry, gap = deepcopy(operation["inputs"][0]), self.gap(operation, "xss")
        operation["browser_testing"] = entry["browser_testing"] = gap["browser_testing"] = "not_needed"
        original = deepcopy((operation, entry, gap))
        policy = self.offline(lambda: browser_policy.classify(operation, gap=gap, entry=entry))
        self.assert_policy(policy, "required")
        self.assertEqual((operation, entry, gap), original)

    def test_declared_xss_input_family_is_respected_when_gap_is_not_supplied(self):
        operation = self.operation(family="xss", consumer="unknown")
        policy = self.offline(lambda: browser_policy.classify(operation, entry=operation["inputs"][0]))
        self.assert_policy(policy, "required")

    def test_file_upload_is_browser_assisted_but_not_a_new_positive_oracle(self):
        operation = self.operation(family="file_upload", consumer="file_upload", method="POST", content_type="multipart/form-data")
        policy = self.offline(lambda: browser_policy.classify(operation, gap=self.gap(operation, "file_upload"),
                                                             entry=operation["inputs"][0]))
        self.assert_policy(policy, "assisted")
        self.assertIs(policy["proof_requires_browser"], False)
        self.assertIn("file_upload", policy["unsupported_by_native"])
        self.assertIs(policy["native_supported"], False)

    def test_backend_sql_ssrf_and_xxe_do_not_require_unrelated_browser_work(self):
        for family, consumer in (("sql_injection", "sql_like"), ("ssrf", "outbound_http"), ("xxe", "xml_parser")):
            with self.subTest(family=family):
                operation = self.operation("/" + family, family=family, consumer=consumer)
                policy = self.offline(lambda: browser_policy.classify(operation, gap=self.gap(operation, family),
                                                                     entry=operation["inputs"][0]))
                self.assert_policy(policy, "not_needed")
                self.assertIs(policy["proof_requires_browser"], False)

    def test_business_logic_requires_explicit_ui_context_to_be_browser_assisted(self):
        backend = self.operation("/business", family="business_logic", consumer="business_state")
        policy = browser_policy.classify(backend, gap=self.gap(backend, "business_logic"), entry=backend["inputs"][0])
        self.assert_policy(policy, "not_needed")
        ui = self.operation("/business-ui", family="business_logic", consumer="business_logic_ui")
        policy = browser_policy.classify(ui, gap=self.gap(ui, "business_logic"), entry=ui["inputs"][0])
        self.assert_policy(policy, "assisted")

    def test_explicit_page_operation_id_link_assists_even_backend_sql(self):
        operation = self.operation(family="sql_injection", consumer="sql_like")
        linked = self.linked_page(operation)
        policy = self.offline(lambda: browser_policy.classify(operation, gap=self.gap(operation, "sql_injection"),
            entry=operation["inputs"][0], linked_pages=(linked,)))
        self.assert_policy(policy, "assisted")
        row = self.work_row(self.planned(), operation, "sql_injection")
        self.assert_handoff(row["browser_testing"], "assisted")

    def test_exact_api_url_links_are_accepted_but_same_origin_other_urls_are_not_links(self):
        operation = self.operation(family="sql_injection", consumer="sql_like")
        for api, expected in ((operation["url"], "assisted"), ({"url": operation["url"]}, "assisted"),
                              (self.base + "/different-api", "not_needed"),
                              (operation["url"] + "?unrelated=1", "not_needed")):
            with self.subTest(api=api):
                linked = {"id": "PG-explicit", "url": self.base + "/ui", "functions": [{"id": "FN-link", "apis": [api]}]}
                context = browser_policy.Context(self.project)
                context.pages = [linked]
                policy = self.offline(lambda: browser_policy.classify(operation, gap=self.gap(operation, "sql_injection"),
                    entry=operation["inputs"][0], linked_pages=context.linked_pages(operation)))
                self.assert_policy(policy, expected)

    def test_same_input_sql_and_xss_work_items_have_independent_browser_policies(self):
        operation = self.operation(consumer="sql_like", inputs=[{"name": "q", "location": "query", "consumer": "sql_like",
            "test_families": ["sql_injection", "xss"]}])
        result = self.planned(limit=25)
        self.assert_handoff(self.work_row(result, operation, "sql_injection")["browser_testing"], "not_needed")
        self.assert_handoff(self.work_row(result, operation, "xss")["browser_testing"], "required")
        self.assertEqual(self.project.get("operation", operation["id"])["inputs"][0]["test_families"], ["sql_injection", "xss"])

    def test_unsupported_cross_origin_cookie_and_oauth_profiles_cannot_borrow_native_support(self):
        for consumer, reason in (("csrf_flow", "cross_origin_browser_semantics"), ("cors_policy", "cross_origin_browser_semantics"),
                                 ("cookie_attributes", "native_cookie_semantics"), ("oauth_redirect", "redirect_chain")):
            with self.subTest(consumer=consumer):
                operation = self.operation("/" + consumer, consumer=consumer)
                policy = browser_policy.classify(operation, gap=self.gap(operation, "generic"), entry=operation["inputs"][0])
                self.assert_policy(policy, "required")
                self.assertIn(reason, policy["unsupported_by_native"])
                self.assertIs(policy["native_supported"], False)

    def test_new_xss_requires_controls_before_browser_invocation_and_has_valid_http_template(self):
        operation = self.operation(family="xss", consumer="html_render")
        row = self.work_row(self.planned(), operation, "xss")
        policy = row["browser_testing"]
        self.assertEqual(row["queue_status"], "review")
        self.assertEqual(policy["stage"], "capture_controls")
        self.assertFalse(policy["invoke_now"])
        self.assertEqual(row["suggested_action"], "http.preflight")
        self.assertEqual(row["input_template"]["operation_id"], operation["id"])
        self.assertIsNone(policy.get("native_visit_input"))

    def test_two_xss_captures_without_identified_consumer_do_not_guess_browser_url(self):
        with runtime_fixture() as fixture:
            operation, item, captures, url = self.controls(fixture)
            row = self.fixture_row(fixture, operation)
            self.assertEqual(row["browser_testing"]["stage"], "identify_consumer")
            self.assertFalse(row["browser_testing"]["invoke_now"])
            self.assertIsNone(row["browser_testing"].get("native_visit_input"))
            self.assertEqual(row["suggested_action"], "evidence.inspect")
            self.assertTrue(row["control_candidate_review_required"])
            self.assertEqual([capture["id"] for capture in captures], row["control_candidate_evidence_ids"])
            self.assertEqual({"evidence_id": captures[0]["id"]}, row["input_template"])
            self.assertEqual(fixture.project.get("obligation", item["id"])["status"], "open")

    def test_bound_existing_runtime_is_reviewed_offline_without_auto_confirmation(self):
        with runtime_fixture() as fixture:
            operation, item, captures, visit, args = fixture.prepared()
            row = self.fixture_row(fixture, operation)
            self.assertEqual(row["browser_testing"]["stage"], "review_existing")
            self.assertFalse(row["browser_testing"]["call_needed"])
            self.assertFalse(row["browser_testing"]["invoke_now"])
            self.assertEqual(row["suggested_action"], "finding.record")
            self.assertEqual(fixture.project.list("decision"), [])
            self.assertEqual(fixture.project.list("finding"), [])
            self.assertEqual(fixture.project.get("obligation", item["id"])["status"], "open")

    def test_expired_session_does_not_require_replaying_qualified_historical_xss(self):
        with runtime_fixture() as fixture:
            actor, session = fixture.actor("alice")
            operation, item, captures, visit, args = fixture.prepared(session=session, actor=actor)
            stored = fixture.project.get("session", session["id"])
            stored["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
            fixture.project.put("session", stored)
            row = self.fixture_row(fixture, operation)
            self.assertEqual(row["browser_testing"]["stage"], "review_existing")
            self.assertFalse(row["browser_testing"]["call_needed"])
            self.assertFalse(row["browser_testing"]["invoke_now"])
            self.assertEqual(row["suggested_action"], "finding.record")
            self.assertEqual(fixture.project.list("finding"), [])

    def test_page_visit_without_dialog_never_turns_xss_into_negative_or_completed_work(self):
        with runtime_fixture() as fixture:
            operation, item, captures, url = self.controls(fixture)
            fixture.visit(url, dialogs=[])
            row = self.fixture_row(fixture, operation)
            self.assertNotEqual(row["browser_testing"]["stage"], "review_existing")
            self.assertTrue(row["browser_testing"]["proof_requires_browser"])
            self.assertEqual(fixture.project.get("obligation", item["id"])["status"], "open")
            self.assertEqual(fixture.project.list("decision"), [])

    def test_sanitized_get_page_locator_does_not_claim_attack_url_is_ready_for_invocation(self):
        with runtime_fixture() as fixture:
            operation, item, captures, url = self.controls(fixture)
            fixture.visit(url, dialogs=[])
            row = self.fixture_row(fixture, operation)
            policy = row["browser_testing"]
            self.assertIn("exact_captured_attack_url", policy["required_input_fields"])
            self.assertFalse(policy["invoke_now"])
            native = policy.get("native_visit_input")
            if native is not None:
                self.assertEqual(native["url"], url)

    def test_plain_page_observation_does_not_satisfy_required_cors_browser_semantics(self):
        operation = self.operation(consumer="cors_policy")
        linked = self.linked_page(operation)
        raw = {"url": linked["url"], "finalUrl": linked["url"], "status": 200, "signals": {"forms": 1},
               "network": [{"url": linked["url"], "method": "GET", "type": "document", "status": 200, "request_headers": {}}]}
        browser._record_observation(self.project, raw, self.project.id("PV"), "local_playwright")
        row = self.work_row(self.planned(limit=25), operation, "generic")
        self.assert_handoff(row["browser_testing"], "required")
        self.assertFalse(row["browser_testing"]["native_supported"])
        self.assertNotEqual(row["browser_testing"]["stage"], "review_existing")
        self.assertTrue(row["browser_testing"]["call_needed"])
        self.assertEqual(self.project.list("decision"), [])

    def test_fill_or_other_document_runtime_cannot_satisfy_selected_input_attribution(self):
        for mode in ("fill", "other_document"):
            with self.subTest(mode=mode), runtime_fixture() as fixture:
                operation, item, captures, url = self.controls(fixture)
                changes = {"actions": [{"action": "fill", "ok": True, "selector": "#input"}]} if mode == "fill" else {
                    "network": [{"url": url, "method": "GET", "type": "document", "status": 200, "request_headers": {}},
                                {"url": fixture.base + "/other", "method": "GET", "type": "document", "status": 200, "request_headers": {}}]}
                fixture.visit(url, **changes)
                row = self.fixture_row(fixture, operation)
                self.assertNotEqual(row["browser_testing"]["stage"], "review_existing")
                self.assertEqual(fixture.project.get("obligation", item["id"])["status"], "open")

    def test_other_actor_runtime_cannot_be_reused_as_the_controls_identity(self):
        with runtime_fixture() as fixture:
            alice, alice_session = fixture.actor("alice")
            bob, bob_session = fixture.actor("bob")
            operation, item, captures, url = self.controls(fixture, session=alice_session, actor=alice)
            fixture.visit(url, session=bob_session, actor=bob)
            row = self.fixture_row(fixture, operation)
            self.assertNotEqual(row["browser_testing"]["stage"], "review_existing")
            self.assertEqual(fixture.project.list("finding"), [])

    def test_authenticated_mcp_import_does_not_invent_session_bound_xss_runtime(self):
        with runtime_fixture() as fixture:
            actor, session = fixture.actor("alice")
            operation, item, captures, url = self.controls(fixture, session=session, actor=actor)
            raw = {"url": url, "finalUrl": url, "status": 200, "signals": {"forms": 1},
                   "dialogs": [{"type": "alert", "message": fixture.marker, "action_index": None}],
                   "network": [{"url": url, "method": "GET", "type": "document", "status": 200,
                                "request_headers": session["headers"]}]}
            visit = browser._record_observation(fixture.project, raw, fixture.project.id("PV"), "imported_mcp")
            self.assertFalse(visit["machine_authenticated"])
            self.assertIsNone(visit["session_id"])
            row = self.fixture_row(fixture, operation)
            self.assertNotEqual(row["browser_testing"]["stage"], "review_existing")
            self.assertEqual(fixture.project.get("obligation", item["id"])["status"], "open")

    def test_tampered_runtime_artifact_cannot_be_projected_as_qualified_existing_proof(self):
        with runtime_fixture() as fixture:
            operation, item, captures, visit, args = fixture.prepared()
            (fixture.project.base / visit["artifact_path"]).write_text("{}", encoding="utf-8")
            row = self.fixture_row(fixture, operation)
            self.assertNotEqual(row["browser_testing"]["stage"], "review_existing")
            self.assertEqual(fixture.project.get("obligation", item["id"])["status"], "open")

    def test_caller_blocked_xss_requires_offline_reopen_without_browser_invocation(self):
        operation = self.operation(family="xss", consumer="html_render")
        engine.build_plan(self.project)
        item = next(item for item in self.project.list("obligation") if item.get("test_family") == "xss")
        engine.disposition(self.project, {"obligation_id": item["id"], "status": "blocked", "reason": "Fixture authorization unavailable"})
        result = self.offline(lambda: workflow.next_work(self.project, {"include_blocked": True, "limit": 25}))
        row = self.work_row(result, operation, "xss")
        self.assert_handoff(row["browser_testing"], "required")
        self.assertEqual(row["browser_testing"]["stage"], "blocked")
        self.assertFalse(row["browser_testing"]["invoke_now"])
        self.assertEqual(row["queue_status"], "review")
        self.assertEqual(row["declared_status"], "blocked")
        self.assertEqual(row["suggested_action"], "plan.disposition")
        self.assertEqual(row["input_template"]["status"], "open")
        self.assertTrue(row["blocker_reconciliation_required"])
        self.assertTrue(row["execution_blocked"])
        self.assertEqual(self.project.get("obligation", item["id"])["status"], "blocked")

    def test_missing_live_identity_cannot_be_bypassed_by_playwright_tool_preference(self):
        with runtime_fixture() as fixture:
            actor, session = fixture.actor("alice")
            operation = fixture.operation(auth="authenticated")
            engine.build_plan(fixture.project)
            stored = fixture.project.get("session", session["id"])
            stored["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
            fixture.project.put("session", stored)
            row = self.fixture_row(fixture, operation)
            self.assertEqual(row["browser_testing"]["stage"], "blocked")
            self.assertFalse(row["browser_testing"]["invoke_now"])
            self.assertTrue(row["missing_prerequisites"])

    def test_post_xss_never_guesses_the_write_endpoint_as_the_browser_consumer(self):
        with runtime_fixture() as fixture:
            actor, session = fixture.actor("alice")
            engine.update_project(fixture.project, {"allow_mutation": True})
            operation = engine.register_operation(fixture.project, {"url": fixture.base + "/store", "method": "POST",
                "auth": "authenticated", "content_type": "application/json", "inputs": [
                    {"name": "content", "location": "body", "selector": "/content", "consumer": "html_render", "test_families": ["xss"]},
                    {"name": "id", "location": "body", "selector": "/id"}]})
            resource = engine.add_resource(fixture.project, {"operation_id": operation["id"], "owner_actor_id": actor["id"],
                "external_id": "fixture-1", "request_binding": {"location": "body", "selector": "/id"}})
            engine.build_plan(fixture.project)
            for content in ("normal", fixture.payload):
                with patch.object(engine, "request", side_effect=runtime_fixtures.observation):
                    engine.capture(fixture.project, {"operation_id": operation["id"], "session_id": session["id"],
                        "resource_id": resource["id"], "effect": "test_resource_write", "body": {"id": "fixture-1", "content": content}})
            row = self.fixture_row(fixture, operation)
            self.assertEqual(row["browser_testing"]["stage"], "identify_consumer")
            self.assertIsNone(row["browser_testing"].get("native_visit_input"))
            self.assertFalse(row["browser_testing"]["invoke_now"])

    def test_missing_mutation_permission_and_fixture_still_block_browser_assisted_writes(self):
        operation = self.operation(family="file_upload", consumer="file_upload", method="POST", content_type="multipart/form-data")
        row = self.work_row(self.planned(), operation, "file_upload")
        self.assert_handoff(row["browser_testing"], "assisted")
        self.assertEqual(row["browser_testing"]["stage"], "blocked")
        self.assertFalse(row["browser_testing"]["invoke_now"])
        self.assertIn("project_allow_mutation", row["missing_prerequisites"])
        self.assertIn("matching_test_resource_or_declared_actor_state", row["missing_prerequisites"])

    def test_unvisited_page_and_function_have_explicit_browser_call_handoffs(self):
        page = browser.register_page(self.project, {"url": self.base + "/ui"})
        function = browser.register_function(self.project, {"page_id": page["id"], "name": "Details", "trigger": "button#details"})
        result = self.offline(lambda: workflow.next_work(self.project, {"limit": 25}))
        for kind, stage in (("unvisited_page", "observe_page"), ("untriggered_function", "interact_function")):
            row = next(item for item in result["review_followups"] if item["kind"] == kind)
            self.assert_handoff(row["browser_testing"], "required")
            self.assertEqual(row["browser_testing"]["stage"], stage)
            self.assertTrue(row["browser_testing"]["call_needed"])
            self.assertNotEqual(row.get("suggested_action", row["action"]), "page.mark")
            if row["browser_testing"].get("native_visit_input") is not None:
                self.assertEqual(row["browser_testing"]["native_visit_input"]["url"], page["url"])
        self.assertEqual(browser.coverage(self.project)["pages_visited"], 0)
        self.assertEqual(browser.coverage(self.project)["functions_triggered"], 0)

    def test_page_audit_exposes_same_browser_requirements_without_creating_observations(self):
        from awa_ddd import completeness

        page = browser.register_page(self.project, {"url": self.base + "/ui"})
        result = self.offline(lambda: completeness.audit(self.project, {"limit": 100}))
        row = next(item for item in result["checklist"] if item["kind"] == "unvisited_page")
        self.assert_handoff(row["browser_testing"], "required")
        self.assertEqual(row["browser_testing"]["stage"], "observe_page")
        self.assertEqual(self.project.list("page_visit"), [])

    def test_existing_orphan_observation_uses_adoption_instead_of_repeating_browser_calls(self):
        raw = {"url": self.base + "/ui", "finalUrl": self.base + "/ui", "status": 200, "signals": {"forms": 1},
               "network": [{"url": self.base + "/ui", "method": "GET", "type": "document", "status": 200, "request_headers": {}}]}
        visit = browser._record_observation(self.project, raw, self.project.id("PV"), "imported_mcp")
        result = self.offline(lambda: workflow.next_work(self.project, {"limit": 25}))
        row = next(item for item in result["review_followups"] if item["kind"] == "orphan_browser_visit")
        self.assertEqual(row["suggested_action"], "page.adopt")
        self.assertFalse(row["browser_testing"]["call_needed"])
        self.assertFalse(row["browser_testing"]["invoke_now"])
        self.assertEqual(row["browser_testing"]["stage"], "review_existing")
        self.assertEqual(row["input_template"], {"page_visit_id": visit["id"]})
        self.assertEqual(self.project.list("page"), [])

    def test_browser_summary_covers_all_followups_even_when_returned_queue_page_is_empty(self):
        for index in range(14):
            page = browser.register_page(self.project, {"url": self.base + "/ui/" + str(index)})
            browser.register_function(self.project, {"page_id": page["id"], "name": "Details", "trigger": "button#details"})
        first = self.offline(lambda: workflow.next_work(self.project, {"limit": 1}))
        empty = self.offline(lambda: workflow.next_work(self.project, {"limit": 1, "offset": 10000}))
        self.assertEqual(empty["work_items"], [])
        self.assertEqual(first["browser_testing_summary"], empty["browser_testing_summary"])
        summary = empty["browser_testing_summary"]
        self.assertEqual(set(summary), SUMMARY_FIELDS)
        self.assertTrue(all(type(value) is int and value >= 0 for value in summary.values()))
        self.assertEqual(summary["followup_total"], 28)
        self.assertEqual(summary["task_total"], 28)
        self.assertEqual(summary["required_total"], 28)
        self.assertEqual(summary["call_needed_total"], 28)

    def test_browser_summary_includes_blocked_work_independently_of_include_blocked(self):
        operation = self.operation(family="xss", consumer="html_render")
        engine.build_plan(self.project)
        item = next(item for item in self.project.list("obligation") if item.get("test_family") == "xss")
        engine.disposition(self.project, {"obligation_id": item["id"], "status": "blocked", "reason": "Authorization missing"})
        hidden = self.offline(lambda: workflow.next_work(self.project, {"include_blocked": False, "offset": 10000}))
        visible = self.offline(lambda: workflow.next_work(self.project, {"include_blocked": True, "limit": 25}))
        self.assertEqual(hidden["browser_testing_summary"], visible["browser_testing_summary"])
        self.assertGreaterEqual(hidden["browser_testing_summary"]["required_total"], 1)
        self.assertGreaterEqual(hidden["browser_testing_summary"]["blocked_total"], 1)

    def test_plan_next_offline_annotation_never_counts_as_new_security_coverage(self):
        operation = self.operation(family="xss", consumer="html_render")
        result = self.planned()
        self.assertEqual(result["requests_sent"], 0)
        self.assertEqual(result["security_coverage"]["evaluated"], 0)
        self.assertEqual(self.project.list("page_visit"), [])
        self.assertEqual(self.project.list("evidence"), [])
        self.assertEqual(self.project.list("decision"), [])
        self.assertEqual(self.project.list("finding"), [])

    def test_not_needed_backend_work_keeps_empty_browser_provider_and_fallback(self):
        operation = self.operation(family="sql_injection", consumer="sql_like")
        row = self.work_row(self.planned(), operation, "sql_injection")
        self.assert_handoff(row["browser_testing"], "not_needed")
        self.assertEqual(row["browser_testing"]["stage"], "not_needed")
        self.assertFalse(row["browser_testing"]["call_needed"])
        self.assertFalse(row["browser_testing"]["invoke_now"])
        self.assertIsNone(row["browser_testing"].get("native_visit_input"))

    def test_registered_page_function_orphan_and_operation_recheck_changed_scope(self):
        for change in ("exclude", "scope"):
            with self.subTest(change=change):
                identity = "scope-" + change
                engine.create_project(self.project.workspace, {"project_id": identity,
                    "target": self.base + "/allowed", "scope": [self.base]})
                with Project(self.project.workspace, identity) as project:
                    operation = engine.register_operation(project, {"url": self.base + "/api", "method": "GET", "auth": "public",
                        "inputs": [{"name": "q", "location": "query", "consumer": "html_render", "test_families": ["xss"]}]})
                    page = browser.register_page(project, {"url": self.base + "/ui"})
                    browser.register_function(project, {"page_id": page["id"], "name": "Details", "trigger": "button#details",
                        "apis": [{"operation_id": operation["id"]}]})
                    raw = {"url": page["url"], "finalUrl": page["url"], "status": 200, "signals": {"forms": 1},
                           "network": [{"url": page["url"], "method": "GET", "type": "document", "status": 200, "request_headers": {}}]}
                    browser._record_observation(project, raw, project.id("PV"), "imported_mcp")
                    engine.build_plan(project)
                    config = project.config
                    project.set_config({**config, **({"exclude": [page["url"], operation["url"]]} if change == "exclude"
                                                      else {"scope": [self.base + "/allowed"]})})
                    result = self.offline(lambda: workflow.next_work(project, {"include_blocked": True, "limit": 25}), project=project)
                    policy = self.work_row(result, operation, "xss")["browser_testing"]
                    self.assertEqual(policy["stage"], "blocked")
                    self.assertTrue(policy["execution_blocked"])
                    self.assertFalse(policy["invoke_now"])
                    self.assertIn(policy.get("native_visit_input"), (None, {}))
                    self.assertNotIn(operation["url"], json.dumps(policy))
                    for kind in ("unvisited_page", "untriggered_function", "orphan_browser_visit"):
                        item = next(row for row in result["review_followups"] if row["kind"] == kind)
                        self.assertEqual(item["browser_testing"]["stage"], "blocked")
                        self.assertTrue(item["browser_testing"]["execution_blocked"])
                        self.assertFalse(item["browser_testing"]["invoke_now"])
                        self.assertEqual(item["browser_testing"]["native_visit_input"], {})
                        self.assertNotIn(page["url"], json.dumps(item["browser_testing"]))

    def test_explicitly_blocked_linked_page_is_not_implicitly_reopened_for_assisted_work(self):
        operation = self.operation(family="sql_injection", consumer="sql_like")
        linked = self.linked_page(operation)
        initial = self.work_row(self.planned(limit=25), operation, "sql_injection")
        self.assertTrue(initial["browser_testing"]["invoke_now"])
        browser.mark(self.project, {"page_id": linked["id"], "target": "page", "status": "BLOCKED",
            "reason": "This consumer page is explicitly unavailable for browser execution."})
        result = self.offline(lambda: workflow.next_work(self.project, {"include_blocked": True, "limit": 25}))
        row = self.work_row(result, operation, "sql_injection")
        self.assert_policy(row["browser_testing"], "assisted")
        self.assertEqual(row["browser_testing"]["stage"], "blocked")
        self.assertTrue(row["browser_testing"]["execution_blocked"])
        self.assertFalse(row["browser_testing"]["invoke_now"])
        self.assertIn(row["browser_testing"].get("native_visit_input"), (None, {}))
        self.assertEqual(row["suggested_action"], "http.preflight")
        self.assertEqual(self.project.get("page", linked["id"])["visit_status"], "BLOCKED")

    def test_legal_unblocked_linked_alternative_is_preferred_and_excluded_alternatives_are_not_used(self):
        operation = self.operation(family="sql_injection", consumer="sql_like")
        blocked = browser.register_page(self.project, {"url": self.base + "/blocked-ui"})
        browser.register_function(self.project, {"page_id": blocked["id"], "name": "Blocked UI", "trigger": "button#blocked",
            "apis": [{"operation_id": operation["id"]}]})
        alternative = browser.register_page(self.project, {"url": self.base + "/alternative-ui"})
        browser.register_function(self.project, {"page_id": alternative["id"], "name": "Alternative UI", "trigger": "button#alternative",
            "apis": [{"operation_id": operation["id"]}]})
        browser.mark(self.project, {"page_id": blocked["id"], "target": "page", "status": "BLOCKED", "reason": "Explicit consumer blocker"})
        config = self.project.config
        for excluded in (False, True):
            with self.subTest(excluded=excluded):
                self.project.set_config({**config, "exclude": config["exclude"] + ([alternative["url"]] if excluded else [])})
                row = self.work_row(self.planned(limit=25), operation, "sql_injection")
                policy = row["browser_testing"]
                if excluded:
                    self.assertEqual(policy["stage"], "blocked")
                    self.assertFalse(policy["invoke_now"])
                    self.assertIn(policy.get("native_visit_input"), (None, {}))
                else:
                    self.assertEqual(policy["stage"], "browser_assist")
                    self.assertTrue(policy["invoke_now"])
                    self.assertEqual(policy["native_visit_input"]["url"], alternative["url"])
                self.assertNotIn(blocked["url"], json.dumps(policy))
                self.assertEqual(self.project.get("page", blocked["id"])["visit_status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
