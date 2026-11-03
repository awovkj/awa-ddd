"""Only current ledger-bound timestamps survive private-value collisions."""
from __future__ import annotations

from copy import deepcopy
import json
import subprocess
import tempfile
import unittest
import base64
from unittest.mock import patch

from awa_ddd import browser, engine, publication
from awa_ddd.__main__ import dispatch
from awa_ddd.store import Project


START = "2026-11-01T23:59:59.123000+00:00"
FINISH = "2026-11-02T13:12:33.151233+00:00"
COMPLETE = "2026-11-03T13:12:33.151233+08:00"
OTHER = "2026-11-05T06:07:08.123456+00:00"


class TimestampPublicationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="awa-timestamp-")
        self.addCleanup(temporary.cleanup)
        self.root, self.url = temporary.name, "http://fixture.invalid/ui"
        engine.create_project(self.root, {"project_id": "timestamp", "target": "http://fixture.invalid"})
        self.project = Project(self.root, "timestamp")
        self.addCleanup(self.project.close)
        self.visit = self.seed("123")
        self.run = self.record_run()

    def seed(self, pin):
        raw = {"url": self.url, "finalUrl": self.url, "status": 200, "title": pin,
               "signals": {"forms": 123}, "network": [{"url": self.url, "method": "GET", "status": 200}],
               "actions": [{"action": "fill", "selector": "#pin", "value": pin, "ok": True, "finalUrl": self.url}],
               "console": [{"type": "log", "text": pin}], "dialogs": [{"type": "alert", "message": pin}]}
        with patch.object(browser, "now", return_value=COMPLETE):
            result = browser._record_observation(self.project, raw, self.project.id("PV"), "imported_mcp")
        return self.project.get("page_visit", result["id"])

    def record_run(self, *, kind="browser", start=START, finish=FINISH):
        record = {"id": self.project.id("RUN"), "kind": kind, "status": "succeeded", "started_at": start,
                  "finished_at": finish, "completed_at": COMPLETE, "request_signature": "BR-" + "a" * 24,
                  "page_visit_id": self.visit["id"], "planned_page_visit_id": self.visit["id"],
                  "error": "Private PIN 123 must stay private"}
        for key in ("credentials", "redaction_context_required", "redaction_context_checked", "redaction_context_available", "redaction_context_sha256"):
            record[key] = deepcopy(self.visit[key])
        self.project.put("run", record)
        return record

    def published(self, value, action="run.inspect"):
        with patch.object(engine, "request") as network:
            result = publication.publish(self.project, action, value)
        network.assert_not_called()
        return result

    def assert_masked(self, value, field="started_at", *, action="run.inspect"):
        result = self.published(value, action)
        self.assertNotEqual(value[field], result[field])
        self.assertNotIn("123", result[field])
        return result

    def minted_session(self):
        actor = dispatch(self.root, "identity.actor", {"project_id": "timestamp", "subject": "fixture", "roles": []})
        with patch.object(engine, "now", return_value=START):
            session = dispatch(self.root, "identity.session", {"project_id": "timestamp", "actor_id": actor["id"], "headers": {"X-API-Key": "123"}})
        return self.project.get("session", session["id"])

    def test_browser_inner_preservation_is_not_destroyed_by_outer_publication(self):
        inner = browser.public_metadata(self.project, self.run)
        self.assertEqual(FINISH, inner["finished_at"])
        outer = self.published(inner)
        for field in ("started_at", "finished_at", "completed_at", "request_signature"):
            self.assertEqual(self.run[field], outer[field])
        self.assertNotIn("123", outer["error"])
        self.assertNotIn("credentials", outer)

    def test_rpc_native_browser_times_are_deterministically_preserved(self):
        raw = {"url": self.url, "finalUrl": self.url, "status": 200, "title": "123",
               "signals": {"forms": 123}, "network": [{"url": self.url, "method": "GET", "status": 200}],
               "actions": [{"action": "fill", "selector": "#pin", "ok": True, "finalUrl": self.url}]}
        state = {"available": True, "node": "fixture-node", "module_root": "fixture-runtime"}
        with patch.object(browser, "probe", return_value=state), patch.object(browser, "now", return_value=FINISH), \
                patch.object(browser.subprocess, "run", side_effect=lambda command, **options: subprocess.CompletedProcess(command, 0, json.dumps(raw), "")), \
                patch.object(engine, "request") as network:
            public = dispatch(self.root, "browser.visit", {"project_id": "timestamp", "url": self.url,
                "actions": [{"type": "fill", "selector": "#pin", "value": "123"}]})
            inspected = dispatch(self.root, "run.inspect", {"project_id": "timestamp", "run_id": public["run_id"]})
        network.assert_not_called()
        saved = self.project.get("run", public["run_id"])
        self.assertEqual(FINISH, public["created_at"])
        self.assertEqual(FINISH, inspected["started_at"])
        self.assertEqual(FINISH, inspected["finished_at"])
        self.assertEqual(saved["request_signature"], inspected["request_signature"])
        self.assertNotEqual("123", public["title"])

    def test_short_pins_across_dates_do_not_rewrite_current_run_metadata(self):
        for pin in ("123", "11", "2026"):
            with self.subTest(pin=pin):
                self.seed(pin)
                run = {**self.run, "error": "Private value " + pin}
                self.project.put("run", run)
                public = self.published(run)
                for field in ("started_at", "finished_at", "completed_at"):
                    self.assertEqual(run[field], public[field])
                self.assertNotIn(pin, public["error"])

    def test_run_times_in_project_lists_keep_their_own_row_bindings(self):
        other = self.record_run(kind="http", start=OTHER, finish=COMPLETE)
        public = self.published({"runs": [self.run, other]}, "project.status")
        self.assertEqual([START, OTHER], [row["started_at"] for row in public["runs"]])
        self.assertEqual([FINISH, COMPLETE], [row["finished_at"] for row in public["runs"]])

    def test_page_visit_creation_time_is_bound_to_the_page_visit_not_the_run(self):
        public = self.published(browser.public_metadata(self.project, self.visit), "browser.visit")
        self.assertEqual(COMPLETE, public["created_at"])
        self.assertNotEqual("123", public["title"])
        fake = {"id": self.run["id"], "kind": "page_visit", "created_at": COMPLETE}
        self.assert_masked(fake, "created_at", action="browser.visit")

    def test_current_minted_session_generated_times_survive(self):
        actual = self.minted_session()
        actual.update(verified_at=FINISH, expires_at=COMPLETE, renewed_at=OTHER)
        self.project.put("session", actual)
        public = self.published(engine.public_session(actual), "identity.session")
        for field in ("created_at", "verified_at", "expires_at", "renewed_at"):
            self.assertEqual(actual[field], public[field])

    def test_custom_session_ids_do_not_grant_timestamp_restoration(self):
        actor = engine.add_actor(self.project, {"actor_id": "private-actor-123", "subject": "fixture", "roles": []})
        with patch.object(engine, "now", return_value=START):
            session = engine.add_session(self.project, {"session_id": "private-session-123", "actor_id": actor["id"], "headers": {}})
        actual = self.project.get("session", session["id"])
        actual.update(verified_at=FINISH, expires_at=COMPLETE, renewed_at=OTHER)
        self.project.put("session", actual)
        public = self.published(engine.public_session(actual), "identity.session")
        for field in ("created_at", "verified_at", "expires_at", "renewed_at"):
            self.assertNotEqual(actual[field], public[field])
        self.assertNotEqual(actual["id"], public["id"])
        self.assertNotEqual(actual["actor_id"], public["actor_id"])

    def test_real_renewal_candidate_expiry_uses_its_current_session_alias(self):
        session = self.minted_session()
        identity = engine.register_operation(self.project, {"url": "http://fixture.invalid/whoami", "method": "GET", "auth": "authenticated"})
        raw = base64.b64encode(b'{"subject":"fixture"}').decode("ascii")

        def observed(url, method, headers, body, timeout, max_bytes):
            return {"request": {"url": url, "method": method, "headers": headers, "body_base64": ""},
                    "response": {"status": 200, "headers": [["content-type", "application/json"]], "length": 21, "body_base64": raw},
                    "started_at": START, "completed_at": START, "complete": True}

        with patch.object(engine, "request", side_effect=observed):
            engine.verify_identity(self.project, {"operation_id": identity["id"], "session_id": session["id"], "subject_selector": "/subject"})
        session = self.project.get("session", session["id"])
        session["expires_at"] = START
        self.project.put("session", session)
        operation = engine.register_operation(self.project, {"url": "http://fixture.invalid/items", "method": "GET", "auth": "authenticated",
            "inputs": [{"name": "q", "location": "query", "consumer": "business_input", "test_families": ["generic"]}]})
        engine.build_plan(self.project)
        with patch.object(engine, "request") as network:
            result = dispatch(self.root, "plan.next", {"project_id": "timestamp", "include_blocked": True, "limit": 25})
        network.assert_not_called()
        row = next(item for item in result["work_items"] if item["operation_id"] == operation["id"] and item["obligation_kind"] == "input_test")
        candidate = row["session_renewal_candidates"][0]
        self.assertEqual(START, candidate["expires_at"])
        self.assertEqual("blocked", row["queue_status"])
        for generation in (True, 1.0):
            with self.subTest(generation=generation):
                value = {"work_items": [{"session_renewal_candidates": [{**candidate, "generation": generation}]}]}
                public = self.published(value, "plan.next")
                self.assertNotEqual(START, public["work_items"][0]["session_renewal_candidates"][0]["expires_at"])

    def test_wrong_namespace_legacy_run_cannot_restore_a_matching_ledger_time(self):
        for identity in ("legacy-run-123", self.visit["id"]):
            with self.subTest(identity=identity):
                value = {**self.run, "id": identity}
                self.project.put("run", value)
                self.assert_masked(value)

    def test_unknown_run_or_missing_identity_cannot_restore_an_iso_time(self):
        self.assert_masked({"id": "RUN-" + "f" * 32, "kind": "browser", "started_at": START})
        self.assert_masked({"kind": "browser", "started_at": START})
        self.assert_masked({"id": None, "run_id": self.run["id"], "kind": "browser", "started_at": START})

    def test_wrong_kind_and_conflicting_identity_aliases_cannot_borrow_a_run_time(self):
        other = self.record_run()
        for changes in ({"id": self.visit["id"], "run_id": self.run["id"]},
                        {"run_id": other["id"]}, {"kind": "http"}):
            with self.subTest(changes=changes):
                self.assert_masked({**self.run, **changes})

    def test_explicit_run_alias_is_accepted_only_when_it_binds_the_actual_field(self):
        public = self.published({"run_id": self.run["id"], "kind": "browser", "started_at": START})
        self.assertEqual(START, public["started_at"])
        self.assert_masked({"run_id": self.run["id"], "kind": "browser", "started_at": FINISH})

    def test_other_field_other_entity_and_same_instant_other_bytes_are_not_restored(self):
        self.record_run(start=OTHER)
        for value in (FINISH, OTHER, START.replace("+00:00", "Z")):
            with self.subTest(value=value):
                self.assert_masked({**self.run, "started_at": value})

    def test_even_ledger_equal_invalid_or_naive_times_remain_private(self):
        for value in ("2026-11-01T23:59:59.123000", "2026-02-30T23:59:59.123000+00:00",
                      "2026-11-01 23:59:59.123000+00:00", "2026-11-01T23:59:59.1230000+00:00"):
            with self.subTest(value=value):
                changed = {**self.run, "started_at": value}
                self.project.put("run", changed)
                self.assert_masked(changed)

    def test_business_text_source_trees_and_steps_cannot_restore_copied_times(self):
        source = {"id": self.run["id"], "started_at": START, "finished_at": FINISH}
        value = {**self.run, "error": FINISH, "source_meta": source,
                 "checkpoints": [{"step_id": "fixture", "captured_at": FINISH, "started_at": START}],
                 "business_time": FINISH}
        public = self.published(value)
        self.assertEqual(START, public["started_at"])
        self.assertNotEqual(FINISH, public["error"])
        self.assertNotEqual(FINISH, public["business_time"])
        self.assertNotEqual(START, public["source_meta"]["started_at"])
        self.assertNotEqual(FINISH, public["checkpoints"][0]["captured_at"])

    def test_scalar_timestamp_lists_have_no_entity_binding(self):
        context = publication.PublicationContext(self.project)
        rule = publication._record_timestamps("run", "started_at")["started_at"]
        public = context.metadata({"values": [START, FINISH]}, schema={"values": publication._Many(rule)})
        self.assertNotEqual([START, FINISH], public["values"])
        self.assertFalse(context._typed(None, rule, {"id": self.run["id"]}))

    def test_next_publication_rechecks_the_current_entity_field(self):
        self.assertEqual(START, self.published(self.run)["started_at"])
        current = {**self.run, "started_at": OTHER}
        self.project.put("run", current)
        self.assert_masked(self.run)
        self.assertEqual(OTHER, self.published(current)["started_at"])

    def test_legitimate_nullable_run_time_remains_null_without_format_based_restoration(self):
        current = {**self.run, "finished_at": None}
        self.project.put("run", current)
        public = self.published(current)
        self.assertIsNone(public["finished_at"])
        self.assert_masked({**current, "finished_at": FINISH}, "finished_at")


if __name__ == "__main__":
    unittest.main()
