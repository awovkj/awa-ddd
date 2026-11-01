"""Project-known redaction across all candidate views, without target traffic."""
from __future__ import annotations

from copy import deepcopy
import json
import re
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import quote

from awa_ddd import candidates, engine
from awa_ddd.__main__ import dispatch
from awa_ddd.store import EngineError, Project, canonical


class CandidatePrivacyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="awa-candidate-private-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.base = "http://fixture.invalid"
        engine.create_project(self.root, {"project_id": "private", "target": self.base})
        self.project = Project(self.root, "private")
        self.addCleanup(self.project.close)
        guard = patch.object(engine, "request")
        self.network = guard.start()
        self.addCleanup(guard.stop)
        self.index = 0

    def tearDown(self):
        self.network.assert_not_called()
        self.assertEqual([], self.project.list("run"))

    def call(self, action, **args):
        return dispatch(self.root, action, {"project_id": "private", **args})

    def credential(self, value, *, actor="private-actor", cookie=False):
        self.call("identity.actor", actor_id=actor, subject="private-subject")
        return self.call("identity.session", actor_id=actor,
                         headers={"Cookie": "pin=" + value} if cookie else {"Authorization": "Bearer " + value})

    def imported_candidate(self, suffix):
        self.index += 1
        source = self.root / ("candidate-" + str(self.index) + ".js")
        url = self.base + "/" + suffix
        source.write_text("fetch(" + json.dumps(url) + ", {method: runtimeMethod});\n", encoding="utf-8")
        imported = self.call("surface.import", path=str(source), format="javascript")
        self.assertEqual(1, imported["candidates"])
        return next(row for row in self.project.list("candidate") if row.get("url") == url)

    def browser_context(self, secret, *, missing=False):
        page = self.base + "/page"
        action = {"type": "fill", "selector": "#private", "ok": True, "finalUrl": page}
        if not missing:
            action["value"] = secret
        raw = {"url": page, "finalUrl": page, "status": 200, "signals": {"forms": 1}, "title": secret,
               "network": [{"url": page, "method": "GET", "status": 200}], "actions": [action]}
        source = self.root / ("missing-browser.json" if missing else "browser.json")
        source.write_text(json.dumps(raw), encoding="utf-8")
        public = self.call("browser.import_mcp", path=str(source))
        return self.project.get("page_visit", public["id"])

    @staticmethod
    def encoded(value, rounds):
        for _ in range(rounds):
            value = quote(value, safe="")
        return value

    def assert_locator_private(self, public):
        self.assertEqual("[candidate locator omitted: protected context]", public["url"])
        self.assertTrue(public["url_redacted"])
        self.assertTrue(public["native_input_requires_binding"])
        self.assertTrue(public["locator_requires_binding"])
        self.assertFalse(public["requestable"])

    def test_real_session_and_js_path_are_redacted_in_list_inspect_and_lifecycle_views(self):
        secret = "synthetic-private-candidate-credential"
        self.credential(secret)
        row = self.imported_candidate(secret)
        before = deepcopy(row)
        listed = self.call("candidate.list")
        inspected = self.call("candidate.inspect", candidate_id=row["id"])
        for value in (listed, inspected):
            self.assertNotIn(secret, json.dumps(value))
        self.assert_locator_private(listed["candidates"][0])
        self.assert_locator_private(inspected["candidate"])
        self.assertEqual(canonical(before), canonical(self.project.get("candidate", row["id"])))
        dismissed = self.call("candidate.dismiss", candidate_id=row["id"], reason=secret)
        self.assertNotIn(secret, json.dumps(dismissed))
        self.assertEqual("dismissed", dismissed["status"])
        self.assert_locator_private(dismissed)
        reopened = self.call("candidate.reopen", candidate_id=row["id"], reason=secret)
        self.assertNotIn(secret, json.dumps(reopened))
        self.assertEqual("unverified", reopened["status"])
        private = self.project.get("candidate", row["id"])
        self.assertEqual(before["url"], private["url"])
        self.assertEqual(before["sources"], private["sources"])
        self.assertEqual(secret, private["reason"])

    def test_encoded_path_aliases_are_private_at_multiple_percent_encoding_depths(self):
        secret = "synthetic-private+candidate%credential"
        self.credential(secret)
        for rounds in (1, 2, 4):
            encoded = self.encoded(secret, rounds)
            row = self.imported_candidate("value/" + encoded)
            public = self.call("candidate.inspect", candidate_id=row["id"])["candidate"]
            self.assertNotIn(secret, json.dumps(public))
            self.assertNotIn(encoded, json.dumps(public))
            self.assert_locator_private(public)
            self.assertEqual(self.base + "/value/" + encoded, self.project.get("candidate", row["id"])["url"])

    def test_lowercase_encoded_hex_cannot_expose_a_known_session_credential(self):
        secret = "synthetic-private+candidate%credential"
        self.credential(secret)
        encoded = re.sub(r"%[0-9A-Fa-f]{2}", lambda match: match.group().lower(), self.encoded(secret, 1))
        row = self.imported_candidate(encoded)
        public = self.call("candidate.inspect", candidate_id=row["id"])["candidate"]
        self.assertNotIn(encoded, json.dumps(public))
        self.assert_locator_private(public)

    def test_short_pin_is_private_even_when_embedded_in_path_and_reason(self):
        pin = "12"
        self.credential(pin, cookie=True)
        row = self.imported_candidate("before" + pin + "after")
        listed = self.call("candidate.list")
        self.assert_locator_private(listed["candidates"][0])
        public = self.call("candidate.dismiss", candidate_id=row["id"], reason="before" + pin + "after")
        self.assertNotIn("before" + pin + "after", json.dumps(public))
        self.assertEqual(row["id"], public["id"])
        self.assertEqual(1, listed["candidate_total"])
        self.assertEqual(1, listed["counts"]["unverified"])

    def test_whole_linked_operation_metadata_is_private_and_raw_fields_are_unchanged(self):
        secret = "synthetic-whole-operation-credential"
        self.credential(secret, actor=secret)
        row = self.imported_candidate(secret)
        operation = self.call("surface.register", url=row["url"], method="GET", auth="public",
            inputs=[{"name": "q", "location": "query", "consumer": secret}],
            sources=[{"path": str(self.root / (secret + ".js")), "reason": secret,
                      "metadata": {secret: secret, "actor_id": secret}}])
        original_operation = self.project.get("operation", operation["id"])
        linked = self.call("candidate.link", candidate_id=row["id"], operation_id=operation["id"])
        before = self.project.get("candidate", row["id"])
        public = self.call("candidate.inspect", candidate_id=row["id"])
        self.assertNotIn(secret, json.dumps([linked, public]))
        self.assertEqual("linked", linked["status"])
        self.assertEqual(row["id"], linked["id"])
        self.assertEqual(operation["id"], linked["operation_id"])
        self.assertEqual(operation["id"], public["operation"]["id"])
        self.assertEqual("GET", public["operation"]["method"])
        self.assert_locator_private(public["operation"])
        self.assertEqual(canonical(before), canonical(self.project.get("candidate", row["id"])))
        self.assertEqual(canonical(original_operation), canonical(self.project.get("operation", operation["id"])))

    def test_leading_zero_pin_and_numeric_metadata_are_private_but_counts_remain_typed(self):
        pin = "000042"
        self.credential(pin)
        row = self.imported_candidate(pin)
        operation = self.call("surface.register", url=row["url"], method="GET", auth="public",
            inputs=[{"name": "q", "location": "query", "consumer": "business_input", "array_template": [42, 42.0]}],
            sources=[{"metadata": {"numeric": 42, "floating": 42.0, "text": pin}}])
        self.call("candidate.link", candidate_id=row["id"], operation_id=operation["id"])
        public = self.call("candidate.inspect", candidate_id=row["id"])
        self.assertNotIn(pin, json.dumps(public))
        template = public["operation"]["inputs"][0]["array_template"]
        self.assertTrue(all(isinstance(value, str) for value in template))
        self.assertIsInstance(public["operation"]["sources"][0]["metadata"]["numeric"], str)
        self.assertIsInstance(public["operation"]["sources"][0]["metadata"]["floating"], str)
        listed = self.call("candidate.list", status="any")
        self.assertEqual(1, listed["candidate_total"])
        self.assertIs(type(listed["counts"]["linked"]), int)
        self.assertEqual([42, 42.0], self.project.get("operation", operation["id"])["inputs"][0]["array_template"])

    def test_valid_private_browser_fill_context_protects_unlabelled_candidate_path(self):
        secret = "23"
        visit = self.browser_context(secret)
        self.assertTrue(visit["redaction_context_required"])
        row = self.imported_candidate("private" + secret + "path")
        public = self.call("candidate.inspect", candidate_id=row["id"])
        self.assert_locator_private(public["candidate"])
        self.assertNotIn("private" + secret + "path", json.dumps(public))
        self.assertNotIn("credentials", json.dumps(public))

    def test_missing_legacy_fill_context_omits_all_untrusted_candidate_content(self):
        unknown = "synthetic-unknown-legacy-fill"
        visit = self.browser_context(unknown, missing=True)
        self.assertFalse(visit["redaction_context_available"])
        row = self.imported_candidate(unknown)
        before = deepcopy(row)
        listed = self.call("candidate.list")
        inspected = self.call("candidate.inspect", candidate_id=row["id"])
        self.assertNotIn(unknown, json.dumps([listed, inspected]))
        self.assertEqual("unavailable", inspected["redaction_context_status"])
        self.assertEqual("unavailable", listed["redaction_context_status"])
        self.assertEqual(row["id"], listed["candidates"][0]["id"])
        self.assertEqual("unverified", listed["candidates"][0]["status"])
        self.assert_locator_private(inspected["candidate"])
        self.assertEqual(canonical(before), canonical(self.project.get("candidate", row["id"])))

    def test_corrupted_required_browser_context_blocks_publication_and_rolls_back_lifecycle(self):
        secret = "synthetic-required-browser-context"
        visit = self.browser_context(secret)
        row = self.imported_candidate(secret)
        self.call("candidate.dismiss", candidate_id=row["id"], reason="Retain this fixture declaration.")
        before = self.project.get("candidate", row["id"])
        changed = dict(visit)
        changed.pop("credentials")
        self.project.put("page_visit", changed)
        for action, args in (("candidate.list", {}), ("candidate.inspect", {"candidate_id": row["id"]}),
                             ("candidate.reopen", {"candidate_id": row["id"], "reason": secret})):
            with self.subTest(action=action), self.assertRaises(EngineError) as caught:
                self.call(action, **args)
            self.assertEqual("browser_redaction_context", caught.exception.code)
            self.assertNotIn(secret, str(caught.exception))
        self.assertEqual(canonical(before), canonical(self.project.get("candidate", row["id"])))

    def test_codeword_secret_does_not_restore_reason_or_corrupt_lifecycle_controls(self):
        secret = "unverified"
        self.credential(secret)
        row = self.imported_candidate(secret)
        listed = self.call("candidate.list")
        self.assertEqual("unverified", listed["candidates"][0]["status"])
        public = self.call("candidate.dismiss", candidate_id=row["id"], reason=secret)
        self.assertEqual("dismissed", public["status"])
        self.assertNotEqual(secret, public["reason"])
        self.assert_locator_private(public)

    def test_engine_handles_survive_a_credential_collision_without_restoring_prose(self):
        row = self.imported_candidate("ordinary")
        secret = row["id"]
        self.credential(secret)
        public = self.call("candidate.dismiss", candidate_id=row["id"], reason="Private literal " + secret)
        self.assertEqual(secret, public["id"])
        self.assertNotIn(secret, public["reason"])
        self.assertEqual("dismissed", public["status"])

    def test_private_public_locator_never_changes_real_scope_exclusion_facts(self):
        secret = "synthetic-private-scope-credential"
        self.credential(secret)
        source = self.root / "outside.openapi.json"
        source.write_text(json.dumps({"openapi": "3.0.3", "info": {"title": "Local scope fixture", "version": "1"},
            "servers": [{"url": "https://outside-fixture.invalid"}],
            "paths": {"/" + secret: {"get": {"responses": {"200": {"description": "ok"}}}}}}), encoding="utf-8")
        self.call("surface.import", path=str(source), format="openapi")
        row = self.project.list("candidate")[0]
        before = deepcopy(row)
        public = self.call("candidate.inspect", candidate_id=row["id"])["candidate"]
        self.assertNotIn(secret, json.dumps(public))
        self.assertTrue(public["native_input_requires_binding"])
        self.assertEqual(canonical(before), canonical(self.project.get("candidate", row["id"])))
        result = self.call("candidate.dismiss", candidate_id=row["id"], reason="Actual declared scope excludes this source.", basis="outside_scope")
        self.assertNotIn(secret, json.dumps(result))
        self.assertTrue(candidates.dismissal_valid(self.project, self.project.get("candidate", row["id"]), engine.evaluate_coverage(self.project)))
        self.assertEqual(before["hint"], self.project.get("candidate", row["id"])["hint"])

    def test_in_scope_raw_candidate_cannot_borrow_exclusion_from_its_private_public_view(self):
        secret = "synthetic-private-in-scope-credential"
        self.credential(secret)
        row = self.imported_candidate(secret)
        public = self.call("candidate.inspect", candidate_id=row["id"])["candidate"]
        self.assert_locator_private(public)
        with self.assertRaises(EngineError) as caught:
            self.call("candidate.dismiss", candidate_id=row["id"], reason="A sanitized locator is not exclusion proof.", basis="outside_scope")
        self.assertEqual("candidate_closure", caught.exception.code)
        self.assertEqual("unverified", self.project.get("candidate", row["id"])["status"])

    def test_unrelated_plain_runtime_marker_is_not_assumed_to_be_a_credential(self):
        marker = "AWA-XSS-0011223344556677"
        row = self.imported_candidate(marker)
        public = self.call("candidate.inspect", candidate_id=row["id"])["candidate"]
        self.assertEqual(row["url"], public["url"])
        self.assertNotIn("url_redacted", public)

    def test_existing_private_locator_flags_survive_list_and_inspection(self):
        identity, _ = candidates.store_candidate(self.project, {"kind": "unverified_source_hint",
            "url": "[private URL omitted]", "url_redacted": True,
            "source": {"sha256": "a" * 64, "locator": "fixture#private-url"}})
        listed = self.call("candidate.list")["candidates"][0]
        inspected = self.call("candidate.inspect", candidate_id=identity)["candidate"]
        for public in (listed, inspected):
            self.assertTrue(public["url_redacted"])
            self.assertTrue(public["native_input_requires_binding"])
            self.assertFalse(public["requestable"])


if __name__ == "__main__":
    unittest.main()
