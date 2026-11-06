"""Regression tests for the anti-repeat guards and report redaction selftest."""
from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import engine
from awa_ddd.browser import _learn_private_value
from awa_ddd.loop_guard import observe_next_page, preflight_seen, repeat_seen
from awa_ddd.reporting_legacy import _report_redaction_selftest
from awa_ddd.reproduction import Redactor
from awa_ddd.store import EngineError, Project


class LoopGuardAndRedactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-loop-guard-")
        self.addCleanup(self.tmp.cleanup)
        engine.create_project(self.tmp.name, {"project_id": "loop-guard", "target": "http://fixture.invalid"})
        self.project = Project(self.tmp.name, "loop-guard")
        self.addCleanup(self.project.close)

    def test_short_browser_fill_values_do_not_become_prose_aliases(self):
        redactor = Redactor()
        for value in ("l", "p", "s", "t", "n", "y", "a"):
            _learn_private_value(redactor, value, short_alias=False)
        text = "local api https login innerHTML maijia2 shop_java"
        self.assertEqual(text, redactor.prose(text))
        self.assertFalse(redactor.aliases)

    def test_known_short_submitted_field_promotes_without_global_alias(self):
        redactor = Redactor()
        redactor.field_slot("x", "BROWSER_INPUT", allow_new=True)
        _learn_private_value(redactor, "x", short_alias=False)
        self.assertIn("x", redactor.field_values)
        self.assertNotIn("x", redactor.aliases)
        self.assertEqual("pre", redactor.prose("pre"))

    def test_preflight_seen_is_bounded_and_duplicate_aware(self):
        self.assertFalse(preflight_seen(self.project, "REQ-abc"))
        self.assertTrue(preflight_seen(self.project, "REQ-abc"))
        self.assertFalse(preflight_seen(self.project, "REQ-def"))

    def test_generic_repeat_guard_counts_only_identical_signatures(self):
        self.assertFalse(repeat_seen(self.project, "prepare", "sig-a"))
        self.assertFalse(repeat_seen(self.project, "prepare", "sig-a"))
        self.assertTrue(repeat_seen(self.project, "prepare", "sig-a"))
        self.assertFalse(repeat_seen(self.project, "prepare", "sig-b"))

    def test_next_page_freezes_only_after_three_identical_pages(self):
        rows = [{"obligation_id": "OB-one", "queue_status": "ready", "suggested_action": "http.preflight",
                 "missing_prerequisites": [], "evidence_ids": []}]
        self.assertEqual(set(), observe_next_page(self.project, 0, 3, rows))
        self.assertEqual(set(), observe_next_page(self.project, 0, 3, rows))
        self.assertEqual({"OB-one"}, observe_next_page(self.project, 0, 3, rows))
        # A changed row signature starts a fresh counter.
        changed = [{**rows[0], "evidence_ids": ["E-new"]}]
        self.assertEqual(set(), observe_next_page(self.project, 0, 3, changed))

    def test_report_redaction_selftest_rejects_corrupted_route_vocabulary(self):
        engine.register_operation(self.project, {"url": "http://fixture.invalid/api/login", "method": "GET", "auth": "public"})
        with self.assertRaises(EngineError) as caught:
            _report_redaction_selftest(self.project, "# Report\nproject: loop-guard\n")
        self.assertEqual("report_redaction_failed", caught.exception.code)
        _report_redaction_selftest(self.project, "# Report\nproject: loop-guard\nGET http://fixture.invalid/api/login\n")
