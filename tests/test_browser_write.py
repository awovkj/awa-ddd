"""Offline checks for browser write policy.

The browser used to abort every non-GET request unconditionally, which made it
impossible to verify anything behind a login form. Writes are now opt-in per
project; two invariants must survive: a project without allow_mutation still
cannot write, and an allowed write must count as a successful visit instead of
being rejected for containing a POST.
"""
from __future__ import annotations

import unittest
from unittest import mock

from awa_ddd import browser
from awa_ddd.store import EngineError


def _raw(**overrides):
    raw = {
        "url": "http://example.test/user/login",
        "finalUrl": "http://example.test/user/login",
        "status": 200,
        "signals": {"hasApp": True, "forms": 1, "inputs": 2},
        "network": [{"url": "http://example.test/user/login", "method": "GET", "status": 200}],
        "actions": [{"index": 0, "action": "click", "selector": "button", "ok": True,
                     "blocked_request_count": 0}],
        "blocked_requests": [],
    }
    raw.update(overrides)
    return raw


def _post_network(**entry):
    item = {"url": "http://example.test/api/user/login", "method": "POST", "status": 200,
            "write": True, "allowed": True}
    item.update(entry)
    return [_raw()["network"][0], item]


class BrowserWritePolicyTests(unittest.TestCase):
    project = None

    def _successful(self, raw):
        with mock.patch.object(type(self).project, "config",
                               {"scope": ["http://example.test/"], "exclude": []}, create=True):
            return browser._successful(type(self).project, raw)

    def setUp(self):
        self.project = mock.MagicMock()
        self.project.config = {"scope": ["http://example.test/"], "exclude": []}

    def test_get_only_observation_stays_successful(self):
        self.assertTrue(browser._successful(self.project, _raw()))

    def test_write_without_authorization_is_not_successful(self):
        raw = _raw(network=_post_network(), write_requests=[
            {"method": "POST", "url": "http://example.test/api/user/login", "status": 200}],
            write_authorized=False)
        self.assertFalse(browser._successful(self.project, raw))

    def test_authorized_write_counts_as_successful_visit(self):
        raw = _raw(network=_post_network(), write_requests=[
            {"method": "POST", "url": "http://example.test/api/user/login", "status": 200}],
            write_authorized=True)
        self.assertTrue(browser._successful(self.project, raw))

    def test_unmarked_write_still_fails(self):
        raw = _raw(network=_post_network(write=False), write_authorized=True)
        self.assertFalse(browser._successful(self.project, raw))

    def test_blocked_request_still_fails(self):
        raw = _raw(blocked_requests=[{"reason": "write_out_of_origin", "method": "POST"}])
        self.assertFalse(browser._successful(self.project, raw))


class BrowserWriteGateTests(unittest.TestCase):
    def _visit_args(self, **extra):
        args = {"url": "http://example.test/user/login", "actions": []}
        args.update(extra)
        return args

    def test_allow_write_is_refused_without_project_permission(self):
        project = mock.MagicMock()
        project.config = {"scope": ["http://example.test/"], "exclude": [], "allow_mutation": False}
        with self.assertRaises(EngineError) as caught:
            browser.visit(project, self._visit_args(allow_write=True))
        self.assertEqual(caught.exception.code, "browser_write_not_authorized")

    def test_allow_write_defaults_to_project_permission(self):
        project = mock.MagicMock()
        project.config = {"scope": ["http://example.test/"], "exclude": [], "allow_mutation": True}
        with mock.patch.object(browser, "_browser_identity",
                               return_value=({}, {}, None, [], None, None)), \
                mock.patch.object(browser, "probe", return_value={"available": False, "reason": "test"}):
            with self.assertRaises(EngineError) as caught:
                browser.visit(project, self._visit_args())
        self.assertEqual(caught.exception.code, "browser_unavailable")

    def test_allow_write_false_opts_one_visit_out(self):
        project = mock.MagicMock()
        project.config = {"scope": ["http://example.test/"], "exclude": [], "allow_mutation": True}
        with mock.patch.object(browser, "_browser_identity",
                               return_value=({}, {}, None, [], None, None)), \
                mock.patch.object(browser, "probe", return_value={"available": False, "reason": "test"}):
            with self.assertRaises(EngineError) as caught:
                browser.visit(project, self._visit_args(allow_write=False))
        self.assertEqual(caught.exception.code, "browser_unavailable")


if __name__ == "__main__":
    unittest.main()
