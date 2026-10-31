"""Regression for the three-round heasec-mall engagement (offline; no network).

Each test pins one defect that actually cost the engagement something:

* a 30 minute session TTL silently invalidated already-captured evidence, so
  verified findings flipped to `current: false` and had to be re-run;
* there was no way to renew a session, so the only recovery was to recreate it;
* `origin` rejected values without naming the legal ones;
* the sql_metadata equality template made ORDER BY / LIKE injection points
  unprovable even when sqlmap had already returned database()/current_user();
* an unparameterised DELETE could be proven destructive but had no way to be
  recorded, because analyst SQL demanded a metadata proof decision;
* a path tested only with GET never advertised its DELETE/PUT siblings.

Run:  python -m unittest awa_ddd.tests_heasec_rounds -v
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest

PACKAGE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def call(workspace, action, args):
    process = subprocess.run(
        [sys.executable, "-m", "awa_ddd", "--workspace", workspace],
        input=json.dumps({"action": action, "args": args}),
        text=True, capture_output=True, cwd=PACKAGE,
        env={**os.environ, "PYTHONPATH": PACKAGE})
    try:
        return json.loads(process.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "error": {"code": "unparseable", "raw": process.stdout[:400]}}


PROJECT = "heasec"


class SessionRenewal(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = self.tmp.name
        self.assertTrue(call(self.ws, "project.create", {
            "project_id": PROJECT, "target": "http://shop.test/",
            "scope": ["http://shop.test/"]})["ok"])
        self.assertTrue(call(self.ws, "identity.actor", {
            "project_id": PROJECT, "actor_id": "u1", "label": "u1", "roles": []})["ok"])

    def tearDown(self):
        self.tmp.cleanup()

    def test_renew_keeps_id_and_generation(self):
        created = call(self.ws, "identity.session", {
            "project_id": PROJECT, "actor_id": "u1",
            "headers": {"Cookie": "SID=abc"}, "ttl_seconds": 60})
        self.assertTrue(created["ok"], created)
        sid = created["data"]["id"]
        gen = created["data"]["generation"]

        renewed = call(self.ws, "identity.session", {
            "project_id": PROJECT, "actor_id": "u1", "session_id": sid,
            "ttl_seconds": 3600, "renew": True})
        self.assertTrue(renewed["ok"], renewed)
        # Generation must NOT advance: every capture bound to this identity has to
        # stay current, which a recreate would have invalidated.
        self.assertEqual(renewed["data"]["id"], sid)
        self.assertEqual(renewed["data"]["generation"], gen)
        self.assertGreater(renewed["data"]["expires_at"], created["data"]["expires_at"])

    def test_renew_cannot_swap_credentials(self):
        created = call(self.ws, "identity.session", {
            "project_id": PROJECT, "actor_id": "u1", "headers": {"Cookie": "SID=abc"}})
        sid = created["data"]["id"]
        swapped = call(self.ws, "identity.session", {
            "project_id": PROJECT, "actor_id": "u1", "session_id": sid,
            "headers": {"Cookie": "SID=other"}, "renew": True})
        self.assertFalse(swapped["ok"])
        self.assertEqual(swapped["error"]["code"], "renew_shape")


class OriginErgonomics(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = self.tmp.name
        self.assertTrue(call(self.ws, "project.create", {
            "project_id": PROJECT, "target": "http://shop.test/",
            "scope": ["http://shop.test/"]})["ok"])

    def tearDown(self):
        self.tmp.cleanup()

    def test_bad_origin_names_the_legal_values(self):
        result = call(self.ws, "finding.record", {
            "project_id": PROJECT, "mode": "analyst", "reviewer": "r", "reason": "why",
            "title": "t", "category": "Open Redirect", "impact": "i", "remediation": "x",
            "origin": "bogus", "evidence_ids": ["E-x"]})
        self.assertFalse(result["ok"])
        message = result["error"]["message"]
        for value in ("independent", "hint_guided", "imported"):
            self.assertIn(value, message)


class SqlProofChannels(unittest.TestCase):
    """Pure-function checks on the oracle helpers, no HTTP required."""

    def test_metadata_expression_detects_order_by_payload(self):
        from awa_ddd.assessment import _metadata_expression
        # The exact shape sqlmap uses against an ORDER BY injection point.
        payload = "id,(SELECT (CASE WHEN (1=1) THEN 1 ELSE (SELECT DATABASE()) END))"
        self.assertIsNotNone(_metadata_expression(payload, "database"))
        self.assertIsNone(_metadata_expression("price", "database"))

    def test_error_channel_requires_named_group(self):
        from awa_ddd.assessment import _extract_value, _sql_metadata  # noqa: F401
        artifact = {"response": {"body_base64": base64.b64encode(
            b"XPATH syntax error: '~shop_java'").decode()}}
        bad = {"response_pattern": r"~(\w+)"}          # no (?P<value>...)
        good = {"response_pattern": r"~(?P<value>\w+)"}
        observation = ({"id": "E1"}, artifact)
        with self.assertRaises(Exception) as raised:
            _extract_value(observation, bad)
        self.assertEqual(raised.exception.code, "selector")
        self.assertEqual(_extract_value(observation, good), "shop_java")


class MethodCoverage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = self.tmp.name
        self.assertTrue(call(self.ws, "project.create", {
            "project_id": PROJECT, "target": "http://shop.test/",
            "scope": ["http://shop.test/"]})["ok"])

    def tearDown(self):
        self.tmp.cleanup()

    def test_sibling_verbs_are_derived_from_the_same_path(self):
        from awa_ddd.engine import _path_shape
        a = _path_shape("http://shop.test/api/merchant/products/{productNo}")
        b = _path_shape("http://shop.test/api/merchant/products/SP20260101001")
        self.assertEqual(a, b)
        self.assertNotEqual(a, _path_shape("http://shop.test/api/merchant/products"))

    def test_plan_reports_untested_sibling_methods(self):
        self.assertTrue(call(self.ws, "surface.register", {
            "project_id": PROJECT, "url": "http://shop.test/api/merchant/products/{productNo}",
            "method": "GET", "protocol": "http", "operation_name": "product detail",
            "content_type": "application/json", "auth": "public",
            "allowed_roles": ["anonymous"], "ownership": False,
            "inputs": [], "sources": ["test"]})["ok"])
        self.assertTrue(call(self.ws, "surface.register", {
            "project_id": PROJECT, "url": "http://shop.test/api/merchant/products/{productNo}",
            "method": "DELETE", "protocol": "http", "operation_name": "product delete",
            "content_type": "application/json", "auth": "public",
            "allowed_roles": ["anonymous"], "ownership": False,
            "inputs": [], "sources": ["test"]})["ok"])
        covered = call(self.ws, "report.coverage", {"project_id": PROJECT})
        self.assertTrue(covered["ok"], covered)
        methods = covered["data"].get("method_coverage") or []
        self.assertTrue(methods, "coverage should report per-path method matrix")
        entry = next(item for item in methods
                     if "products" in item["path_shape"][2])
        self.assertEqual(sorted(entry["tested"]), ["DELETE", "GET"])
        self.assertIn("PUT", entry["untested_siblings"])


if __name__ == "__main__":
    unittest.main()
