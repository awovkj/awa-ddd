"""Deep encoded private content stays private in direct APIs and disk exports."""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import quote

from awa_ddd import browser, candidates, engine
from awa_ddd.reporting import build_report
from awa_ddd.reproduction import Redactor, _step
from awa_ddd.store import Project, canonical


def encoded(value, rounds):
    for _ in range(rounds):
        value = quote(value, safe="")
    return value


class EncodedPublicationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="awa-deep-private-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.base = "http://fixture.invalid"
        self.secret = "synthetic-deep+private%credential"
        engine.create_project(self.root, {"project_id": "deep", "target": self.base})
        self.project = Project(self.root, "deep")
        self.addCleanup(self.project.close)
        engine.add_actor(self.project, {"actor_id": "fixture-actor", "subject": "fixture-subject"})
        engine.add_session(self.project, {"actor_id": "fixture-actor", "headers": {"Authorization": "Bearer " + self.secret}})
        guard = patch.object(engine, "request", side_effect=AssertionError("No target requests are allowed"))
        self.network = guard.start()
        self.addCleanup(guard.stop)

    def tearDown(self):
        self.network.assert_not_called()

    def test_private_percent_values_are_omitted_at_and_beyond_the_decode_boundary(self):
        redactor = Redactor()
        redactor.slot(self.secret)
        for depth in (1, 2, 4, 5, 6, 10):
            value = encoded(self.secret, depth)
            with self.subTest(depth=depth):
                for public in (redactor.replace("prefix/" + value), redactor.prose(value), redactor.metadata({"annotation": value})["annotation"]):
                    self.assertNotIn(value, public)
                    self.assertNotIn(self.secret, public)
                with self.assertRaises(ValueError):
                    redactor.url(self.base + "/" + value)

    def test_ordinary_nonce_and_stable_benign_percent_paths_remain_unchanged(self):
        redactor = Redactor()
        redactor.slot(self.secret)
        for value in ("AWA-XSS-" + "a" * 32, "ordinary 25% prose", "some%20business%2Fvalue", encoded("business/value", 2)):
            with self.subTest(value=value):
                self.assertEqual(value, redactor.replace(value))
        self.assertEqual(self.base + "/some%20business%2Fvalue", redactor.url(self.base + "/some%20business%2Fvalue"))

    def test_unresolved_deep_benign_encoding_is_not_published_as_a_bound_request(self):
        redactor = Redactor()
        value = encoded("business/value", 10)
        self.assertEqual("[content omitted: nested encoding limit]", redactor.replace(value))
        with self.assertRaises(ValueError):
            redactor.url(self.base + "/" + value)

    def test_direct_candidate_views_omit_encoded_credentials_and_retain_private_source(self):
        value = encoded(self.secret, 10)
        candidate_id, _ = candidates.store_candidate(self.project, {"kind": "operation_hint", "method": "unknown",
            "url": self.base + "/" + value, "source": {"locator": "fixture#deep", "annotation": value}})
        original = deepcopy(self.project.get("candidate", candidate_id))
        for public in (candidates.inspect_candidate(self.project, {"candidate_id": candidate_id})["candidate"],
                       candidates.list_candidates(self.project, {})["candidates"][0]):
            self.assertNotIn(value, canonical(public))
            self.assertTrue(public["url_redacted"])
            self.assertTrue(public["locator_requires_binding"])
            self.assertTrue(public["native_input_requires_binding"])
            self.assertFalse(public["requestable"])
        self.assertEqual(original, self.project.get("candidate", candidate_id))

    def test_caller_flag_order_cannot_reenable_a_direct_private_candidate_locator(self):
        value = encoded(self.secret, 6)
        candidate_id, _ = candidates.store_candidate(self.project, {"kind": "operation_hint", "method": "unknown",
            "url": self.base + "/" + value, "url_redacted": False, "requestable": True,
            "native_input_requires_binding": False, "locator_requires_binding": False})
        public = candidates.inspect_candidate(self.project, {"candidate_id": candidate_id})["candidate"]
        self.assertTrue(public["url_redacted"])
        self.assertTrue(public["locator_requires_binding"])
        self.assertTrue(public["native_input_requires_binding"])
        self.assertFalse(public["requestable"])
        self.assertTrue(self.project.get("candidate", candidate_id)["requestable"])

    def test_direct_browser_projection_does_not_republish_deep_encoded_content(self):
        for depth in (5, 6, 10):
            value = encoded(self.secret, depth)
            original = {"url": self.base + "/" + value, "title": value, "requestable": True,
                        "locator_requires_binding": False, "native_input_requires_binding": False}
            before = deepcopy(original)
            with self.subTest(depth=depth):
                public = browser.public_metadata(self.project, original)
                self.assertNotIn(value, canonical(public))
                self.assertTrue(public["url_redacted"])
                self.assertTrue(public["locator_requires_binding"])
                self.assertTrue(public["native_input_requires_binding"])
                self.assertFalse(public["requestable"])
                self.assertEqual(before, original)

    def test_direct_report_disk_and_manifest_omit_encoded_credentials(self):
        value = encoded(self.secret, 10)
        operation = engine.register_operation(self.project, {"url": self.base + "/" + value, "method": "GET", "auth": "public",
            "sources": [{"path": "fixture/" + value, "annotation": value}]})
        engine.build_plan(self.project)
        original = deepcopy(self.project.get("operation", operation["id"]))
        result = build_report(self.project)
        folder = Path(result["report"]).parent
        for path in folder.rglob("*"):
            if path.is_file():
                self.assertNotIn(value, path.read_text(encoding="utf-8"))
                self.assertNotIn(self.secret, path.read_text(encoding="utf-8"))
        manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
        for item in manifest["files"]:
            data = (folder / item["path"]).read_bytes()
            self.assertEqual(item["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(item["size_bytes"], len(data))
        self.assertEqual(original, self.project.get("operation", operation["id"]))
        self.assertEqual([], self.project.list("run"))

    def test_encoded_private_locator_never_becomes_a_manual_execution_template(self):
        redactor = Redactor()
        redactor.slot(self.secret)
        data = base64.b64encode(b"{}").decode("ascii")
        artifact = {"request": {"url": self.base + "/" + encoded(self.secret, 10), "method": "GET", "headers": {}, "body_base64": ""},
                    "response": {"status": 200, "headers": [], "body_base64": data}}
        files = {}
        with self.assertRaises(ValueError):
            _step(self.project, redactor, {"id": "E-" + "a" * 32}, artifact, {}, 0, "reproduction/F-" + "b" * 32, files)
        self.assertEqual({}, files)

    def report_fixture(self, pin="12"):
        from test_report_reproduction_20261030 import ReportReproductionTests
        fixture = ReportReproductionTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        engine.add_actor(fixture.project, {"actor_id": "pin-source", "subject": "pin-principal"})
        engine.add_session(fixture.project, {"actor_id": "pin-source", "headers": {"Cookie": "pin=" + pin}})
        return fixture

    def test_direct_mcp_import_and_disk_report_remove_embedded_short_fill_values(self):
        for secret in ("12", "abc1234"):
            with self.subTest(secret=secret):
                url = self.base + "/before" + secret + "after"
                source = self.root / ("short-" + secret + ".json")
                raw = {"url": url, "finalUrl": url, "status": 200, "signals": {"forms": 1},
                       "title": "before" + secret + "after", "network": [{"url": url, "method": "GET", "status": 200}],
                       "actions": [{"type": "fill", "selector": "#fixture", "value": secret, "ok": True, "finalUrl": url}]}
                source.write_text(canonical(raw), encoding="utf-8")
                imported = browser.import_observation(self.project, {"path": str(source)})
                self.assertNotIn("before" + secret + "after", canonical(imported))
                self.assertFalse(imported["requestable"])
                engine.register_operation(self.project, {"url": url, "method": "GET", "auth": "public"})
                engine.build_plan(self.project)
                result = build_report(self.project)
                for path in Path(result["report"]).parent.rglob("*"):
                    if path.is_file():
                        self.assertNotIn("before" + secret + "after", path.read_text(encoding="utf-8"))
                self.assertEqual(raw, self.project.read_artifact(self.project.get("page_visit", imported["id"])))

    def test_body_numeric_aliases_are_content_not_generated_report_counts(self):
        for pin in ("12", "000012"):
            with self.subTest(pin=pin):
                fixture = self.report_fixture(pin)
                original = {"note": "before" + pin + "after", "n": 12, "fraction": 12.0, "nested": [12, 12.0]}
                evidence = fixture.capture(fixture.operation(), body=original, headers={"Content-Type": "application/json"}, response=original)
                saved = deepcopy(fixture.project.read_artifact(evidence))
                finding = fixture.finding([evidence["id"]])
                _, folder, summary, _ = fixture.report()
                step = summary["reproduction"][finding["id"]]["steps"][0]
                body = json.loads((folder / step["body_file"]).read_text(encoding="utf-8"))
                self.assertIsInstance(body["n"], str)
                self.assertIsInstance(body["fraction"], str)
                self.assertTrue(all(isinstance(value, str) for value in body["nested"]))
                self.assertNotIn("before" + pin + "after", step["response_excerpt"])
                self.assertIs(type(summary["coverage"]["operations"]), int)
                self.assertEqual(evidence["id"], step["evidence_id"])
                self.assertEqual(evidence["sha256"], step["source_sha256"])
                self.assertEqual(saved, fixture.project.read_artifact(evidence))

    def test_json_keys_and_target_declared_hex_are_not_opaque_control_exceptions(self):
        fixture = self.report_fixture("1234")
        digest = "0" * 28 + "a1234b" + "0" * 30
        original = {"before1234after": "ordinary fixture data", "digest": digest}
        evidence = fixture.capture(fixture.operation(), body=original, headers={"Content-Type": "application/json"}, response=original)
        finding = fixture.finding([evidence["id"]])
        _, folder, summary, _ = fixture.report()
        step = summary["reproduction"][finding["id"]]["steps"][0]
        data = (folder / step["body_file"]).read_text(encoding="utf-8")
        for content in (data, step["response_excerpt"]):
            self.assertNotIn("before1234after", content)
            self.assertNotIn(digest, content)
        self.assertEqual(evidence["sha256"], step["source_sha256"])
        self.assertEqual(original, json.loads(base64.b64decode(fixture.project.read_artifact(evidence)["request"]["body_base64"])))

    def test_text_xml_form_and_multipart_preserve_framing_without_embedded_pin(self):
        variants = (("text/plain", "before12after"), ("application/xml", "<record><note>before12after</note></record>"),
                    ("application/x-www-form-urlencoded", "note=before12after"),
                    ("multipart/form-data; boundary=fixture-boundary", '--fixture-boundary\r\nContent-Disposition: form-data; name="note"\r\n\r\nbefore12after\r\n--fixture-boundary--\r\n'))
        for media, original in variants:
            with self.subTest(media=media):
                fixture = self.report_fixture()
                evidence = fixture.write("/write", original, content_type=media)
                saved = deepcopy(fixture.project.read_artifact(evidence))
                finding = fixture.finding([evidence["id"]])
                _, folder, summary, _ = fixture.report()
                step = summary["reproduction"][finding["id"]]["steps"][0]
                self.assertTrue(step["body_redacted"])
                self.assertNotIn("before12after", (folder / step["body_file"]).read_text(encoding="utf-8"))
                request = (folder / step["request_file"]).read_bytes()
                head, _, body = request.partition(b"\r\n\r\n")
                self.assertIn(("Content-Length: " + str(len(body))).encode("ascii"), head)
                if media.startswith("multipart"):
                    from awa_ddd.inputs import _multipart
                    self.assertEqual({"note"}, set(_multipart(body, media)))
                self.assertEqual(saved, fixture.project.read_artifact(evidence))

    def test_private_multipart_framing_is_unavailable_not_a_broken_template(self):
        from awa_ddd.reproduction import _safe_body
        redactor = Redactor()
        redactor.slot("12")
        media = "multipart/form-data; boundary=before12after"
        original = b'--before12after\r\nContent-Disposition: form-data; name="note"\r\n\r\nordinary data\r\n--before12after--\r\n'
        body, _, _ = _safe_body(redactor, original, media)
        self.assertIsNone(body)

    def test_direct_signal_extras_are_content_but_declared_structural_counts_remain_typed(self):
        url = self.base + "/signal-fixture"
        raw = {"url": url, "finalUrl": url, "status": 200,
               "signals": {"forms": 12, "business_count": 12, "fraction": 12.0, "nested": {"number": 12}},
               "network": [{"url": url, "method": "GET", "status": 200}],
               "actions": [{"type": "fill", "selector": "#fixture", "value": "12", "ok": True, "finalUrl": url}]}
        path = self.root / "signal-fixture.json"
        path.write_text(canonical(raw), encoding="utf-8")
        public = browser.import_observation(self.project, {"path": str(path)})
        self.assertEqual(12, public["signals"]["forms"])
        self.assertIs(type(public["signals"]["forms"]), int)
        for value in (public["signals"]["business_count"], public["signals"]["fraction"], public["signals"]["nested"]["number"]):
            self.assertIsInstance(value, str)
        self.assertEqual(raw, self.project.read_artifact(self.project.get("page_visit", public["id"])))

    def test_unknown_legacy_fill_context_exports_metadata_only_without_request_material(self):
        fixture = self.report_fixture()
        url = fixture.base + "/page"
        raw = {"url": url, "finalUrl": url, "status": 200, "signals": {"forms": 1},
               "network": [{"url": url, "method": "GET", "status": 200}],
               "actions": [{"type": "fill", "selector": "#fixture", "ok": True, "finalUrl": url}]}
        path = fixture.root / "unknown-fill.json"
        path.write_text(canonical(raw), encoding="utf-8")
        browser.import_observation(fixture.project, {"path": str(path)})
        evidence = fixture.capture(fixture.operation(), url=fixture.base + "/public?q=unknown-private-fill-value")
        finding = fixture.finding([evidence["id"]])
        _, folder, summary, _ = fixture.report()
        self.assertTrue(summary["reproduction_metadata_only"])
        self.assertFalse(summary["reproduction"][finding["id"]]["available"])
        self.assertEqual([], summary["artifacts"])
        self.assertFalse((folder / "reproduction").exists())
        self.assertEqual({"report.md", "summary.json", "manifest.json"}, {file.name for file in folder.iterdir()})
        self.assertTrue(summary["continuation"]["continue_required"])
        self.assertNotIn("unknown-private-fill-value", b"\n".join(file.read_bytes() for file in folder.iterdir()).decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
