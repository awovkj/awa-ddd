"""Short submitted probe fields must not corrupt unrelated report content."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import browser, engine
from awa_ddd.assessment import record_finding
from awa_ddd.reporting import build_report
from awa_ddd.reproduction import Redactor, _artifact_redactor, _learn_body, _learn_header, _safe_body, _submitted_field_scope
from awa_ddd.store import Project, canonical, now


def artifact(body=b'{"password":"x"}', *, status=400, response=None, complete=True):
    payload = canonical(response if response is not None else {"success": False, "message": "Rejected"}).encode()
    return {"request": {"url": "http://fixture.invalid/login", "method": "POST", "headers": {},
                        "body_base64": base64.b64encode(body).decode()},
            "response": {"status": status, "headers": [["content-type", "application/json"]],
                         "length": len(payload), "body_base64": base64.b64encode(payload).decode()},
            "complete": complete, "started_at": now(), "completed_at": now()}


class SubmittedFieldRedactionTests(unittest.TestCase):
    def learn_probe(self, body, media="application/json"):
        redactor = Redactor()
        source = artifact(body)
        _learn_body(redactor, body, media, field_only=_submitted_field_scope(source))
        return redactor

    def test_short_json_submission_is_masked_by_field_without_corrupting_code(self):
        body = b'{"password":"x","description":"xxe external-general-entities fixture","xxe":"xml"}'
        redactor = self.learn_probe(body)
        self.assertNotIn("x", redactor.values)
        self.assertIn("x", redactor.field_values)
        clean, _, changed = _safe_body(redactor, body, "application/json")
        self.assertTrue(changed)
        public = json.loads(clean)
        self.assertRegex(public["password"], r"^<AWA_PASSWORD_[0-9]+>$")
        self.assertEqual("xxe external-general-entities fixture", public["description"])
        self.assertEqual("xml", public["xxe"])
        self.assertEqual("xxe external-general-entities fixture", redactor.prose(public["description"]))
        self.assertNotIn("x", redactor.values)

    def test_encoded_form_multipart_xml_and_proof_assignments_keep_local_scope(self):
        form = b'password=%78&description=xxe+external-general-entities'
        redactor = self.learn_probe(form, "application/x-www-form-urlencoded")
        clean, _, _ = _safe_body(redactor, form, "application/x-www-form-urlencoded")
        self.assertNotIn(b"password=%78", clean)
        self.assertIn(b"description=xxe+external-general-entities", clean)
        self.assertNotIn("x", redactor.values)

        multipart = (b'--fixture-boundary\r\nContent-Disposition: form-data; name="password"\r\n\r\nx\r\n'
                     b'--fixture-boundary\r\nContent-Disposition: form-data; name="description"\r\n\r\n'
                     b'xxe external-general-entities\r\n--fixture-boundary--\r\n')
        media = "multipart/form-data; boundary=fixture-boundary"
        redactor = self.learn_probe(multipart, media)
        clean, _, _ = _safe_body(redactor, multipart, media)
        self.assertIsNotNone(clean)
        self.assertNotIn(b"\r\n\r\nx\r\n", clean)
        self.assertIn(b"xxe external-general-entities", clean)
        self.assertNotIn("x", redactor.values)

        text = b'<request><password>x</password><description>xxe fixture</description></request>'
        redactor = self.learn_probe(text, "application/xml")
        clean, _, _ = _safe_body(redactor, text, "application/xml")
        self.assertNotIn(b"<password>x</password>", clean)
        self.assertIn(b"<description>xxe fixture</description>", clean)
        for value in ('password="x"', "password='x'", "password=%78", '<password>x</password>'):
            self.assertNotEqual(value, redactor.content(value))
        self.assertEqual("xxe fixture", redactor.content("xxe fixture"))
        self.assertNotIn("x", redactor.values)

    def test_request_field_scoping_does_not_classify_credentials_as_invalid(self):
        for source in (artifact(status=500), artifact(status=200, response={"success": False}),
                       artifact(status=423)):
            self.assertTrue(_submitted_field_scope(source))
        for source in (artifact(status=200, response={"success": True}),
                       artifact(status=200, response={"message": "Rejected"}), artifact(complete=False)):
            self.assertFalse(_submitted_field_scope(source))

    def test_successful_submission_and_long_candidates_still_have_global_protection(self):
        source = artifact(status=200, response={"success": True})
        redactor = Redactor()
        _learn_body(redactor, b'{"password":"x"}', "application/json",
                    field_only=_submitted_field_scope(source))
        self.assertIn("x", redactor.values)
        self.assertNotIn("x", redactor.content("prefixx"))
        redactor = self.learn_probe(b'{"password":"xxxx"}')
        self.assertIn("xxxx", redactor.values)

    def test_session_headers_browser_fill_and_response_secrets_promote_same_value(self):
        for learn in (lambda redactor: _learn_header(redactor, "Authorization", "Bearer x"),
                      lambda redactor: browser._learn_private_value(redactor, "x"),
                      lambda redactor: _learn_body(redactor, b'{"password":"x"}', "application/json"),
                      lambda redactor: _learn_body(redactor, b'password="x"', "text/plain")):
            with self.subTest(learn=learn):
                redactor = self.learn_probe(b'{"password":"x"}')
                placeholder = redactor.field_values["x"]
                learn(redactor)
                self.assertNotIn("x", redactor.field_values)
                self.assertEqual(placeholder, redactor.values["x"])
                self.assertNotIn("x", redactor.content("prefixx"))
                self.assertEqual(placeholder, redactor.structured({"password": "x"})["password"])

    def test_private_context_learned_first_cannot_be_demoted_by_probe_fields(self):
        for private in ("x", "xy", "123"):
            redactor = Redactor()
            browser._learn_private_value(redactor, private)
            _learn_body(redactor, canonical({"password": private}).encode(), "application/json", field_only=True)
            self.assertIn(private, redactor.values)
            self.assertNotIn(private, redactor.field_values)
            self.assertNotIn(private, redactor.content("prefix-" + private + "-suffix"))

    def test_field_masking_remains_stable_through_metadata_and_serialization(self):
        redactor = self.learn_probe(b'{"password":"x"}')
        placeholder = redactor.field_values["x"]
        public = redactor.metadata({"reason": 'xxe; password="x"; fixture', "value_text": "xxe"})
        self.assertIn(placeholder, public["reason"])
        redactor.content(canonical(public))
        self.assertEqual({"x": placeholder}, redactor.field_values)
        self.assertNotIn("x", redactor.values)
        self.assertEqual("xxe", public["value_text"])

    def test_unlabelled_response_echo_and_related_proof_are_local_not_global(self):
        body = b'{"password":"x"}'
        source = artifact(body, response={"success": False, "debug": {"submitted_value": "x"}})
        redactor = self.learn_probe(body)
        _learn_body(redactor, base64.b64decode(source["response"]["body_base64"]), "application/json")
        local = _artifact_redactor(redactor, [source])
        clean, _, _ = _safe_body(local, base64.b64decode(source["response"]["body_base64"]), "application/json")
        self.assertNotEqual("x", json.loads(clean)["debug"]["submitted_value"])
        self.assertNotIn('"observed_value":"x"', local.content('{"observed_value":"x","source_field":"password"}'))
        self.assertNotIn("x", redactor.values)
        self.assertEqual("xxe external_id fixture", redactor.content("xxe external_id fixture"))
        self.assertNotIn("x", redactor.aliases)

    def test_related_artifacts_union_candidates_without_contaminating_other_artifacts(self):
        first = artifact(b'{"password":"x"}')
        second = artifact(b'{"password":"y"}', response={"success": False, "business_text": "xxe fixture"})
        redactor = self.learn_probe(b'{"password":"x"}')
        _learn_body(redactor, b'{"password":"y"}', "application/json", field_only=True)
        independent = _artifact_redactor(redactor, [second])
        self.assertEqual("xxe fixture", independent.content("xxe fixture"))
        related = _artifact_redactor(redactor, [first, second])
        public = related.structured({"first_echo": "x", "second_echo": "y"})
        self.assertNotEqual("x", public["first_echo"])
        self.assertNotEqual("y", public["second_echo"])
        self.assertEqual(set(redactor.field_values), {"x", "y"})
        self.assertFalse(redactor.values)

    def test_local_view_preserves_global_priority_and_late_real_secrets(self):
        source = artifact()
        redactor = self.learn_probe(b'{"password":"x"}')
        local = _artifact_redactor(redactor, [source])
        local.slot("synthetic-late-real-secret", "PASSWORD")
        self.assertIn("synthetic-late-real-secret", redactor.values)
        self.assertNotIn("x", redactor.values)
        _learn_header(redactor, "Authorization", "Bearer x")
        self.assertIn("x", redactor.values)
        self.assertNotIn("x", local.content("prefixx"))
        self.assertNotIn("x", redactor.content("prefixx"))


class AuthorizationProseRedactionTests(unittest.TestCase):
    def test_multitoken_authorization_masks_credentials_not_scheme_words(self):
        token = "PRIVATE-PROSE-AUTHORIZATION-SECRET"
        for scheme in ("Bearer", "Basic", "Negotiate", "NTLM", "Token", "DPoP", "OAuth"):
            for name in ("Authorization", "Proxy-Authorization", "proxy_authorization"):
                with self.subTest(scheme=scheme, name=name):
                    redactor = Redactor()
                    value = name + ": " + scheme + " " + token + "; xxe external-general-entities fixture"
                    public = redactor.prose(value)
                    self.assertNotIn(token, public)
                    self.assertIn("xxe external-general-entities fixture", public)
                    self.assertNotIn(scheme, redactor.values)
                    self.assertNotIn(scheme, redactor.field_values)
                    self.assertNotIn(token, redactor.prose("Unlabelled echo: " + token))
                    self.assertEqual("xxe external_id fixture", redactor.prose("xxe external_id fixture"))

    def test_quoted_header_assignments_and_horizontal_whitespace_are_complete(self):
        token = "PRIVATE-QUOTED-AND-TABBED-SECRET"
        for value in ("Authorization:\tBearer\t" + token,
                      '"Authorization": "Bearer ' + token + '"',
                      "'proxy-authorization'='Bearer " + token + "'",
                      "Proxy-Authorization = Bearer  " + token):
            with self.subTest(value=value):
                redactor = Redactor()
                self.assertNotIn(token, redactor.prose(value))
                self.assertNotIn("Bearer", redactor.values)

    def test_basic_prose_and_real_tabbed_header_protect_encoded_and_decoded_secrets(self):
        password = "PRIVATE-DECODED-BASIC-PASSWORD"
        decoded = "synthetic-user:" + password
        token = base64.b64encode(decoded.encode()).decode()
        for source in ("prose", "header"):
            with self.subTest(source=source):
                redactor = Redactor()
                if source == "prose":
                    public = redactor.prose("Authorization: Basic " + token)
                else:
                    _learn_header(redactor, "Proxy-Authorization", "Basic\t" + token)
                    public = redactor.prose("Observed " + token + " and " + decoded + " and " + password)
                self.assertNotIn(token, public)
                self.assertNotIn(decoded, redactor.prose("Observed " + decoded))
                self.assertNotIn(password, redactor.prose("Observed " + password))
                self.assertNotIn("Basic", redactor.values)

    def test_auth_parameter_lists_and_custom_schemes_do_not_leak_trailing_fields(self):
        for scheme in ("Digest", "Signature", "AWS4-HMAC-SHA256"):
            with self.subTest(scheme=scheme):
                redactor = Redactor()
                parameters = 'username="PRIVATE-USER", credential=PRIVATE-CREDENTIAL, response="PRIVATE-RESPONSE"'
                public = redactor.prose("Authorization: " + scheme + " " + parameters + "; xxe external-general-entities fixture")
                for private in ("PRIVATE-USER", "PRIVATE-CREDENTIAL", "PRIVATE-RESPONSE"):
                    self.assertNotIn(private, public)
                self.assertNotIn(scheme, redactor.values)
                self.assertIn("xxe external-general-entities fixture", public)
        redactor = Redactor()
        self.assertNotIn("PRIVATE-CUSTOM-CREDENTIAL", redactor.prose("Authorization: CustomScheme PRIVATE-CUSTOM-CREDENTIAL"))
        self.assertNotIn("CustomScheme", redactor.values)

    def test_failed_probe_auth_text_does_not_promote_short_candidates(self):
        redactor = Redactor()
        _learn_body(redactor, b'{"password":"x","reason":"Authorization: Bearer x"}', "application/json", field_only=True)
        self.assertIn("x", redactor.field_values)
        self.assertNotIn("x", redactor.values)
        self.assertNotIn("Bearer", redactor.values)
        self.assertEqual("xxe external-general-entities fixture", redactor.prose("xxe external-general-entities fixture"))
        _learn_header(redactor, "Authorization", "Bearer\tx")
        self.assertIn("x", redactor.values)
        self.assertNotIn("x", redactor.field_values)
        self.assertNotIn("x", redactor.content("prefixx"))


class ProbeReportIntegrationTests(unittest.TestCase):
    def test_failed_probe_keeps_report_readable_and_raw_evidence_private(self):
        temporary = tempfile.TemporaryDirectory(prefix="awa-probe-report-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        engine.create_project(root, {"project_id": "probe", "target": "http://fixture.invalid", "allow_mutation": True})
        project = Project(root, "probe")
        self.addCleanup(project.close)
        engine.add_actor(project, {"actor_id": "tester", "subject": "tester", "roles": []})
        identity = engine.register_operation(project, {"url": "http://fixture.invalid/whoami", "method": "GET", "auth": "authenticated"})
        session = engine.add_session(project, {"actor_id": "tester", "headers": {"Authorization": "Bearer synthetic-session-token"}})

        def observed(url, method, headers, body, timeout, max_bytes, *, response, status=200):
            sent = body if isinstance(body, bytes) else body.encode() if isinstance(body, str) else \
                canonical(body).encode() if body is not None else b""
            result = artifact(sent,
                              status=status, response=response)
            result["request"].update(url=url, method=method, headers=headers)
            return result

        with patch.object(engine, "request", side_effect=lambda *args: observed(*args, response={"subject": "tester"})):
            engine.verify_identity(project, {"operation_id": identity["id"], "session_id": session["id"], "subject_selector": "/subject"})
        operation = engine.register_operation(project, {"url": "http://fixture.invalid/login/{id}", "method": "POST", "auth": "authenticated"})
        resource = engine.add_resource(project, {"operation_id": operation["id"], "owner_actor_id": "tester",
            "external_id": "fixture-1", "request_binding": {"location": "path", "selector": "id"}})
        body = {"password": "x", "description": "xxe external-general-entities fixture"}
        with patch.object(engine, "request", side_effect=lambda *args: observed(*args,
                response={"success": False, "debug": {"submitted_value": "x"}}, status=400)):
            evidence = engine.capture(project, {"operation_id": operation["id"], "url": "http://fixture.invalid/login/fixture-1",
                "session_id": session["id"], "resource_id": resource["id"], "effect": "test_resource_write",
                "headers": {"Content-Type": "application/json"}, "body": body})
        record_finding(project, {"mode": "analyst", "title": "xxe parser controls", "category": "Information Disclosure",
            "impact": "Reviewed response only", "remediation": "disable external-general-entities; preserve fixture",
            "reviewer": "fixture reviewer", "reason": "Reviewed original synthetic observation", "evidence_ids": [evidence["id"]]})
        with patch.object(engine, "request", side_effect=AssertionError("Report must not send requests")):
            report = build_report(project)
        text = Path(report["report"]).read_text(encoding="utf-8")
        self.assertIn("xxe parser controls", text)
        self.assertIn("external-general-entities", text)
        self.assertNotIn('"password":"x"', text)
        self.assertNotIn('"submitted_value": "x"', text)
        summary = json.loads(Path(report["summary"]).read_text(encoding="utf-8"))
        self.assertNotIn('"submitted_value":"x"', canonical(summary))
        self.assertIn("external_id", canonical(summary))
        folder = Path(report["report"]).parent
        requests = list((folder / "reproduction").rglob("*.http"))
        self.assertTrue(requests)
        for path in requests:
            raw = path.read_bytes()
            self.assertNotIn(b'"password":"x"', raw)
            self.assertNotIn(b"synthetic-session-token", raw)
            self.assertIn(b"xxe external-general-entities fixture", raw)
        original = project.read_artifact(evidence)
        self.assertEqual(body, json.loads(base64.b64decode(original["request"]["body_base64"])))


if __name__ == "__main__":
    unittest.main()
