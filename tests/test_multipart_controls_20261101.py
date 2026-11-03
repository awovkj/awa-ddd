"""Lossless multipart experiments and early framing failures, without target traffic."""
from __future__ import annotations

import base64
import json
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import engine
from awa_ddd.assessment import _input_context_equal, _input_controls, _input_view, evaluate
from awa_ddd.inputs import control_context, parse_multipart
from awa_ddd.store import EngineError, Project, now


def multipart(content=b"fixed-binary\x00\xff", *, filename=b"normal.png", boundary=b"Bound",
              extra=b"fixed", preamble=b"", epilogue=b"", disposition=None, file_first=True):
    disposition = disposition or b'form-data; name="file"; filename="' + filename + b'"'
    file_part = (b"Content-Disposition: " + disposition + b"\r\nContent-Type: application/octet-stream"
                 + b"\r\n\r\n" + content)
    other_part = b'Content-Disposition: form-data; name="other"\r\n\r\n' + extra
    parts = [file_part, other_part] if file_first else [other_part, file_part]
    return (preamble + b"--" + boundary + b"\r\n" + (b"\r\n--" + boundary + b"\r\n").join(parts)
            + b"\r\n--" + boundary + b"--\r\n" + epilogue)


def observation(raw, *, selector="file", boundary="Bound", media=None, operation_inputs=None):
    operation = {"url": "http://fixture.invalid/upload", "method": "POST", "inputs": operation_inputs
                 if operation_inputs is not None else [{"location": "body", "selector": selector}]}
    request = {"url": operation["url"], "method": "POST", "headers": {"content-type": media
               or "multipart/form-data; boundary=" + boundary}, "body_base64": base64.b64encode(raw).decode("ascii")}
    meta = {"actor_id": "alice", "session_id": "session", "session_generation": 1}
    return (meta, {"request": request}), {"input_location": "body", "input_selector": selector}, operation


def observed(url, method, headers, body, timeout, max_bytes):
    sent = body if isinstance(body, bytes) else body.encode("utf-8") if isinstance(body, str) else b""
    raw = json.dumps({"subject": "alice", "success": True}).encode("utf-8")
    return {"request": {"url": url, "method": method, "headers": headers,
                        "body_base64": base64.b64encode(sent).decode("ascii")},
            "response": {"status": 200, "headers": [], "length": len(raw),
                         "body_base64": base64.b64encode(raw).decode("ascii")},
            "complete": True, "started_at": now(), "completed_at": now()}


class MultipartControlTests(unittest.TestCase):
    def controls(self, bodies, *, selector="file", boundaries=None, media=None):
        boundaries = boundaries or ["Bound"] * len(bodies)
        rows = [observation(raw, selector=selector, boundary=boundary,
                            media=media[index] if media else None)[0]
                for index, (raw, boundary) in enumerate(zip(bodies, boundaries))]
        _, item, operation = observation(bodies[0], selector=selector)
        _input_controls(rows, item, operation)
        return rows, item, operation

    def rejects_controls(self, bodies, *, selector="file", **extra):
        with self.assertRaises(EngineError) as raised:
            self.controls(bodies, selector=selector, **extra)
        self.assertIn(raised.exception.code, {"input_binding", "input_ambiguous", "multipart_framing"})

    def test_only_wire_boundary_may_change_alongside_selected_content(self):
        bodies = [multipart(value, boundary=boundary) for value, boundary in
                  ((b"normal", b"One"), (b"variant", b"Two"), (b"sensitivity", b"Three"))]
        rows, item, operation = self.controls(bodies, boundaries=["One", "Two", "Three"])
        value, context = _input_view(rows[0], item, operation)
        self.assertEqual(b"normal", value)
        self.assertEqual(bodies[0], base64.b64decode(context["body"]["prefix_base64"]) + value
                         + base64.b64decode(context["body"]["suffix_base64"]))
        self.assertIn(b"fixed", base64.b64decode(context["body"]["control_parts"][1]["content_base64"]))

    def test_filename_is_a_separate_declared_input_and_keeps_binary_content(self):
        bodies = [multipart(filename=value) for value in (b"normal.png", b"../variant.png", b"control.png")]
        for selector in ("filename", "file.filename"):
            with self.subTest(selector=selector):
                rows, item, operation = self.controls(bodies, selector=selector)
                value, context = _input_view(rows[1], item, operation)
                self.assertEqual("../variant.png", value)
                self.assertEqual(b"fixed-binary\x00\xff", base64.b64decode(context["body"]["control_parts"][0]["content_base64"]))
        self.rejects_controls([bodies[0], multipart(b"changed", filename=b"../variant.png"), bodies[2]], selector="file.filename")
        self.rejects_controls(bodies, selector="file")

    def test_filename_boundary_variants_preserve_all_other_parameters(self):
        bodies = [multipart(filename=filename, boundary=boundary) for filename, boundary in
                  ((b"normal.png", b"One"), (b"variant.png", b"Two"), (b"control.png", b"Three"))]
        self.controls(bodies, selector="file.filename", boundaries=["One", "Two", "Three"], media=[
            'multipart/form-data; charset=UTF-8; boundary="One"',
            'multipart/form-data; charset=UTF-8; boundary=Two',
            'multipart/form-data; charset=UTF-8; boundary="Three"'])
        self.rejects_controls(bodies, selector="file.filename", boundaries=["One", "Two", "Three"], media=[
            "multipart/form-data; charset=UTF-8; boundary=One",
            "multipart/form-data; charset=ASCII; boundary=Two",
            "multipart/form-data; charset=UTF-8; boundary=Three"])

    def test_nonselected_bytes_part_order_and_padding_remain_controls(self):
        normal, variant, sensitivity = [multipart(value) for value in (b"normal", b"variant", b"control")]
        for changed in (multipart(b"variant", extra=b"different"), multipart(b"variant", file_first=False),
                        variant.replace(b"--Bound\r\n", b"--Bound \r\n"),
                        variant.replace(b"Content-Type: application/octet-stream", b"Content-Type: image/png")):
            with self.subTest(change=changed[:90]):
                self.rejects_controls([normal, changed, sensitivity])

    def test_legal_preamble_and_epilogue_are_preserved_not_ignored(self):
        bodies = [multipart(value, preamble=b"MIME preamble\r\n", epilogue=b"epilogue\x00\xff")
                  for value in (b"normal", b"variant", b"control")]
        rows, item, operation = self.controls(bodies)
        context = _input_view(rows[0], item, operation)[1]["body"]
        self.assertEqual(b"MIME preamble\r\n", base64.b64decode(context["preamble_base64"]))
        self.assertEqual(b"epilogue\x00\xff", base64.b64decode(context["epilogue_base64"]))
        self.rejects_controls([bodies[0], multipart(b"variant", preamble=b"changed\r\n", epilogue=b"epilogue\x00\xff"), bodies[2]])
        self.rejects_controls([bodies[0], bodies[1] + b"changed", bodies[2]])

    def test_header_quoted_filename_is_lossless_utf8_and_exactly_masked(self):
        filename = "\u6d4b\u8bd5.png".encode("utf-8")
        raw = multipart(filename=filename)
        row, item, operation = observation(raw, selector="file.filename")
        self.assertEqual("\u6d4b\u8bd5.png", _input_view(row, item, operation)[0])
        raw = multipart(disposition=b'form-data; name="file"; filename="quoted\\\"name.png"')
        row, item, operation = observation(raw, selector="file.filename")
        self.assertEqual('quoted"name.png', _input_view(row, item, operation)[0])

    def test_filename_controls_require_one_current_exact_declaration(self):
        for inputs in ([], [{"location": "body", "selector": "file.filename"}] * 2,
                       [{"location": "body", "selector": "file.filename", "schema_branch": "different"}]):
            row, item, operation = observation(multipart(), selector="file.filename", operation_inputs=inputs)
            with self.assertRaises(EngineError) as raised:
                _input_view(row, item, operation)
            self.assertEqual("input_ambiguous", raised.exception.code)

    def test_aliases_never_guess_among_multiple_files_or_literal_fields(self):
        extra_file = b'--Bound\r\nContent-Disposition: form-data; name="second"; filename="other.png"\r\n\r\nother\r\n'
        two_files = multipart().replace(b"--Bound--\r\n", extra_file + b"--Bound--\r\n")
        row, item, operation = observation(two_files, selector="filename")
        with self.assertRaises(EngineError) as raised:
            _input_view(row, item, operation)
        self.assertEqual("input_ambiguous", raised.exception.code)
        row, item, operation = observation(two_files, selector="second.filename")
        self.assertEqual("other.png", _input_view(row, item, operation)[0])
        for selector in ("filename", "file.filename"):
            collision = b'--Bound\r\nContent-Disposition: form-data; name="' + selector.encode() + b'"\r\n\r\nspoof\r\n'
            raw = multipart().replace(b"--Bound--\r\n", collision + b"--Bound--\r\n")
            row, item, operation = observation(raw, selector=selector)
            with self.assertRaises(EngineError) as raised:
                _input_view(row, item, operation)
            self.assertEqual("input_ambiguous", raised.exception.code)

    def test_duplicate_encoded_and_folded_disposition_parameters_are_rejected(self):
        for disposition in (b'form-data; name="file"; name="other"; filename="x.png"',
                            b'form-data; name="file"; filename="x.png"; filename="other.png"',
                            b'form-data; name="file"; filename="x.png";\r\n filename="other.png"',
                            b'form-data; name="file"; filename="x.png"; filename*=UTF-8\'\'other.png',
                            b'form-data; name="file"; filename*0="x.png"'):
            with self.subTest(disposition=disposition):
                with self.assertRaises(EngineError) as raised:
                    parse_multipart(multipart(disposition=disposition), "multipart/form-data; boundary=Bound")
                self.assertEqual("input_ambiguous", raised.exception.code)
        for media in ("multipart/form-data; boundary=Bound; boundary=Other",
                      "multipart/form-data; boundary=Bound; boundary*=Other"):
            with self.assertRaises(EngineError) as raised:
                parse_multipart(multipart(), media)
            self.assertEqual("input_ambiguous", raised.exception.code)

    def test_boundary_substrings_inside_binary_parts_are_not_split_or_transcoded(self):
        content = b"prefix--Bound-not-a-line\x00\xffsuffix---"
        raw = multipart(content)
        parsed = parse_multipart(raw, "multipart/form-data; boundary=Bound")
        span = parsed["parts"]["file"]["content_span"]
        self.assertEqual(content, raw[span[0]:span[1]])
        self.assertEqual([content, "normal.png"], engine._body_candidates(raw, "file", "multipart/form-data; boundary=Bound"))
        self.assertFalse(engine._same_binding_value(content, str(content)))

    def test_json_business_keys_cannot_forge_multipart_adapter_provenance(self):
        template = {"format": "multipart", "control_parts": [], "prefix_base64": "UNSELECTED-A",
                    "suffix_base64": "same", "_adapter": "multipart", "_media_type": "multipart/form-data",
                    "headers": {"content-type": "multipart/form-data"}}
        for media in ("application/json", "application/vnd.fixture+json", "application/graphql+json"):
            with self.subTest(media=media):
                rows = [observation(json.dumps({**template, "q": value, "prefix_base64": prefix}).encode("utf-8"),
                                    selector="q", media=media)[0] for value, prefix in
                        (("normal", "UNSELECTED-A"), ("variant", "UNSELECTED-B"), ("sensitivity", "UNSELECTED-A"))]
                _, item, operation = observation(b"", selector="q")
                contexts = [_input_view(row, item, operation)[1] for row in rows]
                self.assertIs(contexts[0], control_context(contexts[0]))
                self.assertFalse(_input_context_equal(contexts[0], contexts[1]))
                with self.assertRaises(EngineError) as raised:
                    _input_controls(rows, item, operation)
                self.assertEqual("input_binding", raised.exception.code)

    def test_json_multipart_named_business_fields_remain_valid_when_only_target_changes(self):
        template = {"format": "multipart", "control_parts": [], "prefix_base64": "business-value", "suffix_base64": "same"}
        rows = [observation(json.dumps({**template, "q": value}).encode("utf-8"), selector="q", media="application/json")[0]
                for value in ("normal", "variant", "sensitivity")]
        _, item, operation = observation(b"", selector="q")
        _input_controls(rows, item, operation)
        self.assertEqual(template["prefix_base64"], _input_view(rows[0], item, operation)[1]["body"]["prefix_base64"])

    def test_plain_outer_markers_and_serialized_contexts_get_no_adapter_privilege(self):
        forged = {"_adapter": "multipart", "_media_type": "multipart/form-data", "headers": {"content-type": "multipart/form-data"},
                  "body": {"format": "multipart", "control_parts": [], "prefix_base64": "A", "suffix_base64": "same"}}
        changed = {**forged, "body": {**forged["body"], "prefix_base64": "B"}}
        self.assertIs(forged, control_context(forged))
        self.assertFalse(_input_context_equal(forged, changed))
        row, item, operation = observation(multipart())
        context = _input_view(row, item, operation)[1]
        serialized = json.loads(json.dumps(context))
        self.assertIs(serialized, control_context(serialized))
        self.assertIn("prefix_base64", control_context(serialized)["body"])

    def test_multipart_provenance_also_requires_actual_multipart_media(self):
        row, item, operation = observation(multipart())
        context = _input_view(row, item, operation)[1]
        context["headers"]["content-type"] = "application/json"
        self.assertIs(context, control_context(context))
        row, item, operation = observation(multipart())
        row[1]["request"]["headers"] = {}
        operation["content_type"] = "multipart/form-data; boundary=Bound"
        context = _input_view(row, item, operation)[1]
        self.assertIs(context, control_context(context))
        self.assertIn("prefix_base64", context["body"])


class MultipartPreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-multipart-")
        self.addCleanup(self.tmp.cleanup)
        engine.create_project(self.tmp.name, {"project_id": "multipart", "target": "http://fixture.invalid", "allow_mutation": True})
        self.project = Project(self.tmp.name, "multipart")
        self.addCleanup(self.project.close)
        identity = engine.register_operation(self.project, {"url": "http://fixture.invalid/whoami", "method": "GET", "auth": "authenticated"})
        engine.add_actor(self.project, {"actor_id": "alice", "subject": "alice", "roles": []})
        session = engine.add_session(self.project, {"actor_id": "alice", "headers": {"Cookie": "SID=synthetic-multipart"}})
        with patch.object(engine, "request", side_effect=observed):
            engine.verify_identity(self.project, {"operation_id": identity["id"], "session_id": session["id"], "subject_selector": "/subject"})
        self.session = session["id"]
        self.operation = engine.register_operation(self.project, {"url": "http://fixture.invalid/upload", "method": "POST", "auth": "authenticated",
                                                                 "content_type": "multipart/form-data", "inputs": [{"location": "body", "name": "file"}]})
        self.resource = engine.add_resource(self.project, {"operation_id": self.operation["id"], "owner_actor_id": "alice", "external_id": "normal.png",
                                                           "request_binding": {"location": "body", "selector": "file.filename"}})

    def args(self, raw):
        return {"operation_id": self.operation["id"], "session_id": self.session, "resource_id": self.resource["id"],
                "body_base64": base64.b64encode(raw).decode("ascii"), "headers": {"Content-Type": "multipart/form-data; boundary=Bound"},
                "effect": "test_resource_write"}

    def test_actual_round_bom_failure_is_rejected_before_a_run_or_request(self):
        args = self.args(b"\xef\xbb\xbf" + multipart())
        before = self.project.list("run")
        for action in (engine.preflight_capture, engine.capture):
            with self.subTest(action=action.__name__), patch.object(engine, "request") as network:
                with self.assertRaises(EngineError) as raised:
                    action(self.project, args)
                self.assertEqual("multipart_framing", raised.exception.code)
                self.assertEqual("utf8_bom", raised.exception.details["framing_issue"])
                self.assertEqual("rewrite_utf8_without_bom", raised.exception.details["repair"])
                self.assertEqual("http.preflight", raised.exception.details["next_action"])
                network.assert_not_called()
                self.assertEqual(before, self.project.list("run"))

    def test_lf_only_missing_closing_and_duplicate_parts_fail_before_execution(self):
        valid = multipart()
        duplicate = valid.replace(b'name="other"', b'name="file"')
        for raw, code in ((valid.replace(b"\r\n", b"\n"), "multipart_framing"),
                          (valid.removesuffix(b"--Bound--\r\n"), "multipart_framing"),
                          (duplicate, "resource_ambiguous")):
            with self.subTest(code=code), patch.object(engine, "request") as network:
                with self.assertRaises(EngineError) as raised:
                    engine.preflight_capture(self.project, self.args(raw))
                self.assertEqual(code, raised.exception.code)
                network.assert_not_called()

    def test_valid_preflight_keeps_original_binary_body_and_does_not_grant_mutation(self):
        raw = multipart(preamble=b"preamble\r\n", epilogue=b"epilogue\xff")
        with patch.object(engine, "request") as network:
            prepared = engine.preflight_capture(self.project, self.args(raw))
            self.assertEqual(raw, prepared["body"])
            network.assert_not_called()
        engine.update_project(self.project, {"allow_mutation": False})
        with self.assertRaises(EngineError) as raised:
            engine.preflight_capture(self.project, self.args(raw))
        self.assertEqual("operation_effect", raised.exception.code)

    def test_captured_filename_experiment_uses_a_fixed_owned_content_fixture(self):
        operation = engine.register_operation(self.project, {"url": self.operation["url"], "method": "POST", "auth": "authenticated",
                    "content_type": "multipart/form-data", "inputs": [{"location": "body", "name": "file.filename",
                    "consumer": "storage_path", "test_families": ["path_traversal"]}]})
        resource = engine.add_resource(self.project, {"operation_id": operation["id"], "owner_actor_id": "alice",
                    "external_id": "fixture-owned-marker", "request_binding": {"location": "body", "selector": "file.content"}})
        rows = []
        for filename in (b"normal.png", b"../variant.png", b"control.png"):
            args = {**self.args(multipart(b"fixture-owned-marker", filename=filename)), "resource_id": resource["id"]}
            with patch.object(engine, "request", side_effect=observed):
                evidence = engine.capture(self.project, args)
            rows.append(engine.verify_current_evidence(self.project, evidence["id"]))
        _input_controls(rows, {"input_location": "body", "input_selector": "file.filename"}, operation)
        with patch.object(engine, "request") as network:
            args = {**self.args(multipart(b"changed-marker", filename=b"../variant.png")), "resource_id": resource["id"]}
            with self.assertRaises(EngineError) as raised:
                engine.preflight_capture(self.project, args)
            self.assertEqual("resource_mismatch", raised.exception.code)
            network.assert_not_called()

    def test_legacy_bom_capture_stays_historical_and_cannot_become_current_proof(self):
        original = engine._multipart_parts
        def legacy_parser(raw, media):
            return original(raw[3:] if raw.startswith(b"\xef\xbb\xbf") else raw, media)
        with patch.object(engine, "_multipart_parts", side_effect=legacy_parser), patch.object(engine, "request", side_effect=observed):
            evidence = engine.capture(self.project, self.args(b"\xef\xbb\xbf" + multipart()))
        with self.assertRaises(EngineError) as raised:
            engine.verify_current_evidence(self.project, evidence["id"])
        self.assertEqual("resource_changed", raised.exception.code)
        self.assertEqual(evidence["id"], self.project.get("evidence", evidence["id"])["id"])

    def test_json_multipart_spoof_cannot_close_a_typed_negative_decision(self):
        operation = engine.register_operation(self.project, {"url": "http://fixture.invalid/json", "method": "POST", "auth": "authenticated",
                    "content_type": "application/json", "inputs": [{"name": "q", "location": "body", "consumer": "business_value",
                    "test_families": ["business_logic"]}]})
        resource = engine.add_resource(self.project, {"operation_id": operation["id"], "owner_actor_id": "alice", "external_id": "owned-fixture",
                    "request_binding": {"location": "body", "selector": "fixture_id"}})
        engine.build_plan(self.project)
        item = next(row for row in self.project.list("obligation") if row["operation_id"] == operation["id"]
                    and row.get("input_selector") == "q" and row.get("test_family") == "business_logic" and not row.get("superseded"))
        def business_response(url, method, headers, body, timeout, max_bytes):
            sent = json.dumps(body).encode("utf-8")
            response = json.dumps({"balance": 200 if body["q"] == "sensitivity" else 100}).encode("utf-8")
            return {"request": {"url": url, "method": method, "headers": headers, "body_base64": base64.b64encode(sent).decode("ascii")},
                    "response": {"status": 200, "headers": [], "length": len(response), "body_base64": base64.b64encode(response).decode("ascii")},
                    "complete": True, "started_at": now(), "completed_at": now()}
        ids = []
        for value, prefix in (("normal", "UNSELECTED-A"), ("variant", "UNSELECTED-B"), ("sensitivity", "UNSELECTED-A")):
            body = {"q": value, "fixture_id": "owned-fixture", "format": "multipart", "control_parts": [],
                    "prefix_base64": prefix, "suffix_base64": "same"}
            with patch.object(engine, "request", side_effect=business_response):
                evidence = engine.capture(self.project, {"operation_id": operation["id"], "session_id": self.session,
                          "resource_id": resource["id"], "effect": "test_resource_write", "body": body})
            ids.append(evidence["id"])
        before = self.project.list("decision")
        with self.assertRaises(EngineError) as raised:
            evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": ids, "oracle": {"type": "semantic_negative",
                     "test_family": "business_logic", "selector": "/balance", "baseline_expected": 100, "control_expected": 200}})
        self.assertEqual("input_binding", raised.exception.code)
        self.assertEqual(before, self.project.list("decision"))
        self.assertEqual("open", self.project.get("obligation", item["id"])["status"])
        def legacy_normalizer(context):
            body = context.get("body")
            if isinstance(body, dict) and body.get("format") == "multipart" and "control_parts" in body:
                return {**context, "body": {key: value for key, value in body.items()
                                           if key not in {"prefix_base64", "suffix_base64"}}}
            return context
        with patch("awa_ddd.inputs.control_context", side_effect=legacy_normalizer):
            legacy = evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": ids,
                              "oracle": {"type": "semantic_negative", "test_family": "business_logic", "selector": "/balance",
                                         "baseline_expected": 100, "control_expected": 200}})
        self.assertEqual("refuted", legacy["outcome"])
        original = self.project.get("decision", legacy["id"])
        with self.assertRaises(EngineError) as raised:
            engine._decision_valid(self.project, original)
        self.assertEqual("input_binding", raised.exception.code)
        self.assertEqual(original, self.project.get("decision", legacy["id"]))


if __name__ == "__main__":
    unittest.main()
