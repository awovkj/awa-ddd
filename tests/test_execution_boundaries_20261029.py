"""No-network regressions for identity origins and unique test-resource binding."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from awa_ddd import engine
from awa_ddd.__main__ import dispatch
from awa_ddd.scenario import preflight, run_scenario
from awa_ddd.store import EngineError, Project, now


def observed(url, method, headers, body, timeout, max_bytes):
    sent = body if isinstance(body, bytes) else (body.encode("utf-8") if isinstance(body, str)
           else json.dumps(body).encode("utf-8") if body is not None else b"")
    raw = json.dumps({"subject": "alice", "roles": [], "value": "fixture"}).encode("utf-8")
    return {"request": {"url": url, "method": method, "headers": headers,
                        "body_base64": base64.b64encode(sent).decode("ascii")},
            "response": {"status": 200, "headers": [], "length": len(raw),
                         "body_base64": base64.b64encode(raw).decode("ascii")},
            "complete": True, "started_at": now(), "completed_at": now()}


class ExecutionBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-boundaries-")
        self.addCleanup(self.tmp.cleanup)
        self.base, self.other = "http://identity.invalid", "http://other.invalid"
        engine.create_project(self.tmp.name, {"project_id": "boundaries", "target": self.base,
                                             "scope": [self.base, self.other], "allow_mutation": True})
        self.project = Project(self.tmp.name, "boundaries")
        self.addCleanup(self.project.close)
        self.identity = self.operation("/whoami")
        engine.add_actor(self.project, {"actor_id": "alice", "subject": "alice", "roles": []})
        session = engine.add_session(self.project, {"actor_id": "alice", "headers": {"Cookie": "subject=alice-synthetic"}})
        with patch.object(engine, "request", side_effect=observed):
            engine.verify_identity(self.project, {"operation_id": self.identity["id"], "session_id": session["id"],
                                                  "subject_selector": "/subject"})
        self.session = self.project.get("session", session["id"])

    def operation(self, path, **extra):
        return engine.register_operation(self.project, {"url": self.base + path, "method": "GET",
                                                        "auth": "authenticated", **extra})

    def resource(self, operation, *, location="query", selector="id", external="fixture"):
        return engine.add_resource(self.project, {"operation_id": operation["id"], "owner_actor_id": "alice",
                                                 "external_id": external,
                                                 "request_binding": {"location": location, "selector": selector}})

    def args(self, operation, **extra):
        return {"operation_id": operation["id"], "session_id": self.session["id"], **extra}

    def rejects(self, args, code):
        before = self.project.list("run")
        with patch.object(engine, "request") as network:
            for action in (engine.preflight_capture, engine.capture):
                with self.assertRaises(EngineError) as raised:
                    action(self.project, args)
                self.assertEqual(raised.exception.code, code)
        network.assert_not_called()
        self.assertEqual(self.project.list("run"), before)

    def test_native_capture_never_forwards_a_verified_session_to_another_origin(self):
        operation = self.operation("/data", url=self.other + "/data")
        self.rejects(self.args(operation), "identity_origin")

    def test_first_verification_can_explicitly_bind_a_new_session_to_another_scoped_origin(self):
        operation = self.operation("/whoami", url=self.other + "/whoami")
        session = engine.add_session(self.project, {"actor_id": "alice", "headers": {"Cookie": "other-synthetic"}})
        with patch.object(engine, "request", side_effect=observed) as network:
            result = engine.verify_identity(self.project, {"operation_id": operation["id"], "session_id": session["id"],
                                                           "subject_selector": "/subject"})
        self.assertEqual(network.call_count, 1)
        self.assertTrue(self.project.get("session", session["id"])["verified_at"])

    def test_reverification_cannot_move_an_established_session_to_another_origin(self):
        operation = self.operation("/whoami", url=self.other + "/whoami")
        before = self.project.list("run")
        with patch.object(engine, "request") as network:
            with self.assertRaises(EngineError) as raised:
                engine.verify_identity(self.project, {**self.args(operation), "subject_selector": "/subject"})
        self.assertEqual(raised.exception.code, "identity_origin")
        self.assertEqual(self.project.list("run"), before)
        network.assert_not_called()

    def test_origin_binding_includes_scheme_and_port(self):
        for url in ("https://identity.invalid/data", "http://identity.invalid:8080/data"):
            with self.assertRaises(EngineError) as raised:
                engine.require_session_origin(self.project, self.session, url)
            self.assertEqual(raised.exception.code, "identity_origin")

    def test_old_cross_origin_capture_is_readable_but_not_current(self):
        operation = self.operation("/data", url=self.other + "/data")
        with patch.object(engine, "require_session_origin"), patch.object(engine, "request", side_effect=observed):
            evidence = engine.capture(self.project, self.args(operation))
        self.assertTrue(self.project.read_artifact(evidence)["complete"])
        with self.assertRaises(EngineError) as raised:
            engine.verify_current_evidence(self.project, evidence["id"])
        self.assertEqual(raised.exception.code, "identity_origin")

    def test_inspect_explicitly_marks_corrupt_artifacts_unusable(self):
        operation = self.operation("/data", auth="public")
        with patch.object(engine, "request", side_effect=observed):
            evidence = engine.capture(self.project, {"operation_id": operation["id"]})
        (self.project.base / evidence["artifact_path"]).write_text("{}", encoding="utf-8")
        result = dispatch(self.tmp.name, "evidence.inspect", {"project_id": "boundaries", "evidence_id": evidence["id"]})
        self.assertEqual((result["integrity"], result["lineage"]), ("invalid", "invalid"))
        self.assertFalse(result["usable"])
        self.assertFalse(result["usable_for_new_requests"])
        self.assertEqual(result["session_status"], "none")
        self.assertTrue(result["complete"])

    def test_inspect_of_removed_operation_keeps_explicit_unusable_fields(self):
        operation = self.operation("/data", auth="public")
        with patch.object(engine, "request", side_effect=observed):
            evidence = engine.capture(self.project, {"operation_id": operation["id"]})
        with self.project.transaction():
            self.project.connection.execute("DELETE FROM entities WHERE kind='operation' AND id=?", (operation["id"],))
        result = dispatch(self.tmp.name, "evidence.inspect", {"project_id": "boundaries", "evidence_id": evidence["id"]})
        self.assertEqual(result["lineage"], "operation_missing")
        self.assertFalse(result["usable"])
        self.assertFalse(result["usable_for_new_requests"])
        self.assertEqual(result["session_status"], "none")

    def test_query_resource_selector_must_occur_once_even_with_equal_values(self):
        operation = self.operation("/modify", method="POST")
        resource = self.resource(operation)
        for query in ("id=fixture&id=other", "id=other&id=fixture", "id=fixture&id=fixture", "i%64=fixture&id=other"):
            self.rejects(self.args(operation, url=self.base + "/modify?" + query, resource_id=resource["id"],
                                   effect="test_resource_write"), "resource_ambiguous")
        prepared = engine.preflight_capture(self.project, self.args(operation, url=self.base + "/modify?id=fixture",
                                             resource_id=resource["id"], effect="test_resource_write"))
        self.assertEqual(prepared["resource"]["id"], resource["id"])

    def test_old_duplicate_query_capture_cannot_remain_a_current_fixture_proof(self):
        operation = self.operation("/modify", method="POST")
        resource = self.resource(operation)
        with patch.object(engine, "_resource_binding"), patch.object(engine, "request", side_effect=observed):
            evidence = engine.capture(self.project, self.args(operation, url=self.base + "/modify?id=fixture&id=other",
                                       resource_id=resource["id"], effect="test_resource_write"))
        with self.assertRaises(EngineError) as raised:
            engine.verify_current_evidence(self.project, evidence["id"])
        self.assertEqual(raised.exception.code, "resource_changed")

    def test_plain_json_keys_and_duplicate_object_keys_cannot_hide_another_binding(self):
        operation = self.operation("/modify", method="POST", content_type="application/json")
        resource = self.resource(operation, location="body")
        for body in ({"one": {"id": "fixture"}, "two": {"id": "other"}}, '{"id":"other","id":"fixture"}'):
            self.rejects(self.args(operation, resource_id=resource["id"], body=body,
                                   effect="test_resource_write"), "resource_ambiguous")
        exact = self.resource(operation, location="body", selector="/one/id")
        prepared = engine.preflight_capture(self.project, self.args(operation, resource_id=exact["id"],
                                             body={"one": {"id": "fixture"}}, effect="test_resource_write"))
        self.assertEqual(prepared["resource"]["id"], exact["id"])

    def test_repeated_multipart_fields_or_disposition_parameters_are_rejected(self):
        operation = self.operation("/upload", method="POST", content_type="multipart/form-data")
        resource = self.resource(operation, location="body", selector="file", external="fixture.txt")
        part = '--awa\r\nContent-Disposition: form-data; name="file"; filename="{}"\r\n\r\ncontent\r\n'
        payloads = [part.format("other.txt") + part.format("fixture.txt") + "--awa--\r\n",
                    '--awa\r\nContent-Disposition: form-data; name="other"; name="file"; filename="fixture.txt"'
                    '\r\n\r\ncontent\r\n--awa--\r\n',
                    '--awa\r\nContent-Disposition: form-data; name="file"; filename="other.txt"; filename="fixture.txt"'
                    '\r\n\r\ncontent\r\n--awa--\r\n',
                    '--awa\r\nContent-Disposition: form-data; name="file"; filename=other.txt; filename="fixture.txt"'
                    '\r\n\r\ncontent\r\n--awa--\r\n',
                    '--awa\r\nContent-Disposition: form-data; name=other; name="file"; filename="fixture.txt"'
                    '\r\n\r\ncontent\r\n--awa--\r\n',
                    '--awa\r\nContent-Disposition: form-data; name="file"; filename=other.txt;'
                    '\r\n filename="fixture.txt"\r\n\r\ncontent\r\n--awa--\r\n']
        for body in payloads:
            self.rejects(self.args(operation, resource_id=resource["id"], body=body,
                                   headers={"Content-Type": "multipart/form-data; boundary=awa"},
                                   effect="test_resource_write"), "resource_ambiguous")

    def test_global_multipart_aliases_must_select_exactly_one_part(self):
        operation = self.operation("/upload", method="POST", content_type="multipart/form-data")
        part = '--awa\r\nContent-Disposition: form-data; name="{}"; filename="{}"\r\n\r\n{}\r\n'
        body = part.format("one", "fixture.txt", "fixture") + part.format("two", "other.txt", "other") + "--awa--\r\n"
        for selector in ("filename", "file.filename", "content", "file.content"):
            resource = self.resource(operation, location="body", selector=selector,
                                     external="fixture.txt" if selector.endswith("filename") else "fixture")
            self.rejects(self.args(operation, resource_id=resource["id"], body=body,
                                   headers={"Content-Type": "multipart/form-data; boundary=awa"},
                                   effect="test_resource_write"), "resource_ambiguous")

    def test_multipart_binding_does_not_strip_real_trailing_hyphens(self):
        body = '--awa\r\nContent-Disposition: form-data; name="id"\r\n\r\nfixture---\r\n--awa--\r\n'
        self.assertEqual(engine._body_candidates(body, "id", "multipart/form-data; boundary=awa"), ["fixture---"])

    def test_actor_scoped_writes_cannot_hide_undeclared_query_or_body_inputs(self):
        operation = self.operation("/self-state", method="POST", state_scope="actor")
        for extra in ({"url": self.base + "/self-state?id=other"}, {"body": {"id": "other"}},
                      {"body": {}}, {"body": "other"}, {"body_base64": "b3RoZXI="}):
            self.rejects(self.args(operation, effect="test_resource_write", **extra), "operation_effect")
        for extra in ({}, {"body": ""}, {"body_base64": ""}):
            prepared = engine.preflight_capture(self.project, self.args(operation, effect="test_resource_write", **extra))
            self.assertEqual(prepared["body_bytes"], 0)

    def test_actor_scope_cannot_bind_an_undeclared_path_placeholder(self):
        with self.assertRaises(EngineError) as raised:
            self.operation("/self-state/{id}", method="POST", state_scope="actor")
        self.assertEqual(raised.exception.code, "state_scope")

    def test_old_fixture_free_write_with_business_body_is_preserved_but_not_current(self):
        operation = self.operation("/self-state", method="POST", state_scope="actor")
        with patch.object(engine, "_actor_bound_write", return_value=True), patch.object(engine, "request", side_effect=observed):
            evidence = engine.capture(self.project, self.args(operation, body={"id": "other"}, effect="test_resource_write"))
        self.assertTrue(self.project.read_artifact(evidence)["complete"])
        with self.assertRaises(EngineError) as raised:
            engine.verify_current_evidence(self.project, evidence["id"])
        self.assertEqual(raised.exception.code, "resource_unbound")

    def test_dynamic_scenario_data_does_not_hide_static_origin_or_fixture_failures(self):
        first = self.operation("/echo", auth="public")
        query = self.operation("/modify", method="POST")
        resource = self.resource(query)
        self_state = self.operation("/self-state", method="POST", state_scope="actor")
        other = self.operation("/data", url=self.other + "/data")
        variants = [self.args(query, url=self.base + "/modify?id=fixture&id=other", resource_id=resource["id"],
                              body={"x": "${one.value}"}, effect="test_resource_write"),
                    self.args(self_state, body={"x": "${one.value}"}, effect="test_resource_write"),
                    self.args(other, body={"x": "${one.value}"})]
        before = self.project.list("run")
        for variant in variants:
            args = {"scenario": {"steps": [{"id": "one", "operation_id": first["id"], "extract": {"value": "/value"}},
                                             {"id": "two", **variant}]}}
            with patch.object(engine, "request") as network:
                self.assertFalse(preflight(self.project, args)["static_valid"])
                with self.assertRaises(EngineError) as raised:
                    run_scenario(self.project, args)
                self.assertEqual(raised.exception.code, "scenario_preflight")
            network.assert_not_called()
        self.assertEqual(self.project.list("run"), before)

    def test_body_file_read_is_bounded_even_when_its_size_changes(self):
        path = Path(self.tmp.name) / "body.bin"
        path.write_bytes(b"x" * (2 * 1024 * 1024))
        operation = self.operation("/data")
        self.rejects(self.args(operation, body_file=str(path)), "body_file")
        with patch.object(engine.os, "fstat", return_value=SimpleNamespace(st_mode=stat.S_IFREG, st_size=0)):
            self.rejects(self.args(operation, body_file=str(path)), "body_budget")

    @unittest.skipUnless(os.name == "nt", "Windows device path")
    def test_body_file_cannot_read_a_windows_device(self):
        operation = self.operation("/data")
        self.rejects(self.args(operation, body_file=str(Path(self.tmp.name) / "NUL")), "body_file")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO")
    def test_body_file_rejects_fifo_without_waiting_for_a_writer(self):
        path = Path(self.tmp.name) / "body.fifo"
        os.mkfifo(path)
        operation = self.operation("/data")
        self.rejects(self.args(operation, body_file=str(path)), "body_file")


if __name__ == "__main__":
    unittest.main()
