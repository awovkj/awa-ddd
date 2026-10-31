"""Loopback regressions for identity, fixture lineage and honest coverage."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import http.server
import json
import sqlite3
import tempfile
import threading
import unittest
from urllib.parse import quote, unquote, urlsplit
from unittest.mock import patch

from awa_ddd import engine
from awa_ddd.__main__ import dispatch
from awa_ddd.assessment import _sql_behaviour_proof, evaluate, record_finding
from awa_ddd.scope import require_scope
from awa_ddd.store import EngineError, Project, canonical


class IntegrityHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.calls += 1
        cookie = self.headers.get("Cookie", "")
        actor = "alice" if "actor=alice" in cookie else "bob" if "actor=bob" in cookie else self.headers.get("X-Actor")
        if self.path == "/whoami":
            payload = {"id": actor, "roles": self.server.role_by_actor.get(actor, ["user"]),
                       "tenant": "tenant-one", "logged_in": bool(actor)}
        elif self.path.startswith("/items/"):
            payload = {"id": self.path.split("/", 2)[-1], "secret": "synthetic-protected-value"}
        else:
            payload = {"ok": True}
        raw = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        self.server.calls += 1
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        raw = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_DELETE(self):
        self.server.calls += 1
        identifier = unquote(urlsplit(self.path).path.rsplit("/", 1)[-1])
        # This intentionally vulnerable, isolated loopback fixture exercises a
        # real destructive SQL effect instead of treating response text as proof.
        with self.server.database_lock:
            cursor = self.server.database.execute("DELETE FROM products WHERE id = '" + identifier + "'")
            deleted = cursor.rowcount
            self.server.database.commit()
        raw = json.dumps({"deleted_count": deleted, "nonce": self.server.calls,
                          "message": "removed" if deleted else "not found"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-integrity-")
        self.addCleanup(self.tmp.cleanup)
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), IntegrityHandler)
        self.server.calls = 0
        self.server.role_by_actor = {}
        self.server.database = sqlite3.connect(":memory:", check_same_thread=False)
        self.server.database.execute("CREATE TABLE products (id TEXT PRIMARY KEY)")
        self.server.database.executemany("INSERT INTO products VALUES (?)", [("one",), ("two",), ("three",)])
        self.server.database.commit()
        self.server.database_lock = threading.Lock()
        self.addCleanup(self.server.database.close)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = "http://127.0.0.1:" + str(self.server.server_port)
        engine.create_project(self.tmp.name, {
            "project_id": "integrity", "target": self.base, "allow_mutation": True})
        self.project = Project(self.tmp.name, "integrity")
        self.addCleanup(self.project.close)
        self.identity = engine.register_operation(self.project, {
            "url": self.base + "/whoami", "method": "GET", "auth": "authenticated"})

    def actor(self, identity, subject=None, **extra):
        session_headers = extra.pop("session_headers", {"X-Actor": subject or identity})
        credentials = extra.pop("credential_header_names", ["X-Actor"])
        verify_roles = extra.pop("verify_roles", True)
        args = {"actor_id": identity, "subject": subject or identity,
                "roles": ["user"], "tenant_id": "tenant-one"}
        args.update(extra)
        actor = engine.add_actor(self.project, args)
        session = engine.add_session(self.project, {
            "actor_id": identity, "headers": session_headers, "credential_header_names": credentials})
        engine.verify_identity(self.project, {
            "operation_id": self.identity["id"], "session_id": session["id"],
            "subject_selector": "/id", "roles_selector": "/roles" if verify_roles else None, "tenant_selector": "/tenant"})
        return actor, self.project.get("session", session["id"])

    def operation(self, path="/items/{id}", **extra):
        args = {"url": self.base + path, "method": "GET", "auth": "authenticated"}
        args.update(extra)
        return engine.register_operation(self.project, args)

    def resource(self, operation, owner, external="owned-1", **extra):
        args = {"operation_id": operation["id"], "owner_actor_id": owner,
                "external_id": external, "request_binding": {"location": "path", "selector": "id"}}
        args.update(extra)
        return engine.add_resource(self.project, args)

    def capture(self, operation, session, resource=None, **extra):
        args = {"operation_id": operation["id"], "session_id": session["id"]}
        if resource:
            args.update(url=self.base + "/items/" + quote(resource["external_id"], safe=""), resource_id=resource["id"])
        args.update(extra)
        return engine.capture(self.project, args)

    def test_actor_role_change_invalidates_old_evidence(self):
        actor, session = self.actor("alice")
        operation = self.operation("/data")
        evidence = self.capture(operation, session)
        finding = record_finding(self.project, {
            "mode": "analyst", "reviewer": "local-reviewer", "reason": "synthetic disclosure",
            "title": "Synthetic disclosure", "category": "Information Disclosure",
            "impact": "test", "remediation": "test", "evidence_ids": [evidence["id"]]})
        engine.add_actor(self.project, {**actor, "actor_id": actor["id"], "roles": ["guest"]})
        with self.assertRaises(EngineError) as raised:
            engine.verify_current_evidence(self.project, evidence["id"])
        self.assertEqual("actor_changed", raised.exception.code)
        row = next(row for row in engine.evaluate_coverage(self.project)["findings"] if row["id"] == finding["id"])
        self.assertFalse(row["current"])
        self.assertEqual("actor_changed", row["reason_code"])
        self.assertEqual(evidence["id"], self.project.get("evidence", evidence["id"])["id"])

    def test_label_only_update_preserves_verified_security_attributes(self):
        actor, session = self.actor("alice")
        evidence = self.capture(self.operation("/data"), session)
        changed = engine.add_actor(self.project, {"actor_id": "alice", "label": "New label"})
        self.assertEqual(actor["subject"], changed["subject"])
        self.assertEqual(actor["roles"], changed["roles"])
        self.assertEqual(actor["tenant_id"], changed["tenant_id"])
        self.assertEqual(evidence["id"], engine.verify_current_evidence(self.project, evidence["id"])[0]["id"])

    def test_subject_and_tenant_changes_cannot_relabel_verified_capture(self):
        for key, value in (("subject", "another-subject"), ("tenant_id", "another-tenant")):
            with self.subTest(field=key):
                _, session = self.actor("alice")
                evidence = self.capture(self.operation("/data"), session)
                engine.add_actor(self.project, {"actor_id": "alice", key: value})
                with self.assertRaises(EngineError) as raised:
                    engine.verify_current_evidence(self.project, evidence["id"])
                self.assertEqual("actor_changed", raised.exception.code)

    def test_status_boolean_is_not_a_server_side_account_id(self):
        engine.add_actor(self.project, {"actor_id": "one", "subject": 1, "roles": []})
        session = engine.add_session(self.project, {"actor_id": "one", "headers": {"X-Actor": "alice"},
                                                   "credential_header_names": ["X-Actor"]})
        with self.assertRaises(EngineError) as raised:
            engine.verify_identity(self.project, {"operation_id": self.identity["id"], "session_id": session["id"],
                                                  "subject_selector": "/logged_in"})
        self.assertEqual("identity_assertion", raised.exception.code)
        self.assertIsNone(self.project.get("session", session["id"])["verified_at"])

    def test_duplicate_server_subject_is_not_an_independent_actor(self):
        _, owner = self.actor("owner", "alice")
        _, alias = self.actor("alias", "bob")
        operation = self.operation(ownership=True)
        resource = self.resource(operation, "owner")
        engine.build_plan(self.project)
        obligation = next(row for row in self.project.list("obligation") if row["kind"] == "ownership")
        # A previously planned alias must not bypass the evaluator after its
        # credentials are corrected to point at the same real account.
        _, alias = self.actor("alias", "alice")
        ids = [self.capture(operation, session, resource)["id"] for session in (owner, alias)]
        with self.assertRaises(EngineError) as raised:
            evaluate(self.project, {"obligation_id": obligation["id"], "evidence_ids": ids,
                                    "oracle": {"type": "authorization", "selector": "/secret"}})
        self.assertEqual("actor_independence", raised.exception.code)
        self.assertEqual([], self.project.list("decision"))

    def test_owner_fixture_cannot_bind_a_different_request_identifier(self):
        _, session = self.actor("alice")
        operation = self.operation()
        resource = self.resource(operation, "alice")
        calls = self.server.calls
        with self.assertRaises(EngineError) as raised:
            self.capture(operation, session, resource, url=self.base + "/items/someone-elses-item")
        self.assertEqual("resource_mismatch", raised.exception.code)
        self.assertEqual(calls, self.server.calls)

    def test_resource_binding_update_cannot_relabel_old_capture(self):
        _, session = self.actor("alice")
        operation = self.operation()
        resource = self.resource(operation, "alice")
        evidence = self.capture(operation, session, resource)
        self.resource(operation, "alice", external="owned-2", resource_id=resource["id"])
        with self.assertRaises(EngineError) as raised:
            engine.verify_current_evidence(self.project, evidence["id"])
        self.assertEqual("resource_changed", raised.exception.code)
        self.assertEqual(evidence["id"], self.project.get("evidence", evidence["id"])["id"])

    def test_resource_state_update_does_not_invalidate_capture(self):
        _, session = self.actor("alice")
        operation = self.operation()
        resource = self.resource(operation, "alice")
        evidence = self.capture(operation, session, resource)
        self.resource(operation, "alice", resource_id=resource["id"], state={"verified": True})
        self.assertEqual(evidence["id"], engine.verify_current_evidence(self.project, evidence["id"])[0]["id"])

    def owned_finding(self, operation, resource, baseline, variant):
        engine.build_plan(self.project)
        obligation = next(row for row in self.project.list("obligation")
                          if row["operation_id"] == operation["id"] and row["kind"] == "ownership"
                          and not row.get("superseded"))
        ids = [self.capture(operation, session, resource)["id"] for session in (baseline, variant)]
        decision = evaluate(self.project, {"obligation_id": obligation["id"], "evidence_ids": ids,
                                          "oracle": {"type": "authorization", "selector": "/secret"}})
        finding = record_finding(self.project, {"decision_id": decision["id"], "title": "Synthetic ownership issue",
                                               "category": "IDOR", "impact": "Fixture value crosses actors",
                                               "remediation": "Enforce resource ownership"})
        return obligation, decision, finding

    def assert_owned_proof_current(self, obligation, decision, finding):
        self.assertFalse(self.project.get("obligation", obligation["id"]).get("superseded", False))
        self.assertEqual(decision, self.project.get("decision", decision["id"]))
        row = next(row for row in engine.evaluate_coverage(self.project)["findings"] if row["id"] == finding["id"])
        self.assertTrue(row["current"])

    def test_new_fixture_keeps_existing_ownership_representative_and_finding(self):
        _, baseline = self.actor("alice")
        _, variant = self.actor("bob")
        operation = self.operation(ownership=True)
        first = self.resource(operation, "alice", "first")
        obligation, decision, finding = self.owned_finding(operation, first, baseline, variant)
        dispatch(self.tmp.name, "identity.resource", {
            "project_id": "integrity", "operation_id": operation["id"], "owner_actor_id": "alice",
            "external_id": "later", "request_binding": {"location": "path", "selector": "id"}})
        self.assert_owned_proof_current(obligation, decision, finding)

    def test_existing_representative_wins_over_an_imported_older_fixture(self):
        _, baseline = self.actor("alice")
        _, variant = self.actor("bob")
        operation = self.operation(ownership=True)
        current = self.resource(operation, "alice", "current")
        obligation, decision, finding = self.owned_finding(operation, current, baseline, variant)
        older = self.resource(operation, "alice", "imported-older")
        older["created_at"] = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        self.project.put("resource", older)
        engine.build_plan(self.project)
        self.assert_owned_proof_current(obligation, decision, finding)

    def test_fixture_state_changes_do_not_switch_ownership_representative(self):
        _, baseline = self.actor("alice")
        _, variant = self.actor("bob")
        operation = self.operation(ownership=True)
        first = self.resource(operation, "alice", "first", state={"configured": True})
        later = self.resource(operation, "alice", "later")
        obligation, decision, finding = self.owned_finding(operation, first, baseline, variant)
        for resource, state in ((later, {"a": True, "b": True, "c": True}), (first, {})):
            dispatch(self.tmp.name, "identity.resource", {
                "project_id": "integrity", "resource_id": resource["id"], "operation_id": operation["id"],
                "owner_actor_id": "alice", "external_id": resource["external_id"],
                "request_binding": resource["request_binding"], "state": state})
            self.assert_owned_proof_current(obligation, decision, finding)

    def test_missing_scope_defaults_to_target_path_not_origin_siblings(self):
        created = engine.create_project(self.tmp.name, {"project_id": "scoped-path", "target": self.base + "/app"})
        self.assertEqual([self.base + "/app"], created["config"]["scope"])
        for path in ("/app", "/app/orders"):
            self.assertEqual(self.base + path, require_scope(created["config"], self.base + path))
        for path in ("/other", "/application"):
            with self.assertRaises(EngineError) as raised:
                require_scope(created["config"], self.base + path)
            self.assertEqual("out_of_scope", raised.exception.code)

    def test_explicit_empty_or_nonarray_scope_never_falls_back_to_origin(self):
        for index, scope in enumerate(([], False, "")):
            with self.subTest(scope_type=type(scope).__name__):
                with self.assertRaises(EngineError) as raised:
                    engine.create_project(self.tmp.name, {"project_id": "invalid-scope-" + str(index),
                                                          "target": self.base + "/app", "scope": scope})
                self.assertEqual("scope", raised.exception.code)

    def test_explicit_root_scope_can_authorize_siblings_and_is_preserved(self):
        created = engine.create_project(self.tmp.name, {
            "project_id": "explicit-root-scope", "target": self.base + "/app", "scope": [self.base + "/"]})
        self.assertEqual(self.base + "/other", require_scope(created["config"], self.base + "/other"))
        with Project(self.tmp.name, "explicit-root-scope") as project:
            engine.update_project(project, {"allow_mutation": True})
            self.assertEqual([self.base + "/"], project.config["scope"])
            self.assertEqual(self.base + "/other", require_scope(project.config, self.base + "/other"))

    def test_expiry_is_not_a_change_of_verified_identity(self):
        _, session = self.actor("alice")
        evidence = self.capture(self.operation("/data"), session)
        session["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
        self.project.put("session", session)
        self.assertEqual(evidence["id"], engine.verify_current_evidence(self.project, evidence["id"])[0]["id"])
        with self.assertRaises(EngineError) as raised:
            engine.session_valid(self.project, session)
        self.assertEqual("session_expired", raised.exception.code)

    def test_security_property_change_back_cannot_resurrect_old_evidence(self):
        actor, session = self.actor("alice")
        evidence = self.capture(self.operation("/data"), session)
        engine.add_actor(self.project, {"actor_id": "alice", "roles": ["guest"]})
        engine.add_actor(self.project, {"actor_id": "alice", "roles": actor["roles"]})
        engine.verify_identity(self.project, {
            "operation_id": self.identity["id"], "session_id": session["id"],
            "subject_selector": "/id", "roles_selector": "/roles", "tenant_selector": "/tenant"})
        with self.assertRaises(EngineError) as raised:
            engine.verify_current_evidence(self.project, evidence["id"])
        self.assertEqual("actor_changed", raised.exception.code)
        new_evidence = self.capture(self.operation("/data"), self.project.get("session", session["id"]))
        self.assertEqual(new_evidence["id"], engine.verify_current_evidence(self.project, new_evidence["id"])[0]["id"])

    def test_unknown_roles_do_not_silently_remove_authenticated_ownership(self):
        engine.add_actor(self.project, {"actor_id": "owner", "subject": "alice", "roles": []})
        engine.add_actor(self.project, {"actor_id": "variant", "subject": "bob", "roles": []})
        operation = self.operation(ownership=True)
        self.resource(operation, "owner")
        coverage = engine.build_plan(self.project)
        self.assertTrue(any(row["operation_id"] == operation["id"] and row["kind"] == "ownership"
                            for row in self.project.list("obligation") if not row.get("superseded")))
        self.assertTrue(any(row["operation_id"] == operation["id"] and row["next_action"] == "execute"
                            for row in coverage["gaps"]))

    def test_restricted_admin_cannot_be_mislabelled_as_unknown_disallowed_role(self):
        self.server.role_by_actor = {"admin-one": ["admin"], "admin-two": ["admin"]}
        _, baseline = self.actor("admin-one", roles=["admin"])
        _, variant = self.actor("admin-two", roles=[], verify_roles=False)
        operation = self.operation(auth="restricted", allowed_roles=["admin"])
        resource = self.resource(operation, "admin-one")
        engine.build_plan(self.project)
        obligation = next(row for row in self.project.list("obligation")
                          if row["operation_id"] == operation["id"] and row["kind"] == "access"
                          and row.get("actor_id") == "admin-two")
        ids = [self.capture(operation, session, resource)["id"] for session in (baseline, variant)]
        with self.assertRaises(EngineError) as raised:
            evaluate(self.project, {"obligation_id": obligation["id"], "evidence_ids": ids,
                                    "oracle": {"type": "authorization", "selector": "/secret"}})
        self.assertEqual("roles_unverified", raised.exception.code)
        self.assertEqual("identity.verify", raised.exception.details["next_action"])
        self.assertEqual([], self.project.list("decision"))

    def test_explicit_empty_role_assertion_must_match_actual_server_roles(self):
        self.server.role_by_actor = {"admin": ["admin"]}
        engine.add_actor(self.project, {"actor_id": "admin", "subject": "admin", "roles": []})
        session = engine.add_session(self.project, {"actor_id": "admin", "headers": {"X-Actor": "admin"},
                                                   "credential_header_names": ["X-Actor"]})
        with self.assertRaises(EngineError) as raised:
            engine.verify_identity(self.project, {"operation_id": self.identity["id"], "session_id": session["id"],
                                                  "subject_selector": "/id", "roles_selector": "/roles"})
        self.assertEqual("roles_mismatch", raised.exception.code)
        self.assertIsNone(self.project.get("session", session["id"])["verified_at"])

    def test_authenticated_empty_roles_support_real_cross_subject_ownership(self):
        _, baseline = self.actor("alice", roles=[], verify_roles=False)
        _, variant = self.actor("bob", roles=[], verify_roles=False)
        operation = self.operation(ownership=True)
        resource = self.resource(operation, "alice")
        engine.build_plan(self.project)
        obligation = next(row for row in self.project.list("obligation")
                          if row["operation_id"] == operation["id"] and row["kind"] == "ownership")
        ids = [self.capture(operation, session, resource)["id"] for session in (baseline, variant)]
        decision = evaluate(self.project, {"obligation_id": obligation["id"], "evidence_ids": ids,
                                          "oracle": {"type": "authorization", "selector": "/secret"}})
        self.assertEqual("confirmed", decision["outcome"])

    def test_restricted_unknown_roles_keep_ownership_precondition_gap(self):
        self.server.role_by_actor = {"admin": ["admin"]}
        self.actor("admin", roles=["admin"])
        self.actor("unknown", roles=[], verify_roles=False)
        operation = self.operation(auth="restricted", allowed_roles=["admin"], ownership=True)
        self.resource(operation, "admin")
        engine.build_plan(self.project)
        self.assertTrue(any(row["operation_id"] == operation["id"] and row["kind"] == "ownership_setup"
                            for row in self.project.list("obligation") if not row.get("superseded")))

    def test_restricted_explicitly_verified_empty_role_set_can_be_evaluated(self):
        self.server.role_by_actor = {"admin": ["admin"], "guest": []}
        _, baseline = self.actor("admin", roles=["admin"])
        _, variant = self.actor("guest", roles=[])
        operation = self.operation(auth="restricted", allowed_roles=["admin"])
        resource = self.resource(operation, "admin")
        engine.build_plan(self.project)
        obligation = next(row for row in self.project.list("obligation")
                          if row["operation_id"] == operation["id"] and row["kind"] == "access"
                          and row.get("actor_id") == "guest")
        ids = [self.capture(operation, session, resource)["id"] for session in (baseline, variant)]
        decision = evaluate(self.project, {"obligation_id": obligation["id"], "evidence_ids": ids,
                                          "oracle": {"type": "authorization", "selector": "/secret"}})
        self.assertEqual("confirmed", decision["outcome"])

    def test_aliases_leave_an_ownership_setup_gap(self):
        self.actor("owner", "alice")
        self.actor("alias", "alice")
        operation = self.operation(ownership=True)
        self.resource(operation, "owner")
        engine.build_plan(self.project)
        obligations = [row for row in self.project.list("obligation")
                       if row["operation_id"] == operation["id"] and not row.get("superseded")]
        self.assertTrue(any(row["kind"] == "ownership_setup" for row in obligations))
        self.assertFalse(any(row["kind"] == "ownership" for row in obligations))

    def test_empty_input_declaration_is_not_implicit_write_permission(self):
        _, session = self.actor("alice")
        operation = self.operation("/self-state", method="POST")
        calls = self.server.calls
        with self.assertRaises(EngineError) as raised:
            self.capture(operation, session, body={"status": "test"}, effect="test_resource_write")
        self.assertEqual("operation_effect", raised.exception.code)
        self.assertEqual(calls, self.server.calls)

    def test_explicit_self_state_still_requires_permission_and_a_verified_session(self):
        _, session = self.actor("alice")
        operation = self.operation("/self-state", method="POST", state_scope="actor")
        evidence = self.capture(operation, session, effect="test_resource_write")
        self.assertTrue(evidence["complete"])
        engine.update_project(self.project, {"allow_mutation": False})
        calls = self.server.calls
        with self.assertRaises(EngineError):
            self.capture(operation, session, effect="test_resource_write")
        self.assertEqual(calls, self.server.calls)

    def test_self_state_authority_is_part_of_operation_lineage(self):
        _, session = self.actor("alice")
        operation = self.operation("/self-state", method="POST", state_scope="actor")
        evidence = self.capture(operation, session, effect="test_resource_write")
        self.operation("/self-state", method="POST", state_scope=None)
        with self.assertRaises(EngineError) as raised:
            engine.verify_current_evidence(self.project, evidence["id"])
        self.assertEqual("operation_changed", raised.exception.code)

    def test_registration_is_not_method_execution_or_surface_testing(self):
        operation = self.operation("/public", auth="public")
        engine.build_plan(self.project)
        coverage = engine.evaluate_coverage(self.project)
        row = next(row for row in coverage["method_coverage"] if operation["id"] in row["operations"])
        self.assertEqual([], row["tested"])
        self.assertEqual(["GET"], row["registered_methods"])
        self.assertEqual(["GET"], row["untested_registered_methods"])
        self.assertEqual(0, coverage["surface_coverage"]["operations_tested"])

    def test_capture_is_observed_but_only_an_evaluated_obligation_is_tested(self):
        operation = self.operation("/public", auth="public")
        engine.build_plan(self.project)
        evidence = engine.capture(self.project, {"operation_id": operation["id"]})
        coverage = engine.evaluate_coverage(self.project)
        row = next(row for row in coverage["method_coverage"] if operation["id"] in row["operations"])
        self.assertEqual(["GET"], row["observed_methods"])
        self.assertEqual([], row["tested"])
        obligation = next(row for row in self.project.list("obligation")
                          if row["operation_id"] == operation["id"] and row["kind"] == "baseline")
        evaluate(self.project, {"obligation_id": obligation["id"], "evidence_ids": [evidence["id"]],
                                "oracle": {"type": "baseline", "selector": "/ok", "expected": True}})
        coverage = engine.evaluate_coverage(self.project)
        row = next(row for row in coverage["method_coverage"] if operation["id"] in row["operations"])
        self.assertEqual(["GET"], row["tested"])
        self.assertEqual([], row["untested_registered_methods"])
        self.assertEqual(1, coverage["surface_coverage"]["operations_tested"])
        (self.project.base / evidence["artifact_path"]).write_text("{}", encoding="utf-8")
        coverage = engine.evaluate_coverage(self.project)
        row = next(row for row in coverage["method_coverage"] if operation["id"] in row["operations"])
        self.assertEqual([], row["tested"])
        self.assertEqual([], row["observed_methods"])
        self.assertEqual(0, coverage["surface_coverage"]["operations_tested"])

    def test_preflight_does_not_claim_runs_or_send_requests(self):
        operation = self.operation("/public", auth="public")
        counts = (self.server.calls, len(self.project.list("run")), len(self.project.list("evidence")))
        with patch.object(engine, "request") as request:
            prepared = engine.preflight_capture(self.project, {"operation_id": operation["id"]})
            request.assert_not_called()
        self.assertIsNone(prepared["run_id"])
        self.assertIsNone(prepared["existing"])
        self.assertEqual(counts, (self.server.calls, len(self.project.list("run")), len(self.project.list("evidence"))))

    def test_minimal_renewal_preserves_actor_generation_and_verification(self):
        _, session = self.actor("alice")
        renewed = engine.add_session(self.project, {"session_id": session["id"], "renew": True})
        stored = self.project.get("session", session["id"])
        for key in ("actor_id", "generation", "headers", "actor_signature", "verification_evidence_id", "verification_assertion",
                    "credential_header_names", "credential_signature"):
            self.assertEqual(session[key], stored[key])
        self.assertEqual(session["id"], renewed["id"])
        with self.assertRaises(EngineError) as raised:
            engine.add_session(self.project, {"session_id": session["id"], "renew": True, "actor_id": "another"})
        self.assertEqual("identity_mismatch", raised.exception.code)

    def test_session_defaults_classify_credentials_not_arbitrary_business_headers(self):
        engine.add_actor(self.project, {"actor_id": "alice", "subject": "alice"})
        session = engine.add_session(self.project, {"actor_id": "alice", "headers": {
            "Cookie": "actor=alice", "X-Mode": "business", "Content-Type": "application/json"}})
        self.assertEqual(["cookie"], session["credential_header_names"])
        explicit = engine.add_session(self.project, {"actor_id": "alice", "headers": {"X-Actor": "alice"},
                                                   "credential_header_names": ["X-Actor"]})
        self.assertEqual(["x-actor"], explicit["credential_header_names"])

    def test_credential_names_must_be_bounded_header_names_already_registered(self):
        engine.add_actor(self.project, {"actor_id": "alice", "subject": "alice"})
        for names in (["X-Missing"], ["X-Actor", "x-actor"], ["Bad\r\nName"], "X-Actor", ["X-Actor"] * 65):
            with self.subTest(names_type=type(names).__name__):
                with self.assertRaises(EngineError):
                    engine.add_session(self.project, {"actor_id": "alice", "headers": {"X-Actor": "alice"},
                                                       "credential_header_names": names})
        self.assertEqual([], self.project.list("session"))

    def test_renewal_cannot_reclassify_headers(self):
        _, session = self.actor("alice")
        with self.assertRaises(EngineError) as raised:
            engine.add_session(self.project, {"session_id": session["id"], "renew": True,
                                               "credential_header_names": []})
        self.assertEqual("renew_shape", raised.exception.code)
        self.assertEqual(session, self.project.get("session", session["id"]))

    def test_authorization_comparison_retains_business_headers(self):
        _, owner = self.actor("alice", session_headers={"X-Actor": "alice", "X-Mode": "normal"})
        _, variant = self.actor("bob", session_headers={"X-Actor": "bob", "X-Mode": "changed"})
        operation = self.operation(ownership=True)
        resource = self.resource(operation, "alice")
        engine.build_plan(self.project)
        obligation = next(row for row in self.project.list("obligation") if row["kind"] == "ownership")
        ids = [self.capture(operation, session, resource)["id"] for session in (owner, variant)]
        with self.assertRaises(EngineError) as raised:
            evaluate(self.project, {"obligation_id": obligation["id"], "evidence_ids": ids,
                                    "oracle": {"type": "authorization", "selector": "/secret"}})
        self.assertEqual("control_request", raised.exception.code)
        self.assertEqual([], self.project.list("decision"))

    def test_legacy_business_header_confounder_reopens_findings_and_coverage(self):
        _, owner = self.actor("alice", session_headers={"Cookie": "actor=alice", "X-Mode": "normal"},
                              credential_header_names=["Cookie"])
        _, variant = self.actor("bob", session_headers={"Cookie": "actor=bob", "X-Mode": "changed"},
                                credential_header_names=["Cookie"])
        operation = self.operation(ownership=True)
        resource = self.resource(operation, "alice")
        engine.build_plan(self.project)
        obligation = next(row for row in self.project.list("obligation") if row["kind"] == "ownership")
        ids = [self.capture(operation, session, resource)["id"] for session in (owner, variant)]
        # Model a real older-format ledger; do not promote it through today's API.
        for session in self.project.list("session"):
            session.pop("credential_header_names", None)
            session.pop("credential_signature", None)
            self.project.put("session", session)
        for evidence in self.project.list("evidence"):
            evidence.pop("credential_header_names", None)
            evidence.pop("credential_signature", None)
            self.project.connection.execute("UPDATE entities SET document=? WHERE kind='evidence' AND id=?",
                                            (canonical(evidence), evidence["id"]))
        self.project.connection.commit()
        decision = {"id": "legacy-header-decision", "mode": "machine", "outcome": "confirmed",
                    "obligation_id": obligation["id"], "operation_id": operation["id"], "evidence_ids": ids,
                    "oracle": {"type": "authorization", "selector": "/secret"}}
        self.project.put("decision", decision)
        obligation.update(status="evaluated", decision_id=decision["id"])
        self.project.put("obligation", obligation)
        self.project.put("finding", {"id": "legacy-header-finding", "decision_id": decision["id"],
                                     "category": "IDOR", "title": "Legacy header-confounded proof"})
        coverage = engine.evaluate_coverage(self.project)
        row = next(row for row in coverage["findings"] if row["id"] == "legacy-header-finding")
        self.assertFalse(row["current"])
        self.assertEqual("control_request", row["reason_code"])
        self.assertTrue(any(row["id"] == obligation["id"] and row["next_action"] == "repair_evidence"
                            for row in coverage["gaps"]))

    def test_credential_classification_cannot_relabel_verified_evidence(self):
        _, session = self.actor("alice", session_headers={"X-Actor": "alice", "X-Mode": "business"})
        evidence = self.capture(self.operation("/data"), session)
        changed = self.project.get("session", session["id"])
        changed["credential_header_names"] = ["x-actor", "x-mode"]
        self.project.put("session", changed)
        with self.assertRaises(EngineError) as raised:
            engine.verify_current_evidence(self.project, evidence["id"])
        self.assertEqual("credential_changed", raised.exception.code)

    def test_credential_snapshot_is_bound_to_the_actual_captured_header_bytes(self):
        _, session = self.actor("alice", session_headers={"Cookie": "actor=alice"}, credential_header_names=["Cookie"])
        evidence = self.capture(self.operation("/data"), session)
        artifact = self.project.read_artifact(evidence)
        artifact["request"]["headers"]["cookie"] = "actor=bob"
        copied = {**evidence, "id": self.project.id("E")}
        copied["artifact_path"], copied["sha256"] = self.project.artifact(copied["id"], artifact)
        self.project.put("evidence", copied)
        with self.assertRaises(EngineError) as raised:
            engine.verify_current_evidence(self.project, copied["id"])
        self.assertEqual("credential_changed", raised.exception.code)

    def test_recover_persists_actionable_interruption_without_replay(self):
        self.project.claim({"id": "orphaned-run", "kind": "http", "status": "running",
                            "started_at": (datetime.now(timezone.utc) - timedelta(seconds=600)).isoformat()})
        recovered = engine.recover_runs(self.project, {"stale_seconds": 60})
        self.assertEqual(["orphaned-run"], recovered["recovered"])
        self.assertEqual(0, recovered["requests_replayed"])
        run = self.project.get("run", "orphaned-run")
        self.assertEqual("execution_interrupted", run["error_code"])
        self.assertEqual("run.inspect", run["next_action"])
        self.assertEqual(0, self.server.calls)

    def test_capture_exception_returns_a_reconcilable_persisted_run(self):
        operation = self.operation("/public", auth="public")
        args = {"operation_id": operation["id"], "idempotency_key": "failure-context"}
        with patch.object(engine, "request", side_effect=RuntimeError("synthetic failure")):
            with self.assertRaises(EngineError) as raised:
                engine.capture(self.project, args)
        details = raised.exception.details
        self.assertEqual("run.inspect", details["next_action"])
        self.assertEqual(operation["id"], details["operation_id"])
        run = self.project.get("run", details["run_id"])
        self.assertEqual("failed", run["status"])
        self.assertEqual("capture_failed", run["error_code"])
        with patch.object(engine, "request") as request:
            with self.assertRaises(EngineError) as repeated:
                engine.capture(self.project, args)
            request.assert_not_called()
        self.assertEqual("run_uncertain", repeated.exception.code)
        self.assertEqual(details["run_id"], repeated.exception.details["run_id"])

    def test_preflight_rejects_all_budgets_and_framing_before_claim(self):
        operation = self.operation("/public", auth="public")
        before = len(self.project.list("run"))
        for extra in ({"timeout": 0}, {"timeout": float("nan")}, {"max_bytes": 0},
                      {"headers": {"Host": "other.test"}}, {"headers": {"Content-Length": "0"}},
                      {"body": {"oversized": "x" * (1024 * 1024)}}, {"body": {"x": float("inf")}}):
            with self.subTest(extra_keys=list(extra)):
                with self.assertRaises(EngineError):
                    engine.capture(self.project, {"operation_id": operation["id"], **extra})
        self.assertEqual(before, len(self.project.list("run")))
        self.assertEqual(0, self.server.calls)

    def test_anonymous_cookie_can_mix_noncredential_headers_but_not_identity_headers(self):
        operation = self.operation("/public", auth="public")
        args = {"operation_id": operation["id"], "anonymous_cookie": "cart=synthetic",
                "headers": {"Accept": "application/json", "X-Test": "marker"}}
        evidence = engine.capture(self.project, args)
        self.assertEqual("anonymous_cookie", evidence["auth_mode"])
        request = self.project.read_artifact(evidence)["request"]
        self.assertEqual("cart=synthetic", request["headers"]["cookie"])
        with self.assertRaises(EngineError) as raised:
            engine.preflight_capture(self.project, {**args, "headers": {"Authorization": "Bearer synthetic"}})
        self.assertEqual("credential_override", raised.exception.code)

    def test_body_file_preserves_bytes_and_rejects_conflicts_and_relative_escape(self):
        _, session = self.actor("alice")
        operation = self.operation("/raw-body", method="GET")
        path = self.project.base / "raw-body.bin"
        raw = b"\x00\xff\x80\r\nsynthetic bytes"
        path.write_bytes(raw)
        args = {"operation_id": operation["id"], "session_id": session["id"],
                "effect": "read_only", "body_file": "raw-body.bin"}
        prepared = engine.preflight_capture(self.project, args)
        self.assertEqual(raw, prepared["body"])
        self.assertEqual(len(raw), prepared["body_bytes"])
        absolute = engine.preflight_capture(self.project, {**args, "body_file": str(path)})
        self.assertEqual(raw, absolute["body"])
        with self.assertRaises(EngineError):
            engine.preflight_capture(self.project, {**args, "body": "conflict"})
        with self.assertRaises(EngineError) as raised:
            engine.preflight_capture(self.project, {**args, "body_file": "../outside.bin"})
        self.assertEqual("path_escape", raised.exception.code)

    def destructive_pair(self, control="missing", injection="missing' OR 1=1--", **extra):
        _, session = self.actor("alice")
        operation = self.operation(method="DELETE", inputs=[
            {"name": "id", "location": "path", "selector": "id", "consumer": "sql_where"}])
        normal = self.resource(operation, "alice", control)
        injected = self.resource(operation, "alice", injection)
        baseline = self.capture(operation, session, normal, effect="test_resource_write")
        attack = self.capture(operation, session, injected, effect="test_resource_write", **extra)
        return {"control_evidence_id": baseline["id"], "injection_evidence_id": attack["id"],
                "input_location": "path", "input_selector": "id", "response_selector": "/deleted_count",
                "observed_change": "Control deletes no rows; injected predicate deletes the three local test rows."}

    def test_destructive_sql_proof_records_actual_business_counts(self):
        proof = self.destructive_pair()
        validated = _sql_behaviour_proof(self.project, proof)
        self.assertEqual(0, validated["control_value"])
        self.assertEqual(3, validated["injection_value"])
        self.assertEqual(2, validated["proof_version"])
        finding = record_finding(self.project, {
            "mode": "analyst", "reviewer": "local-reviewer", "reason": "Local predicate changes deleted row count",
            "title": "Synthetic destructive SQL", "category": "SQL Injection", "impact": "Three fixture rows removed",
            "remediation": "Parameterize the predicate", "sql_evidence": proof})
        self.assertEqual("sql_behaviour", finding["confirmed_scope"])
        self.assertTrue(next(row for row in engine.evaluate_coverage(self.project)["findings"]
                             if row["id"] == finding["id"])["current"])

    def test_sql_expression_with_only_nonce_or_message_difference_is_not_proof(self):
        proof = self.destructive_pair()
        for selector in ("/nonce", "/message"):
            with self.subTest(selector=selector):
                with self.assertRaises(EngineError) as raised:
                    _sql_behaviour_proof(self.project, {**proof, "response_selector": selector})
                self.assertEqual("sql_evidence", raised.exception.code)

    def test_sql_business_controls_cannot_mix_session_generations_or_ids(self):
        proof = self.destructive_pair()
        control = self.project.get("evidence", proof["control_evidence_id"])
        operation = self.project.get("operation", control["operation_id"])
        _, other = self.actor("alice")
        resource = self.resource(operation, "alice", "missing' OR 1=1--")
        injection = self.capture(operation, other, resource, effect="test_resource_write")
        with self.assertRaises(EngineError) as raised:
            _sql_behaviour_proof(self.project, {**proof, "injection_evidence_id": injection["id"]})
        self.assertEqual("control_identity", raised.exception.code)

    def test_sql_behaviour_rejects_ordinary_inputs_and_other_request_changes(self):
        proof = self.destructive_pair(control="missing", injection="one")
        with self.assertRaises(EngineError):
            _sql_behaviour_proof(self.project, proof)
        self.server.database.execute("INSERT INTO products VALUES ('one')")
        self.server.database.commit()
        proof = self.destructive_pair(url=self.base + "/items/" + quote("missing' OR 1=1--", safe="") + "?other=changed")
        with self.assertRaises(EngineError) as raised:
            _sql_behaviour_proof(self.project, proof)
        self.assertEqual("input_binding", raised.exception.code)

    def test_read_only_response_difference_cannot_use_destructive_sql_channel(self):
        _, session = self.actor("alice")
        operation = self.operation(inputs=[{"name": "id", "location": "path", "selector": "id", "consumer": "sql_where"}])
        ids = [self.capture(operation, session, self.resource(operation, "alice", value))["id"]
               for value in ("normal", "test' OR 1=1--")]
        with self.assertRaises(EngineError) as raised:
            _sql_behaviour_proof(self.project, {
                "control_evidence_id": ids[0], "injection_evidence_id": ids[1],
                "input_location": "path", "input_selector": "id", "response_selector": "/deleted_count",
                "observed_change": "Response strings differ"})
        self.assertEqual("sql_behaviour_proof_required", raised.exception.code)

    def test_legacy_sql_behaviour_remains_historical_instead_of_being_promoted(self):
        proof = self.destructive_pair()
        legacy = {key: proof[key] for key in ("control_evidence_id", "injection_evidence_id", "observed_change")}
        legacy["channel"] = "behavioural_diff"
        decision = {"id": "legacy-sql-decision", "mode": "analyst", "outcome": "confirmed", "proof": legacy,
                    "evidence_ids": [proof["control_evidence_id"], proof["injection_evidence_id"]]}
        self.project.put("decision", decision)
        self.project.put("finding", {"id": "legacy-sql-finding", "decision_id": decision["id"],
                                     "category": "SQL Injection", "title": "Legacy weak proof"})
        row = next(row for row in engine.evaluate_coverage(self.project)["findings"]
                   if row["id"] == "legacy-sql-finding")
        self.assertFalse(row["current"])
        self.assertEqual("sql_behaviour_proof_required", row["reason_code"])


if __name__ == "__main__":
    unittest.main()
