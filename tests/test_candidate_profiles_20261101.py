"""Source/profile identity and exact legacy aliases; fixture imports send no traffic."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import candidates, discovery, engine
from awa_ddd.__main__ import dispatch
from awa_ddd.store import Project, canonical, now


def legacy_id(row, *, nested=False):
    source = row.get("source")
    if not isinstance(source, dict):
        sources = row.get("sources") or []
        source = sources[0] if sources else {}
    hint = row.get("hint") if isinstance(row.get("hint"), dict) else {}
    if nested and not source:
        source = hint.get("source")
        if not isinstance(source, dict):
            sources = hint.get("sources") or []
            source = sources[0] if sources else {}
    key = [source.get("sha256"), source.get("locator"), row.get("kind"),
           row.get("url", hint.get("url")) if nested else row.get("url"),
           row.get("method", hint.get("method")) if nested else row.get("method"),
           row.get("name"), row.get("locator"), row.get("legacy_id")]
    return "C-" + hashlib.sha256(canonical(key).encode()).hexdigest()[:24]


class CandidateProfileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="awa-candidate-profiles-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.base = "http://fixture.invalid"
        engine.create_project(self.root, {"project_id": "profiles", "target": self.base})
        self.project = Project(self.root, "profiles")
        self.addCleanup(self.project.close)
        guard = patch.object(engine, "request")
        self.network = guard.start()
        self.addCleanup(guard.stop)

    def tearDown(self):
        self.network.assert_not_called()
        self.assertEqual([], self.project.list("run"))

    def call(self, action, **args):
        return dispatch(self.root, action, {"project_id": "profiles", **args})

    def source(self, method="post", *, name="profiles.openapi.json", title="Local profiles"):
        path = self.root / name
        path.write_text(json.dumps({"openapi": "3.0.3", "info": {"title": title, "version": "1"},
            "servers": [{"url": self.base}], "paths": {"/multi": {method: {
                "requestBody": {"content": {
                    "application/json": {"schema": {"type": "object", "properties": {"q": {"type": "string"}}}},
                    "application/xml": {"schema": {"type": "object", "properties": {"xml": {"type": "string"}}}},
                }}, "responses": {"200": {"description": "ok"}},
            }}}}), encoding="utf-8")
        return path

    def import_source(self, path):
        return self.call("surface.import", path=str(path), format="openapi")

    def row(self, **changes):
        row = {"kind": "operation_hint", "url": self.base + "/multi", "method": "POST",
               "protocol": "http", "operation_name": "", "content_type": "application/json",
               "inputs": [{"name": "q", "location": "body", "selector": "/q", "consumer": "unknown"}],
               "sources": [{"path": "declared-fixture.json", "sha256": "a" * 64,
                            "locator": "#/operation", "trust": "declared"}]}
        row.update(deepcopy(changes))
        return row

    @staticmethod
    def profile(row):
        return row["hint"] if isinstance(row.get("hint"), dict) else row

    def seed_legacy(self, row, *, nested=False):
        saved = {**deepcopy(row), "id": legacy_id(row, nested=nested), "status": "unverified",
                 "created_at": now(), "updated_at": now()}
        self.project.put("candidate", saved, create_only=True)
        self.call("candidate.dismiss", candidate_id=saved["id"], reason="Original fixture source disposition.")
        return self.project.get("candidate", saved["id"])

    def preserved(self, before):
        after = self.project.get("candidate", before["id"])
        for key in before:
            if key != "updated_at":
                self.assertEqual(canonical(before[key]), canonical(after[key]), key)
        return after

    def test_real_direct_static_only_source_retains_both_media_profiles(self):
        path = self.source("trace")
        found = discovery.discover(path, "openapi")
        self.assertEqual(2, len(found["candidates"]))
        self.assertEqual([], found["operations"])
        first = self.import_source(path)
        second = self.import_source(path)
        self.assertEqual([], first["operation_ids"])
        self.assertEqual(2, first["candidates"])
        self.assertEqual(0, second["candidates"])
        rows = self.project.list("candidate")
        self.assertEqual(2, len({row["id"] for row in rows}))
        self.assertTrue(all("hint" not in row for row in rows))
        self.assertEqual({"application/json", "application/xml"}, {row["content_type"] for row in rows})

    def test_real_wrapped_rejections_retain_both_media_profiles_without_replay(self):
        path = self.source("post")
        found = discovery.discover(path, "openapi")
        self.assertEqual(2, len(found["operations"]))
        self.call("project.update", exclude=[self.base + "/multi"])
        first = self.import_source(path)
        second = self.import_source(path)
        self.assertEqual([], first["operation_ids"])
        self.assertEqual(2, first["candidates"])
        self.assertEqual(0, second["candidates"])
        rows = self.project.list("candidate")
        self.assertEqual(2, len({row["id"] for row in rows}))
        self.assertTrue(all("hint" in row for row in rows))
        self.assertEqual({"application/json", "application/xml"}, {row["hint"]["content_type"] for row in rows})
        self.assertEqual(2, self.call("plan.audit", limit=100)["completion"]["unresolved_candidates"])

    def test_legacy_direct_media_profile_preserves_its_id_and_recovers_missing_sibling(self):
        path = self.source("trace")
        row = discovery.discover(path, "openapi")["candidates"][0]
        before = self.seed_legacy(row)
        first = self.import_source(path)
        second = self.import_source(path)
        self.assertEqual(1, first["candidates"])
        self.assertEqual(0, second["candidates"])
        self.preserved(before)
        rows = self.project.list("candidate")
        self.assertEqual(2, len(rows))
        sibling = next(row for row in rows if row["id"] != before["id"])
        self.assertNotEqual(before["content_type"], sibling["content_type"])
        self.assertEqual("unverified", sibling["status"])

    def test_both_legacy_wrapper_id_algorithms_preserve_only_the_exact_profile(self):
        for nested in (False, True):
            with self.subTest(nested=nested):
                project_id = "wrapper-" + str(int(nested))
                engine.create_project(self.root, {"project_id": project_id, "target": self.base})
                path = self.source("post", name=project_id + ".openapi.json")
                hint = discovery.discover(path, "openapi")["operations"][0]
                row = {"kind": "operation_hint", "hint": hint, "reason": "out_of_scope"}
                with Project(self.root, project_id) as project:
                    saved = {**row, "id": legacy_id(row, nested=nested), "status": "dismissed",
                             "reason": "Original wrapper fixture declaration.", "created_at": now(), "updated_at": now()}
                    project.put("candidate", saved, create_only=True)
                    dispatch(self.root, "project.update", {"project_id": project_id, "exclude": [self.base + "/multi"]})
                    args = {"project_id": project_id, "path": str(path), "format": "openapi"}
                    first = dispatch(self.root, "surface.import", args)
                    second = dispatch(self.root, "surface.import", args)
                    self.assertEqual(1, first["candidates"])
                    self.assertEqual(0, second["candidates"])
                    retained = project.get("candidate", saved["id"])
                    for key in ("kind", "hint", "status", "reason", "created_at"):
                        self.assertEqual(canonical(saved[key]), canonical(retained[key]))
                    rows = project.list("candidate")
                    self.assertEqual(2, len(rows))
                    self.assertEqual({"application/json", "application/xml"}, {row["hint"]["content_type"] for row in rows})
                    self.assertEqual([], project.list("run"))

    def test_legacy_link_and_private_source_history_are_preserved_on_exact_alias(self):
        path = self.source("post")
        hint = discovery.discover(path, "openapi")["operations"][0]
        row = {"kind": "operation_hint", "hint": hint, "reason": "out_of_scope"}
        saved = {**row, "id": legacy_id(row), "status": "unverified", "created_at": now(), "updated_at": now()}
        self.project.put("candidate", saved, create_only=True)
        operation = self.call("surface.register", **hint)
        entry = hint["inputs"][0]
        linked = self.call("candidate.link", candidate_id=saved["id"], operation_id=operation["id"],
                           input_location=entry["location"], input_selector=entry["selector"])
        before = self.project.get("candidate", linked["id"])
        with self.project._lock:
            event_before = self.project.connection.execute("SELECT document FROM events WHERE type='candidate.linked'").fetchone()[0]
        self.call("project.update", exclude=[self.base + "/multi"])
        self.assertEqual(1, self.import_source(path)["candidates"])
        after = self.preserved(before)
        self.assertEqual("linked", after["status"])
        self.assertEqual(linked["link"], after["link"])
        with self.project._lock:
            self.assertEqual(event_before, self.project.connection.execute(
                "SELECT document FROM events WHERE type='candidate.linked'").fetchone()[0])

    def test_same_locator_protocol_and_graphql_operation_names_are_distinct(self):
        profiles = (self.row(protocol="http"), self.row(protocol="graphql", operation_name="GetItems"),
                    self.row(protocol="graphql", operation_name="UpdateItems"))
        ids = []
        for row in profiles:
            identity, created = candidates.store_candidate(self.project, row)
            self.assertTrue(created)
            ids.append(identity)
        self.assertEqual(3, len(set(ids)))
        for row, identity in zip(profiles, ids):
            repeated, created = candidates.store_candidate(self.project, row)
            self.assertFalse(created)
            self.assertEqual(identity, repeated)

    def test_same_media_but_distinct_input_schema_branches_are_not_merged(self):
        entry = self.row()["inputs"][0]
        profiles = [self.row(inputs=[{**entry, "schema_branch": branch}]) for branch in ("one", "two")]
        first, created = candidates.store_candidate(self.project, profiles[0])
        self.assertTrue(created)
        second, created = candidates.store_candidate(self.project, profiles[1])
        self.assertTrue(created)
        self.assertNotEqual(first, second)
        self.assertEqual("one", self.project.get("candidate", first)["inputs"][0]["schema_branch"])
        self.assertEqual("two", self.project.get("candidate", second)["inputs"][0]["schema_branch"])

    def test_schema_boolean_and_number_do_not_alias_a_legacy_profile(self):
        entry = self.row()["inputs"][0]
        boolean = self.row(inputs=[{**entry, "required": True}])
        number = self.row(inputs=[{**entry, "required": 1}])
        before = self.seed_legacy(boolean)
        identity, created = candidates.store_candidate(self.project, number)
        self.assertTrue(created)
        self.assertNotEqual(before["id"], identity)
        self.preserved(before)
        self.assertIs(type(self.project.get("candidate", before["id"])["inputs"][0]["required"]), bool)
        self.assertIs(type(self.project.get("candidate", identity)["inputs"][0]["required"]), int)

    def test_wrapped_schema_boolean_and_number_remain_distinct_from_legacy_hint(self):
        entry = self.row()["inputs"][0]
        boolean = {"kind": "operation_hint", "hint": {key: value for key, value in
                   self.row(inputs=[{**entry, "required": True}]).items() if key != "kind"}}
        number = {"kind": "operation_hint", "hint": {key: value for key, value in
                  self.row(inputs=[{**entry, "required": 1}]).items() if key != "kind"}}
        before = self.seed_legacy(boolean)
        identity, created = candidates.store_candidate(self.project, number)
        self.assertTrue(created)
        self.assertNotEqual(before["id"], identity)
        self.preserved(before)

    def test_unprofiled_ordinary_direct_candidates_keep_the_old_identity(self):
        row = {"kind": "operation_hint", "url": self.base + "/bare", "method": None,
               "sources": [{"path": "bare.js", "sha256": "b" * 64, "locator": "line:1"}]}
        self.assertEqual(legacy_id(row), candidates.candidate_id(row))
        identity, created = candidates.store_candidate(self.project, row)
        self.assertTrue(created)
        self.call("candidate.dismiss", candidate_id=identity, reason="Original unverified fixture declaration.")
        before = self.project.get("candidate", identity)
        repeated, created = candidates.store_candidate(self.project, row)
        self.assertFalse(created)
        self.assertEqual(identity, repeated)
        self.preserved(before)

    def test_non_operation_candidates_do_not_get_new_profile_id_semantics(self):
        row = self.row(kind="tool_metadata", name="database")
        self.assertEqual(legacy_id(row), candidates.candidate_id(row))

    def test_a_missing_profile_never_overwrites_richer_legacy_information(self):
        row = self.row()
        before = self.seed_legacy(row)
        bare = {key: value for key, value in row.items() if key in {"kind", "url", "method", "sources"}}
        identity, created = candidates.store_candidate(self.project, bare)
        self.assertTrue(created)
        self.assertNotEqual(before["id"], identity)
        self.preserved(before)
        repeated, created = candidates.store_candidate(self.project, bare)
        self.assertFalse(created)
        self.assertEqual(identity, repeated)

    def test_actual_profile_definition_has_the_same_identity_in_both_shapes(self):
        direct = self.row()
        wrapped = {"kind": "operation_hint", "hint": {key: value for key, value in direct.items() if key != "kind"},
                   "reason": "fixture rejection"}
        self.assertEqual(candidates.candidate_id(direct), candidates.candidate_id(wrapped))
        identity, created = candidates.store_candidate(self.project, direct)
        self.assertTrue(created)
        repeated, created = candidates.store_candidate(self.project, wrapped)
        self.assertFalse(created)
        self.assertEqual(identity, repeated)

    def test_exact_profile_alias_preserves_legacy_history_across_wrapper_shape(self):
        direct = self.row()
        wrapped = {"kind": "operation_hint", "hint": {key: value for key, value in direct.items() if key != "kind"}}
        before = self.seed_legacy(wrapped)
        identity, created = candidates.store_candidate(self.project, direct)
        self.assertFalse(created)
        self.assertEqual(before["id"], identity)
        self.preserved(before)
        for _ in range(2):
            repeated, created = candidates.store_candidate(self.project, direct)
            self.assertFalse(created)
            self.assertEqual(identity, repeated)
            self.assertNotIn("sources", self.project.get("candidate", identity))
            self.preserved(before)
        self.assertEqual(1, len(self.project.list("candidate")))

    def test_reverse_source_shape_preserves_direct_legacy_history_and_idempotence(self):
        direct = self.row()
        wrapped = {"kind": "operation_hint", "hint": {key: value for key, value in direct.items() if key != "kind"}}
        before = self.seed_legacy(direct)
        for _ in range(3):
            identity, created = candidates.store_candidate(self.project, wrapped)
            self.assertFalse(created)
            self.assertEqual(before["id"], identity)
            self.assertNotIn("hint", self.project.get("candidate", identity))
            self.preserved(before)
        self.assertEqual(1, len(self.project.list("candidate")))

    def test_profile_name_locator_and_legacy_id_are_consistent_between_shapes(self):
        for field, value in (("name", "named-operation-hint"), ("locator", "definition#one"), ("legacy_id", "old-operation-one")):
            with self.subTest(field=field):
                direct = self.row(**{field: value})
                wrapped = {"kind": "operation_hint", "hint": {key: value for key, value in direct.items() if key != "kind"}}
                self.assertEqual(candidates.candidate_id(direct), candidates.candidate_id(wrapped))
                identity, created = candidates.store_candidate(self.project, direct)
                self.assertTrue(created)
                for _ in range(2):
                    repeated, created = candidates.store_candidate(self.project, wrapped)
                    self.assertFalse(created)
                    self.assertEqual(identity, repeated)
        self.assertEqual(3, len(self.project.list("candidate")))

    def test_named_legacy_nested_profile_keeps_its_original_key_on_reimport(self):
        direct = self.row(name="named-operation-hint", locator="definition#one", legacy_id="old-operation-one")
        wrapped = {"kind": "operation_hint", "hint": {key: value for key, value in direct.items() if key != "kind"}}
        before = self.seed_legacy(wrapped, nested=True)
        for row in (direct, wrapped, direct):
            identity, created = candidates.store_candidate(self.project, row)
            self.assertFalse(created)
            self.assertEqual(before["id"], identity)
            self.preserved(before)
        self.assertEqual(1, len(self.project.list("candidate")))

    def test_different_named_envelope_is_not_normalized_into_the_definition(self):
        direct = self.row(name="definition-name")
        wrapped = {"kind": "operation_hint", "hint": {key: value for key, value in direct.items() if key != "kind"},
                   "name": "different-envelope-name", "url_redacted": True}
        self.assertNotEqual(candidates.candidate_id(direct), candidates.candidate_id(wrapped))
        first, _ = candidates.store_candidate(self.project, direct)
        second, created = candidates.store_candidate(self.project, wrapped)
        self.assertTrue(created)
        self.assertNotEqual(first, second)
        self.assertTrue(self.project.get("candidate", second)["url_redacted"])

    def test_merging_new_sources_preserves_the_actual_wrapper_and_safety_envelope(self):
        direct = self.row()
        wrapped = {"kind": "operation_hint", "hint": {key: value for key, value in direct.items() if key != "kind"},
                   "url_redacted": True}
        identity, _ = candidates.store_candidate(self.project, wrapped)
        incoming = deepcopy(wrapped)
        incoming["hint"]["sources"].append({"path": "additional-fixture.json", "sha256": "b" * 64,
                                             "locator": "#/additional", "trust": "declared"})
        repeated, created = candidates.store_candidate(self.project, incoming)
        self.assertFalse(created)
        self.assertEqual(identity, repeated)
        stored = self.project.get("candidate", identity)
        self.assertTrue(stored["url_redacted"])
        self.assertNotIn("sources", stored)
        self.assertEqual(2, len(stored["hint"]["sources"]))
        repeated, created = candidates.store_candidate(self.project, incoming)
        self.assertFalse(created)
        self.assertEqual(identity, repeated)

    def test_an_unrelated_actual_source_cannot_inherit_a_legacy_wrapper_disposition(self):
        first = self.source("post", name="first.openapi.json", title="First source")
        hint = discovery.discover(first, "openapi")["operations"][0]
        before = self.seed_legacy({"kind": "operation_hint", "hint": hint})
        second = self.source("post", name="second.openapi.json", title="Different source")
        self.call("project.update", exclude=[self.base + "/multi"])
        imported = self.import_source(second)
        self.assertEqual(2, imported["candidates"])
        self.assertEqual(3, len(self.project.list("candidate")))
        self.preserved(before)

    def test_profile_and_envelope_fields_cannot_collide_in_the_identity(self):
        first = {"kind": "operation_hint", "hint": {key: value for key, value in
                 self.row(_envelope={"url_redacted": False}).items() if key != "kind"}, "url_redacted": True}
        second = {"kind": "operation_hint", "hint": {key: value for key, value in
                  self.row(_envelope={"url_redacted": True}).items() if key != "kind"}, "url_redacted": True}
        self.assertNotEqual(candidates.candidate_id(first), candidates.candidate_id(second))


if __name__ == "__main__":
    unittest.main()
