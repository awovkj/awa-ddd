"""Real dispatch publication of parameter controls under private-value collisions."""
from __future__ import annotations

import hashlib
import re
import unittest

import test_project_publication_20261101 as fixtures
from awa_ddd import parameter_coverage
from awa_ddd.store import canonical


class ParameterPublicationTests(unittest.TestCase):
    def setUp(self):
        # Compose fixture helpers: importing/inheriting its TestCase would load
        # the older publication suite again from this module.
        self.fixture = fixtures.ProjectPublicationTests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.project = self.fixture.project
        self.values = ("synthetic-normal-private-input", "synthetic-variant-private-input", "synthetic-sensitive-private-input")
        self.collisions = ("true", "0", "tested", "consumer_review")
        self.private_digests = set()

    def seed_collisions(self):
        for value in self.collisions:
            visit = self.fixture.browser_context(value)
            self.private_digests.update(item for item in (visit.get("credentials") or {}).values()
                                        if isinstance(item, str) and re.fullmatch(r"[a-f0-9]{64}", item))

    def register(self, path="/items", *, method="GET", inputs=None, **extra):
        result = self.fixture.call("surface.register", url=self.fixture.base + path, method=method, auth="public",
            inputs=inputs or [{"name": "keyword", "location": "query", "selector": "keyword",
                               "consumer": "business_input", "test_families": ["generic"]}], **extra)
        return self.project.get("operation", result["id"])

    def close_generic(self, operation):
        captures = []
        for value, count in zip(self.values, (1, 1, 2)):
            self.fixture.network.side_effect = fixtures.observed({"count": count})
            captures.append(self.fixture.call("http.capture", operation_id=operation["id"],
                url=operation["url"] + "?keyword=" + value)["id"])
        obligation = next(row for row in self.project.list("obligation") if row["operation_id"] == operation["id"]
                          and row.get("test_family") == "generic" and not row.get("superseded"))
        result = self.fixture.call("assessment.evaluate", obligation_id=obligation["id"], evidence_ids=captures,
            oracle={"type": "semantic_negative", "test_family": "generic", "selector": "/count",
                    "baseline_expected": 1, "control_expected": 2})
        self.assertEqual(result["outcome"], "refuted")
        return result

    def expected_id(self, operation, selector="keyword", family="generic", location="query"):
        return parameter_coverage.row_id(operation["id"], location, selector, None, family)

    def assert_count(self, row, key, expected=None):
        self.assertIs(type(row[key]), int, key)
        self.assertGreaterEqual(row[key], 0)
        if expected is not None:
            self.assertEqual(row[key], expected)

    def assert_no_value_or_private_digest(self, public):
        text = canonical(public)
        for value in self.values:
            self.assertNotIn(value, text)
            for digest in (hashlib.sha256(value.encode("utf-8")).hexdigest(),
                           hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()):
                self.assertNotIn(digest, text)
        for digest in self.private_digests:
            self.assertNotIn(digest, text)
        for key in ("credential_nonce", "credential_signature", "redaction_context_sha256", "context_digest", "value_digest", "parameter_progress"):
            self.assertNotIn('"' + key + '"', text)

    def test_matrix_keeps_typed_states_counts_and_parameter_identity_when_fill_values_collide(self):
        self.seed_collisions()
        opaque = "opaque-true-0-tested-consumer_review"
        operation = self.register("/" + opaque, inputs=[{"name": "name-" + opaque, "location": "query", "selector": "keyword",
            "consumer": "business_input-" + opaque, "test_families": ["generic"]}])
        review = self.register("/review/" + opaque, inputs=[{"name": "shop_name", "location": "query", "selector": "shop_name",
            "consumer": "unknown", "test_families": ["xss"]}])
        self.close_generic(operation)
        audit = self.fixture.call("plan.audit", parameter_limit=100, limit=100)
        matrix = audit["parameter_coverage"]
        self.assertEqual(matrix["filter"], "any")
        self.assert_count(matrix, "total", 2)
        for key, expected in (("cell_total", 2), ("parameter_total", 2), ("typed_tested_total", 1), ("untested_total", 1),
                              ("consumer_review_total", 1), ("variant_observed_total", 1)):
            self.assert_count(matrix["summary"], key, expected)
        self.assertIs(matrix["summary"]["observation_is_testing"], False)
        rows = {row["operation_id"]: row for row in matrix["items"]}
        tested = rows[operation["id"]]
        self.assertEqual(tested["id"], self.expected_id(operation))
        self.assertEqual(tested["status"], "tested")
        self.assertEqual(tested["queue_status"], "closed")
        self.assertEqual(tested["control_candidate_state"], "three_values")
        self.assertEqual(tested["test_family"], "generic")
        self.assertIs(tested["typed_tested"], True)
        self.assertIs(tested["has_input_variant"], True)
        self.assertIs(tested["observations_limited"], False)
        self.assertIs(tested["observation_is_testing"], False)
        self.assert_count(tested, "observation_count", 3)
        pending = rows[review["id"]]
        self.assertEqual(pending["id"], self.expected_id(review, "shop_name", "xss"))
        self.assertEqual(pending["status"], "consumer_review")
        self.assertIs(pending["typed_tested"], False)
        self.assertIs(pending["has_input_variant"], False)
        self.assert_count(pending, "observation_count", 0)
        for row in rows.values():
            self.fixture.assert_private_locator(row)
        self.assertNotIn(opaque, canonical(matrix))
        self.assert_no_value_or_private_digest(matrix)
        queued = self.fixture.call("plan.next", parameter_limit=100, limit=25)
        work = next(row for row in queued["work_items"] if row.get("operation_id") == review["id"]
                    and row.get("obligation_kind") == "input_review")
        self.assertEqual(work["parameter_coverage_id"], pending["id"])
        self.assertEqual(work["parameter_test_status"], "consumer_review")
        self.assertIs(work["selected_input_variant_observed"], False)
        self.assertIs(work["controls_are_candidates_only"], True)
        self.assert_count(work, "selected_input_observation_count", 0)
        self.assertEqual(self.fixture.network.call_count, 3)

    def test_checkpoint_delta_keeps_parameter_identity_and_control_types_without_private_values(self):
        self.seed_collisions()
        opaque = "opaque-true-0-tested-consumer_review"
        operation = self.register(inputs=[{"name": opaque, "location": "query", "selector": "keyword",
                                          "consumer": "business_input", "test_families": ["generic"]}])
        before = self.fixture.call("plan.checkpoint", label="before-true-0-tested-consumer_review")
        self.assertIs(before["checkpoint"]["parameter_delta"]["comparison_available"], False)
        self.assert_count(before["checkpoint"]["parameter_delta"], "newly_tested_total", 0)
        self.close_generic(operation)
        after = self.fixture.call("plan.checkpoint", label="after-true-0-tested-consumer_review")
        checkpoint = after["checkpoint"]
        delta = checkpoint["parameter_delta"]
        self.assertIs(delta["comparison_available"], True)
        self.assertIs(delta["projection_complete"], True)
        self.assertIs(delta["items_truncated"], False)
        self.assertIs(delta["observation_is_testing"], False)
        self.assert_count(delta, "newly_tested_total", 1)
        self.assert_count(delta, "newly_observed_variants_total", 1)
        self.assert_count(delta, "reopened_total", 0)
        for row in delta["newly_tested"] + delta["newly_observed_variants"]:
            self.assertEqual(row["id"], self.expected_id(operation))
            self.assertEqual(row["operation_id"], operation["id"])
            self.assertEqual(row["input_location"], "query")
            self.assertEqual(row["test_family"], "generic")
        private = self.project.get("checkpoint", checkpoint["id"])
        self.assertEqual(checkpoint["snapshot_id"], private["snapshot_id"])
        self.assertEqual(checkpoint["progress_id"], private["progress_id"])
        self.assert_no_value_or_private_digest({"before": before, "after": after})
        self.assertNotIn(opaque, canonical(delta))
        self.assertNotIn("after-true-0-tested-consumer_review", checkpoint["label"])
        self.assertEqual(self.fixture.network.call_count, 3)

    def test_preparation_and_captcha_controls_remain_typed_and_do_not_forward_cookies(self):
        self.seed_collisions()
        operation = self.register("/register/opaque-true-0-tested-consumer_review", method="POST", content_type="application/json",
            inputs=[{"name": "sms_code", "location": "body", "selector": "/sms_code", "consumer": "business_input", "test_families": ["generic"]}])
        queued = self.fixture.call("plan.next", include_blocked=True, limit=25)
        work = next(row for row in queued["work_items"] if row.get("operation_id") == operation["id"]
                    and row.get("obligation_kind") == "input_test")
        self.assertEqual(work["parameter_coverage_id"], self.expected_id(operation, "/sms_code", "generic", "body"))
        self.assertEqual(work["parameter_test_status"], "unobserved")
        self.assertEqual(work["queue_status"], "blocked")
        self.assertIs(work["selected_input_variant_observed"], False)
        self.assertIs(work["controls_are_candidates_only"], True)
        self.assert_count(work, "selected_input_observation_count", 0)
        self.assertTrue(work["preparation_actions"])
        for action in work["preparation_actions"]:
            self.assertIs(action["automatic_execution_allowed"], False)
            self.assertIn(action["action"], {"project.status", "identity.resource"})
            self.assertIn(action["prerequisite"], {"project_allow_mutation", "matching_test_resource_or_declared_actor_state"})
            self.assertIsInstance(action["instruction"], str)
            if action["action"] == "identity.resource":
                self.assertEqual(action["input_template"]["operation_id"], operation["id"])
        continuity = work["session_continuity"]
        self.assertIs(continuity["hint_only"], True)
        self.assertIs(continuity["automatic_cookie_forwarding"], False)
        self.assertEqual(continuity["anonymous_input_field"], "anonymous_cookie")
        self.assertEqual(continuity["authenticated_input_field"], "session_id")
        self.assertIsInstance(continuity["instructions"], list)
        self.fixture.assert_private_locator(work)
        self.assertNotIn("opaque-true-0-tested-consumer_review", canonical(queued))
        self.assert_no_value_or_private_digest(queued["parameter_coverage"])
        self.fixture.network.assert_not_called()

    def test_required_consumer_family_is_publicly_visible_as_unplanned_not_tested(self):
        self.seed_collisions()
        operation = self.register("/sql", inputs=[{"name": "keyword", "location": "query", "selector": "keyword",
                                                   "consumer": "sql_like", "test_families": ["generic"]}])
        self.close_generic(operation)
        matrix = self.fixture.call("plan.audit", parameter_limit=100)["parameter_coverage"]
        self.assert_count(matrix["summary"], "cell_total", 2)
        self.assert_count(matrix["summary"], "typed_tested_total", 1)
        self.assert_count(matrix["summary"], "untested_total", 1)
        sql = next(row for row in matrix["items"] if row["test_family"] == "sql_injection")
        self.assertEqual(sql["id"], self.expected_id(operation, family="sql_injection"))
        self.assertEqual(sql["queue_status"], "unplanned")
        self.assertEqual(sql["next_action"], "surface.declare_consumer")
        self.assertIs(sql["typed_tested"], False)
        self.assertIs(sql["observation_is_testing"], False)
        self.assertEqual(sql["obligation_ids"], [])
        self.assert_no_value_or_private_digest(matrix)
        self.assertEqual(self.fixture.network.call_count, 3)

    def test_missing_fill_context_omits_free_prose_but_retains_parameter_and_delta_controls(self):
        secret = "synthetic-unknown-private-fill-material"
        operation = self.register("/" + secret)
        before = self.fixture.call("plan.checkpoint")
        self.close_generic(operation)
        self.fixture.browser_context(secret, missing=True)
        audit = self.fixture.call("plan.audit", parameter_limit=100)
        self.assertEqual(audit["redaction_context_status"], "unavailable")
        matrix = audit["parameter_coverage"]
        self.assert_count(matrix["summary"], "typed_tested_total", 1)
        row = matrix["items"][0]
        self.assertEqual(row["id"], self.expected_id(operation))
        self.assertEqual(row["status"], "tested")
        self.assertEqual(row["queue_status"], "closed")
        self.assertIs(row["typed_tested"], True)
        self.assertIs(row["has_input_variant"], True)
        self.assertIs(row["observation_is_testing"], False)
        self.assert_count(row, "observation_count", 3)
        self.fixture.assert_private_locator(row)
        self.assertNotEqual(row["consumer"], "business_input")
        checkpoint = self.fixture.call("plan.checkpoint")
        self.assertEqual(checkpoint["redaction_context_status"], "unavailable")
        delta = checkpoint["checkpoint"]["parameter_delta"]
        self.assertIs(delta["comparison_available"], True)
        self.assertIs(delta["projection_complete"], True)
        self.assertIs(delta["observation_is_testing"], False)
        self.assert_count(delta, "newly_tested_total", 1)
        self.assert_count(delta, "newly_observed_variants_total", 1)
        self.assertEqual(delta["newly_tested"][0]["id"], self.expected_id(operation))
        self.assertIs(checkpoint["continuation"]["continue_required"], True)
        self.assertIs(checkpoint["continuation"]["automatic_stop_allowed"], False)
        self.assertNotIn(secret, canonical({"matrix": matrix, "checkpoint": checkpoint}))
        self.assert_no_value_or_private_digest({"matrix": matrix, "checkpoint": checkpoint})
        self.assertEqual(before["checkpoint"]["id"], checkpoint["checkpoint"]["previous_checkpoint_id"])
        self.assertEqual(self.fixture.network.call_count, 3)


if __name__ == "__main__":
    unittest.main()
