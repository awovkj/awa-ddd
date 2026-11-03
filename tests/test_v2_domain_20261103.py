"""2.0 domain contracts: stable identity, coverage separation and honest statuses."""
from __future__ import annotations

import unittest

from awa_ddd.domain import new_hypothesis, new_known_case
from awa_ddd.domain.coverage_claim import make_claim
from awa_ddd.domain.hypothesis import transition
from awa_ddd.domain.known_case import public_view, summary
from awa_ddd.store import EngineError


def hypothesis(**changes):
    base = dict(
        family="sql_injection", security_property="sql_injection_property",
        operation_id="O-1", input_key="IN-1", scope_epoch="scope-1", target_build="build-1",
        source_kind="declared_family", statement="first wording")
    base.update(changes)
    return new_hypothesis(**base)


class HypothesisIdentityTests(unittest.TestCase):
    def test_statement_wording_does_not_change_identity(self):
        first = hypothesis(statement="first wording")
        second = hypothesis(statement="completely different wording")
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(first["identity_hash"], second["identity_hash"])

    def test_mechanism_input_and_relation_do_change_identity(self):
        first = hypothesis()
        self.assertNotEqual(first["id"], hypothesis(input_key="IN-2")["id"])
        self.assertNotEqual(first["id"], hypothesis(relation={"actor": "merchant", "resource": "any"})["id"])
        self.assertNotEqual(first["id"], hypothesis(family="xss")["id"])

    def test_not_applicable_requires_a_business_basis(self):
        row = hypothesis(status="ready")
        with self.assertRaises(EngineError) as caught:
            transition(row, "not_applicable")
        self.assertEqual("v2_hypothesis_applicability", caught.exception.code)

    def test_blocked_requires_context_and_never_becomes_na(self):
        row = hypothesis(status="blocked", missing_context=["actual_input_consumer"])
        with self.assertRaises(EngineError):
            transition(row, "not_applicable")
        transition(row, "ready", reason="consumer declared")
        self.assertEqual("ready", row["status"])


class CoverageSeparationTests(unittest.TestCase):
    def test_blocked_disposition_is_not_tested_coverage(self):
        claim = make_claim(dimension="hypothesis", scope="current", numerator=0, denominator=4,
                           status="gap")
        self.assertEqual(0, claim["numerator"])
        self.assertEqual(0.0, claim["ratio"])

    def test_caller_cannot_exceed_denominator(self):
        with self.assertRaises(EngineError):
            make_claim(dimension="hypothesis", scope="x", numerator=5, denominator=4, status="covered")

    def test_unknown_discovery_has_no_site_wide_percentage(self):
        claim = make_claim(dimension="discovery", scope="known", numerator=2, denominator=3,
                           status="partial", unknown_extent="unknown")
        self.assertIsNone(claim["percentage_of_unknown_total"])


class KnownCaseTrackTests(unittest.TestCase):
    def test_tracks_never_merge_and_blind_labels_stay_hidden(self):
        hint = new_known_case(source_group="root", source_ref="#1", url="http://x/a", method="GET",
                              family="xss", mechanism="stored", expected_outcome="vulnerable",
                              track="hint_assisted")
        blind = new_known_case(source_group="root", source_ref="#2", url="http://x/b", method="GET",
                               family="xss", mechanism="stored", expected_outcome="secure",
                               track="blind")
        rows = summary([hint, blind])
        self.assertEqual(1, rows["by_track"]["hint_assisted"]["total"])
        self.assertEqual(1, rows["by_track"]["blind"]["total"])
        self.assertEqual("withheld", public_view(blind)["expected_outcome"])
        self.assertEqual("vulnerable", public_view(hint)["expected_outcome"])


if __name__ == "__main__":
    unittest.main()
