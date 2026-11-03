"""Coverage claims are engine-computed, multi-dimensional, and never one percentage.

The five dimensions required by the 2.0 design are independent: discovery,
consumer semantics, hypothesis disposition/testing, known-case recall and
machine proof.  Delivery acceptance is kept separate from exhaustion authority
so that a partial delivery cannot be mistaken for complete assessment.
"""
from __future__ import annotations

from .common import digest, enum, fail, integer, mapping, optional_text, sequence, stable_id

DIMENSIONS = ("discovery", "consumer", "hypothesis", "known_case", "machine_proof")
STATUSES = {"covered", "partial", "gap", "blocked", "not_applicable", "unknown"}


def make_claim(*, dimension, scope, numerator, denominator, status, unknown_extent=None,
               dependency=None, notes=None, source_kind=None):
    """Only the coverage engine should call this.  Numerator/denominator are derived facts."""
    enum(dimension, "coverage_dimension", set(DIMENSIONS))
    integer(numerator, "numerator", minimum=0)
    if denominator is not None:
        integer(denominator, "denominator", minimum=0)
        if numerator > denominator:
            fail("v2_coverage", "Coverage numerator cannot exceed its denominator")
    enum(status, "coverage_status", STATUSES)
    ratio = (numerator / denominator) if denominator else None
    identity = {"dimension": dimension, "scope": scope, "numerator": numerator,
                "denominator": denominator, "dependency": dependency or {}}
    return {
        "id": stable_id("COV", identity),
        "dimension": dimension,
        "scope": optional_text(scope, "scope", maximum=256) or "known_universe",
        "numerator": numerator,
        "denominator": denominator,
        "ratio": round(ratio, 6) if ratio is not None else None,
        "status": status,
        "unknown_extent": unknown_extent if isinstance(unknown_extent, str) else "unknown",
        "percentage_of_unknown_total": None,
        "dependency": mapping(dependency or {}, "dependency"),
        "source_kind": optional_text(source_kind, "source_kind", maximum=64),
        "notes": sequence(notes or [], "notes", maximum=32),
        "computed_by": "engine",
        "claim_version": 1,
    }


def discovery(*, known_total, registered, visited, unknown_counts, site_wide_allowed):
    unknown = dict(unknown_counts or {})
    status = "covered" if known_total and registered == known_total and visited >= known_total and site_wide_allowed \
        else "partial" if registered else "gap"
    if not site_wide_allowed:
        status = "partial" if registered else "unknown"
    claim = make_claim(dimension="discovery", scope="known_universe", numerator=registered,
                       denominator=known_total, status=status, unknown_extent="unknown",
                       dependency={"site_wide_discovery_allowed": bool(site_wide_allowed),
                                   "unknown_counts": unknown},
                       notes=["Discovery denominators cover only source-backed known routes/pages/operations; no site-wide percentage is possible without a complete source inventory."])
    claim["visited"] = visited
    claim["unknown_counts"] = unknown
    return claim


def consumer(*, inputs, declared):
    status = "covered" if inputs and declared == inputs else "partial" if declared else "gap"
    return make_claim(dimension="consumer", scope="known_inputs", numerator=declared,
                      denominator=inputs, status=status,
                      dependency={"consumer_status_source": "registered_or_imported"},
                      notes=["Unknown consumers remain explicit hypotheses/gaps; they never count as tested."])


def hypothesis(*, total, applicable, tested, dispositioned, outcomes):
    tested = min(tested, applicable)
    status = "covered" if applicable and tested == applicable else "partial" if tested else "gap"
    claim = make_claim(dimension="hypothesis", scope="current_hypotheses", numerator=tested,
                       denominator=applicable, status=status,
                       dependency={"outcomes": dict(outcomes or {}), "total_including_na": total},
                       notes=["Numerator is actual test coverage; disposition_rate is reported separately and blocked/inconclusive do not equal tested."])
    claim["dispositioned"] = dispositioned
    claim["disposition_rate"] = round(dispositioned / total, 6) if total else None
    claim["tested_coverage"] = round(tested / applicable, 6) if applicable else None
    return claim


def known_case(*, track, total, verified, duplicate=0, blocked=0):
    status = "covered" if total and verified == total else "partial" if verified else "gap" if total else "not_applicable"
    claim = make_claim(dimension="known_case", scope="track:" + track, numerator=verified,
                       denominator=total, status=status,
                       dependency={"track": track, "duplicates": duplicate, "blocked": blocked},
                       notes=["Tracks are never merged: hint-assisted verification cannot measure blind discovery."])
    return claim


def machine_proof(*, current_findings, machine_confirmed):
    status = "covered" if current_findings and machine_confirmed == current_findings else \
        "partial" if machine_confirmed else "not_applicable" if not current_findings else "gap"
    return make_claim(dimension="machine_proof", scope="current_findings", numerator=machine_confirmed,
                      denominator=current_findings, status=status,
                      notes=["Evidence-quality measure only; reviewed findings count as detection but not machine proof."])


def delivery(*, exhausted, partial_accepted, remaining):
    return {
        "exhausted_authority": bool(exhausted),
        "delivery_status": "completed" if exhausted else "partial_accepted" if partial_accepted else "in_progress",
        "remaining": list(remaining),
        "computed_by": "engine",
    }
