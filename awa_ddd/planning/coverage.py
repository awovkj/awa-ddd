"""Engine-computed multi-dimensional coverage for 2.0 campaigns."""
from __future__ import annotations

from collections import Counter

from ..domain import DIMENSIONS
from ..domain.coverage_claim import consumer as consumer_claim
from ..domain.coverage_claim import delivery as delivery_claim
from ..domain.coverage_claim import discovery as discovery_claim
from ..domain.coverage_claim import hypothesis as hypothesis_claim
from ..domain.coverage_claim import known_case as known_case_claim
from ..domain.coverage_claim import machine_proof as machine_claim
from ..domain.repository import Repository
from .hypotheses import family_applicability

TERMINAL_HYPOTHESIS = {"supported", "refuted", "inconclusive", "not_applicable"}


def _page_visited(page):
    return bool(page.get("page_visit_id") or page.get("visit_id"))


def compute(project, campaign_id):
    repository = Repository(project)
    campaign = repository.get("campaign", campaign_id)
    universe = repository.get("universe", campaign.get("universe_id"))
    hypotheses, _ = repository.list("hypothesis", limit=None)
    hypotheses = [row for row in hypotheses if not row.get("superseded")]
    known_cases, _ = repository.list("known_case", limit=None)
    findings, _ = repository.list("finding", limit=None)
    gaps, _ = repository.list("gap", limit=None)
    runs, _ = repository.list("run", limit=None)
    from ..domain.known_case import summary as known_summary
    case_summary = known_summary(known_cases)
    known_claims = []
    for track, bucket in case_summary["by_track"].items():
        known_claims.append(known_case_claim(track=track, total=bucket["total"],
                                              verified=bucket["verified"] + bucket["reported"],
                                              blocked=bucket["blocked"]))
    pages = universe.get("pages", [])
    operations = universe.get("operations", [])
    known_total = len(universe.get("routes", []))
    registered = sum(bool(row.get("page_ids") or row.get("operation_ids")) for row in universe.get("routes", []))
    visited = sum(_page_visited(page) for page in pages)
    discovery = discovery_claim(known_total=known_total, registered=registered, visited=visited,
                                unknown_counts=universe.get("unknown_counts", {}),
                                site_wide_allowed=bool(universe.get("site_wide_discovery_allowed")))
    inputs = universe.get("inputs", [])
    declared = sum(row.get("consumer_status") == "declared" for row in inputs)
    consumer = consumer_claim(inputs=len(inputs), declared=declared)
    applicable = [row for row in hypotheses if row.get("status") != "not_applicable"]
    tested = [row for row in applicable if row.get("status") in TERMINAL_HYPOTHESIS]
    dispositioned = [row for row in hypotheses if row.get("status") not in {"unplanned", "ready", "running"}]
    outcomes = Counter(row.get("status") for row in hypotheses)
    hypothesis = hypothesis_claim(total=len(hypotheses), applicable=len(applicable), tested=len(tested),
                                  dispositioned=len(dispositioned), outcomes=dict(outcomes))
    current_findings = [row for row in findings if row.get("current")]
    machine = machine_claim(current_findings=len(current_findings),
                            machine_confirmed=sum(row.get("mode") == "machine" for row in current_findings))
    family_matrix = family_applicability(hypotheses)
    status_by_family = {row["test_family"]: row for row in family_matrix}
    unplanned_family_count = sum(row["status"] == "not_planned" for row in family_matrix)
    route_matrix = []
    unregistered_routes = 0
    for route in universe.get("routes", []):
        registered_route = bool(route.get("page_ids") or route.get("operation_ids"))
        if not registered_route:
            unregistered_routes += 1
        route_matrix.append({
            "route_id": route.get("route_id"),
            "path_template": route.get("path_template"),
            "source_kind": route.get("source_kind"),
            "registered": registered_route,
            "page_total": len(route.get("page_ids", [])),
            "operation_total": len(route.get("operation_ids", [])),
            "unresolved": bool(route.get("unresolved")),
        })
    consumer_matrix = [{
        "input_key": row.get("input_key"), "operation_id": row.get("operation_id"),
        "location": row.get("location"), "selector": row.get("selector"),
        "consumer": row.get("consumer"), "status": row.get("consumer_status"),
    } for row in inputs]
    known_case_matrix = [{
        "id": case.get("id"), "source_group": case.get("source_group"), "family": case.get("family"),
        "track": case.get("track"), "status": case.get("status"), "dedupe_key": case.get("dedupe_key"),
    } for case in known_cases]
    open_hypotheses = [row for row in hypotheses if row.get("status") in {"unplanned", "ready", "running", "blocked"}]
    family_status = {row["test_family"]: row["status"] for row in family_matrix}
    effective_gaps = []
    for gap in gaps:
        if gap.get("status", "open") != "open":
            continue
        if gap.get("kind") == "family" and family_status.get(gap.get("scope")) != "not_planned":
            continue
        if gap.get("kind") == "consumer":
            matching = next((row for row in inputs if row.get("input_key") == gap.get("scope")), None)
            if matching is not None and matching.get("consumer_status") != "unknown":
                continue
        effective_gaps.append(gap)
    open_gaps = effective_gaps
    remaining = []
    if unplanned_family_count:
        remaining.append({"kind": "family", "count": unplanned_family_count})
    if unregistered_routes:
        remaining.append({"kind": "route", "count": unregistered_routes})
    if open_hypotheses:
        remaining.append({"kind": "hypothesis", "count": len(open_hypotheses)})
    if open_gaps:
        remaining.append({"kind": "gap", "count": len(open_gaps)})
    # Delivery acceptance is independent of coverage ratios; only zero remaining
    # work plus at least one confirmed/refuted hypothesis and no unresolved
    # inconclusive result grants exhaustion authority. Blocked/N/A/inconclusive
    # states never become a completed assessment by themselves.
    tested_count = sum(row.get("status") in {"supported", "refuted"} for row in hypotheses)
    inconclusive_count = sum(row.get("status") == "inconclusive" for row in hypotheses)
    if inconclusive_count:
        remaining.append({"kind": "inconclusive", "count": inconclusive_count})
    exhausted = bool(hypotheses) and not remaining and tested_count > 0 and inconclusive_count == 0
    delivery = delivery_claim(exhausted=exhausted, partial_accepted=campaign.get("state") == "delivered_partial",
                              remaining=remaining)
    tool_yield = _tool_yield(project)
    dependency = {"scope_epoch": universe.get("scope_epoch"),
                  "universe_snapshot_hash": universe.get("snapshot_hash"),
                  "target_build": universe.get("target_build")}
    for claim in [discovery, consumer, hypothesis, machine, *known_claims]:
        claim["dependency"].update(dependency)
    return {
        "campaign": campaign,
        "universe": {key: universe.get(key) for key in (
            "id", "snapshot_hash", "completeness_level", "site_wide_discovery_allowed", "unknown_counts")},
        "dimensions": {
            "discovery": discovery,
            "consumer": consumer,
            "hypothesis": hypothesis,
            "known_case": known_claims,
            "machine_proof": machine,
        },
        "family_matrix": family_matrix,
        "route_matrix": route_matrix,
        "consumer_matrix": consumer_matrix,
        "known_case_matrix": known_case_matrix,
        "known_case_summary": case_summary,
        "tool_yield": tool_yield,
        "delivery": delivery,
        "unplanned_family_count": unplanned_family_count,
        "unregistered_route_count": unregistered_routes,
        "open_hypothesis_count": len(open_hypotheses),
        "open_gap_count": len(open_gaps),
        "finding_summary": {
            "current_total": len(current_findings),
            "machine": sum(row.get("mode") == "machine" for row in current_findings),
            "reviewed": sum(row.get("mode") == "reviewed" for row in current_findings),
        },
        "computed_by": "engine",
        "dimension_order": list(DIMENSIONS),
    }


def _tool_yield(project):
    runs = project.list("run")
    adapters = Counter()
    for run in runs:
        adapter = run.get("adapter")
        if adapter:
            adapters[adapter] += 1
    candidates = project.list("candidate")
    return {
        "calls": {adapter: adapters.get(adapter, 0) for adapter in ("yakit", "tscanplus", "sqlmap", "playwright")},
        "candidates": len(candidates),
        "promoted_hypotheses": 0,
        "findings": None,
        "unavailable_reasons": [],
        "note": "Tool calls alone are not coverage; candidates must be promoted through explicit typed work.",
    }


def summary(project, campaign_id):
    matrix = compute(project, campaign_id)
    return {
        "campaign_id": campaign_id,
        "dimensions": matrix["dimensions"],
        "delivery": matrix["delivery"],
        "unplanned_family_count": matrix["unplanned_family_count"],
        "unregistered_route_count": matrix["unregistered_route_count"],
        "open_hypothesis_count": matrix["open_hypothesis_count"],
        "finding_summary": matrix["finding_summary"],
        "family_matrix": matrix["family_matrix"],
    }
