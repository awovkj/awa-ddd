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
from ..domain.receipt import evaluate_receipt
from ..domain.repository import Repository
from .hypotheses import family_applicability

TERMINAL_HYPOTHESIS = {"supported", "refuted", "inconclusive", "not_applicable"}


def _page_visited(page):
    return bool(page.get("page_visit_id") or page.get("visit_id"))


def _current_receipt(project, receipt_id, kind):
    if not receipt_id:
        return None, {
            "id": receipt_id,
            "status": "missing",
            "current": False,
            "reason": f"{kind} receipt is missing",
        }
    store_kind = {
        "applicability": "v2_applicability_receipt",
        "proof": "v2_review_proof_receipt",
    }[kind]
    receipt = project.get(store_kind, receipt_id, required=False)
    if receipt is None or receipt.get("kind") != kind:
        return receipt, {
            "id": receipt_id,
            "status": "missing",
            "current": False,
            "reason": f"{kind} receipt is missing or has the wrong kind",
        }
    return receipt, evaluate_receipt(project, receipt)


def _effective_hypothesis(project, hypothesis, campaign_id):
    """Derive terminal authority from immutable receipts, never status alone."""
    row = dict(hypothesis)
    row["receipt_reopened"] = False
    status = row.get("status")
    if status == "not_applicable":
        receipt, evaluation = _current_receipt(
            project, row.get("applicability_receipt_id"), "applicability")
        matches = bool(
            receipt
            and receipt.get("campaign_id") == campaign_id
            and receipt.get("hypothesis_id") == row.get("id")
            and receipt.get("security_property") == row.get("security_property")
            and receipt.get("input_key") == row.get("input_key")
        )
        if not evaluation["current"] or not matches:
            row["status"] = "ready"
            row["state_reason"] = "applicability receipt is expired or invalid"
            row["receipt_evaluation"] = evaluation
            row["receipt_reopened"] = True
    elif status in {"supported", "refuted"}:
        receipt, evaluation = _current_receipt(
            project, row.get("proof_receipt_id"), "proof")
        matches = bool(
            receipt
            and receipt.get("campaign_id") == campaign_id
            and receipt.get("hypothesis_id") == row.get("id")
        )
        if not evaluation["current"] or not matches:
            row["status"] = "ready"
            row["state_reason"] = "proof receipt is expired or invalid"
            row["receipt_evaluation"] = evaluation
            row["receipt_reopened"] = True
    return row


def _finding_current(project, finding, campaign_id):
    """A finding is current only while its lifecycle and proof receipt are current."""
    if finding.get("campaign_id") != campaign_id:
        return False, {"status": "wrong_campaign", "current": False}
    if finding.get("status") in {"withdrawn", "superseded"} or finding.get("current") is False:
        return False, {"status": finding.get("status") or "inactive", "current": False}
    receipt, evaluation = _current_receipt(
        project, finding.get("proof_receipt_id"), "proof")
    if receipt is None or not evaluation["current"]:
        return False, evaluation
    if receipt.get("campaign_id") != campaign_id \
            or receipt.get("hypothesis_id") != finding.get("hypothesis_id"):
        return False, {
            "status": "scope_mismatch",
            "current": False,
            "reason": "proof receipt does not bind this campaign and hypothesis",
        }
    accepted = set((receipt.get("proof_scope") or {}).get("accepted") or [])
    receipt_evidence = set((receipt.get("material") or {}).get("evidence_ids") or [])
    if finding.get("proof_scope") not in accepted:
        return False, {
            "status": "scope_mismatch",
            "current": False,
            "reason": "finding proof scope is outside the receipt",
        }
    if not set(finding.get("evidence_ids") or []).issubset(receipt_evidence):
        return False, {
            "status": "material_mismatch",
            "current": False,
            "reason": "finding cites evidence outside the receipt",
        }
    return True, evaluation


def compute(project, campaign_id):
    repository = Repository(project)
    campaign = repository.get("campaign", campaign_id)
    universe = repository.get("universe", campaign.get("universe_id"))
    hypotheses, _ = repository.list_campaign("hypothesis", campaign_id, limit=None)
    hypotheses = [
        _effective_hypothesis(project, row, campaign_id)
        for row in hypotheses
        if not row.get("superseded") and row.get("universe_id") == universe.get("id")
    ]
    known_cases, _ = repository.list("known_case", limit=None)
    known_cases = [
        row for row in known_cases
        if campaign_id in (row.get("campaign_memberships") or {})
    ]
    findings, _ = repository.list_campaign("finding", campaign_id, limit=None)
    gaps, _ = repository.list_campaign("gap", campaign_id, limit=None)
    runs, _ = repository.list_campaign("run", campaign_id, limit=None)
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
    finding_evaluations = {
        row["id"]: _finding_current(project, row, campaign_id) for row in findings
    }
    current_findings = [row for row in findings if finding_evaluations[row["id"]][0]]
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
    accepted = campaign.get("delivery") or {}
    for key in (
            "acceptance_id", "reason", "accepted_by", "explanation",
            "checkpoint_id", "completion_decision_id"):
        if accepted.get(key) is not None:
            delivery[key] = accepted[key]
    tool_yield = _tool_yield(project, campaign_id)
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
            "expired_or_invalid_total": sum(
                not current for current, _evaluation in finding_evaluations.values()),
        },
        "_current_findings": current_findings,
        "_finding_evaluations": finding_evaluations,
        "receipt_summary": {
            "applicability_current": sum(
                row.get("status") == "not_applicable" for row in hypotheses),
            "applicability_reopened": sum(
                row.get("receipt_reopened")
                and row.get("state_reason") == "applicability receipt is expired or invalid"
                for row in hypotheses),
            "proof_current": sum(
                row.get("status") in {"supported", "refuted"} for row in hypotheses),
            "proof_reopened": sum(
                row.get("receipt_reopened")
                and row.get("state_reason") == "proof receipt is expired or invalid"
                for row in hypotheses),
        },
        "computed_by": "engine",
        "dimension_order": list(DIMENSIONS),
    }


def _tool_yield(project, campaign_id):
    repository = Repository(project, read_only=True)
    runs = repository.list_campaign(
        "run", campaign_id, limit=None)[0]
    adapters = Counter()
    for run in runs:
        adapter = run.get("adapter")
        if adapter:
            adapters[adapter] += 1
    candidates = [
        row for row in project.list("candidate")
        if row.get("campaign_id") == campaign_id
        or campaign_id in (row.get("campaign_memberships") or {})
    ]
    hypotheses = repository.list_campaign(
        "hypothesis", campaign_id, limit=None)[0]
    findings = repository.list_campaign(
        "finding", campaign_id, limit=None)[0]
    current_finding_ids = {
        row["id"] for row in findings
        if _finding_current(project, row, campaign_id)[0]
    }
    return {
        "calls": {adapter: adapters.get(adapter, 0) for adapter in ("yakit", "tscanplus", "sqlmap", "playwright")},
        "candidates": len(candidates),
        "promoted_hypotheses": sum(
            row.get("source_kind") in {"candidate", "tool_candidate"}
            for row in hypotheses if not row.get("superseded")),
        "findings": len(current_finding_ids),
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
