"""Campaign lifecycle: start, status, next, checkpoint and delivery."""
from __future__ import annotations

from copy import deepcopy
from urllib.parse import urlsplit

from .. import engine
from ..domain import new_campaign
from ..domain.campaign import (
    deliver,
    delivery_acceptance,
    public_view as campaign_public,
)
from ..domain.common import digest, fail, string_list, text, utc_now
from ..domain.gap import new_gap
from ..domain.repository import Repository, checkpoint_record
from ..domain.test_recipe import public_view as recipe_public_view
from ..domain.universe import (
    new_universe,
    operation_record,
    page_record,
    route_record,
    validate_operation_context,
)
from . import coverage, scheduler
from .hypotheses import generate_hypotheses


def _scoped(config, url):
    try:
        from ..scope import require_scope
        require_scope(config, url)
        return True
    except (engine.EngineError, TypeError, ValueError):
        return False


def build_universe(project, *, campaign_id=None, read_only=False):
    config = project.config
    operations, pages, functions, inputs, consumers, routes = [], [], [], [], [], {}
    scoped_operations = {}
    for operation in project.list("operation"):
        if not _scoped(config, operation.get("url")):
            continue
        scoped_operations[operation["id"]] = operation
        record = operation_record(operation, consumers)
        record["operation_signature"] = engine.operation_signature(operation)
        operations.append(record)
        inputs.extend(record["inputs"])
        template = record["url_template"]
        route = routes.setdefault(template, {"path": template, "page_ids": [], "operation_ids": []})
        route["operation_ids"].append(record["operation_id"])
    for page in project.list("page"):
        if not _scoped(config, page.get("url")):
            continue
        record = page_record(page)
        pages.append(record)
        functions.extend(record["functions"])
        route = routes.setdefault(record["route_template"], {"path": record["route_template"], "page_ids": [], "operation_ids": []})
        route["page_ids"].append(record["page_id"])
    route_rows = [route_record(path_template=row["path"], source_kind="registered_operation" if row["operation_ids"] else "page_ledger",
                               source_ref="ledger", dynamic_params=[], page_ids=row["page_ids"],
                               operation_ids=row["operation_ids"]) for row in routes.values()]
    for imported in Repository(project, read_only=read_only).list("route_source", limit=None)[0]:
        route_rows.append(route_record(
            path_template=imported["path_template"], source_kind="imported_route",
            source_ref=imported.get("source_ref", "route_import"), dynamic_params=imported.get("dynamic_params"),
            limitations=imported.get("limitations"), aliases=imported.get("aliases"),
            redirect=imported.get("redirect"), catch_all=imported.get("catch_all", False),
            lazy=imported.get("lazy", False), unresolved=imported.get("unresolved", False)))
    origins = sorted({urlsplit(rule).scheme + "://" + urlsplit(rule).netloc for rule in config.get("scope", []) if urlsplit(rule).netloc})
    from ..source_inventory import inventory
    source_inventory = inventory(project, operations=scoped_operations)
    source_summary = source_inventory["summary"]
    source_complete = not any((
        source_summary.get("pending_import_total", 0),
        source_summary.get("needs_binding_total", 0),
        source_summary.get("known_not_registered_total", 0),
        source_summary.get("unresolved_total", 0),
        len(source_inventory.get("source_issues") or {}),
        sum(source_inventory.get("snapshot_issues", {}).values()),
    ))
    unknown_counts = {
        "registered_operation_total": len(operations),
        "page_total": len(pages),
        "function_total": len(functions),
        "unknown_consumer_total": sum(row.get("status") == "unknown" for row in consumers),
        "unregistered_route_total": sum(not (row.get("page_ids") or row.get("operation_ids")) for row in route_rows),
        "truncated_source_total": int(
            source_summary.get("unresolved_total", 0)),
        "source_inventory_complete": source_complete,
        "source_inventory_summary": source_summary,
    }
    sources = [{"kind": "scope_declaration", "ref": "project.config.scope",
                "sha256": digest(config.get("scope") or []),
                "complete": bool(config.get("scope"))},
               {"kind": "registered_operation", "ref": "ledger.operations",
                "sha256": digest([[row.get("operation_id"), row.get("operation_signature")] for row in operations]),
                "complete": source_complete},
               {"kind": "page_ledger", "ref": "ledger.pages", "sha256": digest(pages), "complete": False}]
    declared_build = config.get("target_build")
    if isinstance(declared_build, str) and declared_build.strip():
        build_provenance = {
            "status": "declared",
            "source": "project.config.target_build",
            "observed_at": config.get("target_build_observed_at"),
            "limitations": ["Configuration declares a build; it does not prove the live deployment version."],
        }
        target_build = declared_build.strip()
    else:
        build_provenance = {
            "status": "unknown",
            "source": "none",
            "observed_at": None,
            "limitations": ["No trusted deployment/build identifier was observed."],
        }
        target_build = "unknown"
    universe = new_universe(
        scope_epoch=digest([config.get("scope"), config.get("exclude")]),
        origins=origins, routes=route_rows, pages=pages, functions=functions,
        operations=operations, inputs=inputs, consumers=consumers, sources=sources,
        unknown_counts=unknown_counts,
        completeness_level="source_inventory" if operations or pages else "declared_only",
        target_build=target_build,
        target_build_provenance=build_provenance)
    universe["project_id"] = project.config.get("project_id")
    validate_operation_context(universe)
    return universe


def _model_allowed(project):
    model = project.config.get("assessment_model", "v1")
    if model == "v2":
        return True
    obligations = [row for row in project.list("obligation") if not row.get("superseded")]
    return not obligations


def start(project, args):
    repository = Repository(project)
    if args.get("target"):
        from ..scope import normalize_url
        if normalize_url(args["target"]) != project.config.get("target"):
            fail("v2_campaign_target", "Campaign target must match the project target; scope cannot be widened by campaign.start")
    if not _model_allowed(project):
        migrated = repository.find_one("migration") if repository.list("migration", limit=1)[0] else None
        if not args.get("confirm_migration") or migrated is None:
            fail("v2_migration_required",
                 "Project has v1 obligations; run campaign.migrate apply and pass confirm_migration:true")
    model = args.get("model", "v2")
    if model != "v2":
        fail("v2_campaign_model", "campaign.start requires model:v2")
    campaign = new_campaign(project.config.get("project_id"), target=project.config.get("target"),
                            objective=args.get("objective") or "完成登记范围的评估：所有 Universe 缺口处置且 hypothesis 均有结果",
                            model="v2", scope_snapshot=project.config.get("scope"),
                            exclude_snapshot=project.config.get("exclude"),
                            max_rounds=args.get("max_rounds", 40),
                            allow_mutation=bool(project.config.get("allow_mutation")))
    if repository.list("campaign", limit=100)[0]:
        active = [row for row in repository.list("campaign", limit=100)[0] if row.get("state") == "active"]
        if active and not args.get("new_campaign"):
            fail("v2_campaign_exists", "An active campaign already exists; resume it or pass new_campaign:true")
    universe = build_universe(project, campaign_id=campaign["id"])
    campaign["universe_id"] = universe["id"]
    repository.add("campaign", campaign, immutable=False)
    if repository.get("universe", universe["id"], required=False) is None:
        repository.add("universe", universe, immutable=True)
    known_cases = [row for row in repository.list("known_case", limit=None)[0]
                   if row.get("status") != "duplicate"]
    known_cases = _attach_known_cases(repository, known_cases, campaign)
    hypotheses, limited = generate_hypotheses(universe, known_cases, campaign_id=campaign["id"])
    for hypothesis in hypotheses:
        if repository.get("hypothesis", hypothesis["id"], required=False) is None:
            repository.add("hypothesis", hypothesis, immutable=False)
        else:
            # Reuse the existing stable identity; never overwrite attempt history or findings.
            hypothesis = repository.get("hypothesis", hypothesis["id"])
    gaps = _gaps(universe, hypotheses, campaign)
    for gap in gaps:
        repository.add("gap", gap, immutable=False)
    coverage_row = coverage.compute(project, campaign["id"])
    checkpoint = checkpoint_record(campaign_id=campaign["id"], universe=universe, coverage=coverage_row,
                                   hypotheses=hypotheses, known_cases=coverage_row["known_case_matrix"],
                                   gaps=[row["id"] for row in gaps], label="initial")
    repository.add("checkpoint", checkpoint, immutable=True)
    config = dict(project.config)
    config["assessment_model"] = "v2"
    project.set_config(config)
    project.event("v2.campaign_started", {"campaign_id": campaign["id"], "universe_id": universe["id"],
                                          "hypotheses": len(hypotheses), "limited": limited})
    return {"campaign": campaign_public(campaign), "universe": {
        "id": universe["id"], "snapshot_hash": universe["snapshot_hash"],
        "operation_total": len(universe["operations"]), "page_total": len(universe["pages"]),
        "route_total": len(universe["routes"]), "input_total": len(universe["inputs"]),
        "hypothesis_total": len(hypotheses), "hypothesis_limited": limited,
        "completeness_level": universe["completeness_level"]},
        "checkpoint_id": checkpoint["id"], "next_action": "campaign.next"}


def _attach_known_cases(repository, cases, campaign):
    attached = []
    for case in cases:
        case.setdefault("campaign_memberships", {})[campaign["id"]] = {
            "universe_id": campaign["universe_id"],
            "status": case.get("status", "unplanned"),
            "attached_at": case.get("created_at"),
        }
        repository.save("known_case", case)
        attached.append(case)
    return attached


_HYPOTHESIS_HISTORY_FIELDS = (
    "status", "state_reason", "missing_context", "attempt", "recipe_ids",
    "run_ids", "finding_ids", "proof_receipt_id",
    "applicability_receipt_id", "blocked_prerequisite", "created_at",
    "revision",
)


def _carry_hypothesis_history(target, previous):
    """Carry attempts and dispositions without changing mechanism identity.

    Receipts still revalidate against their own immutable Universe/hypothesis
    dependencies.  Preserving a receipt ID therefore preserves history, not
    automatic authority for a changed mechanism.
    """
    for key in _HYPOTHESIS_HISTORY_FIELDS:
        if key in previous:
            target[key] = deepcopy(previous[key])
    target["history_carried_from"] = previous["id"]
    target["superseded"] = False
    target["superseded_at"] = None
    target.pop("superseded_by", None)
    target["updated_at"] = utc_now()
    return target


def _supersede(row, replacement_id=None):
    row["superseded"] = True
    row["superseded_at"] = utc_now()
    if replacement_id:
        row["superseded_by"] = replacement_id
    row["updated_at"] = utc_now()
    return row


def _advance_campaign_universe(project, repository, campaign, universe, *,
                               campaign_revision):
    """Advance one active campaign and retain unchanged mechanism history."""
    previous_universe_id = campaign["universe_id"]
    previous_hypotheses = [
        row for row in repository.list_campaign(
            "hypothesis", campaign["id"], limit=None)[0]
        if row.get("universe_id") == previous_universe_id
        and not row.get("superseded")
    ]
    previous_by_mechanism = {
        row.get("mechanism_key"): row for row in previous_hypotheses
    }
    known_cases = [
        row for row in repository.list("known_case", limit=None)[0]
        if row.get("status") != "duplicate"
    ]
    generated, limited = generate_hypotheses(
        universe, known_cases, campaign_id=campaign["id"])
    carried, added = 0, 0
    replacements = {}
    for hypothesis in generated:
        previous = previous_by_mechanism.get(hypothesis.get("mechanism_key"))
        existing = repository.get(
            "hypothesis", hypothesis["id"], required=False)
        row = existing if existing is not None else hypothesis
        if previous is not None:
            _carry_hypothesis_history(row, previous)
            carried += 1
            replacements[previous["id"]] = row["id"]
        else:
            row["superseded"] = False
            row["superseded_at"] = None
            row.pop("superseded_by", None)
        if existing is None:
            repository.add("hypothesis", row, immutable=False)
            added += 1
        else:
            repository.save("hypothesis", row)
    for previous in previous_hypotheses:
        replacement = replacements.get(previous["id"])
        if replacement is None:
            # A removed mechanism remains immutable history, not current work.
            _supersede(previous)
        else:
            _supersede(previous, replacement)
        repository.save("hypothesis", previous)

    previous_gaps = [
        row for row in repository.list_campaign(
            "gap", campaign["id"], limit=None)[0]
        if row.get("universe_id") == previous_universe_id
        and row.get("status", "open") != "superseded"
    ]
    gaps_by_key = {(row.get("kind"), row.get("scope")): row
                   for row in previous_gaps}
    generated_gaps = _gaps(universe, generated, campaign)
    gap_replacements = {}
    for gap in generated_gaps:
        previous = gaps_by_key.get((gap.get("kind"), gap.get("scope")))
        existing = repository.get("gap", gap["id"], required=False)
        row = existing if existing is not None else gap
        if previous is not None:
            for key in ("status", "state_reason", "detail", "resolution",
                        "disposition", "created_at"):
                if key in previous:
                    row[key] = deepcopy(previous[key])
            gap_replacements[previous["id"]] = row["id"]
        row["superseded"] = False
        if existing is None:
            repository.add("gap", row, immutable=False)
        else:
            repository.save("gap", row)
    for previous in previous_gaps:
        replacement = gap_replacements.get(previous["id"])
        previous["status"] = "superseded"
        previous["superseded"] = True
        previous["superseded_at"] = utc_now()
        if replacement:
            previous["superseded_by"] = replacement
        repository.save("gap", previous)

    known_cases = _attach_known_cases(repository, known_cases, {
        **campaign, "universe_id": universe["id"]})
    campaign["universe_id"] = universe["id"]
    campaign["version"] = int(campaign.get("version", 1)) + 1
    campaign["updated_at"] = utc_now()
    campaign["completion_invalidated"] = {
        "from_universe_id": previous_universe_id,
        "to_universe_id": universe["id"],
        "reason": "universe_advanced",
        "at": utc_now(),
    }
    repository.save(
        "campaign", campaign, expected_revision=campaign_revision)
    project.event("v2.campaign_universe_advanced", {
        "campaign_id": campaign["id"],
        "previous_universe_id": previous_universe_id,
        "universe_id": universe["id"],
        "hypotheses_added": added,
        "hypotheses_carried": carried,
        "hypothesis_limited": limited,
        "known_cases": len(known_cases),
        "checkpoint_current": False,
        "frontier_current": False,
        "finalization_current": False,
    })
    return {
        "campaign_id": campaign["id"],
        "previous_universe_id": previous_universe_id,
        "universe_id": universe["id"],
        "hypothesis_total": len(generated),
        "hypotheses_added": added,
        "hypotheses_carried": carried,
        "hypothesis_limited": limited,
    }


def save_universe(project, universe, *, campaign_id=None):
    """Persist a snapshot and atomically advance the selected active scope.

    With no campaign ID every active campaign advances, preventing a second
    active campaign from remaining pinned to an obsolete registered surface.
    """
    repository = Repository(project)
    campaigns = [
        row for row in repository.list("campaign", limit=None)[0]
        if row.get("state") == "active"
        and (campaign_id is None or row.get("id") == campaign_id)
    ]
    if campaign_id is not None and not campaigns:
        fail("v2_campaign_state",
             "Universe advancement requires the selected active campaign")
    campaign_revisions = {
        row["id"]: repository.get_revision("campaign", row["id"])
        for row in campaigns
    }
    for row in campaigns:
        if repository.get("campaign", row["id"]) != row:
            fail("revision_conflict",
                 "Campaign changed while the Universe snapshot was being read",
                 {"entity_id": row["id"],
                  "expected_revision": campaign_revisions[row["id"]]})
    changes = []
    with project.transaction():
        needs_universe = repository.get(
            "universe", universe["id"], required=False) is None
        if needs_universe:
            repository.add("universe", universe, immutable=True)
        for campaign in campaigns:
            if campaign.get("universe_id") == universe["id"]:
                continue
            changes.append(_advance_campaign_universe(
                project, repository, campaign, universe,
                campaign_revision=campaign_revisions[campaign["id"]]))
    return changes


def _gaps(universe, hypotheses, campaign=None):
    gaps = []
    from .hypotheses import family_applicability
    campaign_id = campaign.get("id") if campaign else None
    universe_id = universe.get("id")
    for row in family_applicability(hypotheses):
        if row["status"] == "not_planned":
            gaps.append(new_gap(kind="family", scope=row["test_family"],
                                reason="No hypothesis exists for this security family in the current universe.",
                                next_action="review.disposition",
                                campaign_id=campaign_id, universe_id=universe_id))
    for consumer in universe.get("consumers", []):
        if consumer.get("status") == "unknown":
            gaps.append(new_gap(kind="consumer", scope=consumer["input_key"],
                                reason="Input consumer is unknown; hypothesis remains needs_consumer.",
                                next_action="recon.snapshot",
                                campaign_id=campaign_id, universe_id=universe_id))
    return gaps


def status(project, args):
    campaign = _campaign(project, args.get("campaign_id"))
    matrix = coverage.compute(project, campaign["id"])
    from ..execution import capabilities
    continuation, bounded_ids = _continuation(project, campaign, matrix)
    return {
        "campaign_id": campaign["id"],
        "universe_id": campaign["universe_id"],
        "bounded_ids": bounded_ids,
        "campaign": campaign_public(campaign),
        "universe": matrix["universe"],
        "dimensions": matrix["dimensions"],
        "family_matrix": matrix["family_matrix"],
        "route_matrix": matrix["route_matrix"],
        "consumer_matrix": matrix["consumer_matrix"],
        "known_case_matrix": matrix["known_case_matrix"],
        "known_case_summary": matrix["known_case_summary"],
        "tool_yield": matrix["tool_yield"],
        "finding_summary": matrix["finding_summary"],
        "delivery": matrix["delivery"],
        "unplanned_family_count": matrix["unplanned_family_count"],
        "unregistered_route_count": matrix["unregistered_route_count"],
        "open_hypothesis_count": matrix["open_hypothesis_count"],
        "open_gap_count": matrix["open_gap_count"],
        "capabilities": capabilities.snapshot(project),
        "continuation": continuation,
        "completion_decision": continuation["completion_decision"],
        "next_action": continuation["next_action"],
    }


_ACTIVE_RUN_STATES = {
    "prepared", "claimed", "dispatch_started", "response_saved",
    "evaluation_pending",
}


def _frontier_state(project, campaign, matrix):
    """Count only accepted, current and Universe-bound frontier rounds."""
    from ..domain.receipt import current_receipts

    rounds = {}
    receipt_ids = []
    for receipt, _evaluation in current_receipts(
            project, "frontier", campaign["id"]):
        material = receipt.get("material") or {}
        if (
                material.get("campaign_id") != campaign["id"]
                or material.get("universe_id") != campaign["universe_id"]
                or material.get("universe_snapshot_hash")
                != matrix["universe"].get("snapshot_hash")
                or receipt.get("unresolved_items")
                or material.get("boundary_complete") is not True
                or not isinstance(material.get("round_sha256"), str)
                or len(material["round_sha256"]) != 64):
            continue
        if material.get("semantic_schema") == "awa-v2-frontier/v1" and (
                material.get("round_sha256") != digest(material.get("semantic"))
                or material.get("round_key")
                != "UNIVERSE:" + str(material.get("universe_id"))
                + ":" + str(material.get("round_sha256"))):
            continue
        rounds.setdefault(material["round_sha256"], receipt["id"])
        receipt_ids.append(receipt["id"])
    return {
        "frontier_rounds": len(rounds),
        "frontier_current": len(rounds) >= 2,
        "frontier_receipt_ids": sorted(set(receipt_ids)),
    }


def _frontier_evidence(project, repository, campaign, requested=None):
    runs = repository.list_campaign("run", campaign["id"], limit=None)[0]
    allowed = {
        evidence_id
        for run in runs
        for evidence_id in (run.get("evidence_ids") or [])
    }
    if requested is None:
        selected = sorted(allowed)
    else:
        selected = string_list(
            requested, "frontier_evidence_ids", maximum=256)
    if len(selected) > 256:
        fail("v2_frontier_material",
             "A frontier review binds at most 256 evidence observations")
    missing = sorted(set(selected) - allowed)
    if missing:
        fail("v2_frontier_scope",
             "Frontier evidence must belong to a durable run in this campaign",
             evidence_ids=missing)
    observations = {}
    for evidence_id in selected:
        evidence, _artifact = engine.verify_current_evidence(
            project, evidence_id)
        sha256 = evidence.get("sha256")
        if not isinstance(sha256, str) or len(sha256) != 64:
            fail("v2_frontier_material",
                 "Frontier evidence has no current SHA-256 digest")
        observations.setdefault(sha256, []).append(evidence_id)
    return [{
        "sha256": sha256,
        "evidence_ids": sorted(observations[sha256]),
    } for sha256 in sorted(observations)]


def _frontier_semantic(project, repository, campaign, universe, matrix,
                       observations):
    routes = [{
        key: row.get(key) for key in (
            "path_template", "source_kind", "source_ref", "registered",
            "unresolved")
    } for row in matrix.get("route_matrix") or []]
    sources = [{
        key: row.get(key) for key in ("kind", "ref", "sha256", "complete")
    } for row in universe.get("sources") or []]
    pages = [{
        "page_id": row.get("page_id"),
        "url": row.get("url"),
        "route_template": row.get("route_template"),
        "visited": bool(row.get("page_visit_id") or row.get("visit_id")),
        "functions": sorted({
            (row_function.get("function_id"), row_function.get("name"),
             row_function.get("trigger"))
            for row_function in row.get("functions") or []
        }),
    } for row in universe.get("pages") or []]
    hypotheses = [
        row for row in repository.list_campaign(
            "hypothesis", campaign["id"], limit=None)[0]
        if not row.get("superseded")
        and row.get("universe_id") == universe["id"]
    ]
    work = sorted(({
        "mechanism_key": row.get("mechanism_key"),
        "family": row.get("family"),
        "security_property": row.get("security_property"),
        "operation_id": row.get("operation_id"),
        "input_key": row.get("input_key"),
        "status": row.get("status"),
    } for row in hypotheses), key=digest)
    return {
        "schema": "awa-v2-frontier/v1",
        "campaign_id": campaign["id"],
        "universe_id": universe["id"],
        "universe_snapshot_hash": universe["snapshot_hash"],
        "discovery": {
            "routes": routes,
            "sources": sources,
            "operation_total": len(universe.get("operations") or []),
            "input_total": len(universe.get("inputs") or []),
            "unknown_counts": universe.get("unknown_counts") or {},
        },
        "categories": matrix.get("family_matrix") or [],
        "pages": pages,
        "work": work,
        # Evidence IDs and transport clocks are deliberately absent: repeated
        # captures of identical bytes are not independent semantic rounds.
        "observation_sha256": sorted({row["sha256"] for row in observations}),
    }


def _frontier_unresolved(campaign, matrix, continuation):
    unresolved = []
    for kind in ("ready", "review", "blocked", "unresolved", "effect_unknown"):
        count = int(continuation.get(kind + "_total", 0))
        if count:
            unresolved.append("work:" + kind + ":" + str(count))
    unknown_counts = matrix["universe"].get("unknown_counts") or {}
    if not unknown_counts.get("source_inventory_complete"):
        unresolved.append("source_inventory:incomplete")
    if not (unknown_counts.get("registered_operation_total")
            or unknown_counts.get("page_total")):
        unresolved.append("scope:empty")
    if not matrix["delivery"].get("exhausted_authority") \
            and "delivery:not_exhausted" not in unresolved:
        unresolved.append("delivery:not_exhausted")
    return sorted(set(unresolved))


def review_frontier(project, args):
    """Construct and persist a real Universe/evidence-bound review round."""
    from ..domain.receipt import (
        entity_dependency,
        evaluate_receipt,
        evidence_dependencies,
        new_frontier_receipt,
        public_view as receipt_public,
    )

    repository = Repository(project)
    campaign = _campaign(project, args.get("campaign_id"))
    if campaign.get("state") != "active":
        fail("v2_campaign_state",
             "Frontier review requires an active campaign")
    universe = repository.get("universe", campaign["universe_id"])
    matrix = coverage.compute(project, campaign["id"])
    before, _bounded = _continuation(project, campaign, matrix)
    observations = _frontier_evidence(
        project, repository, campaign, args.get("evidence_ids"))
    semantic = _frontier_semantic(
        project, repository, campaign, universe, matrix, observations)
    round_sha256 = digest(semantic)
    round_key = "UNIVERSE:" + universe["id"] + ":" + round_sha256
    unresolved = _frontier_unresolved(campaign, matrix, before)
    decision = "accepted" if not unresolved else "proposed"
    material = {
        "campaign_id": campaign["id"],
        "universe_id": universe["id"],
        "universe_snapshot_hash": universe["snapshot_hash"],
        "round_key": round_key,
        "round_sha256": round_sha256,
        "semantic_schema": "awa-v2-frontier/v1",
        "semantic": semantic,
        "observations": observations,
        "boundary_complete": not unresolved,
    }
    dependencies = [
        entity_dependency(
            project, "campaign", campaign["id"], fingerprint_fields=(
                "id", "project_id", "target", "objective", "model",
                "scope_snapshot", "exclude_snapshot", "scope_epoch",
                "max_rounds", "allow_mutation", "universe_id")),
        entity_dependency(
            project, "universe", universe["id"],
            fingerprint_fields=("id", "snapshot_hash", "scope_epoch")),
    ]
    evidence_ids = sorted({
        evidence_id
        for row in observations
        for evidence_id in row["evidence_ids"]
    })
    dependencies.extend(evidence_dependencies(project, evidence_ids))
    reviewer_id = text(
        args.get("reviewer_id") or "campaign.review_frontier",
        "frontier_reviewer_id", maximum=200)
    receipt = None
    reused = False
    if decision == "accepted":
        for candidate in reversed(repository.list_campaign(
                "frontier_receipt", campaign["id"], limit=None)[0]):
            candidate_material = candidate.get("material") or {}
            if candidate.get("decision") != "accepted" \
                    or candidate_material.get("round_sha256") != round_sha256 \
                    or candidate_material.get("round_key") != round_key \
                    or candidate_material.get("semantic_schema") \
                    != "awa-v2-frontier/v1" \
                    or candidate_material.get("semantic") != semantic \
                    or candidate_material.get("boundary_complete") is not True \
                    or candidate_material.get("universe_id") != universe["id"]:
                continue
            if evaluate_receipt(project, candidate)["current"]:
                receipt = candidate
                reused = True
                break
    if receipt is None:
        receipt = new_frontier_receipt(
            campaign_id=campaign["id"],
            topic=args.get("topic") or "Current Universe discovery/category/page frontier",
            material=material,
            dependencies=dependencies,
            reviewer={
                "type": "agent_recorded",
                "id": reviewer_id,
                "source": "campaign.review_frontier",
            },
            unresolved_items=unresolved,
            limitations=[
                "The review covers the current source-bound Universe, never the unknown site-wide surface.",
            ],
            decision=decision,
        )
        repository.add("frontier_receipt", receipt, immutable=True)
    evaluation = evaluate_receipt(project, receipt)
    updated_matrix = coverage.compute(project, campaign["id"])
    continuation, bounded_ids = _continuation(
        project, campaign, updated_matrix)
    return {
        "frontier_receipt": receipt_public(receipt),
        "receipt_current": evaluation["current"],
        "reused": reused,
        "frontier_rounds": continuation["frontier_rounds"],
        "frontier_current": not continuation["frontier_review_required"],
        "bounded_ids": bounded_ids,
        "continuation": continuation,
        "completion_decision": continuation["completion_decision"],
        "next_action": continuation["next_action"],
    }


def _open_gaps(campaign, gaps, inputs, family_matrix):
    family_status = {
        row.get("test_family"): row.get("status") for row in family_matrix
    }
    consumer_status = {
        row.get("input_key"): row.get("consumer_status") for row in inputs
    }
    effective = {}
    for gap in gaps:
        if gap.get("status", "open") != "open":
            continue
        if gap.get("universe_id", campaign["universe_id"]) \
                != campaign["universe_id"]:
            continue
        if gap.get("kind") == "family" \
                and family_status.get(gap.get("scope")) != "not_planned":
            continue
        if gap.get("kind") == "consumer" \
                and consumer_status.get(gap.get("scope")) != "unknown":
            continue
        effective[(gap.get("kind"), gap.get("scope"), gap.get("id"))] = gap
    # Gap IDs are content-derived, so insertion/creation order is not a stable
    # semantic order. Persist one canonical order for checkpoint comparison and
    # host projections instead of intermittently invalidating a fresh checkpoint.
    return sorted(effective.values(), key=lambda row: row["id"])


def _work_categories(active_hypotheses, runs, gaps, universe):
    """Assign each outstanding identity to exactly one completion bucket."""
    ready = set()
    review = set()
    blocked = set()
    unresolved = set()
    effect_unknown = set()
    recoverable = set()
    runs_by_hypothesis = {}
    for run in runs:
        runs_by_hypothesis.setdefault(run.get("hypothesis_id"), []).append(run)
    for hypothesis in active_hypotheses:
        identity = hypothesis["id"]
        status = hypothesis.get("status", "unplanned")
        matching = runs_by_hypothesis.get(identity, [])
        unknown_runs = [
            run for run in matching
            if run.get("status") == "effect_unknown"
            or (run.get("effect") or {}).get("unknown") is True
        ]
        durable = [
            run for run in matching
            if run.get("status") in _ACTIVE_RUN_STATES
            and (run.get("effect") or {}).get("unknown") is not True
        ]
        reconciled = [
            run for run in matching
            if run.get("reconciliation_id")
            and run.get("effect_unknown") is not True
        ]
        effect_unknown_attempt = (
            (hypothesis.get("attempt") or {}).get("last_outcome")
            == "effect_unknown"
            or "state_readback" in (hypothesis.get("missing_context") or [])
        )
        if status in {"unplanned", "ready"}:
            ready.add(identity)
        elif status == "running":
            if unknown_runs:
                effect_unknown.add(identity)
            elif durable:
                ready.add(identity)
                recoverable.add(identity)
            else:
                review.add("running:" + identity)
        elif status == "blocked":
            if unknown_runs or effect_unknown_attempt and not reconciled:
                effect_unknown.add(identity)
            elif effect_unknown_attempt and reconciled:
                review.add("effect-unknown:" + identity)
            else:
                blocked.add(identity)
    for gap in gaps:
        if gap.get("kind") == "consumer":
            unresolved.add("consumer:" + str(gap.get("scope")))
        else:
            review.add(
                "gap:" + str(gap.get("kind")) + ":"
                + str(gap.get("scope")))
    for consumer in universe.get("consumers", []):
        if consumer.get("status") == "unknown":
            unresolved.add("consumer:" + str(consumer.get("input_key")))
    for route in universe.get("routes", []):
        if not (route.get("page_ids") or route.get("operation_ids")):
            unresolved.add("route:" + str(route.get("route_id")))
    unknown_counts = universe.get("unknown_counts") or {}
    for number in range(int(
            unknown_counts.get("truncated_source_total", 0))):
        unresolved.add(f"source-truncated:{number}")
    return {
        "ready": ready,
        "review": review,
        "blocked": blocked,
        "unresolved": unresolved,
        "effect_unknown": effect_unknown,
        "recoverable": recoverable,
    }


def _checkpoint_current(latest, matrix, active_hypotheses, open_gaps,
                        frontier_ids):
    if not latest:
        return False
    projection = sorted([
        [row.get("id"), row.get("status"), row.get("state_reason"),
         row.get("proof_receipt_id"), row.get("applicability_receipt_id")]
        for row in active_hypotheses
    ])
    return (
        latest.get("universe_snapshot_hash")
        == matrix["universe"].get("snapshot_hash")
        and latest.get("hypotheses") == projection
        and latest.get("gaps") == sorted(row["id"] for row in open_gaps)
        and latest.get("frontier_receipt_ids") == sorted(frontier_ids)
        and latest.get("work_semantic_hash") == digest({
            "hypotheses": projection,
            "gaps": sorted(row["id"] for row in open_gaps),
            "frontier_receipt_ids": sorted(frontier_ids),
        })
    )


def _completion(project, campaign, matrix, *, latest_checkpoint_id=None,
                checkpoint_current=False, finalized=False, next_action=None):
    from ..completion import CompletionEvaluator

    universe = matrix["universe"]
    unknown_counts = universe.get("unknown_counts") or {}
    has_scope = bool(project.config.get("scope")) and bool(
        unknown_counts.get("registered_operation_total", 0)
        or unknown_counts.get("page_total", 0))
    source_complete = bool(
        unknown_counts.get(
            "source_inventory_complete"))
    receipt_summary = matrix.get("receipt_summary") or {}
    material_current = not (
        receipt_summary.get("applicability_reopened", 0)
        or receipt_summary.get("proof_reopened", 0)
        or (matrix.get("finding_summary") or {}).get(
            "expired_or_invalid_total", 0)
    )
    partial = campaign.get("state") == "delivered_partial"
    counts = {
        "ready": len(matrix["_work"]["ready"]),
        "review": len(matrix["_work"]["review"]),
        "blocked": len(matrix["_work"]["blocked"]),
        "unresolved": len(matrix["_work"]["unresolved"]),
        "effect_unknown": len(matrix["_work"]["effect_unknown"]),
    }
    return CompletionEvaluator.evaluate(
        model="v2",
        subject_id=campaign["id"],
        has_scope=has_scope,
        coverage_complete=bool(
            matrix["delivery"].get("exhausted_authority")),
        counts=counts,
        frontier_current=bool(matrix["_frontier"]["frontier_current"]),
        material_current=material_current,
        source_complete=source_complete,
        checkpoint_current=checkpoint_current,
        finalized=finalized,
        partial_accepted=partial,
        next_action=next_action,
    )


def _continuation(project, campaign, matrix):
    """Build the host-facing continuation contract from current durable facts."""
    repository = Repository(project, read_only=True)
    universe = repository.get("universe", campaign["universe_id"])
    hypotheses = repository.list_campaign(
        "hypothesis", campaign["id"], limit=None)[0]
    gaps = repository.list_campaign("gap", campaign["id"], limit=None)[0]
    runs = repository.list_campaign("run", campaign["id"], limit=None)[0]
    findings = repository.list_campaign("finding", campaign["id"], limit=None)[0]
    recipes = repository.list_campaign("recipe", campaign["id"], limit=None)[0]
    checkpoints = repository.list_campaign("checkpoint", campaign["id"], limit=None)[0]
    frontiers = repository.list_campaign("frontier_receipt", campaign["id"], limit=None)[0]
    active_hypotheses = [row for row in hypotheses if not row.get("superseded")]
    effective_gaps = _open_gaps(
        campaign, gaps, matrix.get("consumer_matrix") or [],
        matrix.get("family_matrix") or [])
    work = _work_categories(
        active_hypotheses, runs, effective_gaps, universe)
    frontier = _frontier_state(project, campaign, matrix)
    latest_checkpoint = checkpoints[-1] if checkpoints else None
    checkpoint_current = _checkpoint_current(
        latest_checkpoint, matrix, active_hypotheses, effective_gaps,
        frontier["frontier_receipt_ids"])
    exhausted = bool(matrix["delivery"]["exhausted_authority"])
    matrix["_work"] = work
    matrix["_frontier"] = frontier
    finalized = (
        campaign.get("state") == "completed"
        and bool((campaign.get("delivery") or {}).get("exhausted_authority")))
    ready_total = len(work["ready"])
    effect_unknown_total = len(work["effect_unknown"])
    review_total = len(work["review"])
    blocked_total = len(work["blocked"])
    unresolved_total = len(work["unresolved"])
    actionable_total = (
        ready_total + review_total + blocked_total + unresolved_total
        + effect_unknown_total)
    if work["recoverable"]:
        next_action = "test.inspect"
    elif ready_total:
        next_action = "campaign.next"
    elif effect_unknown_total:
        next_action = "test.inspect"
    elif review_total:
        next_action = (effective_gaps[0].get("next_action")
                       if effective_gaps else "review.disposition")
    elif blocked_total:
        next_action = "review.disposition"
    elif unresolved_total:
        next_action = "recon.snapshot"
    elif not checkpoint_current:
        next_action = "campaign.checkpoint"
    elif not frontier["frontier_current"]:
        next_action = "campaign.review_frontier"
    elif campaign.get("state") == "active":
        next_action = "campaign.finish"
    else:
        next_action = "report.build"
    decision = _completion(
        project, campaign, matrix,
        latest_checkpoint_id=(
            latest_checkpoint.get("id") if latest_checkpoint else None),
        checkpoint_current=checkpoint_current,
        finalized=finalized,
        next_action=next_action)
    can_finalize = bool(
        campaign.get("state") == "active"
        and checkpoint_current
        and decision["can_finalize"])
    if can_finalize:
        decision = _completion(
            project, campaign, matrix,
            latest_checkpoint_id=latest_checkpoint.get("id"),
            checkpoint_current=True,
            next_action="campaign.finish")
    if finalized:
        coverage_status = "complete"
    elif campaign.get("state") == "delivered_partial":
        coverage_status = "partial"
    elif any(
            claim.get("status") in {"gap", "blocked", "unknown"}
            for claim in matrix["dimensions"].values()
            if isinstance(claim, dict)):
        coverage_status = "partial"
    elif exhausted:
        coverage_status = "exhausted"
    else:
        coverage_status = "partial"
    semantic = {
        "campaign_id": campaign["id"],
        "universe_id": campaign["universe_id"],
        "snapshot_hash": matrix["universe"].get("snapshot_hash"),
        "hypotheses": sorted(
            (row["id"], row.get("status"), row.get("state_reason"),
             row.get("proof_receipt_id"), row.get("applicability_receipt_id"))
            for row in active_hypotheses),
        "gaps": sorted(row["id"] for row in effective_gaps),
        "runs": sorted(
            (row["id"], row.get("status"), row.get("outcome")) for row in runs),
        "findings": sorted(
            (row["id"], row.get("status"), row.get("current")) for row in findings),
        "frontier_receipt_ids": frontier["frontier_receipt_ids"],
        "work_counts": {
            "ready": ready_total,
            "review": review_total,
            "blocked": blocked_total,
            "unresolved": unresolved_total,
            "effect_unknown": effect_unknown_total,
        },
    }
    progress_id = "PR2-" + digest(semantic)[:32]
    snapshot_id = "US2-" + str(matrix["universe"].get("snapshot_hash") or digest(semantic))[:32]
    latest_checkpoint_id = latest_checkpoint.get("id") if latest_checkpoint else None
    continuation = {
        "contract_version": 2,
        "stop_policy": "exhaustion_only",
        "stop_policy_version": 1,
        "continue_required": decision["continue_required"],
        "automatic_stop_allowed": decision["can_claim_complete"],
        "can_finalize": can_finalize,
        "can_claim_complete": decision["can_claim_complete"],
        "completion_decision": decision,
        "actionable_total": actionable_total,
        "ready_total": ready_total,
        "review_total": review_total,
        "blocked_total": blocked_total,
        "unresolved_total": unresolved_total,
        "effect_unknown_total": effect_unknown_total,
        "recoverable_total": len(work["recoverable"]),
        "frontier_review_required": not frontier["frontier_current"],
        "frontier_rounds": frontier["frontier_rounds"],
        "frontier_receipt_ids": frontier["frontier_receipt_ids"],
        "no_progress_rounds": 0,
        "snapshot_id": snapshot_id,
        "progress_id": progress_id,
        "semantic_progress_id": progress_id,
        "checkpoint_id": latest_checkpoint_id,
        "latest_checkpoint_id": latest_checkpoint_id,
        "finalization_id": None,
        "next_action": next_action,
        "next_step": next_action,
        "state": (
            "finalized" if finalized
            else "ready_to_finalize" if can_finalize
            else "continue"
        ),
        "coverage_status": coverage_status,
    }
    by_kind = {
        "campaign": [campaign["id"]],
        "universe": [campaign["universe_id"]],
        "hypothesis": hypotheses,
        "recipe": recipes,
        "run": runs,
        "finding": findings,
        "gap": gaps,
        "checkpoint": checkpoints,
        "frontier_receipt": frontiers,
    }
    bounded_ids = {
        key: {
            "ids": [row if isinstance(row, str) else row["id"] for row in rows[:200]],
            "returned": min(len(rows), 200),
            "total": len(rows),
            "limited": len(rows) > 200,
        }
        for key, rows in by_kind.items()
    }
    return continuation, bounded_ids


def next_recipes(project, args):
    repository = Repository(project)
    campaign = _campaign(project, args.get("campaign_id"))
    universe = repository.get("universe", campaign["universe_id"])
    selected, preparation, queue = scheduler.next_hypotheses(
        project, campaign, universe, limit=args.get("limit", 3))
    repository.save("campaign", campaign)
    rows = []
    for score_row, hypothesis in selected:
        from ..execution.recipe_builder import build
        built = build(project, campaign, universe, hypothesis)
        if built["status"] != "ready":
            blocked = scheduler._preparation_entry({
                **hypothesis,
                "missing_context": (
                    built.get("missing")
                    or hypothesis.get("missing_context")
                    or []
                ),
            })
            blocked.update({
                key: value for key, value in built.items()
                if key != "missing"
            })
            preparation.append(blocked)
            continue
        recipe = built["recipe"]
        if repository.get("recipe", recipe["id"], required=False) is None:
            repository.add("recipe", recipe, immutable=True)
        rows.append({
            "hypothesis": {
                "id": hypothesis["id"], "family": hypothesis["family"],
                "security_property": hypothesis["security_property"],
                "statement": hypothesis["statement"], "status": hypothesis["status"],
                "why": "来自当前 Universe 的 {family} 假设；statement 不是已证实漏洞。".format(family=hypothesis["family"]),
            },
            "target": {
                "operation_id": recipe["bindings"].get("operation_id"),
                "method": next((op.get("method") for op in universe.get("operations", [])
                                if op.get("operation_id") == recipe["bindings"].get("operation_id")), None),
                "session_id": (recipe["bindings"].get("session") or {}).get("session_id"),
                "resource_id": (recipe["bindings"].get("resource") or {}).get("resource_id"),
                "fixture_id": (recipe["bindings"].get("fixture") or {}).get("fixture_id"),
            },
            "controls": [
                {"group": group.get("id"), "roles": [control.get("role") for control in group.get("controls", [])]}
                for group in recipe.get("control_groups", [])
            ],
            "recipe": recipe_public_view(recipe),
            "score": score_row,
            "prerequisites": [] if not hypothesis.get("missing_context") else hypothesis["missing_context"],
            "expected_outcome": "supported|refuted|inconclusive",
            "steps": recipe.get("steps"),
            "coverage_delta_preview": {"tested": 1, "family": hypothesis["family"]},
        })
    return {"campaign_id": campaign["id"], "recipes": rows, "preparation": preparation[:20],
            "queue": queue, "returned": len(rows),
            "next_action": "test.run" if rows else "review.disposition",
            "note": "Only complete public references are returned; executable bytes and credentials stay in the private capsule."}


def checkpoint(project, args):
    repository = Repository(project)
    campaign = _campaign(project, args.get("campaign_id"))
    universe = repository.get("universe", campaign["universe_id"])
    matrix = coverage.compute(project, campaign["id"])
    hypotheses = repository.list_campaign("hypothesis", campaign["id"], limit=None)[0]
    hypotheses = [
        row for row in hypotheses
        if row.get("universe_id") == campaign["universe_id"]
    ]
    all_gaps = repository.list_campaign("gap", campaign["id"], limit=None)[0]
    gaps = _open_gaps(
        campaign, all_gaps, matrix.get("consumer_matrix") or [],
        matrix.get("family_matrix") or [])
    frontier = _frontier_state(project, campaign, matrix)
    row = checkpoint_record(campaign_id=campaign["id"], universe=universe, coverage=matrix,
                            hypotheses=hypotheses, known_cases=matrix["known_case_matrix"],
                            gaps=[gap["id"] for gap in gaps],
                            frontier_receipt_ids=frontier["frontier_receipt_ids"],
                            label=args.get("label"))
    repository.add("checkpoint", row, immutable=True)
    campaign["rounds"] = int(campaign.get("rounds", 0)) + 1
    repository.save("campaign", campaign)
    continuation, bounded_ids = _continuation(project, campaign, matrix)
    return {
        "checkpoint": row,
        "checkpoint_id": row["id"],
        "campaign": campaign_public(campaign),
        "bounded_ids": bounded_ids,
        "continuation": continuation,
        "completion_decision": continuation["completion_decision"],
        "next_action": continuation["next_action"],
    }


def finish(project, args):
    repository = Repository(project)
    campaign = _campaign(project, args.get("campaign_id"))
    # Freeze the revision that was actually evaluated by every gate below.
    # Reading a fresh revision at save time would let a concurrent Universe
    # advance or scheduler mutation be overwritten with a stale delivery.
    gated_revision = repository.get_revision("campaign", campaign["id"])
    if repository.get("campaign", campaign["id"]) != campaign:
        fail(
            "revision_conflict",
            "Campaign changed while the delivery gate snapshot was being read",
            {"entity_id": campaign["id"], "expected_revision": gated_revision},
        )
    reason = args.get("reason")
    if campaign.get("state") != "active" \
            or campaign.get("delivery") is not None:
        fail(
            "v2_campaign_frozen",
            "A campaign delivery is immutable and can be recorded only once",
        )
    matrix = coverage.compute(project, campaign["id"])
    continuation, bounded_ids = _continuation(project, campaign, matrix)
    decision = continuation["completion_decision"]
    if reason == "completed":
        if not decision.get("can_finalize"):
            code = "v2_campaign_not_exhausted"
            if matrix["delivery"].get("exhausted_authority") \
                    and (
                        continuation["checkpoint_id"] is None
                        or continuation["frontier_review_required"]
                    ):
                code = "v2_campaign_checkpoint"
            fail(
                code,
                "Completed delivery requires the shared CompletionDecision, "
                "current receipts and a current checkpoint",
                completion_decision=decision,
            )
    elif reason == "partial_accepted":
        if not isinstance(args.get("accepted_by"), str) \
                or not args["accepted_by"].strip():
            fail(
                "v2_campaign_delivery",
                "partial_accepted requires a concrete accepted_by identity",
            )
    else:
        fail("v2_campaign_delivery", "finish requires reason completed or partial_accepted")

    # Mutate the in-memory campaign before recomputing continuation so the
    # delivery decision is built from the prospective final state. A partial
    # acceptance is evaluated with exhausted authority explicitly withdrawn.
    deliver(
        campaign,
        reason=reason,
        accepted_by=args.get("accepted_by"),
        explanation=args.get("explanation"),
        checkpoint_id=continuation["checkpoint_id"],
    )
    updated_matrix = coverage.compute(project, campaign["id"])
    if reason == "partial_accepted":
        updated_matrix["delivery"] = {
            **updated_matrix["delivery"],
            "exhausted_authority": False,
            "delivery_status": "partial_accepted",
        }
    updated_continuation, bounded_ids = _continuation(
        project, campaign, updated_matrix)
    final_decision = updated_continuation["completion_decision"]
    if reason == "partial_accepted" and (
            final_decision.get("can_finalize") is True
            or final_decision.get("can_claim_complete") is True
            or updated_continuation.get("automatic_stop_allowed") is True):
        fail(
            "v2_campaign_not_exhausted",
            "partial_accepted can never grant completion or automatic-stop authority",
        )
    campaign["delivery"]["completion_decision_id"] = final_decision["id"]
    acceptance = delivery_acceptance(
        campaign,
        reason=reason,
        accepted_by=args.get("accepted_by"),
        explanation=args.get("explanation"),
        checkpoint_id=continuation["checkpoint_id"],
        completion_decision=final_decision,
        remaining=updated_matrix["delivery"]["remaining"],
    )
    campaign["delivery"]["acceptance_id"] = acceptance["id"]
    with project.transaction():
        repository.add(
            "completion_acceptance", acceptance, immutable=True)
        repository.save(
            "campaign",
            campaign,
            expected_revision=gated_revision,
        )
        project.event("v2.campaign_delivered", {
            "campaign_id": campaign["id"],
            "reason": reason,
            "checkpoint_id": campaign["delivery"].get("checkpoint_id"),
            "completion_decision_id": campaign["delivery"].get(
                "completion_decision_id"),
            "acceptance_id": campaign["delivery"].get("acceptance_id"),
        })
    return {"campaign": campaign_public(campaign), "delivery": campaign["delivery"],
            "dimensions": updated_matrix["dimensions"],
            "checkpoint_id": campaign["delivery"].get("checkpoint_id"),
            "bounded_ids": bounded_ids,
            "continuation": updated_continuation,
            "completion_decision": updated_continuation["completion_decision"],
            "notice": ("partial_accepted delivers a bounded report; it never grants exhaustion authority."
                       if reason == "partial_accepted" else
                       "completed delivery is bound to current evidence and the checkpoint snapshot.")}


def _campaign(project, campaign_id=None):
    repository = Repository(project)
    if campaign_id:
        return repository.get("campaign", campaign_id)
    rows = [row for row in repository.list("campaign", limit=None)[0] if row.get("state") == "active"]
    if not rows:
        fail("v2_campaign_missing", "No active campaign; call campaign.start")
    return rows[-1]
