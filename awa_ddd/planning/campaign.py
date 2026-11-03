"""Campaign lifecycle: start, status, next, checkpoint and delivery."""
from __future__ import annotations

from urllib.parse import urlsplit

from .. import engine
from ..domain import new_campaign
from ..domain.campaign import deliver, public_view as campaign_public
from ..domain.common import digest, fail, text
from ..domain.gap import new_gap
from ..domain.repository import Repository, checkpoint_record
from ..domain.test_recipe import public_view as recipe_public_view
from ..domain.universe import new_universe, operation_record, page_record, route_record
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
    for operation in project.list("operation"):
        if not _scoped(config, operation.get("url")):
            continue
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
    unknown_counts = {
        "registered_operation_total": len(operations),
        "page_total": len(pages),
        "function_total": len(functions),
        "unknown_consumer_total": sum(row.get("status") == "unknown" for row in consumers),
        "unregistered_route_total": sum(not (row.get("page_ids") or row.get("operation_ids")) for row in route_rows),
        "truncated_source_total": 0,
        "source_inventory_complete": False,
    }
    sources = [{"kind": "scope_declaration", "ref": "project.config.scope",
                "sha256": digest(config.get("scope") or []), "complete": False},
               {"kind": "registered_operation", "ref": "ledger.operations",
                "sha256": digest([[row.get("operation_id"), row.get("operation_signature")] for row in operations]),
                "complete": False},
               {"kind": "page_ledger", "ref": "ledger.pages", "sha256": digest(pages), "complete": False}]
    universe = new_universe(
        scope_epoch=digest([config.get("scope"), config.get("exclude")]),
        origins=origins, routes=route_rows, pages=pages, functions=functions,
        operations=operations, inputs=inputs, consumers=consumers, sources=sources,
        unknown_counts=unknown_counts,
        completeness_level="source_inventory" if operations or pages else "declared_only")
    universe["target_build"] = digest({"target": config.get("target"), "scope": config.get("scope")})[:16]
    universe["project_id"] = project.config.get("project_id")
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
    hypotheses, limited = generate_hypotheses(universe, known_cases)
    for hypothesis in hypotheses:
        if repository.get("hypothesis", hypothesis["id"], required=False) is None:
            repository.add("hypothesis", hypothesis, immutable=False)
        else:
            # Reuse the existing stable identity; never overwrite attempt history or findings.
            hypothesis = repository.get("hypothesis", hypothesis["id"])
    gaps = _gaps(universe, hypotheses)
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


def _gaps(universe, hypotheses):
    gaps = []
    from .hypotheses import family_applicability
    for row in family_applicability(hypotheses):
        if row["status"] == "not_planned":
            gaps.append(new_gap(kind="family", scope=row["test_family"],
                                reason="No hypothesis exists for this security family in the current universe.",
                                next_action="review.disposition"))
    for consumer in universe.get("consumers", []):
        if consumer.get("status") == "unknown":
            gaps.append(new_gap(kind="consumer", scope=consumer["input_key"],
                                reason="Input consumer is unknown; hypothesis remains needs_consumer.",
                                next_action="recon.snapshot"))
    return gaps


def status(project, args):
    repository = Repository(project)
    campaign = _campaign(project, args.get("campaign_id"))
    matrix = coverage.compute(project, campaign["id"])
    from ..execution import capabilities
    return {
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
        "next_action": "campaign.next",
    }


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
            preparation.append({**built, "hypothesis_id": hypothesis["id"], "family": hypothesis["family"]})
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
    hypotheses = repository.list("hypothesis", limit=None)[0]
    row = checkpoint_record(campaign_id=campaign["id"], universe=universe, coverage=matrix,
                            hypotheses=hypotheses, known_cases=matrix["known_case_matrix"],
                            gaps=[gap["id"] for gap in repository.list("gap", limit=None)[0]
                                  if gap.get("status") == "open"],
                            label=args.get("label"))
    repository.add("checkpoint", row, immutable=True)
    campaign["rounds"] = int(campaign.get("rounds", 0)) + 1
    repository.save("campaign", campaign)
    return {"checkpoint": row, "checkpoint_id": row["id"], "campaign": campaign_public(campaign),
            "next_action": "campaign.next"}


def finish(project, args):
    repository = Repository(project)
    campaign = _campaign(project, args.get("campaign_id"))
    reason = args.get("reason")
    matrix = coverage.compute(project, campaign["id"])
    if reason == "completed":
        checkpoints = repository.list("checkpoint", where={"campaign_id": campaign["id"]}, limit=None)[0]
        if not matrix["delivery"]["exhausted_authority"]:
            fail("v2_campaign_not_exhausted", "Completed delivery requires zero remaining hypothesis/family/route/gap work",
                 remaining=matrix["delivery"]["remaining"])
        if not checkpoints:
            fail("v2_campaign_checkpoint", "Completed delivery requires a current checkpoint")
        latest = checkpoints[-1]
        if latest.get("universe_snapshot_hash") != matrix["universe"].get("snapshot_hash"):
            fail("v2_campaign_checkpoint", "Latest checkpoint is stale; create a new checkpoint")
        deliver(campaign, reason="completed", explanation=args.get("explanation"))
    elif reason == "partial_accepted":
        deliver(campaign, reason="partial_accepted", accepted_by=args.get("accepted_by"),
                explanation=args.get("explanation"))
    else:
        fail("v2_campaign_delivery", "finish requires reason completed or partial_accepted")
    repository.save("campaign", campaign)
    project.event("v2.campaign_delivered", {"campaign_id": campaign["id"], "reason": reason})
    return {"campaign": campaign_public(campaign), "delivery": campaign["delivery"],
            "dimensions": matrix["dimensions"],
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
