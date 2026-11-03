"""Facade for the 2.0 action groups; all offline planning and scoped execution route here."""
from __future__ import annotations

from pathlib import Path

from .domain.repository import Repository
from .domain.common import fail, text
from .execution import capabilities, external_provider, review_engine, test_runner
from .planning import campaign as campaign_planning
from .planning import coverage, known_cases, migration, route_parser, scheduler
from .reporting import compare as _report_compare
from .reporting import matrix as _report_matrix


def recon_snapshot(project, args):
    imported = None
    if args.get("path"):
        fmt = args.get("format", "assessment_hints")
        imported = recon_import(project, {"kind": "routes" if fmt == "routes" else "known_cases",
                                          "path": args["path"], "source_group": args.get("source_group"),
                                          "track": args.get("track", "hint_assisted")})
    universe = campaign_planning.build_universe(project)
    if args.get("save") is True:
        repository = Repository(project)
        if repository.get("universe", universe["id"], required=False) is None:
            repository.add("universe", universe, immutable=True)
    return {"universe": {
        "id": universe["id"], "snapshot_hash": universe["snapshot_hash"],
        "completeness_level": universe["completeness_level"],
        "site_wide_discovery_allowed": universe["site_wide_discovery_allowed"],
        "unknown_counts": universe["unknown_counts"],
        "origin_total": len(universe["origins"]), "route_total": len(universe["routes"]),
        "page_total": len(universe["pages"]), "function_total": len(universe["functions"]),
        "operation_total": len(universe["operations"]), "input_total": len(universe["inputs"]),
        "consumer_total": len(universe["consumers"]),
    }, "imported": imported, "requests_sent": 0, "notice": "Snapshot is a source-bound inventory; it never claims the true unknown surface."}


def recon_import(project, args):
    kind = args.get("kind", "known_cases")
    if kind in {"known_cases", "assessment_hints"}:
        return known_cases.import_known_cases(
            project, args["path"], source_group=args.get("source_group"),
            track=args.get("track", "hint_assisted"))
    if kind == "routes":
        parsed = route_parser.parse_route_manifest(args["path"])
        repository = Repository(project)
        added = []
        for index, route in enumerate(parsed["routes"]):
            record = {
                "id": "RS-" + __import__("hashlib").sha256(
                    (parsed["source_path"] + "#" + str(index)).encode()).hexdigest()[:24],
                "path_template": route["path_template"],
                "dynamic_params": route.get("dynamic_params", []),
                "limitations": route.get("limitations", []),
                "aliases": route.get("aliases", []),
                "redirect": route.get("redirect"),
                "catch_all": route.get("catch_all", False),
                "lazy": route.get("lazy", False),
                "unresolved": route.get("unresolved", False),
                "source_ref": parsed["source_path"] + "#" + str(index),
                "created_at": __import__("datetime").datetime.now(
                    __import__("datetime").timezone.utc).isoformat(),
            }
            if repository.get("route_source", record["id"], required=False) is None:
                repository.add("route_source", record, immutable=True)
                added.append(record["id"])
        return {"kind": "routes", "added": len(added), "route_total": parsed["route_total"],
                "unresolved_total": parsed["unresolved_total"], "catch_all_total": parsed["catch_all_total"],
                "limitations": parsed["limitations"], "requests_sent": 0}
    fail("v2_recon_import", "kind must be known_cases, assessment_hints or routes")


def recon_routes(project, args):
    if args.get("path"):
        result = route_parser.parse_route_manifest(args["path"])
    else:
        rows = Repository(project).list("route_source", limit=None)[0]
        result = {"source_path": None, "routes": rows, "route_total": len(rows),
                  "unresolved_total": sum(bool(row.get("unresolved")) for row in rows),
                  "catch_all_total": sum(bool(row.get("catch_all")) for row in rows),
                  "limitations": ["stored_route_sources_only"]}
    offset, limit = args.get("offset", 0), args.get("limit", 25)
    routes = result["routes"][offset:offset + limit]
    return {**{key: value for key, value in result.items() if key != "routes"},
            "routes": routes, "offset": offset, "limit": limit,
            "next_offset": offset + limit if offset + limit < result["route_total"] else None}


def recon_hypotheses(project, args):
    repository = Repository(project)
    where = {}
    for key in ("status", "family", "operation_id", "source_kind"):
        if args.get(key):
            where[key] = args[key]
    rows, total = repository.list("hypothesis", where=where, offset=args.get("offset", 0),
                                  limit=args.get("limit", 25))
    return {"items": [row for row in rows if not row.get("superseded")], "total": total,
            "offset": args.get("offset", 0), "limit": args.get("limit", 25),
            "next_offset": (args.get("offset", 0) + args.get("limit", 25))
                            if args.get("offset", 0) + args.get("limit", 25) < total else None}


def capabilities_view(project, args):
    return capabilities.snapshot(project)


def test_run(project, args):
    return test_runner.run(project, args)


def test_inspect(project, args):
    return test_runner.inspect(project, args)


def test_run_browser(project, args):
    from .execution import browser_provider
    if args.get("mode") == "xss_evaluate":
        result = browser_provider.evaluate_xss(
            project, consumer_url=args["consumer_url"], marker=args["marker"],
            attack_visit_id=args["attack_visit_id"], normal_visit_id=args["normal_visit_id"],
            writer_attack_evidence_id=args["writer_attack_evidence_id"],
            writer_normal_evidence_id=args["writer_normal_evidence_id"])
        return {"evaluation": result, "finding_allowed": result.get("finding_allowed"),
                "notice": "Only an application-triggered runtime dialog on the real consumer page satisfies browser_runtime."}
    return browser_provider.visit(project, args)


def test_run_scenario(project, args):
    from . import scenario as scenario_mod
    result = scenario_mod.run_scenario(project, args.get("scenario") or args)
    return {"scenario_result": result, "verification_level": "scenario_evidence",
            "notice": "Scenario execution is preserved as evidence; a state-transition conclusion still needs its typed oracle/readback."}


def test_run_external(project, args):
    return external_provider.run_external(project, args)


def test_record_external(project, args):
    return external_provider.record(project, args)


def review_finding(project, args):
    return review_engine.accept(project, args)


def review_bind(project, args):
    return review_engine.bind(project, args)


def review_disposition(project, args):
    return review_engine.disposition(project, args)


def review_evidence(project, args):
    return review_engine.evidence_view(project, args)


def campaign_start(project, args):
    return campaign_planning.start(project, args)


def campaign_status(project, args):
    return campaign_planning.status(project, args)


def campaign_next(project, args):
    return campaign_planning.next_recipes(project, args)


def campaign_checkpoint(project, args):
    return campaign_planning.checkpoint(project, args)


def campaign_finish(project, args):
    return campaign_planning.finish(project, args)


def campaign_migrate(project, args):
    return migration.project_legacy(project, apply=args.get("apply") is True,
                                    confirm=args.get("confirm") is True)


def campaign_rollback(project, args):
    return migration.rollback(project, args)


def report_matrix_view(project, args):
    return _report_matrix(project, args)


def report_compare(project, args):
    return _report_compare(project, args)
