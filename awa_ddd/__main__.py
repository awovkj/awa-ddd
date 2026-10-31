"""One bounded JSON request per process; stdout is reserved for the protocol."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
from .store import Project, EngineError, canonical
from . import engine
from .contracts import validate_action_args


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EngineError("invalid_input", "Protocol JSON objects cannot contain duplicate keys")
        result[key] = value
    return result


def dispatch(workspace,action,args):
    validate_action_args(action, args)
    if action=="action.help":
        from .contracts import action_help
        return action_help(args)
    if action=="runtime.probe":
        from .runtime import probe
        return probe(args)
    if action=="project.create":
        return engine.create_project(workspace,args)
    if action=="project.list":
        from .workflow import page
        directory=Path(workspace).expanduser().resolve()/"projects"
        rows=[p.name for p in sorted(directory.iterdir()) if p.is_dir() and not p.is_symlink() and (p/"assessment.sqlite3").is_file()] if directory.exists() else []
        window=page(rows,args)
        return {"projects":window.pop("items"),"project_total":window.pop("total"),**window}
    with Project(workspace,args["project_id"]) as project:
        if action=="project.update":
            return engine.update_project(project,args)
        if action=="project.status":
            from .workflow import project_status
            return project_status(project,args)
        if action in {"surface.list", "surface.inspect", "surface.batch"}:
            from . import workflow
            return {"surface.list":workflow.list_surfaces,"surface.inspect":workflow.inspect_surface,
                    "surface.batch":workflow.register_batch}[action](project,args)
        if action=="surface.register":
            operation=engine.register_operation(project,args.get("operation",args))
            engine.build_plan(project)
            return operation
        if action=="surface.declare_consumer":
            return engine.declare_consumer(project,args)
        if action=="browser.probe":
            from . import browser
            return browser.probe()
        if action=="browser.visit":
            from . import browser
            return browser.visit(project,args)
        if action=="browser.import_mcp":
            from . import browser
            return browser.import_observation(project,args)
        if action in {"tool.probe", "tool.sqlmap", "tool.yakit_replay", "tool.inspect", "tool.artifact"}:
            from . import external
            handler = {"tool.probe": external.probe, "tool.sqlmap": external.sqlmap_run,
                       "tool.yakit_replay": external.yakit_replay, "tool.inspect": external.inspect,
                       "tool.artifact": external.read_artifact}[action]
            return handler(project,args)
        if action in {"tool.tscanplus_request", "tool.tscanplus_results", "tool.tscanplus_summary", "tool.tscanplus_routes"}:
            from . import tscanplus
            return {"tool.tscanplus_request": tscanplus.request_run,
                    "tool.tscanplus_results": tscanplus.query_results,
                    "tool.tscanplus_summary": tscanplus.project_summary,
                    "tool.tscanplus_routes": tscanplus.route_candidates}[action](project, args)
        if action=="page.register":
            from . import browser
            return browser.register_page(project,args)
        if action=="page.adopt":
            from . import browser
            return browser.adopt_visit(project,args)
        if action=="page.function":
            from . import browser
            return browser.register_function(project,args)
        if action=="page.mark":
            from . import browser
            return browser.mark(project,args)
        if action=="page.coverage":
            from . import browser
            return browser.coverage(project)
        if action=="surface.import":
            from .discovery import discover
            from .candidates import store_candidate
            result=discover(args["path"],args["format"],args.get("base_url"))
            registered, rejected=[],[]
            for hint in result["operations"]:
                try:
                    registered.append(engine.register_operation(project,hint)["id"])
                except EngineError as exc:
                    rejected.append({"kind":"operation_hint","hint":hint,"reason":exc.code})
            created=0
            for candidate in result.get("candidates",[])+rejected:
                _,is_new=store_candidate(project,candidate)
                created+=1 if is_new else 0
            engine.build_plan(project)
            return {"operation_ids":registered,"candidates":created,
                    "candidate_total":len(project.list("candidate")),
                    "limitations":result.get("limitations",[])}
        if action=="identity.actor":
            result=engine.add_actor(project,args)
            engine.build_plan(project)
            return result
        if action=="identity.session":
            return engine.add_session(project,args)
        if action=="identity.verify":
            return engine.verify_identity(project,args)
        if action=="identity.resource":
            result=engine.add_resource(project,args)
            engine.build_plan(project)
            return result
        if action=="plan.build":
            from .workflow import plan_page
            return plan_page(project,engine.build_plan(project),args)
        if action=="plan.next":
            from .workflow import next_work
            return next_work(project,args)
        if action=="plan.audit":
            from .completeness import audit
            return audit(project,args)
        if action in {"plan.checkpoint", "plan.review", "plan.finalize"}:
            from . import continuation
            return {"plan.checkpoint": continuation.checkpoint, "plan.review": continuation.review,
                    "plan.finalize": continuation.finalize}[action](project, args)
        if action=="candidate.list":
            from .candidates import list_candidates
            return list_candidates(project,args)
        if action=="candidate.inspect":
            from .candidates import inspect_candidate
            return inspect_candidate(project,args)
        if action=="candidate.link":
            from .candidates import link_candidate
            result=link_candidate(project,args)
            engine.build_plan(project)
            return result
        if action=="candidate.dismiss":
            from .candidates import dismiss_candidate
            return dismiss_candidate(project,args)
        if action=="candidate.reopen":
            from .candidates import reopen_candidate
            return reopen_candidate(project,args)
        if action in {"plan.list","report.coverage"}:
            from .workflow import coverage_view
            return coverage_view(engine.evaluate_coverage(project),args)
        if action=="plan.disposition":
            return engine.disposition(project,args)
        if action=="http.capture":
            return engine.capture(project,args)
        if action=="http.preflight":
            from .workflow import capture_preflight
            return capture_preflight(project,args)
        if action=="scenario.preflight":
            from .scenario import preflight
            return preflight(project,args)
        if action=="scenario.run":
            from .scenario import run_scenario
            return run_scenario(project,args)
        if action=="run.recover":
            return engine.recover_runs(project,args)
        if action=="run.inspect":
            return project.get("run",args["run_id"])
        if action=="assessment.evaluate":
            from .assessment import evaluate
            return evaluate(project,args)
        if action=="finding.record":
            from .assessment import record_finding
            return record_finding(project,args)
        if action=="finding.list":
            from .workflow import findings_page
            return findings_page(project,args)
        if action=="finding.update":
            from .workflow import update_finding
            return update_finding(project,args)
        if action=="evidence.inspect":
            evidence=project.get("evidence",args["evidence_id"])
            try:
                project.read_artifact(evidence)
            except (EngineError,OSError,ValueError) as exc:
                return {**evidence,"integrity":"invalid","lineage":"invalid","usable":False,
                        "usable_for_new_requests":False,"session_status":"unchecked" if evidence.get("session_id") else "none",
                        "reason":getattr(exc,"code","artifact_unreadable")}
            # Artifact integrity is not enough: an operation re-registered with a
            # different access policy or method makes the capture unusable for
            # evaluation even though the bytes are intact. Report both separately so a
            # stale-but-readable capture is never mistaken for usable evidence.
            from .lineage import compatibility
            from .engine import operation_signature
            operation=project.get("operation",evidence["operation_id"],required=False)
            if operation is None:
                return {**evidence,"integrity":"valid","lineage":"operation_missing",
                        "usable":False,"usable_for_new_requests":False,
                        "session_status":"unchecked" if evidence.get("session_id") else "none","reason":"operation_removed"}
            ok,detail=compatibility(operation,evidence,operation_signature(operation))
            result={**evidence,"integrity":"valid","lineage":"current" if ok else "stale","usable":ok}
            if not ok:
                result["reason"]="operation_changed"
                result["policy_changes"]=detail.get("changes") or []
            try:
                engine.verify_current_evidence(project,evidence["id"])
            except (EngineError,OSError,ValueError,KeyError) as exc:
                result["usable"]=False
                result["lineage"]="stale"
                result["reason"]=getattr(exc,"code","evidence_invalid")
            # Evidence freshness and identity liveness are different questions.
            # A capture made through an expired session is still a valid historical
            # observation; it just cannot be used to send a new request.
            if evidence.get("session_id"):
                from .engine import session_valid
                session = project.get("session", evidence["session_id"], required=False)
                if session is None:
                    result["session_status"] = "missing"
                    result["usable_for_new_requests"] = False
                elif session.get("generation") != evidence.get("session_generation") or session.get("actor_id") != evidence.get("actor_id"):
                    result["session_status"] = "rotated_or_other_actor"
                    result["usable_for_new_requests"] = False
                else:
                    try:
                        session_valid(project, session)
                        result["session_status"] = "live"
                        result["usable_for_new_requests"] = True
                    except EngineError as exc:
                        result["session_status"] = "expired" if exc.code == "session_expired" else exc.code
                        result["usable_for_new_requests"] = False
                        result["session_hint"] = str(exc)
            else:
                result["session_status"] = "none"
                result["usable_for_new_requests"] = True
            result["usable_for_new_requests"] = result["usable"] and result["usable_for_new_requests"]
            return result
        if action=="report.build":
            from .reporting import build_report
            return build_report(project,args.get("output_dir"), stage=args.get("stage", "draft"),
                                finalization_id=args.get("finalization_id"))
        if action=="project.import_pentest":
            from .importers import import_pentest
            result=import_pentest(project,args["source_path"])
            engine.build_plan(project)
            return result
        raise EngineError("action", "Unknown awa-ddd action")


def main():
    # Own the protocol encoding even when invoked without Python's -X utf8 flag.
    sys.stdout.reconfigure(encoding="utf-8", errors="strict", newline="\n")
    sys.stderr.reconfigure(encoding="utf-8", errors="strict", newline="\n")
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace",required=True)
    options=parser.parse_args()
    action=None
    try:
        raw=sys.stdin.buffer.read(2*1024*1024+1)
        if len(raw)>2*1024*1024:
            raise EngineError("input_budget", "Tool request exceeds 2 MiB")
        request=json.loads(raw.decode("utf-8-sig",errors="strict"),object_pairs_hook=_unique_json_object,
                           parse_constant=lambda x: (_ for _ in ()).throw(ValueError("Nonfinite number")))
        if not isinstance(request,dict) or not isinstance(request.get("action"),str):
            raise EngineError("request", "Request requires action and args")
        action=request["action"]
        data=dispatch(options.workspace,action,request.get("args",{}))
        print(canonical({"ok":True,"data":data}))
        return 0
    except EngineError as exc:
        error={"code":exc.code,"message":str(exc)}
        if exc.details:
            from .reporting import safe_metadata
            error["details"]=safe_metadata(exc.details)
    except KeyError as exc:
        missing = str(exc).strip("'")
        error={"code":"argument_missing",
               "message":str(action or "request")+" requires argument/record field " + repr(missing)
                         + "; inspect action.help for this action.",
               "details":{"action":action,"field":missing,"help_action":"action.help","help_input":{"name":action}}}
    except TypeError as exc:
        error={"code":"invalid_input","message":"Wrong argument shape for " + str(action or "request") + "; inspect action.help rather than guessing fields"}
    except (ValueError,OSError) as exc:
        error={"code":"invalid_input","message":type(exc).__name__+": invalid input or unavailable local resource"}
    except Exception as exc:
        # Never print raw request data, credentials, or a traceback through the tool.
        error={"code":"engine_error","message":type(exc).__name__+": operation failed; inspect project checkpoints"}
    print(canonical({"ok":False,"error":error}))
    return 2


if __name__=="__main__":
    raise SystemExit(main())
