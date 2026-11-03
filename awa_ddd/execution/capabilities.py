"""Capability registry: installed is not configured, and configured is not ready.

Readiness is evaluated per recipe profile (method, body, identity, fixture,
effect, proof scope), not as a global checkmark.  Missing adapters stay visible
as ``unavailable`` with a concrete configuration field.
"""
from __future__ import annotations

from ..domain.repository import Repository
from ..store import EngineError

PROVIDERS = ("playwright", "yakit", "tscanplus", "sqlmap")
PROFILES = {
    "playwright": {
        "profiles": ["native_page_visit", "host_mcp_page_visit", "multi_role_xss"],
        "limitations": ["native cannot upload", "native cannot arbitrary evaluate", "host tabs are not isolated contexts"],
        "configuration": ["host Playwright MCP tools or local Chromium/Playwright runtime"],
    },
    "yakit": {
        "profiles": ["public_get_replay"],
        "limitations": ["no scanning", "no POC", "no authenticated replay in the current adapter"],
        "configuration": ["tool.probe adapter:yakit with absolute yak_path"],
    },
    "tscanplus": {
        "profiles": ["existing_results_read", "route_candidate_read"],
        "limitations": ["no scan execution", "no POC", "no cracking", "no JWT", "no route execution"],
        "configuration": ["loopback MCP URL and nondefault scanner_project"],
    },
    "sqlmap": {
        "profiles": ["metadata_only_single_parameter"],
        "limitations": ["no crawl", "no dump", "no stacked queries", "no time techniques", "single parameter"],
        "configuration": ["tool.probe with absolute sqlmap.py path"],
    },
}


def _row(provider, *, installed, configured, catalog_verified, profile_supported,
         authorized, ready, evidence=None, reasons=None):
    return {
        "provider": provider,
        "installed": bool(installed),
        "configured": bool(configured),
        "catalog_verified": bool(catalog_verified),
        "profile_supported": bool(profile_supported),
        "authorized": bool(authorized),
        "ready": bool(ready and installed and configured and catalog_verified and profile_supported and authorized),
        "unavailable_reasons": list(reasons or []),
        "evidence": evidence or {},
        "profiles": PROFILES[provider]["profiles"],
        "limitations": PROFILES[provider]["limitations"],
        "configuration": PROFILES[provider]["configuration"],
    }


def snapshot(project):
    """Compose current readiness from local configuration/probe records; no target traffic."""
    repository = Repository(project, read_only=False)
    configured_rows = {row["provider"]: row for row in repository.list("capability", limit=None)[0]}
    tool_configs = {row["id"]: row for row in project.list("tool_config")}
    probe_runs = [row for row in project.list("run") if row.get("action") == "probe"]
    by_adapter = {}
    for run in probe_runs:
        by_adapter[run.get("adapter")] = run
    rows = []
    for provider in PROVIDERS:
        configured = configured_rows.get(provider)
        if configured:
            rows.append(_row(provider, **{key: configured.get(key, False) for key in
                          ("installed", "configured", "catalog_verified", "profile_supported",
                           "authorized", "ready")}, evidence=configured.get("evidence"),
                          reasons=configured.get("unavailable_reasons")))
            continue
        if provider == "playwright":
            # Native fallback availability is probed by browser.probe; absence of a
            # host MCP is not treated as unavailability of the provider entirely.
            rows.append(_row("playwright", installed=True, configured=True, catalog_verified=False,
                             profile_supported=True, authorized=True, ready=False,
                             reasons=["runtime_probe_required", "host_mcp_catalog_not_verified"]))
        elif provider in {"yakit", "sqlmap"}:
            config = tool_configs.get(provider)
            run = by_adapter.get(provider)
            installed = bool(run and run.get("available"))
            configured_ok = bool(config)
            rows.append(_row(provider, installed=installed, configured=configured_ok,
                             catalog_verified=bool(run and run.get("verification_level")),
                             profile_supported=installed, authorized=configured_ok, ready=installed and configured_ok,
                             evidence={"probe_run_id": run.get("id") if run else None},
                             reasons=[] if installed and configured_ok else ["probe_required"]))
        else:
            rows.append(_row("tscanplus", installed=False, configured=False, catalog_verified=False,
                             profile_supported=False, authorized=False, ready=False,
                             reasons=["unconfigured", "loopback_mcp_required"]))
    return {"providers": rows, "policy": "installed != configured != ready; recipe-specific readiness is checked before execution.",
            "requests_sent": 0}


def ready_for(project, *, provider, profile, effect="read_only", method="GET"):
    """Recipe-specific readiness check used before a provider is named in a recipe."""
    if provider not in PROVIDERS:
        raise EngineError("capability_provider", "Unknown provider")
    if profile not in PROFILES[provider]["profiles"]:
        raise EngineError("capability_profile", "Unsupported provider profile")
    row = next((item for item in snapshot(project)["providers"] if item["provider"] == provider), None)
    reasons = list((row or {}).get("unavailable_reasons") or [])
    if effect == "test_resource_write":
        reasons.append("write_profile_requires_disposable_fixture")
    if provider == "playwright" and profile == "multi_role_xss":
        reasons.append("requires_independent_provider_owned_contexts")
    ready = bool(row and row.get("ready")) and not reasons
    return {"provider": provider, "profile": profile, "ready": ready,
            "reasons": sorted(set(reasons)), "row": row}


def record(project, provider, **states):
    """Record an actual probe result for tests and local adapters."""
    if provider not in PROVIDERS:
        raise EngineError("capability_provider", "Unknown provider")
    repository = Repository(project)
    existing = repository.find_one("capability", provider=provider)
    row = existing or {"id": "CAP-" + provider, "provider": provider,
                       "created_at": __import__("datetime").datetime.now(
                           __import__("datetime").timezone.utc).isoformat()}
    for key in ("installed", "configured", "catalog_verified", "profile_supported", "authorized"):
        row[key] = bool(states.get(key, row.get(key, False)))
    row["ready"] = all(row[key] for key in ("installed", "configured", "catalog_verified",
                                            "profile_supported", "authorized"))
    row["unavailable_reasons"] = list(states.get("unavailable_reasons") or [])
    row["evidence"] = states.get("evidence") or {}
    if existing:
        repository.save("capability", row)
    else:
        repository.add("capability", row, immutable=False)
    return row
