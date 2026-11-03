"""Known-case import: source-labelled selection material, never proof."""
from __future__ import annotations

import json
from pathlib import Path

from ..domain.known_case import new_known_case
from ..domain.repository import Repository
from ..store import EngineError, canonical


KNOWN_CASE_SCHEMA = 2
TRACKS = {"import", "hint_assisted", "blind"}


def _read(path):
    path = Path(path).expanduser().resolve()
    if not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
        raise EngineError("known_case_source", "Known-case source must be a local UTF-8 file under 16 MiB")
    return path, json.loads(path.read_text(encoding="utf-8-sig", errors="strict"))


def _normalize_entry(entry, *, source_group, source_ref, track, default_family=None):
    if not isinstance(entry, dict):
        raise EngineError("known_case_entry", "Known-case entries must be objects")
    url = entry.get("url")
    method = entry.get("method") or "GET"
    family = entry.get("family") or entry.get("test_family") or default_family or "generic"
    mechanism = entry.get("mechanism") or entry.get("type") or entry.get("security_property") or family
    params = entry.get("params") or entry.get("inputs") or []
    expected = entry.get("expected_outcome")
    if expected not in {"vulnerable", "secure", "unknown"}:
        expected = "unknown"
    return new_known_case(
        source_group=source_group,
        source_ref=source_ref,
        url=url,
        method=method,
        family=family,
        mechanism=mechanism,
        params=params,
        expected_outcome=expected,
        label_source=entry.get("label_source") or entry.get("source_kind"),
        build=entry.get("build"),
        preconditions=entry.get("preconditions"),
        track=entry.get("track") or track,
        case_id=entry.get("case_id") or entry.get("id"),
    )


def load_known_cases(path, *, source_group=None, track="hint_assisted"):
    """Load either the native known-case schema or assessment-hint material."""
    path, document = _read(path)
    if not isinstance(document, dict):
        raise EngineError("known_case_source", "Known-case source must be a JSON object")
    if track not in TRACKS:
        raise EngineError("known_case_track", "Unknown known-case track")
    group = source_group or document.get("source_group") or path.stem
    if not isinstance(group, str) or not group or len(group) > 64:
        raise EngineError("known_case_group", "source_group must be a short nonempty string")
    cases = []
    if "cases" in document:
        rows = document.get("cases")
        if not isinstance(rows, list) or len(rows) > 10000:
            raise EngineError("known_case_source", "cases must be an array of at most 10000 entries")
        for index, entry in enumerate(rows):
            cases.append(_normalize_entry(entry, source_group=group,
                                          source_ref=f"{path}#/cases/{index}",
                                          track=document.get("track", track)))
    elif "entries" in document:
        rows = document.get("entries")
        if not isinstance(rows, list) or len(rows) > 10000:
            raise EngineError("known_case_source", "entries must be an array of at most 10000 entries")
        for index, entry in enumerate(rows):
            cases.append(_normalize_entry(entry, source_group=group,
                                          source_ref=f"{path}#/entries/{index}", track=track))
    elif "vulns" in document:
        rows = document.get("vulns")
        if not isinstance(rows, list) or len(rows) > 10000:
            raise EngineError("known_case_source", "vulns must be an array of at most 10000 entries")
        for index, entry in enumerate(rows):
            if not isinstance(entry, list) or len(entry) != 4:
                raise EngineError("known_case_source", "Native definition entries need [url, params, type, score]")
            url, params, declared_type, _score = entry
            cases.append(new_known_case(
                source_group=group, source_ref=f"{path}#/vulns/{index}", url=url, method="GET",
                family="generic", mechanism=str(declared_type), params=params,
                expected_outcome="vulnerable", label_source="target_definition", track="hint_assisted"))
    else:
        raise EngineError("known_case_source", "Known-case source requires cases, entries or vulns")
    return {"document": document, "path": path, "source_group": group, "cases": cases}


def import_known_cases(project, path, *, source_group=None, track="hint_assisted"):
    loaded = load_known_cases(path, source_group=source_group, track=track)
    repository = Repository(project)
    existing = repository.list("known_case", limit=None)[0]
    seen = {(row["source_group"], row["dedupe_key"]): row["id"] for row in existing}
    added, duplicates = [], []
    for case in loaded["cases"]:
        key = (case["source_group"], case["dedupe_key"])
        if key in seen:
            duplicates.append({"case_id": case["id"], "duplicate_of": seen[key]})
            continue
        seen[key] = case["id"]
        repository.add("known_case", case, immutable=False)
        added.append(case["id"])
    project.event("v2.known_cases_imported", {"source_group": loaded["source_group"],
                                               "added": len(added), "duplicates": len(duplicates)})
    return {"source_group": loaded["source_group"], "track": track, "added": len(added),
            "duplicates": duplicates, "case_ids": added,
            "total": repository.count("known_case"),
            "sha256": __import__("hashlib").sha256(canonical(loaded["document"]).encode()).hexdigest()}
