"""KnownCase: a source-labelled reference case.  It is a selection aid, never proof.

Three benchmark tracks are kept separate and never share a denominator:

``import``
    completeness of importing the user's material.
``hint_assisted``
    cases whose answer key was visible to the operator (verification only).
``blind``
    cases whose labels were withheld (discovery measurement).
"""
from __future__ import annotations

from .common import digest, enum, mapping, optional_text, sequence, stable_id, string_list, text, utc_now

TRACKS = {"import", "hint_assisted", "blind"}
EXPECTED = {"vulnerable", "secure", "unknown"}
STATUSES = {"unplanned", "planned", "verified", "reported", "blocked", "not_applicable", "duplicate"}


def new_known_case(*, source_group, source_ref, url, method, family, mechanism,
                   params=None, expected_outcome="unknown", label_source=None,
                   build=None, preconditions=None, track="hint_assisted",
                   case_id=None, status="unplanned"):
    text(source_group, "source_group", maximum=64)
    text(source_ref, "source_ref", maximum=2048)
    url = text(url, "url", maximum=8192)
    method = text(method, "method", maximum=16).upper()
    family = text(family, "family", maximum=64)
    mechanism = text(mechanism, "mechanism", maximum=256)
    enum(expected_outcome, "expected_outcome", EXPECTED)
    enum(track, "known_case_track", TRACKS)
    enum(status, "known_case_status", STATUSES)
    rows = sequence(params or [], "params", maximum=256)
    identity = {
        "source_group": source_group, "url": url, "method": method, "family": family,
        "mechanism": mechanism, "params": rows, "build": build,
    }
    return {
        "id": case_id or stable_id("KC", identity),
        "source_group": source_group,
        "source_ref": source_ref,
        "url": url,
        "method": method,
        "family": family,
        "mechanism": mechanism,
        "params": rows,
        "expected_outcome": expected_outcome,
        "label_source": optional_text(label_source, "label_source", maximum=1024),
        "build": optional_text(build, "build", maximum=256),
        "preconditions": sequence(preconditions or [], "preconditions", maximum=128),
        "track": track,
        "status": status,
        "duplicate_of": None,
        "dedupe_key": digest(identity),
        "created_at": utc_now(),
        "label_hidden": track == "blind",
    }


def public_view(case):
    """Blind cases never expose their expected outcome before evaluation."""
    row = {key: case.get(key) for key in (
        "id", "source_group", "source_ref", "url", "method", "family", "mechanism", "params",
        "build", "preconditions", "track", "status", "duplicate_of", "dedupe_key")}
    if not case.get("label_hidden"):
        row["expected_outcome"] = case.get("expected_outcome")
        row["label_source"] = case.get("label_source")
    else:
        row["expected_outcome"] = "withheld"
    return row


def dedupe(cases):
    """Group duplicates inside the same source group; never merge cross-group denominators."""
    seen = {}
    output = []
    for case in cases:
        key = (case["source_group"], case["dedupe_key"])
        if key in seen:
            output.append({**case, "status": "duplicate", "duplicate_of": seen[key]})
            continue
        seen[key] = case["id"]
        output.append(case)
    return output


def summary(cases):
    by_track = {}
    for track in TRACKS:
        rows = [case for case in cases if case.get("track") == track and case.get("status") != "duplicate"]
        by_track[track] = {
            "total": len(rows),
            "verified": sum(case.get("status") == "verified" for case in rows),
            "reported": sum(case.get("status") == "reported" for case in rows),
            "blocked": sum(case.get("status") == "blocked" for case in rows),
            "unplanned": sum(case.get("status") == "unplanned" for case in rows),
        }
    return {"by_track": by_track, "total": sum(row["total"] for row in by_track.values())}
