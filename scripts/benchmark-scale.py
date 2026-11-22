#!/usr/bin/env python3
"""Measure recon warm-page cost against a deterministic local-scale ledger."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import statistics
import sqlite3
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from awa_ddd import engine, reconnaissance  # noqa: E402
from awa_ddd.store import Project, canonical, now  # noqa: E402


def _arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operations", type=int, default=2000)
    parser.add_argument("--evidence", type=int, default=20000)
    parser.add_argument("--pages", type=int, default=500)
    parser.add_argument("--repeats", type=int, default=20)
    parser.add_argument("--p95-ms", type=float, default=500.0)
    parser.add_argument("--json", action="store_true", help="emit one JSON report")
    parser.add_argument("--keep", action="store_true", help="keep the generated fixture directory")
    args = parser.parse_args()
    if args.operations < 1 or args.evidence < 1 or args.pages < 1:
        parser.error("operations, evidence and pages must be positive")
    if args.repeats < 1:
        parser.error("repeats must be positive")
    if args.p95_ms <= 0:
        parser.error("p95-ms must be positive")
    return args


def _entity(kind, identity, document, stamp):
    return (kind, identity, canonical(document), stamp, stamp)


def _write_artifact(base, relative, payload):
    path = base / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _seed(project, operations, evidence, pages):
    started = time.perf_counter()
    stamp = now()
    rows = []
    for index in range(operations):
        identity = f"O-{index:032x}"
        rows.append(_entity("operation", identity, {
            "id": identity,
            "url": f"http://benchmark.invalid/api/{index:04d}",
            "method": "GET",
            "protocol": "http",
            "operation_name": f"Benchmark{index}",
            "content_type": "application/json",
            "auth": "public",
            "allowed_roles": [],
            "ownership": False,
            "inputs": [],
        }, stamp))
    for index in range(pages):
        identity = f"PG-{index:032x}"
        rows.append(_entity("page", identity, {
            "id": identity,
            "url": f"http://benchmark.invalid/page/{index:04d}",
            "name": f"Benchmark page {index}",
            "visited": False,
        }, stamp))
    for index in range(evidence):
        identity = f"E-{index:032x}"
        relative = f"evidence/benchmark-{index:05d}.json"
        payload = canonical({
            "fixture": "local-scale",
            "kind": "http",
            "operation_id": f"O-{(index % operations):032x}",
            "index": index,
        }).encode("utf-8")
        digest = _write_artifact(project.base, relative, payload)
        rows.append(_entity("evidence", identity, {
            "id": identity,
            "kind": "http",
            "operation_id": f"O-{(index % operations):032x}",
            "artifact_path": relative,
            "sha256": digest,
        }, stamp))
    for index in range(pages):
        identity = f"PV-{index:032x}"
        relative = f"browser/benchmark-{index:05d}.json"
        payload = canonical({
            "fixture": "local-scale",
            "kind": "page_visit",
            "page_id": f"PG-{index:032x}",
        }).encode("utf-8")
        digest = _write_artifact(project.base, relative, payload)
        rows.append(_entity("page_visit", identity, {
            "id": identity,
            "kind": "page_visit",
            "page_id": f"PG-{index:032x}",
            "artifact_path": relative,
            "sha256": digest,
        }, stamp))
    with project.transaction():
        project.connection.executemany(
            "INSERT INTO entities(kind,id,document,created_at,updated_at) VALUES(?,?,?,?,?)",
            rows,
        )
    return time.perf_counter() - started


def _percentile(samples, percentile):
    ordered = sorted(samples)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * percentile
    lower, upper = math.floor(position), math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _latency(samples):
    milliseconds = [sample * 1000 for sample in samples]
    return {
        "samples": len(milliseconds),
        "min_ms": round(min(milliseconds), 3),
        "p50_ms": round(_percentile(milliseconds, 0.50), 3),
        "p95_ms": round(_percentile(milliseconds, 0.95), 3),
        "max_ms": round(max(milliseconds), 3),
        "mean_ms": round(statistics.fmean(milliseconds), 3),
    }


def _timed(call):
    started = time.perf_counter()
    value = call()
    return value, time.perf_counter() - started


def main():
    args = _arguments()
    temporary = tempfile.TemporaryDirectory(prefix="awa-scale-benchmark-")
    root = Path(temporary.name)
    project = None
    try:
        engine.create_project(root, {
            "project_id": "scale",
            "target": "http://benchmark.invalid/api",
            "scope": ["http://benchmark.invalid"],
        })
        project = Project(root, "scale")
        seed_seconds = _seed(project, args.operations, args.evidence, args.pages)

        _, cold_seconds = _timed(lambda: reconnaissance.profile(project, {
            "mode": "prepare",
            "section": "overview",
            "limit": 10,
        }))
        samples = []
        response_sizes = []
        hydrated_history = 0
        artifact_bytes_hashed = 0
        artifact_stats = []
        for _ in range(args.repeats):
            records_before = project.metrics["records_decoded"]
            bytes_before = project.metrics["artifact_bytes_hashed"]
            stats_before = project.metrics.get("artifact_stats", 0)
            response, elapsed = _timed(lambda: reconnaissance.profile(project, {
                "mode": "prepare",
                "section": "overview",
                "limit": 10,
            }))
            if response.get("projection_reused") is not True:
                raise RuntimeError("warm recon page did not reuse its advisory projection")
            samples.append(elapsed)
            response_sizes.append(len(canonical(response).encode("utf-8")))
            hydrated_history += project.metrics["records_decoded"] - records_before
            artifact_bytes_hashed += project.metrics["artifact_bytes_hashed"] - bytes_before
            artifact_stats.append(project.metrics.get("artifact_stats", 0) - stats_before)

        report = {
            "schema": "awa-scale-benchmark/v1",
            "fixture": {
                "storage": "local_sqlite",
                "operations": args.operations,
                "evidence": args.evidence,
                "pages": args.pages,
                "page_visits": args.pages,
                "artifact_files": args.evidence + args.pages,
                "seed_seconds": round(seed_seconds, 3),
            },
            "environment": {
                "platform": platform.platform(),
                "python": platform.python_version(),
                "sqlite": sqlite3.sqlite_version,
                "processor": platform.processor() or "unknown",
            },
            "cold_recon_prepare_ms": round(cold_seconds * 1000, 3),
            "warm_recon_prepare": _latency(samples),
            "target_p95_ms": args.p95_ms,
            "p95_passed": _percentile([sample * 1000 for sample in samples], 0.95) < args.p95_ms,
            "warm_history_records_hydrated": hydrated_history,
            "warm_artifact_bytes_hashed": artifact_bytes_hashed,
            "artifact_stats_per_warm_page": sorted(set(artifact_stats)),
            "max_response_bytes": max(response_sizes),
            "response_budget_bytes": 32 * 1024,
            "response_budget_passed": max(response_sizes) <= 32 * 1024,
        }
        if args.keep:
            report["fixture"]["kept_path"] = str(root)
        if args.json:
            print(canonical(report))
        else:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["p95_passed"] and report["response_budget_passed"] else 1
    finally:
        if project is not None:
            project.close()
        if not args.keep:
            temporary.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
