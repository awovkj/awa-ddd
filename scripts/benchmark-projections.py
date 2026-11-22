"""Repeatable offline query benchmark with private synthetic .invalid fixtures.

No target is contacted, no proof is generated, and existing project data is never
opened. Cold rebuilds deliberately exercise the full strong evaluator; warm
pages measure advisory reuse, file-stat checks, entity hydration and bytes out.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import sys
import tempfile
import time
from unittest.mock import patch
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from awa_ddd import __version__, browser, completeness, engine, read_model, reconnaissance, source_inventory, workflow
from awa_ddd.fingerprint import core_manifest
from awa_ddd.lineage import policy_digest, policy_snapshot
from awa_ddd.store import Project, canonical, contained, now


def write_result(path, result):
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name("." + path.name + "." + result["run_id"] + ".tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write((json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def metrics_delta(project, before):
    return {key: value - before.get(key, 0) for key, value in project.metrics.items()}


def measure(project, query, iterations):
    latency, sizes, decoded, hashed, stats, directory_reads = [], [], [], [], [], []
    result = {}
    for _ in range(iterations):
        before = dict(project.metrics)
        start = time.perf_counter()
        result = query()
        latency.append((time.perf_counter() - start) * 1000)
        sizes.append(len(canonical(result).encode("utf-8")))
        delta = metrics_delta(project, before)
        decoded.append(delta.get("records_decoded", 0))
        hashed.append(delta.get("artifact_bytes_hashed", 0) + delta.get("material_bytes_hashed", 0))
        stats.append(delta.get("artifact_stats", 0))
        directory_reads.append(delta.get("artifact_directory_reads", 0))
    ordered = sorted(latency)
    return {"iterations": iterations, "p50_ms": round(statistics.median(latency), 3),
            "p95_ms": round(ordered[math.ceil(len(ordered) * 0.95) - 1], 3),
            "max_ms": round(max(latency), 3), "max_bytes_out": max(sizes),
            "max_records_decoded": max(decoded), "max_artifact_bytes_hashed": max(hashed),
            "max_artifact_stats": max(stats), "max_artifact_directory_reads": max(directory_reads),
            "largest_fields_bytes": dict(sorted(((key, len(canonical(value).encode("utf-8")))
                                                   for key, value in result.items()), key=lambda row: row[1], reverse=True)[:5])}


def seed(project, root, operation_total, evidence_total, page_total):
    operations = []
    with project.transaction():
        for index in range(operation_total):
            operations.append(engine.register_operation(project, {
                "url": "http://fixture.invalid/items/" + str(index), "method": "GET", "auth": "public",
                "inputs": [{"name": "q", "location": "query", "consumer": "business_input", "test_families": ["generic"]}]}))
        engine.build_plan(project)
        for index in range(page_total):
            browser.register_page(project, {"page_id": "PG-benchmark-" + str(index),
                "url": "http://fixture.invalid/pages/" + str(index), "name": "Synthetic page " + str(index)})
    evidence_folder = contained(project.base / "evidence", project.base)
    evidence_folder.mkdir()
    body = canonical({"count": 1}).encode("utf-8")
    stamp = now()
    with project.transaction():
        for index in range(evidence_total):
            operation = operations[index % operation_total]
            identity = "E-benchmark-" + str(index)
            artifact = {"request": {"url": operation["url"] + "?q=value-" + str(index // operation_total),
                                     "method": "GET", "headers": {}, "body_base64": ""},
                        "response": {"status": 200, "headers": [["content-type", "application/json"]],
                                     "length": len(body), "body_base64": base64.b64encode(body).decode("ascii")},
                        "complete": True, "started_at": stamp, "completed_at": stamp}
            data = canonical(artifact).encode("utf-8")
            path = evidence_folder / (identity + ".json")
            path.write_bytes(data)
            project.put("evidence", {"id": identity, "kind": "http", "operation_id": operation["id"],
                "operation_signature": engine.operation_signature(operation), "policy_digest": policy_digest(operation),
                "policy_snapshot": policy_snapshot(operation), "complete": True, "trust": "observed",
                "actor_id": None, "session_id": None, "resource_id": None, "session_generation": None,
                "status_code": 200, "response_bytes": len(body), "auth_mode": "none",
                "artifact_path": path.relative_to(project.base).as_posix(), "sha256": hashlib.sha256(data).hexdigest(),
                "created_at": stamp})
    source_path = root / "synthetic-openapi.json"
    source_path.write_text(canonical({"openapi": "3.0.3", "info": {"title": "Synthetic benchmark", "version": "1"},
        "servers": [{"url": "http://fixture.invalid"}], "paths": {
            "/items/" + str(index): {"get": {"parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}],
                "responses": {"200": {"description": "Synthetic fixture"}}}} for index in range(operation_total)}}), encoding="utf-8")
    imported = source_inventory.import_source(project, {"path": str(source_path), "format": "openapi", "mode": "preview", "limit": 1})
    return imported["source_id"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operations", type=int, default=2000)
    parser.add_argument("--evidence", type=int, default=20000)
    parser.add_argument("--pages", type=int, default=500)
    parser.add_argument("--iterations", type=int, default=25)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.operations <= 10000 or not 0 <= args.evidence <= 100000 or not 0 <= args.pages <= 10000 \
            or not 5 <= args.iterations <= 100:
        parser.error("Use bounded positive fixture counts and 5..100 iterations")
    manifest = core_manifest()
    result = {"schema": "awa-query-benchmark/v1", "run_id": uuid4().hex, "result": "running",
              "generated_at": now(), "version": __version__,
              "core_manifest_sha256": manifest["sha256"], "core_file_total": manifest["file_total"],
              "benchmark_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "environment": {"platform": platform.system(), "python": platform.python_version(),
                              "machine": platform.machine(), "cpu_count": os.cpu_count()},
              "scale": {"operations": args.operations, "evidence": args.evidence, "pages": args.pages},
              "network_requests": 0, "proofs_created": 0, "fixture": "synthetic_unassessed",
              "limitations": ["Warm projections are advisory and still inspect fresh file metadata across retained materials; sibling enumeration reduces filesystem calls.",
                              "Cold/invalidated rebuilds still run the full evaluator; this is not per-operation recomputation.",
                              "Cold rebuilds have one sample each; their p95 field is that sample, not a stable percentile estimate.",
                              "Query timings exclude process startup, fixture creation, JSON serialization and cleanup."]}
    write_result(args.output, result)
    with tempfile.TemporaryDirectory(prefix="awa-query-benchmark-") as temporary, \
            patch.object(engine, "request", side_effect=AssertionError("benchmark must be offline")):
        root = Path(temporary).resolve()
        engine.create_project(root, {"project_id": "benchmark", "target": "http://fixture.invalid"})
        with Project(root, "benchmark") as project:
            seeded_at = time.perf_counter()
            source_id = seed(project, root, args.operations, args.evidence, args.pages)
            result["fixture_setup_seconds"] = round(time.perf_counter() - seeded_at, 3)
            print("Synthetic fixture created; measuring cold evaluator and query projections.", flush=True)
            result["cold"] = {"project.projection": measure(project, lambda: read_model.maintain(project, {"mode": "rebuild"}), 1),
                              "surface.recon": measure(project, lambda: reconnaissance.profile(project, {"mode": "aggregate", "limit": 10}), 1)}
            queries = {"project.status": lambda: workflow.project_status(project, {"limit": 10}),
                       "plan.next": lambda: workflow.next_work(project, {"limit": 10}),
                       "plan.next.compact": lambda: workflow.next_work(project, {"limit": 10, "compact": True}),
                       "plan.audit": lambda: completeness.audit(project, {"limit": 10}),
                       "surface.sources": lambda: source_inventory.list_sources(project, {"source_id": source_id, "limit": 10}),
                       "surface.recon": lambda: reconnaissance.profile(project, {"mode": "aggregate", "limit": 10}),
                       "page.list": lambda: project.list_page("page", limit=10)}
            result["warm"] = {}
            for name, query in queries.items():
                query()
                result["warm"][name] = measure(project, query, args.iterations)
                print(name + ": " + canonical(result["warm"][name]), flush=True)
            result["recommended_pages"] = {}
            recommended = {
                "project.status": lambda: workflow.project_status(project, {"limit": 3, "method_limit": 1}),
                "plan.next": lambda: workflow.next_work(project, {"limit": 3, "parameter_limit": 3}),
                "plan.next.compact": lambda: workflow.next_work(project, {"limit": 3, "parameter_limit": 3, "compact": True}),
                "plan.audit": lambda: completeness.audit(project, {"limit": 3, "parameter_limit": 3}),
            }
            for name, query in recommended.items():
                result["recommended_pages"][name] = measure(project, query, args.iterations)
                print("recommended " + name + ": " + canonical(result["recommended_pages"][name]), flush=True)
            result["project_counts"] = {kind: project.connection.execute("SELECT COUNT(*) FROM entities WHERE kind=?", (kind,)).fetchone()[0]
                                        for kind in ("operation", "evidence", "page", "decision", "finding", "run")}
    if core_manifest()["sha256"] != manifest["sha256"] \
            or hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != result["benchmark_script_sha256"]:
        raise RuntimeError("Production sources changed during the benchmark; rerun after the source freeze")
    result.update(result="passed", finished_at=now(), source_unchanged=True, fixture_cleanup_succeeded=True)
    write_result(args.output, result)
    print("Benchmark result: " + str(args.output.resolve()), flush=True)


if __name__ == "__main__":
    main()
