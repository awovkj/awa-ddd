"""External provider adapter: import receipts without laundering them into proof."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..domain.common import fail, text, utc_now
from ..domain.repository import Repository
from ..store import EngineError, canonical


MAX_RECEIPT = 1024 * 1024


def record(project, args):
    """Store a local external result as unverified provenance, never a finding."""
    campaign_id = text(args["campaign_id"], "campaign_id", maximum=128)
    hypothesis_id = text(args["hypothesis_id"], "hypothesis_id", maximum=128)
    repository = Repository(project)
    repository.get("campaign", campaign_id)
    hypothesis = repository.get("hypothesis", hypothesis_id)
    path = Path(args["path"]).expanduser().resolve()
    if not path.is_file() or path.stat().st_size > MAX_RECEIPT:
        fail("v2_external_receipt", "External receipt must be a local file under 1 MiB")
    raw = path.read_bytes()
    try:
        document = json.loads(raw.decode("utf-8-sig", errors="strict"))
    except (UnicodeError, json.JSONDecodeError):
        fail("v2_external_receipt", "External receipt must be UTF-8 JSON")
    if not isinstance(document, dict):
        fail("v2_external_receipt", "External receipt must be an object")
    digest_value = hashlib.sha256(canonical(document).encode("utf-8")).hexdigest()
    artifact_path, stored_digest = project.artifact("EXT-" + digest_value[:24], document)
    run_row = {
        "id": "RUN2-EXT-" + digest_value[:24],
        "schema": 2,
        "campaign_id": campaign_id,
        "hypothesis_id": hypothesis_id,
        "recipe_id": None,
        "mode": "observe",
        "status": "evaluated",
        "provider": text(args.get("provider", "local_script"), "provider", maximum=64),
        "verification_level": "unverified_external",
        "evidence_ids": [],
        "external_receipt": {"artifact_path": artifact_path, "sha256": stored_digest,
                             "source_path": str(path)},
        "evaluation": {"outcome": "unverified", "finding_allowed": False,
                       "limitations": ["Local script output is provenance, not managed execution or proof."]},
        "effect": {"kind": "unknown", "unknown": True, "reconciled": False},
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }
    repository.add("run", run_row, immutable=False)
    return {"run": run_row, "usable_for_confirmation": False,
            "notice": "Preserved as an unverified external receipt. Reconcile actual effects before any new write; this never becomes a managed finding."}


def run_external(project, args):
    """Run a narrow existing read-only adapter and store its tool run as provenance."""
    adapter = args.get("adapter")
    if adapter not in {"sqlmap", "yakit"}:
        fail("v2_external", "run_external supports sqlmap or yakit read-only profiles")
    from .. import external
    handler = external.sqlmap_run if adapter == "sqlmap" else external.yakit_replay
    result = handler(project, args)
    run_id = result.get("run_id") or (result.get("run") or {}).get("id")
    return {"adapter": adapter, "tool_run_id": run_id, "result": result,
            "usable_for_confirmation": False,
            "notice": "External adapter output remains unverified candidate material; use review.evidence only after independent evidence."}
