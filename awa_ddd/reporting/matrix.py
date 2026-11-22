"""2.0 multi-dimensional report and matrix export (Chinese, evidence-backed)."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from ..domain.common import digest, stable_id
from ..domain.receipt import current_receipts
from ..domain.repository import Repository
from ..planning import coverage
from ..planning import campaign as campaign_planning
from ..store import EngineError, canonical, contained
from ..reporting_legacy import (
    _report_redaction_selftest,
    publish_report_batch,
    safe_metadata,
    safe_text,
)


def _campaign(project, campaign_id=None):
    repository = Repository(project)
    if campaign_id:
        return repository.get("campaign", campaign_id)
    rows = [row for row in repository.list("campaign", limit=None)[0] if row.get("state") == "active"]
    if not rows:
        raise EngineError("v2_campaign_missing", "No active campaign; start a campaign first")
    return rows[-1]


def _finding_public(row):
    return {
        key: row.get(key)
        for key in (
            "id", "campaign_id", "hypothesis_id", "run_id", "review_id",
            "proof_receipt_id", "review_proof_receipt_id", "title", "mode",
            "severity", "category", "status", "current", "confirmed_scope",
            "proof_scope", "reviewer_assurance", "machine_proof",
            "evidence_ids", "limitations",
        )
        if key in row
    }


def _snapshot(project, campaign_id=None):
    """Freeze campaign, coverage, continuation and current findings together."""
    with project.transaction():
        campaign = _campaign(project, campaign_id)
        result = coverage.compute(project, campaign["id"])
        continuation, bounded_ids = campaign_planning._continuation(
            project, campaign, result)
        findings = [
            _finding_public(row)
            for row in result.get("_current_findings", [])
            if row.get("campaign_id") == campaign["id"]
        ]
    return campaign, result, continuation, bounded_ids, findings


def _matrix_payload(campaign, result, continuation, bounded_ids, findings):
    public = {
        "campaign_id": campaign["id"],
        "universe": safe_metadata(result["universe"]),
        "dimensions": safe_metadata(result["dimensions"]),
        "family_matrix": safe_metadata(result["family_matrix"]),
        "route_matrix": safe_metadata(result["route_matrix"]),
        "consumer_matrix": safe_metadata(result["consumer_matrix"]),
        "known_case_matrix": safe_metadata(result["known_case_matrix"]),
        "known_case_summary": safe_metadata(result["known_case_summary"]),
        "tool_yield": safe_metadata(result["tool_yield"]),
        "finding_summary": safe_metadata(result["finding_summary"]),
        "findings": safe_metadata(findings),
        "delivery": safe_metadata(result["delivery"]),
        "completion_decision": continuation["completion_decision"],
        "continuation": continuation,
        "checkpoint_id": continuation.get("checkpoint_id"),
        "bounded_ids": bounded_ids,
        "denominators": {
            "discovery": (
                "source-backed known routes only; site-wide percentage is null "
                "unless a complete source inventory exists"
            ),
            "consumer": "all registered/imported inputs in this campaign",
            "hypothesis": "all current campaign hypotheses excluding not_applicable",
            "known_case": "per track; tracks never merge",
            "machine_proof": "current findings with a current proof receipt",
        },
        "computed_by": "engine",
    }
    return public


def matrix(project, args=None):
    args = args or {}
    campaign, result, continuation, bounded_ids, findings = _snapshot(
        project, args.get("campaign_id"))
    return _matrix_payload(
        campaign, result, continuation, bounded_ids, findings)


def _completion_decision_is_content_addressed(decision):
    if not isinstance(decision, dict):
        return False
    identity = decision.get("id")
    facts = {
        key: value
        for key, value in decision.items()
        if key not in {"id", "created_at"}
    }
    return (
        isinstance(identity, str)
        and identity.startswith("CD-")
        and identity == "CD-" + digest(facts)
    )


def _completion_acceptance_is_content_addressed(acceptance):
    if not isinstance(acceptance, dict):
        return False
    identity = acceptance.get("id")
    body = {
        key: value
        for key, value in acceptance.items()
        if key != "id"
    }
    return (
        isinstance(identity, str)
        and identity.startswith("CDA-")
        and identity == stable_id("CDA", body)
    )


def _require_completed_campaign_delivery(
        project, campaign, continuation):
    """Validate the immutable CDA and every current fact it freezes."""
    repository = Repository(project)
    delivery = campaign.get("delivery") or {}
    decision = continuation.get("completion_decision") or {}
    acceptance_id = delivery.get("acceptance_id")
    acceptance = (
        repository.get(
            "completion_acceptance", acceptance_id, required=False)
        if isinstance(acceptance_id, str) and acceptance_id
        else None
    )
    frozen = (acceptance or {}).get("completion_decision") or {}
    checkpoint_rows = repository.list_campaign(
        "checkpoint", campaign["id"], limit=None)[0]
    checkpoint = checkpoint_rows[-1] if checkpoint_rows else {}
    current_frontiers = current_receipts(
        project, "frontier", campaign["id"])
    frontier_rounds = {
        (receipt.get("material") or {}).get("round_sha256")
        for receipt, evaluation in current_frontiers
        if evaluation.get("current") is True
        and isinstance(
            (receipt.get("material") or {}).get("round_sha256"), str)
    }
    frontier_ids = sorted({
        receipt["id"]
        for receipt, evaluation in current_frontiers
        if evaluation.get("current") is True
    })
    partial_receipts = [
        row
        for row in repository.list_campaign(
            "completion_acceptance", campaign["id"], limit=None)[0]
        if row.get("state") == "delivered_partial"
        or row.get("reason") == "partial_accepted"
    ]
    mandatory_decision = {
        "schema": "awa-completion/v1",
        "model": "v2",
        "subject_id": campaign["id"],
        "state": "complete_for_declared_scope",
        "can_finalize": True,
        "can_claim_complete": True,
        "finalized": True,
        "checkpoint_current": True,
        "frontier_current": True,
        "material_current": True,
        "source_complete": True,
        "continue_required": False,
    }
    valid = (
        campaign.get("state") == "completed"
        and delivery.get("reason") == "completed"
        and delivery.get("exhausted_authority") is True
        and delivery.get("checkpoint_id") == continuation.get(
            "checkpoint_id")
        and delivery.get("completion_decision_id") == decision.get("id")
        and _completion_decision_is_content_addressed(decision)
        and _completion_decision_is_content_addressed(frozen)
        and frozen == decision
        and all(decision.get(key) == value
                for key, value in mandatory_decision.items())
        and _completion_acceptance_is_content_addressed(acceptance)
        and acceptance.get("campaign_id") == campaign["id"]
        and acceptance.get("state") == "completed"
        and acceptance.get("reason") == "completed"
        and acceptance.get("checkpoint_id")
        == continuation.get("checkpoint_id")
        and acceptance.get("completion_decision_id") == decision.get("id")
        and acceptance.get("exhausted_authority") is True
        and acceptance.get("automatic_stop_allowed") is True
        and not partial_receipts
        and bool(checkpoint)
        and checkpoint.get("id") == continuation.get("checkpoint_id")
        and checkpoint.get("frontier_receipt_ids") == frontier_ids
        and continuation.get("frontier_receipt_ids") == frontier_ids
        and continuation.get("frontier_review_required") is False
        and type(continuation.get("frontier_rounds")) is int
        and continuation["frontier_rounds"] >= 2
        and len(frontier_rounds) >= 2
    )
    if not valid:
        raise EngineError(
            "v2_report_final",
            "Final report requires an immutable completion acceptance whose "
            "content-addressed decision, current checkpoint, two current "
            "frontier receipts and campaign delivery all match",
            {"completion_decision": decision},
        )
    return acceptance


def _ratio(row):
    if row.get("ratio") is None:
        return "N/A"
    return f"{row['numerator']}/{row['denominator']} ({row['ratio'] * 100:.1f}%)"


def _table(headers, rows):
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(cell).replace("|", "\\|") for cell in row) + " |")
    return "\n".join(lines)


def _render(project, campaign, data):
    dims = data["dimensions"]
    completion = data["completion_decision"]
    discovery = dims["discovery"]
    consumer = dims["consumer"]
    hypothesis = dims["hypothesis"]
    machine = dims["machine_proof"]
    lines = []
    lines.append("# AWA-DDD 2.0 评估报告（多维度）")
    lines.append("")
    lines.append("## 1. 执行摘要")
    lines.append("")
    lines.append(f"- 项目：`{project.config.get('project_id')}`；目标：`{safe_text(str(project.config.get('target')), 2048)}`")
    lines.append(f"- Campaign：`{campaign['id']}`；状态：`{campaign['state']}`；交付：`{data['delivery']['delivery_status']}`")
    lines.append(f"- Findings：当前 {data['finding_summary']['current_total']} 条（machine {data['finding_summary']['machine']} / reviewed {data['finding_summary']['reviewed']}）")
    lines.append(f"- 假设：{hypothesis['numerator']}/{hypothesis['denominator']} 已测试；处置率 {hypothesis.get('disposition_rate')}")
    lines.append(f"- 未规划族：{data.get('unplanned_family_count', 0)}；未登记路由：{data.get('unregistered_route_count', 0)}")
    lines.append(
        f"- CompletionDecision：`{completion['id']}`；状态 `{completion['state']}`；"
        f"可最终交付 `{completion['can_finalize']}`；已终结 `{completion['finalized']}`")
    lines.append(
        f"- 阻塞原因：`{', '.join(completion.get('reason_codes') or []) or '无'}`；"
        f"checkpoint：`{data.get('checkpoint_id')}`")
    lines.append(
        f"- 耗尽权限：`{data['delivery']['exhausted_authority']}`"
        "（partial_accepted 不获得耗尽权限）")
    lines.append("")
    lines.append("## 2. 攻击面宇宙")
    lines.append("")
    universe = data["universe"]
    lines.append(f"- Universe `{universe.get('id')}`，快照 `{universe.get('snapshot_hash', '')[:16]}`，来源完整性：`{universe.get('completeness_level')}`")
    lines.append(f"- 计数：{universe.get('unknown_counts')}")
    lines.append("- 说明：Universe 只代表有来源的已知范围；没有可信完整来源时不输出全站发现百分比。")
    lines.append("")
    lines.append("## 3. 多维覆盖矩阵")
    lines.append("")
    lines.append(_table(["维度", "分子/分母", "状态", "未知范围"], [
        ["Discovery", _ratio(discovery), discovery["status"], discovery["unknown_extent"]],
        ["Consumer", _ratio(consumer), consumer["status"], consumer["unknown_extent"]],
        ["Hypothesis", _ratio(hypothesis), hypothesis["status"], hypothesis["unknown_extent"]],
        ["Machine proof", _ratio(machine), machine["status"], machine["unknown_extent"]],
        ["Known case（按轨道）", ", ".join(_ratio(row) for row in dims["known_case"]), "分轨", "不得合并分母"],
    ]))
    lines.append("")
    lines.append(_table(["族", "状态", "总数", "分布"], [
        [row["test_family"], row["status"], row["total"], row.get("counts", {})] for row in data["family_matrix"]
    ]))
    lines.append("")
    lines.append("## 4. Known Case 对照")
    lines.append("")
    lines.append(_table(["轨道", "总数", "已验证", "报告", "受阻", "未规划"], [
        [track, bucket["total"], bucket["verified"], bucket["reported"], bucket["blocked"], bucket["unplanned"]]
        for track, bucket in data["known_case_summary"]["by_track"].items()
    ]))
    lines.append("")
    lines.append("## 5. Findings")
    lines.append("")
    line = _table(["标题", "模式", "严重度", "假设", "证明凭据", "证据"], [
        [safe_text(row.get("title", ""), 200), row.get("mode"), row.get("severity"),
         row.get("hypothesis_id"), row.get("proof_receipt_id"),
         ", ".join(row.get("evidence_ids", [])[:3])]
        for row in data.get("findings", [])
    ])
    lines.append(line if data.get("findings") else "当前无 finding；hint/candidate 不是 finding。")
    lines.append("")
    lines.append("## 6. 未测/受阻清单")
    lines.append("")
    lines.append(_table(["类型", "数量"], [[gap["kind"], gap["count"]] for gap in data["delivery"]["remaining"]]) if data["delivery"]["remaining"] else "无未测/受阻项（仅在当前登记范围内）。")
    lines.append("")
    lines.append("## 7. 工具能力与调用")
    lines.append("")
    lines.append(f"- Tool yield：{data.get('tool_yield')}")
    lines.append("")
    lines.append("## 8. 方法与边界")
    lines.append("")
    lines.append("- 报告由引擎从当前实体快照计算；Caller 不能自填分子/分母。")
    lines.append("- 所有百分比携带分母；machine proof 与 reviewed detection 分栏；hint 不是 finding。")
    lines.append("- Findings 仅包含本 Campaign 中 proof receipt 仍为 current 的记录；reviewed 不是 machine proof。")
    lines.append("- 完成、交付和最终报告共用同一个 CompletionDecision、checkpoint 与当前证据。")
    lines.append("- scope/exclude、身份/资源、写授权与 fixture 边界保持原样；本报告不发送目标请求。")
    return "\n".join(lines)


def build_v2_report(project, output_dir=None, *, stage="draft", campaign_id=None, profile="full"):
    if profile not in {"full", "technical", "executive", "both", "repro"}:
        raise EngineError(
            "v2_report_stage",
            "profile must be full, technical, executive, both or repro",
        )
    if stage not in {"draft", "final"}:
        raise EngineError(
            "v2_report_stage", "stage must be draft or final")

    campaign, result, continuation, bounded_ids, findings = _snapshot(
        project, campaign_id)
    data = _matrix_payload(
        campaign, result, continuation, bounded_ids, findings)
    data.update({
        key: value
        for key, value in {
            "unplanned_family_count": result.get("unplanned_family_count"),
            "unregistered_route_count": result.get("unregistered_route_count"),
        }.items()
    })
    if stage == "final":
        delivery = campaign.get("delivery") or {}
        decision = data["completion_decision"]
        if campaign.get("state") != "completed" \
                or delivery.get("exhausted_authority") is not True:
            raise EngineError(
                "v2_report_final",
                "Final report requires a completed campaign with exhaustion "
                "authority",
            )
        if decision.get("can_finalize") is not True \
                or decision.get("can_claim_complete") is not True \
                or decision.get("finalized") is not True \
                or decision.get("checkpoint_current") is not True:
            raise EngineError(
                "v2_report_final",
                "Final report requires the shared current CompletionDecision",
                {"completion_decision": decision},
            )
        if delivery.get("completion_decision_id") != decision.get("id") \
                or delivery.get("checkpoint_id") != data.get("checkpoint_id"):
            raise EngineError(
                "v2_report_final",
                "Final report is not bound to the delivered checkpoint and "
                "CompletionDecision",
                {"completion_decision": decision},
            )
        _require_completed_campaign_delivery(
            project, campaign, continuation)

    text = _render(project, campaign, data)
    _report_redaction_selftest(project, text)
    matrix_text = json.dumps(
        safe_metadata(data),
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
        allow_nan=False,
    )
    report_bytes = text.encode("utf-8")
    matrix_bytes = matrix_text.encode("utf-8")
    result = publish_report_batch(
        project,
        Path(output_dir).expanduser().resolve() if output_dir else None,
        files={
            "report.md": report_bytes,
            "matrix.json": matrix_bytes,
        },
        manifest={
            "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
            "matrix_sha256": hashlib.sha256(matrix_bytes).hexdigest(),
            "campaign_id": campaign["id"],
            "stage": stage,
            "profile": profile,
            "checkpoint_id": data.get("checkpoint_id"),
            "completion_decision": data["completion_decision"],
            "delivery": safe_metadata(data["delivery"]),
            "dimensions": safe_metadata(data["dimensions"]),
        },
    )
    files = result["files"]
    return {
        "report": str(files["report.md"]),
        "matrix": str(files["matrix.json"]),
        "manifest": str(result["manifest"]),
        "report_sha256": result["sha256"]["report.md"],
        "matrix_sha256": result["sha256"]["matrix.json"],
        "manifest_sha256": result["manifest_sha256"],
        "stage": stage,
        "profile": profile,
        "checkpoint_id": data.get("checkpoint_id"),
        "completion_decision": data["completion_decision"],
        "delivery": data["delivery"],
        "dimensions": data["dimensions"],
        "bounded_ids": bounded_ids,
        "generated_at": result["generated_at"],
        "notice": (
            "Draft output does not grant exhaustion authority."
            if stage == "draft"
            else "Final delivery is bound to the shared current "
                 "CompletionDecision and delivered checkpoint."
        ),
    }


def compare(project, args):
    repository = Repository(project)
    campaign_ids = args.get("campaign_ids") or []
    if not campaign_ids:
        rows = repository.list("campaign", limit=2)[0]
        campaign_ids = [row["id"] for row in rows]
    if not isinstance(campaign_ids, list) \
            or not all(isinstance(value, str) and value
                       for value in campaign_ids):
        raise EngineError(
            "v2_report_compare",
            "campaign_ids must be an array of concrete campaign IDs",
        )
    if not campaign_ids or len(set(campaign_ids)) != len(campaign_ids):
        raise EngineError(
            "v2_report_compare",
            "Compare requires one or two distinct campaigns",
        )
    if len(campaign_ids) < 1:
        raise EngineError("v2_report_compare", "Compare requires at least one campaign")
    result = []
    for campaign_id in campaign_ids[:2]:
        campaign, coverage_result, continuation, bounded_ids, findings = (
            _snapshot(project, campaign_id)
        )
        result.append({
            "campaign_id": campaign["id"],
            "dimensions": {
                name: safe_metadata(coverage_result["dimensions"][name])
                for name in (
                    "discovery", "consumer", "hypothesis", "machine_proof")
            },
            "known_case": safe_metadata(
                coverage_result["known_case_summary"]),
            "unplanned_family_count": coverage_result[
                "unplanned_family_count"],
            "finding_summary": safe_metadata(
                coverage_result["finding_summary"]),
            "current_finding_ids": [row["id"] for row in findings],
            "completion_decision": continuation["completion_decision"],
            "checkpoint_id": continuation.get("checkpoint_id"),
        })
    return {"campaigns": result,
            "notice": "Rates use different denominators; compare only within the same track and unit. Hint-assisted and blind tracks are not merged."}
