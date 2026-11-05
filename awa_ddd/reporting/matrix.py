"""2.0 multi-dimensional report and matrix export (Chinese, evidence-backed)."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from ..domain.repository import Repository
from ..planning import coverage
from ..store import EngineError, canonical, contained
from ..reporting_legacy import safe_text


def _campaign(project, campaign_id=None):
    repository = Repository(project)
    if campaign_id:
        return repository.get("campaign", campaign_id)
    rows = [row for row in repository.list("campaign", limit=None)[0] if row.get("state") == "active"]
    if not rows:
        raise EngineError("v2_campaign_missing", "No active campaign; start a campaign first")
    return rows[-1]


def matrix(project, args=None):
    args = args or {}
    campaign = _campaign(project, args.get("campaign_id"))
    result = coverage.compute(project, campaign["id"])
    return {
        "campaign_id": campaign["id"],
        "universe": result["universe"],
        "dimensions": result["dimensions"],
        "family_matrix": result["family_matrix"],
        "route_matrix": result["route_matrix"],
        "consumer_matrix": result["consumer_matrix"],
        "known_case_matrix": result["known_case_matrix"],
        "known_case_summary": result["known_case_summary"],
        "tool_yield": result["tool_yield"],
        "finding_summary": result["finding_summary"],
        "delivery": result["delivery"],
        "denominators": {
            "discovery": "source-backed known routes only; site-wide percentage is null unless a complete source inventory exists",
            "consumer": "all registered/imported inputs",
            "hypothesis": "all current hypotheses excluding not_applicable",
            "known_case": "per track; tracks never merge",
            "machine_proof": "current findings; evidence quality only",
        },
        "computed_by": "engine",
    }


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
    lines.append(f"- 耗尽可能：`{data['delivery']['exhausted_authority']}`（partial_accepted 不获得耗尽权限）")
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
    line = _table(["标题", "模式", "严重度", "假设", "证据"], [
        [safe_text(row.get("title", ""), 200), row.get("mode"), row.get("severity"),
         row.get("hypothesis_id"), ", ".join(row.get("evidence_ids", [])[:3])]
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
    lines.append("- scope/exclude、身份/资源、写授权与 fixture 边界保持原样；本报告不发送目标请求。")
    return "\n".join(lines)


def build_v2_report(project, output_dir=None, *, stage="draft", campaign_id=None, profile="full"):
    if profile not in {"full", "technical", "executive", "both", "repro"}:
        raise EngineError("v2_report_stage", "profile must be full, technical, executive, both or repro")
    campaign = _campaign(project, campaign_id)
    data = coverage.compute(project, campaign["id"])
    findings = [row for row in Repository(project).list("finding", limit=None)[0] if row.get("current")]
    data["findings"] = findings
    if stage == "final":
        if campaign.get("state") != "completed" or not (campaign.get("delivery") or {}).get("exhausted_authority"):
            raise EngineError("v2_report_final", "Final report requires a completed campaign with exhaustion authority")
    elif stage != "draft":
        raise EngineError("v2_report_stage", "stage must be draft or final")
    folder = Path(output_dir).expanduser().resolve() if output_dir else (project.base / "reports")
    folder.mkdir(parents=True, exist_ok=True)
    if not folder.is_dir():
        raise EngineError("v2_report_path", "Report output must be a directory")
    stamp = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    prefix = f"awa-v2-{stamp}-{campaign['id'][-8:]}"
    report_path = folder / (prefix + ".md")
    matrix_path = folder / (prefix + ".matrix.json")
    manifest_path = folder / (prefix + ".manifest.json")
    text = _render(project, campaign, data)
    matrix_text = json.dumps({key: value for key, value in data.items() if key != "findings"},
                             ensure_ascii=False, sort_keys=True, indent=2)
    report_bytes, matrix_bytes = text.encode("utf-8"), matrix_text.encode("utf-8")
    report_path.write_bytes(report_bytes)
    matrix_path.write_bytes(matrix_bytes)
    manifest = {
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        "matrix_sha256": hashlib.sha256(matrix_bytes).hexdigest(),
        "campaign_id": campaign["id"],
        "stage": stage,
        "profile": profile,
        "delivery": data["delivery"],
        "dimensions": data["dimensions"],
        "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
    }
    manifest_path.write_bytes(json.dumps(manifest, ensure_ascii=False, sort_keys=True).encode("utf-8"))
    return {"report": str(report_path), "matrix": str(matrix_path), "manifest": str(manifest_path),
            "report_sha256": manifest["report_sha256"], "matrix_sha256": manifest["matrix_sha256"],
            "stage": stage, "profile": profile, "delivery": data["delivery"], "dimensions": data["dimensions"],
            "notice": "Draft output does not grant exhaustion authority." if stage == "draft" else "Final delivery is bound to the completed campaign."}


def compare(project, args):
    repository = Repository(project)
    campaign_ids = args.get("campaign_ids") or []
    if not campaign_ids:
        rows = repository.list("campaign", limit=2)[0]
        campaign_ids = [row["id"] for row in rows]
    if len(campaign_ids) < 1:
        raise EngineError("v2_report_compare", "Compare requires at least one campaign")
    result = []
    for campaign_id in campaign_ids[:2]:
        row = coverage.compute(project, campaign_id)
        result.append({
            "campaign_id": campaign_id,
            "dimensions": {name: row["dimensions"][name] for name in ("discovery", "consumer", "hypothesis", "machine_proof")},
            "known_case": row["known_case_summary"],
            "unplanned_family_count": row["unplanned_family_count"],
            "finding_summary": row["finding_summary"],
        })
    return {"campaigns": result,
            "notice": "Rates use different denominators; compare only within the same track and unit. Hint-assisted and blind tracks are not merged."}
