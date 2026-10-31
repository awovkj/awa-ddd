"""Unresolved discovery线索的生命周期：列出、检查、关联到操作、显式处置。

M3-04 的关闭条件：未解析线索不会因为来源文件变化或静默丢弃而消失，而是
保留稳定 ID、可分页读取、可被显式关联到 Operation/Input，或被显式驳回并
保留理由。这里没有任何自动确认路径：candidate 永远不是证据。
"""
from __future__ import annotations

import hashlib

from .store import EngineError, canonical, now

# 候选的处置状态。unverified 是唯一可被关联的状态；其余为终态。
UNVERIFIED = "unverified"
LINKED = "linked"
DISMISSED = "dismissed"

STATUSES = (UNVERIFIED, LINKED, DISMISSED)

MAX_PAGE = 500


def _primary_source(candidate):
    """发现路径给出 sources 列表，导入路径给出单个 source；两者都可定位。"""
    if isinstance(candidate.get("source"), dict):
        return candidate["source"]
    sources = candidate.get("sources")
    if isinstance(sources, list) and sources and isinstance(sources[0], dict):
        return sources[0]
    return {}


def candidate_id(candidate):
    """稳定身份：同一来源摘要 + 同一定位得到同一 ID，重复导入不增殖。"""
    if not isinstance(candidate, dict):
        raise EngineError("candidate", "Candidate must be an object")
    source = _primary_source(candidate)
    key = [source.get("sha256"), source.get("locator"), candidate.get("kind"),
           candidate.get("url"), candidate.get("method"), candidate.get("name"),
           candidate.get("locator"), candidate.get("legacy_id")]
    if not any(key):
        raise EngineError("candidate_identity", "Candidate needs a source digest or locator")
    return "C-" + hashlib.sha256(canonical(key).encode()).hexdigest()[:24]


def _paging(args):
    offset = args.get("offset", 0)
    limit = args.get("limit", 50)
    if type(offset) is not int or offset < 0:
        raise EngineError("pagination", "offset must be a nonnegative integer")
    if type(limit) is not int or not 1 <= limit <= MAX_PAGE:
        raise EngineError("pagination", "limit must be 1..%d" % MAX_PAGE)
    return offset, limit


def _summary(candidate):
    """列表视图：省略完整输入树和来源正文，只留可判定身份与状态的字段。"""
    return {k: candidate[k] for k in
            ("id", "kind", "status", "url", "method", "protocol", "name",
             "category", "severity", "origin", "operation_id", "legacy_id",
             "reason", "created_at", "updated_at")
            if k in candidate}


def list_candidates(project, args):
    """只读分页。默认只返回仍未处置的线索，便于模型继续处理而不是回看历史。"""
    offset, limit = _paging(args)
    status = args.get("status", UNVERIFIED)
    if status not in STATUSES and status != "any":
        raise EngineError("candidate_status", "status must be one of unverified/linked/dismissed/any")
    kind = args.get("kind")
    rows = []
    for candidate in project.list("candidate"):
        current = candidate.get("status", UNVERIFIED)
        if status != "any" and current != status:
            continue
        if isinstance(kind, str) and kind and candidate.get("kind") != kind:
            continue
        rows.append(candidate)
    rows.sort(key=lambda item: (item.get("created_at", ""), item.get("id", "")))
    total = len(rows)
    window = rows[offset:offset + limit]
    counts = {name: 0 for name in STATUSES}
    for candidate in project.list("candidate"):
        counts[candidate.get("status", UNVERIFIED)] = counts.get(candidate.get("status", UNVERIFIED), 0) + 1
    return {"candidates": [_summary(item) for item in window], "candidate_total": total,
            "offset": offset, "next_offset": offset + limit if offset + limit < total else None,
            "counts": counts,
            "limitations": ["An unresolved candidate is a discovery线索, not验证过的攻击面或漏洞。"]}


def inspect_candidate(project, args):
    """读取单条线索的完整记录，用于判断能否关联到已登记操作。"""
    candidate = project.get("candidate", args["candidate_id"])
    return {"candidate": candidate,
            "operation": project.get("operation", candidate["operation_id"], required=False)
            if candidate.get("operation_id") else None}


def _assert_operation_inputs(project, operation_id, location, selector):
    """关联到具体输入时必须真的存在于该操作，避免把线索挂到不存在的字段上。"""
    operation = project.get("operation", operation_id)
    for entry in operation.get("inputs", []):
        if entry.get("location") == location and entry.get("selector") == selector:
            return operation
    raise EngineError("candidate_input",
                      "The linked input must already be registered on that operation")


def link_candidate(project, args):
    """把未解析线索记录成对应 Operation（可选到具体 Input）的关联。

    只建立来源关系，不产生输入、不关闭义务、不生成证据：语义提升仍然要求
    调用方显式 register 输入或执行实验。
    """
    with project.transaction():
        candidate = project.get("candidate", args["candidate_id"])
        if candidate.get("status") == DISMISSED:
            raise EngineError("candidate_dismissed", "A dismissed candidate must be reopened explicitly")
        operation_id = args["operation_id"]
        location, selector = args.get("input_location"), args.get("input_selector")
        if (location is None) != (selector is None):
            raise EngineError("candidate_input", "Supply both input_location and input_selector, or neither")
        operation = project.get("operation", operation_id)
        if location is not None and selector is not None:
            operation = _assert_operation_inputs(project, operation_id, location, selector)
        if candidate.get("url") and operation.get("url") and candidate["url"] != operation["url"]:
            raise EngineError("candidate_scope",
                              "The operation URL differs from the线索 URL; register the intended operation first")
        previous = candidate.get("operation_id")
        candidate.update(status=LINKED, operation_id=operation_id, updated_at=now(),
                         link={"operation_id": operation_id,
                               "input_location": location, "input_selector": selector,
                               "linked_at": now(), "previous_operation_id": previous})
        project.put("candidate", candidate)
        project.event("candidate.linked", {"candidate_id": candidate["id"],
                                           "operation_id": operation_id,
                                           "input_selector": selector})
        return candidate


def dismiss_candidate(project, args):
    """显式驳回并保留理由。驳回不是“已测”，不会影响任何覆盖分母。"""
    reason = args.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise EngineError("candidate_reason", "Dismissal requires a reason")
    with project.transaction():
        candidate = project.get("candidate", args["candidate_id"])
        if candidate.get("status") == LINKED:
            raise EngineError("candidate_linked",
                              "A linked candidate is part of the operation lineage; unlink is not supported")
        candidate.update(status=DISMISSED, reason=reason.strip()[:1000], updated_at=now())
        project.put("candidate", candidate)
        project.event("candidate.dismissed", {"candidate_id": candidate["id"],
                                              "reason": candidate["reason"]})
        return candidate


def reopen_candidate(project, args):
    """来源文件更新后允许重新打开，但必须给出依据。"""
    reason = args.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise EngineError("candidate_reason", "Reopening requires a reason")
    with project.transaction():
        candidate = project.get("candidate", args["candidate_id"])
        candidate.update(status=UNVERIFIED, reason=reason.strip()[:1000], updated_at=now())
        candidate.pop("link", None)
        project.put("candidate", candidate)
        project.event("candidate.reopened", {"candidate_id": candidate["id"]})
        return candidate


def store_candidate(project, candidate, *, default_status=UNVERIFIED):
    """导入路径共用的写入入口：稳定 ID、幂等、不覆盖已有处置。

    返回 (id, created)。已存在的线索只更新来源集合，保留人工处置状态。
    """
    identity = candidate_id(candidate)
    existing = project.get("candidate", identity, required=False)
    if existing is not None:
        merged = dict(existing)
        seen = {canonical(source) for source in merged.get("sources", [])
                if isinstance(source, dict)}
        sources = list(merged.get("sources", []))
        for source in candidate.get("sources", []) or []:
            if isinstance(source, dict) and canonical(source) not in seen:
                seen.add(canonical(source))
                sources.append(source)
        if sources:
            merged["sources"] = sources[:256]
        merged["updated_at"] = now()
        project.put("candidate", merged)
        return identity, False
    record = dict(candidate)
    record["id"] = identity
    record.setdefault("status", default_status)
    record.setdefault("created_at", now())
    record["updated_at"] = now()
    project.put("candidate", record, create_only=True)
    return identity, True
