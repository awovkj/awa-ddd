"""Offline Playwright selection and handoff; hints never authorize or prove tests."""
from __future__ import annotations

import re

from .reporting import safe_url
from .scope import normalize_url, origin, require_scope
from .store import EngineError


SUMMARY_FIELDS = ("required_total", "assisted_total", "call_needed_total", "invoke_now_total",
                  "blocked_total", "native_unsupported_total", "followup_total", "task_total")
_BACKEND_FAMILIES = frozenset({"sql_injection", "ssrf", "xxe", "path_traversal", "command_injection",
                               "template_injection", "deserialization"})
_RUNTIME_SINKS = ("innerhtml", "htmlrender", "domrender", "domxss", "clientroute", "clientstate", "routeguard",
                  "postmessage", "localstorage", "sessionstorage", "webstorage", "browserdom")
_UI_CONTEXTS = ("uiworkflow", "formworkflow", "multistep", "uploadpreview", "checkoutui", "roleui",
                "dynamicnonce", "clientsignature", "frontendtoken", "browserrequest", "spaworkflow", "businesslogicui")
_MECHANISMS = (
    (("csrf", "cors"), "cross_origin_browser_semantics", ("cross_origin_browser_semantics", "native_cookie_semantics", "script_evaluation")),
    (("samesite", "httponly", "securecookie", "cookiejar", "automaticcredentials", "cookiesecurity", "cookieattributes"),
     "browser_cookie_semantics", ("native_cookie_semantics", "script_evaluation")),
    (("clickjacking", "frameancestors", "xframeoptions"), "browser_framing", ("cross_origin_browser_semantics",)),
    (("oauth", "oidc", "loginredirect"), "browser_auth_flow", ("redirect_chain", "multi_context")),
)


def _entry(operation, gap):
    return next((item for item in operation.get("inputs", [])
                 if item.get("location") == gap.get("input_location")
                 and item.get("selector", item.get("name")) == gap.get("input_selector")
                 and item.get("schema_branch") == gap.get("schema_branch")), {})


def classify(operation, gap=None, entry=None, linked_pages=()):
    """Use declared hypotheses/context, never a parameter name or imported command."""
    gap = gap or {}
    entry = _entry(operation, gap) if entry is None else entry
    family = gap.get("hypothesis_family") or gap.get("test_family")
    sink = re.sub(r"[^a-z0-9]", "", str(entry.get("consumer", "")).lower())
    reasons, unsupported = [], []
    required = family == "xss" or family is None and "xss" in entry.get("test_families", [])
    if required:
        reasons.append("xss_application_runtime")
    if family not in _BACKEND_FAMILIES:
        if any(token in sink for token in _RUNTIME_SINKS):
            required = True
            reasons.append("declared_browser_consumer")
            if any(token in sink for token in ("postmessage", "localstorage", "sessionstorage", "webstorage")):
                unsupported.extend(("script_evaluation", "multi_context"))
        for tokens, reason, limits in _MECHANISMS:
            if any(token in sink for token in tokens):
                required = True
                reasons.append(reason)
                unsupported.extend(limits)
    assisted = bool(linked_pages) or family == "file_upload" or any(token in sink for token in _UI_CONTEXTS)
    if linked_pages:
        reasons.append("linked_browser_workflow")
    if family == "file_upload":
        reasons.append("upload_consumer_context")
        unsupported.append("file_upload")
    if any(token in sink for token in _UI_CONTEXTS):
        reasons.append("declared_ui_context")
    requirement = "required" if required else "assisted" if assisted else "not_needed"
    needed = requirement != "not_needed"
    return {"requirement": requirement, "must_call_playwright": needed, "proof_requires_browser": required,
            "reason_codes": list(dict.fromkeys(reasons)), "preferred_provider": "host_playwright_mcp" if needed else None,
            "native_fallback": ["browser.probe", "browser.visit"] if needed else [],
            "native_supported": not unsupported, "unsupported_by_native": list(dict.fromkeys(unsupported)),
            "stage": "prepare" if needed else "not_needed", "call_needed": needed, "invoke_now": False,
            "execution_blocked": False, "hints_only": True, "usable_for_confirmation": False,
            "required_input_fields": [], "observation_requirements": ["actual_scoped_page", "successful_relevant_interaction",
                "original_runtime_and_network_artifact", "identity_and_resource_context"] if needed else []}


def _same_url(a, b):
    try:
        return normalize_url(a) == normalize_url(b)
    except (EngineError, ValueError, TypeError):
        return False


class Context:
    """One bounded, read-only reuse cache per queue; no probe or browser launch."""
    def __init__(self, project):
        self.project, self.pages = project, project.list("page")
        self.visits = project.list("page_visit")[-20:]
        self._verified, self._proofs, self._links, self._captures = {}, {}, {}, {}

    def linked_pages(self, operation):
        if operation["id"] in self._links:
            return self._links[operation["id"]]
        pages = []
        for page in self.pages:
            try:
                require_scope(self.project.config, page["url"])
            except (EngineError, KeyError):
                continue
            related = _same_url(page["url"], operation["url"])
            for function in page.get("functions", []):
                for reference in function.get("apis", []):
                    if isinstance(reference, str):
                        related |= reference == operation["id"] or _same_url(reference, operation["url"])
                    elif isinstance(reference, dict):
                        related |= reference.get("operation_id") == operation["id"] or (
                            _same_url(reference.get("url"), operation["url"])
                            and (reference.get("method") is None or reference["method"] == operation["method"]))
            if related:
                pages.append(page)
        self._links[operation["id"]] = pages
        return pages

    def verified_visit(self, visit, target):
        key = (visit["id"], target)
        if key not in self._verified:
            from .browser import _verified_visit
            try:
                self._verified[key] = _verified_visit(self.project, visit["id"], target)
            except (EngineError, OSError, ValueError, TypeError, KeyError):
                self._verified[key] = None
        return self._verified[key]

    def observed_page(self, pages, session_id, actor_id=None):
        for visit in reversed(self.visits):
            if visit.get("session_id") != session_id or visit.get("actor_id") != actor_id:
                continue
            if session_id:
                session = self.project.get("session", session_id, required=False)
                if session is None or visit.get("session_generation") != session.get("generation"):
                    continue
            for page in pages:
                if self.verified_visit(visit, page["url"]):
                    return visit["id"]
        return None

    def xss_review_candidate(self, operation, gap, evidence):
        if gap.get("test_family") != "xss" or len(evidence) < 2:
            return None
        pair = evidence[-2:]
        key = (gap["id"], pair[0]["id"], pair[1]["id"])
        if key in self._proofs:
            return self._proofs[key]
        from .assessment import _bound_xss_proof, _input_view
        from .engine import operation_signature
        attack = pair[1]
        try:
            if attack["id"] not in self._captures:
                self._captures[attack["id"]] = self.project.read_artifact(attack)
            value = _input_view((attack, self._captures[attack["id"]]), gap, operation)[0]
            if isinstance(value, bytes):
                value = value.decode("utf-8", errors="replace")
            markers = set(re.findall(r"AWA-XSS-[a-fA-F0-9]{16,64}", value)) if isinstance(value, str) else set()
        except (EngineError, OSError, ValueError, TypeError, KeyError):
            markers = set()
        if not markers:
            self._proofs[key] = None
            return None
        result = None
        for visit in reversed(self.visits[-8:]):
            if any(visit.get(field) != attack.get(field) for field in ("actor_id", "session_id", "session_generation")):
                continue
            dialogs = visit.get("dialogs")
            for dialog in dialogs[:4] if isinstance(dialogs, list) else []:
                marker = dialog.get("message") if isinstance(dialog, dict) else None
                if not isinstance(marker, str) or marker not in markers:
                    continue
                consumer = visit.get("finalUrl") or visit.get("url")
                candidate = {"mode": "analyst", "outcome": "confirmed", "obligation_id": gap["id"],
                    "operation_id": operation["id"], "operation_signature": operation_signature(operation),
                    "oracle": {"type": "analyst_runtime", "test_family": "xss"},
                    "evidence_ids": [item["id"] for item in pair],
                    "runtime": {"marker": marker, "visit_id": visit["id"], "consumer_url": consumer}}
                try:
                    _bound_xss_proof(self.project, candidate)
                except (EngineError, OSError, ValueError, TypeError, KeyError):
                    continue
                # Validation schedules analyst review only; no decision/finding is created.
                result = {"runtime_visit_id": visit["id"], "baseline_evidence_id": pair[0]["id"],
                          "attack_evidence_id": pair[1]["id"]}
                break
            if result:
                break
        self._proofs[key] = result
        return result


def for_work_item(context, operation, gap, row, evidence):
    pages = context.linked_pages(operation)
    policy = classify(operation, {**gap, "hypothesis_family": row.get("hypothesis_family")}, linked_pages=pages)
    if not policy["must_call_playwright"]:
        return policy
    try:
        require_scope(context.project.config, operation["url"])
    except (EngineError, ValueError, TypeError):
        policy.update(stage="blocked", execution_blocked=True, required_input_fields=["authorized_operation_scope"])
        return policy
    if gap.get("obligation_kind", gap.get("kind")) in {"auth_review", "input_review", "identity_setup", "ownership_setup"}:
        policy["required_input_fields"] = ["declared_access_input_or_identity_prerequisite", "scoped_consumer_url"]
        if row.get("queue_status") == "blocked":
            policy.update(stage="blocked", execution_blocked=True)
        return policy
    available_pages = [page for page in pages if page.get("visit_status") != "BLOCKED"]
    if pages and not available_pages:
        policy.update(stage="blocked", execution_blocked=True,
                      required_input_fields=["explicit_consumer_page_unblock_or_authorized_alternative"])
        return policy
    pages = available_pages
    session_id = (row.get("input_template") or {}).get("session_id")
    actor_id = gap.get("actor_id")
    if session_id:
        session = context.project.get("session", session_id, required=False)
        actor_id = session.get("actor_id") if session else actor_id
    family = row.get("hypothesis_family") or gap.get("test_family")
    if family == "xss":
        review = context.xss_review_candidate(operation, gap, evidence)
        if review:
            policy.update(stage="review_existing", call_needed=False, invoke_now=False, existing_observation=review,
                          required_input_fields=["consumer_url", "runtime_marker", "analyst_reviewer"])
            return policy
        policy["observation_requirements"] += ["normal_attack_input_controls", "application_triggered_marker",
                                               "exact_consumer_document_and_credentials"]
        if session_id:
            policy["proof_provider_constraint"] = "Imported MCP observations do not bind this engine session; use a verified session-bound local visit for typed XSS closure."
    if row.get("queue_status") == "blocked" or row.get("execution_blocked") or row.get("missing_prerequisites"):
        policy.update(stage="blocked", execution_blocked=True, invoke_now=False)
        return policy
    if family == "xss" and len([item for item in evidence if 200 <= item.get("status_code", 0) < 300]) < 2:
        policy.update(stage="capture_controls", required_input_fields=["normal_baseline_capture", "selected_attack_capture"])
        return policy
    if policy["requirement"] == "assisted":
        existing = context.observed_page(pages, session_id, actor_id)
        if existing:
            policy.update(stage="review_existing", call_needed=False, existing_observation={"page_visit_id": existing})
            return policy
    if not pages:
        policy.update(stage="identify_consumer", required_input_fields=["scoped_consumer_url"])
        if family == "xss" and operation["method"] == "GET":
            policy["required_input_fields"].append("exact_captured_attack_url")
        return policy
    page = next((page for page in pages if session_id is None and family != "xss"
                 or origin(page["url"]) == origin(operation["url"])), None)
    if page is None or "{" in page["url"] or "}" in page["url"]:
        policy.update(stage="identify_consumer", required_input_fields=["concrete_same_identity_consumer_url"])
        return policy
    native = {"url": safe_url(page["url"]), "allow_write": False}
    if session_id:
        native["session_id"] = session_id
    policy.update(stage="browser_runtime" if policy["proof_requires_browser"] else "browser_assist",
                  invoke_now=True, native_visit_input=native,
                  required_input_fields=["relevant_selectors_and_actions"])
    if family == "xss" and operation["method"] == "GET":
        # A sanitized page locator must never replace the captured attack URL.
        policy["required_input_fields"].append("exact_captured_attack_url")
        policy["consumer_locator"] = native.pop("url")
        policy.update(invoke_now=False, native_input_requires_binding=True)
    elif normalize_url(page["url"]) != native["url"]:
        policy["required_input_fields"].append("exact_scoped_consumer_url_with_bound_values")
        policy["consumer_locator"] = native.pop("url")
        policy.update(invoke_now=False, native_input_requires_binding=True)
    return policy


def for_page(page_url, *, function=False, blocked=False, existing_visit_id=None, config=None):
    policy = classify({}, {"test_family": "xss"})
    policy.update(reason_codes=["actual_function_interaction" if function else "actual_page_observation"],
                  proof_requires_browser=False, stage="interact_function" if function else "observe_page",
                  invoke_now=not blocked, execution_blocked=blocked,
                  native_visit_input={"url": safe_url(page_url), "allow_write": False},
                  required_input_fields=["actual_function_selectors_and_actions"] if function else [])
    try:
        normalized = require_scope(config, page_url) if config is not None else normalize_url(page_url)
    except (EngineError, ValueError, TypeError):
        policy.update(stage="blocked", invoke_now=False, execution_blocked=True, native_visit_input={},
                      required_input_fields=["valid_scoped_page_url"])
        return policy
    if blocked:
        policy.update(stage="blocked", invoke_now=False)
    elif existing_visit_id is not None and not function:
        policy.update(stage="review_existing", call_needed=False, invoke_now=False,
                      existing_observation={"page_visit_id": existing_visit_id})
    elif "{" in normalized or "}" in normalized or normalized != policy["native_visit_input"]["url"]:
        policy["required_input_fields"].append("exact_scoped_page_url_with_bound_values")
        policy["consumer_locator"] = policy["native_visit_input"].pop("url")
        policy.update(invoke_now=False, native_input_requires_binding=True)
    return policy


def summarize(policies, *, followup_total=0):
    result = dict.fromkeys(SUMMARY_FIELDS, 0)
    for policy in policies:
        result["task_total"] += 1
        result["required_total"] += policy.get("requirement") == "required"
        result["assisted_total"] += policy.get("requirement") == "assisted"
        result["call_needed_total"] += policy.get("call_needed") is True
        result["invoke_now_total"] += policy.get("invoke_now") is True
        result["blocked_total"] += policy.get("execution_blocked") is True
        result["native_unsupported_total"] += bool(policy.get("unsupported_by_native"))
    result["followup_total"] = followup_total
    return result
