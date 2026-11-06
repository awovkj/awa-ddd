"""Project-aware public projections; private records and execution outcomes stay intact."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import math
import re
from urllib.parse import unquote

from .store import EngineError


_PRIVATE_CONTENT = "[content omitted: project redaction context unavailable]"
_PRIVATE_LOCATOR = "[locator omitted: protected project context]"
_OPAQUE_LOCATORS = frozenset({_PRIVATE_LOCATOR, "[candidate locator omitted: protected context]",
                            "[private URL omitted]", "[invalid URL]",
                            "[browser content omitted: redaction context unavailable]"})
_ERROR_CODES = frozenset((
    "access_policy action action_failed action_name action_reference actor_binding actor_changed actor_independence "
    "actor_subject analyst_evidence analyst_obligation analyst_review anonymous_cookie argument_missing arguments "
    "assessment_batch assessment_error assessment_not_started assessment_partial auth authorization_proof authorization_response baseline_identity "
    "baseline_invalid basis_missing blocked_reason body body_budget body_file browser_actions browser_arguments "
    "browser_budget browser_execution_blocked browser_failed browser_import browser_observation browser_redaction_context "
    "browser_unavailable browser_write_not_authorized budget candidate candidate_closure candidate_dismissed candidate_identity "
    "candidate_input candidate_linked candidate_reason candidate_scope candidate_status checkpoint_stale closure_review config "
    "consumer continuation_arguments continue_required control_identity control_invalid control_request credential_changed "
    "credential_context credential_header_names credential_override decision_missing deny_statuses disposition evidence_binding "
    "evidence_changed evidence_incomplete evidence_missing exclusion family_proof finalization_policy finalization_required "
    "finalization_stale finding_decision finding_fields finding_immutable finding_lifecycle finding_mode finding_replacement "
    "frontier_categories frontier_evidence frontier_pages frontier_review frontier_review_required function_id function_missing "
    "graphql_binding headers headers_file idempotency_conflict identity_assertion identity_selector_boundary identity_mismatch identity_origin "
    "identity_response identity_stale identity_unverified immutable_record inconclusive independent_evidence input "
    "input_adapter_blocked input_ambiguous input_binding input_budget input_selector input_schema_branch invalid_input json_assertion mcp_budget mcp_capability "
    "mcp_closed mcp_error mcp_io mcp_protocol mcp_schema mcp_timeout media_binding method not_found numeric_invariant "
    "obligation_superseded operation_binding operation_changed operation_effect operation_method operation_name oracle "
    "oracle_binding oracle_family origin out_of_scope ownership page_adoption_required page_binding page_evidence_invalid "
    "page_evidence_required page_status page_visit_binding page_visit_incomplete pagination path_escape path_link project_exists "
    "project_id project_missing protected_selector protected_value protocol reconciliation_context reconciliation_evidence "
    "record_budget record_id recovery_age remote_execution_unverified renew_missing renew_shape report_stage reproduction_binary "
    "request resource_ambiguous resource_binding resource_changed resource_mismatch resource_owner resource_unbound response_encoding "
    "response_json review_material roles roles_mismatch roles_unverified run_active run_uncertain runtime_arguments runtime_backend "
    "runtime_distribution runtime_encoding runtime_output_budget runtime_path runtime_protocol runtime_timeout scenario_assertion "
    "scenario_budget scenario_control scenario_extract scenario_failed scenario_preflight scenario_shape scenario_uncertain "
    "scenario_variable schema_version scope selector sensitivity session_changed session_expired session_ttl severity "
    "sql_behaviour_proof_required sql_evidence sql_metadata_binding sql_metadata_control sql_metadata_expression sql_metadata_predicate "
    "sql_metadata_proof sql_metadata_reflection sql_metadata_required sql_metadata_tool sql_metadata_type sql_metadata_value state_action "
    "state_action_success state_input state_oracle state_order state_proof state_readback state_scenario state_scope state_selector "
    "step_id stop_policy stop_reason superseded surface_batch target tenant_mismatch test_families timestamp tool_adapter tool_artifact "
    "tool_artifact_changed tool_artifact_unavailable tool_baseline_changed tool_context_changed tool_dbms tool_effect tool_headers_changed "
    "tool_identity tool_input tool_input_changed tool_lineage_changed tool_lineage_missing tool_output_budget tool_path tool_profile_changed "
    "tool_resource_binding tool_run tool_target tool_timeout tscanplus_argument_budget tscanplus_arguments tscanplus_artifact tscanplus_body "
    "tscanplus_budget tscanplus_configuration tscanplus_context tscanplus_fixture tscanplus_idempotency tscanplus_namespace tscanplus_profile "
    "tscanplus_project tscanplus_query tscanplus_result tscanplus_tool_error tscanplus_unconfigured unbound_url unsupported_oracle url variable "
    "wsl_cleanup wsl_deadline wsl_input_budget wsl_io wsl_platform wsl_request xss_input_binding xss_runtime_binding xss_runtime_identity "
    "xss_runtime_required engine_error publication_failed capture_failed execution_interrupted browser_timeout "
    "browser_observation_incomplete tool_probe_failed tool_process_failed mcp_start_failed tscanplus_failed tscanplus_probe_failed "
    "artifact_unreadable completed evidence_invalid execution_failed invalid invalid_operation missing_metadata no_injection multipart_framing "
    "finding_proof finding_proof_current finding_binding finding_binding_lifecycle finding_binding_channel finding_binding_source finding_binding_duplicate "
    "page_adoption_failed timeout tool_lineage_invalid wsl_runtime sql_metadata_lineage "
    "already_preflighted report_redaction_failed"
).split())
_ERROR_CODES = _ERROR_CODES | frozenset((
    "action_catalog capability_profile capability_provider known_case_entry known_case_group known_case_source "
    "known_case_track route_manifest v2_campaign_missing v2_migration_confirm v2_migration_exists v2_oracle "
    "v2_report_compare v2_report_final v2_report_path v2_report_stage v2_campaign_state v2_campaign_model "
    "v2_campaign_exists v2_campaign_not_exhausted v2_campaign_checkpoint v2_campaign_delivery v2_campaign_frozen "
    "v2_repository_kind v2_repository_record v2_repository_immutable v2_read_only v2_migration_required "
    "v2_hypothesis_identity v2_hypothesis_transition v2_hypothesis_applicability v2_recipe_controls v2_recipe_effect "
    "v2_recipe_fixture v2_recipe_variable v2_recipe_override v2_recipe_stale v2_run_transition v2_run_claim "
    "v2_run_recipe v2_run_verify v2_run_inspect v2_finding_proof v2_finding_review v2_finding_replacement "
    "v2_review_mechanism v2_review_controls v2_review_observation v2_review_scope v2_review_material v2_review_run "
    "v2_review_hypothesis v2_review_reviewer v2_review_cross_role v2_review_disposition v2_review_bind "
    "v2_review_evidence v2_review_identity v2_recon_import v2_write_authorization v2_scheduler_lease v2_fixture_state v2_fixture_lease "
    "v2_fixture_initial_state v2_oracle_missing v2_browser_marker v2_browser_visit v2_external_receipt v2_external "
    "v2_coverage v2_campaign_not_ready v2_migration_ledger v2_delivery_reason v2_campaign_state_reason "
    "v2_recipe_blocked v2_timestamp v2_observe_effect v2_accepted_by v2_campaign_target v2_explanation"
).split())
_LOCATOR_KEYS = {"url", "finalUrl", "path", "locator", "schema_locator", "source_locator", "selector",
                 "input_selector", "location", "consumer_url", "source_url", "consumer_locator",
                 "report", "summary", "manifest", "reproduction_dir", "target", "target_origin", "base_url"}
_HANDLE_PREFIXES = {"operation": {"O"}, "obligation": {"OB"}, "evidence": {"E"}, "decision": {"D"},
                    "finding": {"F"}, "finding_revision": {"FR"}, "candidate": {"C"}, "run": {"RUN", "SC"},
                    "page_visit": {"PV"}, "checkpoint": {"CP"}, "closure_review": {"CR"}, "finalization": {"FN"},
                    "recon_baseline": {"RC"}}
_LOCAL_ID_KINDS = {"actor", "session", "resource", "page", "function"}
_LOCAL_PREFIXES = {"actor": "ACT", "session": "SES", "resource": "RES", "page": "PG", "function": "FN"}


@dataclass(frozen=True)
class _Rule:
    kind: str
    values: object = None


@dataclass(frozen=True)
class _Many:
    item: object


_TEXT = _Rule("text")
_COUNT = _Rule("count")
_BOOL = _Rule("bool")
_RATIO = _Rule("ratio")
_NUMBER = _Rule("number")
_SHA256 = _Rule("hex", 64)


def _enum(*values):
    return _Rule("enum", frozenset(values))


def _handle(kind):
    return _Rule("handle", kind)


def _digest(prefix, length=24):
    return _Rule("digest", (prefix, length))


def _fields(names, rule=_TEXT):
    return {name: rule for name in names.split()}


def _record_timestamps(kind, names):
    return {name: _Rule("record_timestamp", (kind, name)) for name in names.split()}


class PublicationContext:
    """The same private seed used by candidate publication, scoped to one project."""

    def __init__(self, project, *, minted=None, extra_secrets=()):
        from .browser import _learn_private_value, learn_redaction_context
        from .engine import credential_header_names
        from .reproduction import Redactor, _learn_header
        from .tscanplus import report_context

        self.project = project
        self.redactor = Redactor()
        self.unavailable = learn_redaction_context(project, self.redactor)
        for session in project.list("session"):
            for name in credential_header_names(session):
                value = (session.get("headers") or {}).get(name)
                if value is not None:
                    _learn_header(self.redactor, name, value)
        for value in report_context(project)["secret_values"]:
            _learn_private_value(self.redactor, value, short_alias=False)
        from .reproduction import _PLACEHOLDER
        prepared = extra_secrets if isinstance(extra_secrets, dict) else {}
        for value in extra_secrets:
            if isinstance(value, str):
                placeholder = prepared.get(value)
                short = len(value) <= 3
                if isinstance(placeholder, str) and _PLACEHOLDER.fullmatch(placeholder):
                    if short:
                        self.redactor.field_values[value] = placeholder
                    else:
                        self.redactor.values[value] = placeholder
                _learn_private_value(self.redactor, value, short_alias=not short)
        self.minted = minted or {}
        self._records = {}
        self._generated = None
        self._paths = None
        self._checklists = None

    def _learn(self, value):
        from .browser import _learn_private_value

        self.redactor.learn(value)

        def keys(node):
            if isinstance(node, dict):
                for key, item in node.items():
                    self.redactor.learn_text(key)
                    keys(item)
            elif isinstance(node, list):
                for item in node:
                    keys(item)

        keys(value)
        for private in list(self.redactor.values):
            _learn_private_value(self.redactor, private, short_alias=False)
        self._literal_pattern()

    def _literal_pattern(self):
        from .reproduction import _PLACEHOLDER

        aliases = self.redactor.aliases
        # Short protected values must also be removed from embedded paths/prose.
        self.redactor._pattern = re.compile(_PLACEHOLDER.pattern + "|" + "|".join(
            re.escape(alias) for alias in sorted(aliases, key=len, reverse=True))) if aliases else None

    def _prose(self, text):
        if any(self.unavailable.values()):
            return _PRIVATE_CONTENT
        decoded = text
        for _ in range(5):
            if decoded != text and self.redactor.replace(decoded) != decoded:
                return "[content omitted: encoded protected value]"
            following = unquote(decoded)
            if following == decoded:
                break
            decoded = following
        else:
            return "[content omitted: protected decoding context]"
        self.redactor.learn_text(text)
        self._literal_pattern()
        return self.redactor.prose(text)

    def _record(self, kind, identity):
        if kind not in self._records:
            self._records[kind] = {row["id"]: row for row in self.project.list(kind)}
        return self._records[kind].get(identity)

    def bound_handle(self, kind, value):
        if not isinstance(value, str):
            return False
        # These namespaces allow caller-selected IDs. Only IDs actually minted
        # during this invocation can be restored after a private-value collision.
        if kind in _LOCAL_ID_KINDS:
            if re.fullmatch(_LOCAL_PREFIXES[kind] + r"-[a-f0-9]{32}", value) is None:
                return False
            if self._generated is None:
                with self.project._lock:
                    rows = self.project.connection.execute(
                        "SELECT key FROM metadata WHERE key LIKE 'publication_generated_handle:%' AND value='engine-generated-v1'").fetchall()
                self._generated = {row[0] for row in rows}
            generated = value in self.minted.get(kind, set()) \
                or "publication_generated_handle:" + kind + ":" + value in self._generated
            if kind == "function":
                return generated and any(isinstance(row, dict) and row.get("id") == value for page in self.project.list("page")
                                         for row in page.get("functions", []))
            return generated and self._record(kind, value) is not None
        if kind == "gap":
            from .engine import _gap_id
            return any(_gap_id(row) == value for row in self.project.list("obligation"))
        prefixes = _HANDLE_PREFIXES.get(kind, set())
        return any(re.fullmatch(re.escape(prefix) + r"-[a-f0-9]{24,32}", value) for prefix in prefixes) \
            and self._record(kind, value) is not None

    def _typed(self, value, rule, row=None):
        if rule.kind == "record_timestamp":
            return self._record_timestamp(value, rule.values, row)
        if value is None:
            return rule.kind not in {"count", "bool", "hex", "digest"}
        if rule.kind == "count":
            return type(value) is int and value >= 0
        if rule.kind == "bool":
            return type(value) is bool
        if rule.kind in {"true", "false"}:
            return value is (rule.kind == "true")
        if rule.kind in {"ratio", "number"}:
            return type(value) in {int, float} and (type(value) is int or math.isfinite(value)) \
                and (0 <= value <= 1 if rule.kind == "ratio" else value >= 0)
        if rule.kind == "enum":
            return isinstance(value, str) and value in rule.values
        if rule.kind == "handle":
            return self.bound_handle(rule.values, value)
        if rule.kind == "source_handle":
            from .continuation import SOURCE_KINDS
            return isinstance(row, dict) and isinstance(row.get("kind"), str) and row["kind"] in SOURCE_KINDS \
                and self.bound_handle(SOURCE_KINDS[row["kind"]], value)
        if rule.kind == "checklist":
            if not isinstance(value, str) or re.fullmatch(r"CL-[a-f0-9]{24}", value) is None:
                return False
            if self._checklists is None:
                from .completeness import _checklist, _inventory
                from .engine import evaluate_coverage
                evaluated = evaluate_coverage(self.project)
                self._checklists = {item["id"] for item in _checklist(_inventory(self.project, evaluated))}
                self._checklists.update(item["checklist_id"] for item in self.project.list("closure_review")
                                        if self.bound_handle("closure_review", item["id"]) and isinstance(item.get("checklist_id"), str))
            return value in self._checklists
        if rule.kind == "hex":
            return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{" + str(rule.values) + "}", value) is not None
        if rule.kind == "digest":
            prefix, length = rule.values
            return isinstance(value, str) and re.fullmatch(re.escape(prefix) + r"-[a-f0-9]{" + str(length) + "}", value) is not None
        if rule.kind == "http_status":
            return type(value) is int and 100 <= value <= 599
        if rule.kind == "path":
            if not isinstance(value, str):
                return False
            if self._paths is None:
                self._paths = set()
                for kind in ("evidence", "page_visit", "run"):
                    for record in self.project.list(kind):
                        for key in ("artifact_path", "screenshot", "html", "after_actions_html"):
                            path = record.get(key)
                            if isinstance(path, str) and re.fullmatch(
                                    r"(?:evidence/(?:E|PV|TA)-[a-f0-9]{24,32}\.json|browser/PV-[a-f0-9]{32}(?:\.png|\.html|\.after\.html))", path):
                                self._paths.add(path)
                        for item in record.get("files", []):
                            path = item.get("path") if isinstance(item, dict) else None
                            if isinstance(path, str) and re.fullmatch(
                                    r"tools/RUN-[a-f0-9]{24,32}/(?:stdout\.log|stderr\.log|traffic\.log|mcp-exchanges\.json)", path):
                                self._paths.add(path)
            return value in self._paths
        return False

    def _record_timestamp(self, value, reference, row):
        if not isinstance(value, str) or not isinstance(row, dict) or re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})", value) is None:
            return False
        try:
            if datetime.fromisoformat(value.replace("Z", "+00:00")).utcoffset() is None:
                return False
        except ValueError:
            return False
        kind, field = reference
        keys = ("id", kind + "_id") + (("visit_id",) if kind == "page_visit" else ())
        identities = [row[key] for key in keys if key in row]
        if not identities or any(not isinstance(identity, str) or not identity for identity in identities) \
                or len(set(identities)) != 1:
            return False
        if not self.bound_handle(kind, identities[0]):
            return False
        actual = self._record(kind, identities[0])
        if actual is None or actual.get(field) != value:
            return False
        # Only the actual ledger field is control data; ISO-shaped business text is not.
        return all(type(row[key]) is type(actual.get(key)) and row[key] == actual.get(key) for key in (
            "kind", "actor_id", "session_id", "session_generation", "generation", "operation_id", "resource_id")
            if key in row and key not in keys)

    def _restore(self, original, public, schema):
        if isinstance(schema, dict) and isinstance(original, dict) and isinstance(public, dict):
            for key, rule in schema.items():
                if key not in original or key not in public:
                    continue
                if isinstance(rule, _Rule):
                    if type(original[key]) is type(public[key]) and not isinstance(original[key], (dict, list)) and original[key] == public[key]:
                        continue
                    if rule.kind != "text" and self._typed(original[key], rule, original):
                        public[key] = original[key]
                else:
                    self._restore(original[key], public[key], rule)
        elif isinstance(schema, _Many) and isinstance(original, list) and isinstance(public, list):
            for index, (value, sanitized) in enumerate(zip(original, public)):
                if isinstance(schema.item, _Rule):
                    if schema.item.kind != "text" and self._typed(value, schema.item):
                        public[index] = value
                else:
                    self._restore(value, sanitized, schema.item)

    def metadata(self, value, *, schema=None):
        from .reporting import _PRIVATE_KEYS, public_integrity_metadata, safe_metadata

        original = public_integrity_metadata(value)
        self._learn(original)
        numeric = {int(secret): placeholder for secret, placeholder in self.redactor.values.items()
                   if re.fullmatch(r"[0-9]{1,64}", secret)}
        missing = any(self.unavailable.values())

        def scrub(node, shape):
            if isinstance(node, dict):
                result = {}
                protected = False
                redacted_fields = set()
                known = shape if isinstance(shape, dict) else {}
                for key, item in node.items():
                    if re.sub(r"[^a-z0-9]", "", str(key).lower()) in _PRIVATE_KEYS:
                        continue
                    if missing and key not in known:
                        continue
                    public_key = key if key in known else self._prose(str(key))
                    result[public_key] = scrub(item, known.get(key))
                    opaque = key in known and isinstance(item, str) and item in _OPAQUE_LOCATORS and any(
                        node.get(flag) is True for flag in (key + "_redacted", "locator_requires_binding", "native_input_requires_binding"))
                    if opaque:
                        result[public_key] = item
                        protected = True
                    rule = known.get(key)
                    control = isinstance(rule, _Rule) and rule.kind == "enum" and self._typed(item, rule)
                    changed_locator = key in _LOCATOR_KEYS and not control and isinstance(item, str) and result[public_key] != item
                    changed_shape = key in {"path_shape", "scope", "exclude", "navigation_trail"} \
                        and isinstance(item, list) and result[public_key] != item
                    if changed_locator or changed_shape:
                        protected = True
                        redacted_fields.add(public_key + "_redacted")
                        if changed_locator:
                            result[public_key] = _PRIVATE_LOCATOR
                        result[public_key + "_redacted"] = True
                        result.update(locator_requires_binding=True, native_input_requires_binding=True, requestable=False)
                if protected:
                    result.update({key: True for key in redacted_fields})
                    result.update(locator_requires_binding=True, native_input_requires_binding=True, requestable=False)
                return result
            if isinstance(node, list):
                child = shape.item if isinstance(shape, _Many) else None
                return [scrub(item, child) for item in node]
            if isinstance(node, str):
                return self._prose(node)
            if missing and node is not None:
                return _PRIVATE_CONTENT
            if type(node) is bool:
                for alias in (str(node), "true" if node else "false"):
                    if alias in self.redactor.values:
                        return self.redactor.values[alias]
            if type(node) in {int, float}:
                if str(node) in self.redactor.values:
                    return self.redactor.values[str(node)]
                if node in numeric:
                    return numeric[node]
            return node

        public = safe_metadata(scrub(original, schema), preserve_placeholders=set(self.redactor.values.values()))
        self._restore(original, public, schema)
        if missing and isinstance(public, dict):
            public["redaction_context_status"] = "unavailable"
            public["redaction_context_unavailable"] = {
                key: [identity for identity in values if self.bound_handle("page_visit" if key == "page_visit_ids" else "run", identity)]
                for key, values in self.unavailable.items()}
        return public


def _schemas():
    from .contracts import CONTRACTS, ALL_CONTRACTS
    from .engine import TEST_FAMILIES

    action = _enum(*ALL_CONTRACTS)
    family = _enum("access_control", *TEST_FAMILIES)
    method = _enum("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE")
    auth = _enum("public", "authenticated", "restricted", "unknown")
    state = _enum("open", "blocked", "not_applicable", "evaluated")
    prerequisite = _enum("authorized_operation_scope", "exact_scoped_url_query_binding", "live_verified_session_for_actor",
        "verified_session_for_target_origin", "verified_allowed_baseline", "live_verified_owner_baseline", "server_verified_role_membership",
        "live_verified_allowed_session", "declared_access_policy", "concrete_url_with_bound_path_values", "project_allow_mutation",
        "matching_test_resource_or_declared_actor_state", "explicit_consumer_page_unblock_or_authorized_alternative",
        "offline_obligation_blocker_reconciliation", "declared_access_input_or_identity_prerequisite", "scoped_consumer_url",
        "consumer_url", "runtime_marker", "analyst_reviewer", "normal_baseline_capture", "selected_attack_capture", "exact_captured_attack_url",
        "no_progress_frozen",
        "concrete_same_identity_consumer_url", "relevant_selectors_and_actions", "exact_scoped_consumer_url_with_bound_values",
        "actual_function_selectors_and_actions", "valid_scoped_page_url", "exact_scoped_page_url_with_bound_values")
    page = {**_fields("offset limit next_offset", _COUNT), "next_action": action}
    pending_names = "open_obligations open_security_obligations unresolved_candidates unassessed_observations " \
                    "unlinked_analyst_findings unrecorded_confirmations orphan_browser_visits pages_unvisited " \
                    "functions_untriggered unreconciled_runs failed_partial_tools applicability_review_total " \
                    "scope_reduction_review_total limited_ownership_sampling"
    completion = {**_fields(pending_names, _COUNT), "status": _enum("complete", "partial", "not_started"),
                  "registered_scope_only": _BOOL, **_fields("label_zh reasons_zh limitations_zh")}
    remaining = _fields("ready_total review_total blocked_total unresolved_total", _COUNT)
    continuation = {**remaining, **_fields("contract_version stop_policy_version actionable_total no_progress_rounds frontier_rounds "
                                         "applicability_review_total scope_reduction_review_total", _COUNT),
        **_fields("continue_required automatic_stop_allowed can_finalize can_claim_complete legacy_finalization_ignored "
                  "frontier_review_required registered_scope_only", _BOOL),
        "stop_policy": _enum("exhaustion_only"), "coverage_status": completion["status"], "next_action": action,
        "state": _enum("continue", "blocked", "review_coverage", "review_frontier", "ready_to_finalize", "stalled", "not_started", "finalized"),
        "reason_code": _enum("work_remaining", "blocked_preconditions", "coverage_incomplete", "frontier_review_required",
                             "registered_scope_exhausted", "no_closure_progress", "inventory_missing", "completed"),
        "snapshot_id": _digest("CS", 64), "progress_id": _digest("PR", 64), "semantic_progress_id": _digest("PR", 64),
        "checkpoint_id": _handle("checkpoint"), "finalization_id": _handle("finalization")}
    bucket = {**_fields("total evaluated open blocked not_applicable", _COUNT), "ratio": _RATIO}
    security = {**bucket, **_fields("operations_total operations_with_security_tests operations_complete operations_without_security_tests", _COUNT),
                "by_family": _Many({**bucket, "test_family": family, "label_zh": _TEXT,
                                    "status": _enum("not_planned", "open", "blocked", "not_applicable", "completed", "review_required")}), "note_zh": _TEXT}
    surface_coverage = {**_fields("operations_total operations_tested inputs_total inputs_tested", _COUNT), "ratio": _RATIO, "note": _TEXT}
    methods = {"path_shape": _Many(_TEXT), "auth": auth, "operations": _Many(_handle("operation")), "note": _TEXT,
               **{name: _Many(method) for name in ("tested", "registered_methods", "observed_methods", "untested_registered_methods", "untested_siblings")}}
    binding = {"location": _enum("path", "query", "body"), "selector": _TEXT}
    resource = {**_fields("external_id tenant_id state request_binding created_at"), "request_binding": binding,
                "id": _handle("resource"), "owner_actor_id": _handle("actor"), "operation_id": _handle("operation")}
    actor = {**_fields("label subject tenant_id roles created_at security_updated_at"), "id": _handle("actor"), "security_revision": _COUNT}
    session = {**_fields("verified_at expires_at created_at verification_assertion credential_header_names"),
               "id": _handle("session"), "actor_id": _handle("actor"), "generation": _COUNT,
               "verification_evidence_id": _handle("evidence"), "actor_signature": _digest("AS")}
    session.update(_record_timestamps("session", "created_at verified_at expires_at renewed_at"))
    input_row = {**_fields("name selector consumer schema_branch schema_type array_template source schema_locator"),
                 "location": _enum("path", "query", "header", "cookie", "body", "graphql"),
                 "required": _BOOL, "test_families": _Many(family), "registration_error": _enum("input_not_object")}
    operation = {**_fields("url operation_name content_type allowed_roles sources created_at ownership_sampling"),
                 "id": _handle("operation"), "method": method, "protocol": _enum("http", "graphql"), "auth": auth,
                 "ownership": _BOOL, "state_scope": _enum("actor"), "input_count": _COUNT,
                 "inputs_truncated": _BOOL, "inputs": _Many(input_row)}
    parameter_state = _enum("consumer_review", "tested", "observed_unassessed", "observation_limited", "needs_controls", "unobserved")
    parameter_identity = {**_fields("input_name input_selector schema_branch"), "id": _digest("PC"),
        "operation_id": _handle("operation"), "input_location": input_row["location"], "test_family": _enum("unclassified", "access_control", *TEST_FAMILIES)}
    parameter_summary = {**_fields("parameter_total cell_total typed_tested_total untested_total observed_total variant_observed_total "
                                  "needs_controls_total unobserved_total consumer_review_total observations_limited_total", _COUNT),
                         "observation_is_testing": _Rule("false")}
    parameter_row = {**parameter_identity, **_fields("url consumer"), "method": method, "status": parameter_state,
        **_fields("typed_tested has_input_variant observations_limited schema_branch_requires_binding", _BOOL),
        "observation_is_testing": _Rule("false"), "next_action": action,
        **_fields("operation_observation_count observation_count", _COUNT),
        "control_candidate_state": _enum("no_variant", "two_values", "three_values"),
        "control_candidate_evidence_ids": _Many(_handle("evidence")),
        "control_candidate_required_values": _COUNT,
        "queue_status": _enum("ready", "review", "blocked", "closed", "unplanned"),
        "missing_prerequisites": _Many(prerequisite), "outcome": _enum("confirmed", "refuted"), "proof_mode": _enum("machine", "analyst"),
        "obligation_ids": _Many(_handle("obligation")), "evidence_ids": _Many(_handle("evidence")), "decision_id": _handle("decision"),
        "observation_errors": _fields("schema_branch_requires_binding input_view_unavailable", _COUNT)}
    parameter_page = {**page, "summary": parameter_summary, "items": _Many(parameter_row), "total": _COUNT,
        "filter": _enum("any", "untested", "observed", "needs_controls", "tested", "consumer_review"), "limitation": _TEXT}
    renewal_template = {"session_id": _handle("session"), "renew": _Rule("true")}
    renewal_candidate = {"session_id": _handle("session"), "actor_id": _handle("actor"), "generation": _COUNT,
        "expires_at": session["expires_at"], "prerequisites": _Many(prerequisite), "action": _enum("identity.session"),
        "input_template": renewal_template, "automatic_execution_allowed": _Rule("false"), "renewal_is_login": _Rule("false")}
    preparation = {"action": action, "reason": _TEXT, "instruction": _TEXT, "prerequisite": prerequisite,
                   "automatic_execution_allowed": _Rule("false"), "required_input_fields": _Many(_TEXT),
                   "input_template": {"operation_id": _handle("operation"), "actor_id": _handle("actor"), **renewal_template},
                   "help_input": {"name": action}}
    session_continuity = {"hint_only": _Rule("true"), "automatic_cookie_forwarding": _Rule("false"),
        "anonymous_input_field": _enum("anonymous_cookie"), "authenticated_input_field": _enum("session_id"), "instructions": _Many(_TEXT)}
    gap = {**_fields("input_selector schema_branch tenant_boundary reason operator_reason scope_family consumer_family "
                     "reason_zh required_experiment_fields missing_prerequisites note_zh"),
           "id": _handle("obligation"), "gap_id": _handle("gap"), "obligation_id": _handle("obligation"),
           "operation_id": _handle("operation"), "actor_id": _handle("actor"), "baseline_actor_id": _handle("actor"),
           "resource_id": _handle("resource"), "decision_id": _handle("decision"),
           "kind": _enum("baseline", "access", "ownership", "input_test", "auth_review", "input_review", "identity_setup", "ownership_setup"),
           "obligation_kind": _enum("baseline", "access", "ownership", "input_test", "auth_review", "input_review", "identity_setup", "ownership_setup"),
           "status": state, "input_location": input_row["location"], "test_family": family, "scope_family": family,
           "consumer_family": family, "next_action": action, "input_signature": _digest("I"),
           "reason_code": _enum("not_started", "decision_missing", "obligation_superseded", "evidence_invalid", "exclusion_evidence_invalid",
                                "blocked_precondition", "declared_blocker_unverified", "declared_review_blocker_unverified", "input_identity_invalid"), "operator_reason_invalid_type": _BOOL}
    template = {**_fields("url body body_base64 body_file input_selector consumer schema_branch subject external_id request_binding"),
        "operation_id": _handle("operation"), "obligation_id": _handle("obligation"), "session_id": _handle("session"),
                "resource_id": _handle("resource"), "actor_id": _handle("actor"), "page_visit_id": _handle("page_visit"),
                "runtime_visit_id": _handle("page_visit"), "evidence_ids": _Many(_handle("evidence")),
                "effect": _enum("read_only", "test_resource_write"), "input_location": input_row["location"],
                "status": _enum("reopen", "open", "blocked", "not_applicable"), "mode": _enum("analyst", "machine"),
                "name": action, "allow_write": _BOOL, "timeout": _NUMBER, "max_bytes": _COUNT}
    template.update({"evidence_id": _handle("evidence"), "run_id": _handle("run"), "candidate_id": _handle("candidate"),
                     "finding_id": _handle("finding"), "decision_id": _handle("decision"), "checklist_id": _Rule("checklist"),
                     "page_id": _handle("page"), "function_id": _handle("function"), "reason": _TEXT})
    browser_policy = {**_fields("reason_codes unsupported_by_native required_input_fields observation_requirements consumer_locator "
                                "browser_handoff_note source limitation"),
        **_fields("must_call_playwright proof_requires_browser native_supported call_needed invoke_now execution_blocked hints_only usable_for_confirmation", _BOOL),
        "requirement": _enum("required", "assisted", "not_needed"), "preferred_provider": _enum("host_playwright_mcp"),
        "native_fallback": _Many(action), "native_visit_input": template, "required_input_fields": _Many(prerequisite),
        "stage": _enum("not_needed", "prepare", "capture_controls", "identify_consumer", "browser_runtime", "browser_assist",
                       "observe_page", "interact_function", "review_existing", "blocked"),
        "existing_observation": {"baseline_evidence_id": _handle("evidence"), "attack_evidence_id": _handle("evidence"),
                                 "runtime_visit_id": _handle("page_visit"), "page_visit_id": _handle("page_visit")}}
    browser_counts = _fields("required_total assisted_total call_needed_total invoke_now_total blocked_total "
                             "native_unsupported_total followup_total task_total", _COUNT)
    work = {**gap, **_fields("url help_input required_experiment_fields hypothesis_hint browser_handoff_note"), "method": method,
            "runtime_binding_modes": _Many(_enum("direct_document", "stored_api")),
            "parameter_coverage_id": _digest("PC"), "parameter_test_status": parameter_state,
            "selected_input_observation_count": _COUNT, "selected_input_variant_observed": _BOOL,
            "control_candidate_evidence_ids": _Many(_handle("evidence")), "control_candidate_review_required": _BOOL,
            "controls_are_candidates_only": _Rule("true"), "preparation_actions": _Many(preparation), "session_continuity": session_continuity,
            "session_renewal_candidates": _Many(renewal_candidate),
            **_fields("observation_total", _COUNT), **_fields("execution_blocked hints_only blocker_reconciliation_required scope_binding_review_required", _BOOL),
            "url_requires_binding": _Rule("true"), "scope_binding_followup_action": _enum("http.preflight"),
            "scope_binding_required_input_fields": _Many(_enum("url")),
            "scope_binding_followup_template": {"operation_id": _handle("operation")}, "scope_handoff_note": _TEXT,
            "missing_prerequisites": _Many(prerequisite),
            "queue_status": _enum("ready", "review", "blocked"), "underlying_queue_status": _enum("ready", "review", "blocked"),
            "declared_status": _enum("blocked", "dismissed", "not_applicable"), "hypothesis_family": family, "suggested_action": action,
            "help_input": {"name": action}, "input_template": template, "browser_testing": browser_policy,
            "evidence_ids": _Many(_handle("evidence")), "declared_test_families": _Many(family), "suggested_test_families": _Many(family)}
    checklist = {**work, **_fields("label_zh reason_zh detail_zh"),
                 "kind": _enum("obligation", "candidate", "unassessed_observation", "failed_partial_tool", "unreconciled_run",
                               "orphan_browser_visit", "unlinked_analyst_finding", "unrecorded_confirmation", "unverified_applicability", "scope_reduction", "consumer_family_required"),
                 "id": _Rule("checklist"), "source_id": _Rule("source_handle"), "review_id": _handle("closure_review"),
                 "action": action, "required_action": action}
    checklist.update({"candidate_id": _handle("candidate"), "evidence_id": _handle("evidence"), "finding_id": _handle("finding"),
                      "decision_id": _handle("decision"), "run_id": _handle("run"), "page_visit_id": _handle("page_visit"),
                      "source_obligation_ids": _Many(_handle("obligation")), "administrative_review_allowed": _BOOL,
                      "disposition_review_required": _BOOL})
    common_coverage = {**page, **_fields("operations inputs obligations total evaluated open blocked not_applicable added gap_total "
                                       "finding_total current_findings historical_findings obligation_total method_total method_offset method_next_offset", _COUNT),
        "coverage_ratio": _RATIO, "continuation": continuation, "completion": completion, "security_coverage": security,
        "parameter_coverage_summary": parameter_summary, "parameter_coverage": parameter_page,
        "surface_coverage": surface_coverage, "gaps": _Many(gap), "gap_sample": _Many(gap), "method_coverage": _Many(methods),
        "obligation_items": _Many(gap), "coverage_by_kind": {name: bucket for name in
            ("baseline", "access", "ownership", "input_test", "auth_review", "input_review", "identity_setup", "ownership_setup")},
        "gap_dependencies": {name: _COUNT for name in CONTRACTS}, "limitations": _TEXT}
    checkpoint_step = {**_fields("step_id dynamic_fields failed_phase error_code failure_reasons"),
        "status": _enum("static_valid", "deferred", "captured", "verified", "failed"),
        **_fields("concurrent failed_attempts body_bytes", _COUNT), "operation_id": _handle("operation"), "method": method,
        "effect": _enum("read_only", "test_resource_write"), "session_id": _handle("session"), "actor_id": _handle("actor"),
        "resource_id": _handle("resource"), "evidence_id": _handle("evidence"), "evidence_ids": _Many(_handle("evidence")),
        "attempt_run_id": _handle("run"), "attempt_run_ids": _Many(_handle("run")), "request_signature": _digest("REQ"),
        "actor_signature": _digest("AS"), "resource_signature": _digest("RS"), "next_action": action}
    preflight = {**_fields("valid_spec static_valid", _BOOL), **_fields("deferred_steps total_attempts requests_sent", _COUNT),
                 "steps": _Many(checkpoint_step), "errors": _Many(checkpoint_step), "limitation": _TEXT}
    run = {**_fields("started_at finished_at completed_at error error_code diagnostic limitation reason files partial_files executable "
                     "server_info tools tool_version metadata_candidates request_method input_selector input_location policy_snapshot "
                     "scanner_project instance_id remote_run_id control_endpoint mcp_url selected_tool table declared_flags"),
        "id": _handle("run"), "run_id": _handle("run"), "kind": _enum("http", "scenario", "browser", "external_tool"),
        "status": _enum("running", "interrupted", "succeeded", "failed"), "adapter": _enum("sqlmap", "yakit", "tscanplus"),
        "action": _enum("probe", "sqlmap", "yakit_replay", "http_request", "query_results", "project_summary", "route_candidates"),
        "operation_id": _handle("operation"), "session_id": _handle("session"), "actor_id": _handle("actor"), "resource_id": _handle("resource"),
        "session_generation": _COUNT, "method": method, "effect": _enum("read_only", "test_resource_write"),
        "operation_signature": _digest("S"), "actor_signature": _digest("AS"), "resource_signature": _digest("RS"),
        "request_signature": _digest("REQ"), "spec_signature": _digest("SPEC"),
        "evidence_id": _handle("evidence"), "evidence_ids": _Many(_handle("evidence")), "candidate_ids": _Many(_handle("candidate")),
        "checkpoints": _Many(checkpoint_step), "preflight": preflight, "next_action": action,
        "sha256": _SHA256, "artifact_path": _Rule("path"), "integrity": _enum("valid", "invalid", "incomplete", "invalid_or_stale"),
        **_fields("target_traffic_sent available dispatch_attempted results_complete remote_may_continue remote_stopped_verified "
                  "namespace_cleared response_truncated unretrieved_results namespace_verified instance_verified usable_for_confirmation", _BOOL),
        **_fields("tool_count returned_rows result_limit candidate_count new_candidates duplicate_candidates out_of_scope_rows unmapped_rows imported_candidates "
                  "candidate_total import_limit processed_rows omitted_candidates unsupported_rows asset_count", _COUNT)}
    run.update(_fields("traffic_requests traffic_responses total_rows reported_count reported_total reported_matched"))
    run.update(_record_timestamps("run", "started_at finished_at completed_at"))
    run["files"] = _Many({"path": _Rule("path"), "bytes": _COUNT, "sha256": _SHA256, "complete": _BOOL})
    evidence = {**_fields("created_at artifact_path policy_snapshot credential_header_names error_code session_hint reason policy_changes"),
        "id": _handle("evidence"), "run_id": _handle("run"), "kind": _enum("http"), "operation_id": _handle("operation"),
        "session_id": _handle("session"), "actor_id": _handle("actor"), "resource_id": _handle("resource"),
        "operation_signature": _digest("S"), "actor_signature": _digest("AS"), "resource_signature": _digest("RS"),
        "sha256": _SHA256, "artifact_path": _Rule("path"), "session_generation": _COUNT, "response_bytes": _COUNT,
        "auth_mode": _enum("none", "session", "anonymous_cookie"), "trust": _enum("observed"),
        **_fields("complete usable usable_for_new_requests", _BOOL), "next_action": action,
        "integrity": _enum("valid", "invalid"), "lineage": _enum("current", "stale", "invalid", "operation_missing"),
        "session_status": _enum("live", "expired", "missing", "none", "unchecked", "rotated_or_other_actor"), "status_code": _Rule("http_status")}
    finding = {**_fields("title category impact remediation limitations created_at reviewer reason proof lifecycle_reason lifecycle_reviewer "
                         "lifecycle_updated_at evidence_reason_code limitation"),
        "id": _handle("finding"), "decision_id": _handle("decision"), "evidence_ids": _Many(_handle("evidence")),
        "status": _enum("confirmed"), "mode": _enum("machine", "analyst"), "origin": _enum("independent", "hint_guided", "imported"),
        "severity": _enum("critical", "high", "medium", "low", "info"), "confirmed_scope": _enum("sql_behaviour", "database_metadata", "browser_execution"),
        "verification_level": _enum("runtime_verified", "analyst_review", "unverified", "historical"),
        "lifecycle_status": _enum("active", "withdrawn", "superseded"), "lifecycle_revision_id": _handle("finding_revision"),
        "replacement_finding_id": _handle("finding"), "lifecycle_revision_count": _COUNT, "current": _BOOL, "evidence_current": _BOOL,
        "reason_code": _TEXT}
    verification_assurance = {**_fields("runtime_verified analyst_review unverified historical code_hint hint_only other_unverified", _COUNT),
        "hints_count_as_findings": _Rule("false"), "runtime_level_implies_full_coverage": _Rule("false"), "note_zh": _TEXT}
    candidate = {**_fields("kind url finalUrl method protocol name reason created_at updated_at source sources hint inputs locator path link"),
        "id": _handle("candidate"), "operation_id": _handle("operation"), "status": _enum("unverified", "linked", "dismissed"),
        "link": {**_fields("input_location input_selector linked_at"), "operation_id": _handle("operation")},
        "candidate_closure": {"version": _COUNT, "basis": _enum("outside_scope", "duplicate_operation", "assessed_hint"),
            "operation_id": _handle("operation"), "decision_ids": _Many(_handle("decision"))},
        "verification_level": _enum("hint_only", "code_hint"), "suggested_test_families": _Many(family),
        "source_kind": _enum("target_definition", "validator_export", "assessment_checklist"),
        "validator_result": _enum("hint", "valid", "type_error", "param_error", "unregistered"),
        "hints_only": _Rule("true"), "independent_evidence_required": _Rule("true"),
        "usable_for_confirmation": _Rule("false"), "taint_proven": _Rule("false"), "consumer_declaration_allowed": _Rule("false"),
        **_fields("method_requires_binding references_limited bindings_limited", _BOOL),
        "binding_status": _enum("possible", "ambiguous", "unresolved"),
        **_fields("sink category declared_type referenced_fields value_kind"), **_fields("source_line source_column", _COUNT),
        "possible_input_bindings": _Many({**_fields("url protocol operation_name content_type input_name input_selector schema_branch request_locator"),
            "method": method, "input_location": input_row["location"], "request_locator_count": _COUNT,
            "matching_basis": _enum("same_bundle_field_name_only")})}
    browser_action = {**_fields("selector text message error reason finalUrl key value"), "index": _COUNT, "action_index": _COUNT,
        "action": _enum("click", "fill", "press", "wait", "waitForSelector"), "type": _enum("click", "fill", "press", "wait", "waitForSelector"), "ok": _BOOL}
    visit = {**_fields("url finalUrl title signals console dialogs source_meta forms inputs buttons links textLength selectorCount "
                       "navigation_trail blocked_requests write_requests blocked_reason note artifact_path screenshot html after_actions_html created_at "
                       "started_at finished_at error error_code page_adoption_error"),
        "id": _handle("page_visit"), "run_id": _handle("run"), "session_id": _handle("session"), "actor_id": _handle("actor"),
        "page_visit_id": _handle("page_visit"), "visit_id": _handle("page_visit"), "planned_page_visit_id": _handle("page_visit"),
        "sha256": _SHA256, "source_file_sha256": _SHA256, "screenshot_sha256": _SHA256, "html_sha256": _SHA256, "after_actions_html_sha256": _SHA256,
        "kind": _enum("page_visit", "browser"), "source": _enum("local_playwright", "imported_mcp"), "trust": _enum("observed_render", "imported_mcp"),
        "observation_status": _enum("visited", "BLOCKED"), "run_status": _enum("running", "interrupted", "succeeded", "failed"),
        "status": _Rule("http_status"), "effect": _enum("read_only", "test_resource_write"), "next_action": action,
        **_fields("network_count action_count session_generation", _COUNT),
        **_fields("write_authorized complete machine_authenticated scope_enforced dispatch_attempted allow_write redaction_context_required "
                  "redaction_context_available redaction_context_checked headless network_truncated", _BOOL),
        "actions": _Many(browser_action), "artifact_path": _Rule("path"), "screenshot": _Rule("path"), "html": _Rule("path"),
        "after_actions_html": _Rule("path"), "request_signature": _digest("BR"), "actor_signature": _digest("AS"),
        "page_ids": _Many(_handle("page")), "page_adoption": _enum("adopted", "incomplete")}
    visit.update(_record_timestamps("page_visit", "created_at"))
    page_row = {**_fields("name url source trigger apis reason blocked_reason visited_at triggered_at created_at"),
        "id": _handle("page"), "page_id": _handle("page"), "function_id": _handle("function"), "page_visit_id": _handle("page_visit"),
        "visit_id": _handle("page_visit"), "visited": _BOOL, "triggered": _BOOL, "action_index": _COUNT,
        "visit_status": _enum("visited", "BLOCKED"), "trigger_status": _enum("triggered", "BLOCKED")}
    page_row["functions"] = _Many({**page_row, "id": _handle("function")})
    frontier_row = {**_fields("reason evidence_ids page_visit_ids"), "status": _enum("reviewed", "planned", "completed", "not_applicable", "api_only", "blocked"),
                    "test_family": family, "evidence_ids": _Many(_handle("evidence")), "page_visit_ids": _Many(_handle("page_visit"))}
    frontier = {"complete": _BOOL, "discovery": frontier_row, "categories": _Many(frontier_row), "pages": frontier_row}
    checkpoint = {**_fields("label created_at"), "id": _handle("checkpoint"), "snapshot_id": _digest("CS", 64), "progress_id": _digest("PR", 64),
        "semantic_progress_id": _digest("PR", 64), "semantic_progress_changed": _BOOL,
        "previous_checkpoint_id": _handle("checkpoint"), "progress_changed": _BOOL, "remaining": remaining,
        "completion_status": completion["status"], "frontier_review": frontier,
        "parameter_delta": {**_fields("comparison_available projection_complete items_truncated tested_comparison_available "
                                      "variant_comparison_available tested_projection_complete variant_projection_complete", _BOOL),
            **_fields("newly_tested_total newly_observed_variants_total reopened_total", _COUNT),
            "newly_tested": _Many(parameter_identity), "newly_observed_variants": _Many(parameter_identity),
            "observation_is_testing": _Rule("false")}}
    finalization = {**_fields("explanation reviewer created_at"), "id": _handle("finalization"), "checkpoint_id": _handle("checkpoint"),
        "snapshot_id": _digest("CS", 64), "reason": _enum("completed"), "reason_basis": _enum("engine_gate"),
        "stop_policy": _enum("exhaustion_only"), "stop_policy_version": _COUNT, "completion_status": completion["status"],
        **_fields("can_claim_complete automatic_stop_allowed frontier_reviewed external_constraint_verified blocker_facts_verified", _BOOL), "remaining": remaining}
    result = {name: {} for name in CONTRACTS}
    config = {**_fields("project_id target created_at external_tools"), "scope": _Many(_TEXT), "exclude": _Many(_TEXT),
              "allow_mutation": _BOOL, "schema_version": _COUNT}
    from .security_hypotheses import SECURITY_PROPERTIES, MISSING_CONTEXT_CODES

    recon_mode, recon_section = _enum("prepare", "aggregate"), _enum("overview", "technologies", "functions", "clues", "collection", "hypotheses")
    recon_item = {**_fields("name category version signal reason url target_origin trigger required_input_fields"),
        "kind": _enum("site", "api_operation", "page_function", "link", "form", "script", "http_baseline",
                      "policy_and_input_context", "page_observation", "function_interaction", "scope_seed", "discovery_review"),
        "method": method, "auth": operation["auth"], "confidence": _enum("hint"), "trust": _enum("unverified"),
        "operation_id": _handle("operation"), "page_id": _handle("page"), "function_id": _handle("function"),
        "page_visit_id": _handle("page_visit"), "evidence_id": _handle("evidence"),
        "operation_ids": _Many(_handle("operation")), "matched_operation_ids": _Many(_handle("operation")),
        "observation_state": _enum("observed", "not_observed", "not_checked"),
        "interaction_state": _enum("observed", "not_observed", "not_checked"),
        "inputs": _Many(input_row), "apis": _Many(_TEXT), "technologies": _Many(_TEXT),
        **_fields("operation_total page_total input_total unknown_consumer_total unmapped_input_total", _COUNT),
        **_fields("ambiguous external inputs_preview_truncated apis_preview_truncated input_review_required", _BOOL),
        "declared_test_families": _Many(family), "action": action, "detail_action": action, "testing_action": action,
        "automatic_execution_allowed": _Rule("false"), "profile_is_security_evidence": _Rule("false"),
        "locator_requires_binding": _Rule("true"),
        "input_template": {"operation_id": _handle("operation"), "obligation_id": _handle("obligation"), "page_id": _handle("page")},
        "id": _digest("HYP"), "security_property": _enum(*sorted(SECURITY_PROPERTIES)),
        **_fields("label_zh inference_basis controls_zh note_zh input_selector schema_branch"),
        "input_location": input_row["location"], "suggested_test_families": _Many(family),
        "source": {"kind": _enum("registered_operation"), "operation_id": _handle("operation"),
                   "operation_signature": _digest("S"), "context_trust": _enum("declared")},
        "observed_evidence_ids": _Many(_handle("evidence")), "observations_are_property_proof": _Rule("false"),
        "missing_context": _Many(_enum(*sorted(MISSING_CONTEXT_CODES))), "hint_only": _Rule("true"),
        "usable_for_confirmation": _Rule("false"), "next_action": action, "help_input": {"name": action}}
    recon_summary = {**_fields("origin_total operation_total page_total function_total input_total technology_total clue_total "
        "collection_task_total http_observation_total processed_observation_total current_observation_total "
        "unusable_observation_total omitted_observation_total unobserved_operation_total unvisited_page_total unregistered_ui_page_total "
        "unknown_consumer_total out_of_scope_clue_total out_of_scope_operation_total out_of_scope_api_reference_total "
        "truncated_source_total parse_error_total hypothesis_total", _COUNT), "source_limited": _BOOL, "hypothesis_limited": _BOOL}
    result["surface.recon"] = {**page, "mode": recon_mode, "section": recon_section, "items": _Many(recon_item), "total": _COUNT,
        "summary": recon_summary, "stage": _enum("prepare_collection", "collect_missing_information", "ready_for_hypotheses"),
        "baseline_id": _handle("recon_baseline"), "baseline_reused": _BOOL, "baseline_changed": _BOOL,
        "delta": _fields("new_technology_total removed_technology_total new_function_total removed_function_total "
                         "new_clue_total removed_clue_total", _COUNT),
        "workflow": _Many(_enum("scope_and_identity", "pages_assets_and_api_sources", "functions_and_inputs", "information_baseline", "targeted_hypotheses")),
        "requests_sent": _COUNT, "automatic_execution_allowed": _Rule("false"), "profile_is_security_evidence": _Rule("false"),
        "completion_claim_allowed": _Rule("false"), "unknown_surface_exhausted": _Rule("false"), "next_action": action,
        "collection_entry": {"action": _enum("surface.recon"), "input": {"mode": recon_mode, "section": recon_section, "limit": _COUNT}},
        "hypothesis_entry": {"action": _enum("surface.recon"), "input": {"mode": recon_mode, "section": recon_section, "limit": _COUNT}},
        "limitations": _Many(_TEXT)}
    result.update({"surface.register": operation, "surface.declare_consumer": {"operation_id": _handle("operation"), "input": input_row, "plan": {"added": _COUNT}},
        "identity.actor": actor, "identity.session": session,
        "identity.resource": resource, "identity.verify": {"session": session, "evidence_id": _handle("evidence"),
                                                          "identity_assertion_limitation": _TEXT},
        "surface.list": {**page, "operations": _Many(operation), "operation_total": _COUNT, "registration_is_testing": _BOOL},
        "surface.inspect": {**page, "operation": operation, "inputs": _Many(input_row), "input_total": _COUNT,
                            "obligations": _Many(gap), "obligation_total": _COUNT, "obligations_truncated": _BOOL, "resources": _Many(resource),
                            "inspection_limited": _BOOL, "help_input": {"name": action},
                            "input_identity_error": {"code": _enum("input", "input_selector", "input_schema_branch"),
                                "operation_id": _handle("operation"), "field": _TEXT}},
        "surface.batch": {**_fields("accepted rejected plan_added requests_sent", _COUNT), "next_action": action,
                          "results": _Many({"index": _COUNT, "status": _enum("accepted", "rejected"), "operation_id": _handle("operation"),
                                            "input_count": _COUNT, **_fields("error_code message"), "next_action": action, "help_input": {"name": action}})},
        "surface.import": {"operation_ids": _Many(_handle("operation")), **_fields("candidates candidate_total", _COUNT), "limitations": _TEXT},
        "project.update": {**_fields("project_id changes"), "config": config, "changed": _BOOL},
        "project.status": {**common_coverage, **_fields("project_id path"), "config": config, "next_action": action,
            **_fields("candidates actor_total actor_next_offset session_total session_next_offset run_total run_next_offset", _COUNT),
            "candidate_states": _fields("unverified linked dismissed", _COUNT), "actors": _Many(actor), "sessions": _Many(session), "runs": _Many(run)},
        "plan.build": common_coverage, "plan.list": common_coverage, "report.coverage": common_coverage,
        "plan.next": {**common_coverage, **_fields("queue_total ready_total review_total blocked_total review_followup_total requests_sent", _COUNT),
            "work_items": _Many(work), "blocked_sample": _Many(work), "review_followups": _Many(checklist), "browser_testing_summary": browser_counts,
            "queue_policy": _enum("family_round_robin", "coverage_first"), "queue_fairness": _enum("family_and_operation_round_robin"),
            "closure_action": action, "review_followup_action": action, "limitation": _TEXT},
        "plan.audit": {**common_coverage, **_fields("project_id technical_blindspots note_zh"),
            "layers": {"registered": _fields("operations inputs", _COUNT), "observed": _fields("operations http_observations browser_visits", _COUNT),
                       "assessed": _fields("operations valid_decisions current_findings", _COUNT),
                       "security": _fields("operations_complete evaluated_obligations", _COUNT)},
            "category_matrix": _Many({**bucket, "test_family": family, **_fields("declared_inputs untraced_inputs", _COUNT),
                                     "status": _enum("not_planned", "open", "blocked", "not_applicable", "completed", "review_required"), **_fields("label_zh proof_channels")}),
            "checklist": _Many(checklist), **_fields("requests_sent checklist_total candidate_proof_accounted administrative_reviews", _COUNT)},
        "plan.disposition": gap, "http.capture": evidence, "evidence.inspect": evidence,
        "http.preflight": {**_fields("ready", _BOOL), **_fields("requests_sent body_bytes max_bytes", _COUNT), "operation_id": _handle("operation"),
            "method": method, "url": _TEXT, "request_signature": _digest("REQ"), "auth_mode": evidence["auth_mode"],
            "session_id": _handle("session"), "resource_id": _handle("resource"), "timeout": _NUMBER,
            "existing_run_id": _handle("run"), "next_action": action, "limitation": _TEXT},
        "scenario.preflight": preflight, "scenario.run": run, "run.inspect": run,
        "run.recover": {"recovered": _Many(_handle("run")), "requests_replayed": _COUNT},
        "assessment.evaluate": {**_fields("oracle proof created_at reason"), "id": _handle("decision"), "obligation_id": _handle("obligation"),
            "operation_id": _handle("operation"), "operation_signature": _digest("S"), "outcome": _enum("observed", "denied", "confirmed", "refuted"),
            "mode": _enum("machine", "analyst"), "oracle_version": _COUNT, "evidence_ids": _Many(_handle("evidence"))},
        "assessment.prepare": {**page, "continuation": continuation, "completion": completion,
            "source": {"operation_id": _handle("operation"), "obligation_id": _handle("obligation"),
                       "finding_id": _handle("finding"), "evidence_id": _handle("evidence")},
            **_fields("total source_evidence_total requests_sent decisions_created", _COUNT),
            "automatic_execution_allowed": _Rule("false"), "controls_are_candidates_only": _Rule("true"),
            "note_zh": _TEXT, "evidence_reviews": _Many(evidence),
            "items": _Many({"obligation_id": _handle("obligation"), "operation_id": _handle("operation"),
                "obligation_kind": gap["obligation_kind"], "test_family": family, "status": state,
                "actor_id": _handle("actor"), "baseline_actor_id": _handle("actor"), "resource_id": _handle("resource"),
                **_fields("input_selector schema_branch required_experiment_fields note_zh"),
                "input_location": input_row["location"],
                "controls_are_candidates_only": _Rule("true"), "evidence_review_required": _Rule("true"),
                **_fields("positive_machine_adapter runtime_binding_supported observations_limited schema_branch_requires_binding hints_only", _BOOL),
                "control_candidate_evidence_ids": _Many(_handle("evidence")), "control_candidate_required_values": _COUNT,
                "control_review_blockers": _Many(_enum("roles_unverified", "actor_independence", "declared_access_policy")),
                "decision_id": _handle("decision"), "outcome": _enum("confirmed", "refuted", "inconclusive"),
                "preparation_state": _enum("proof_current", "proof_outside_selection", "needs_consumer", "needs_policy_or_identity", "inspect_existing", "needs_controls", "frozen"),
                "suggested_action": action, "assessment_action": action, "input_template": template, "help_input": {"name": action},
                "assessment_template": template, "suggested_test_families": _Many(family),
                 "runtime_binding_modes": _Many(_enum("direct_document", "stored_api")),
                "scenario_run_ids": _Many(_handle("run")), "oracle_options": _Many({
                    "oracle_type": _enum("baseline", "authorization", "semantic_negative", "extraction", "sql_metadata", "error_channel", "state_invariant", "state_transition"),
                    "oracle_template": {"type": _enum("baseline", "authorization", "semantic_negative", "extraction", "sql_metadata", "error_channel", "state_invariant", "state_transition"), "test_family": family},
                    **_fields("evidence_order required_fields conditional_fields"), "can_confirm": _BOOL,
                    "help_input": {"name": action}})})},
        "finding.record": finding, "finding.list": {**page, "findings": _Many(finding), "finding_total": _COUNT},
        "finding.bind": {"finding": finding, "previous_finding": finding,
            "decision_id": _handle("decision"), "obligation_id": _handle("obligation"),
            "requests_sent": _COUNT, "original_proof_preserved": _Rule("true"),
            "revision": {**_fields("reviewer reason created_at"), "id": _handle("finding_revision"), "finding_id": _handle("finding"),
                "previous_status": finding["lifecycle_status"], "status": finding["lifecycle_status"], "replacement_finding_id": _handle("finding")}},
        "finding.update": {"finding": finding, "original_proof_preserved": _BOOL,
            "revision": {**_fields("reviewer reason created_at"), "id": _handle("finding_revision"), "finding_id": _handle("finding"),
                "previous_status": finding["lifecycle_status"], "status": finding["lifecycle_status"], "replacement_finding_id": _handle("finding")}},
        "candidate.list": {**page, "candidates": _Many(candidate), "candidate_total": _COUNT, "counts": _fields("unverified linked dismissed", _COUNT)},
        "candidate.inspect": {"candidate": candidate, "operation": operation},
        "candidate.link": candidate, "candidate.dismiss": candidate, "candidate.reopen": candidate,
        "browser.visit": visit, "browser.import_mcp": visit, "page.register": page_row, "page.function": {**page_row, "id": _handle("function")},
        "page.mark": page_row, "page.adopt": {"page_visit_id": _handle("page_visit"), "page_ids": _Many(_handle("page")), "pages": _Many(page_row)},
        "page.coverage": {"unvisited": _Many(page_row), "untriggered": _Many(page_row),
                          **_fields("pages functions pages_visited functions_triggered", _COUNT), "complete": _BOOL, "note": _TEXT},
        "plan.checkpoint": {"checkpoint": checkpoint, "continuation": continuation, "requests_sent": _COUNT, "note": _TEXT},
        "plan.review": {"review": {**_fields("reviewer reason created_at readback_bindings"), "id": _handle("closure_review"),
            "checklist_id": _Rule("checklist"), "source_id": _Rule("source_handle"),
            "kind": _enum("unassessed_observation", "failed_partial_tool", "unreconciled_run", "orphan_browser_visit", "unlinked_analyst_finding"),
            "status": _enum("reviewed", "blocked", "reopen"), "evidence_ids": _Many(_handle("evidence"))}, "continuation": continuation, "requests_sent": _COUNT, "note": _TEXT},
        "plan.finalize": {"finalization": finalization, "continuation": continuation, "requests_sent": _COUNT, "note": _TEXT},
        "report.build": {**_fields("report summary manifest reproduction_dir generated_at"), "stage": _enum("draft", "final"),
            "verification_assurance": verification_assurance,
            "completion": completion, "continuation": continuation, "finalization": finalization, "snapshot": _BOOL,
            "delivery_status": _enum("draft", "final-completed"),
            "report_sha256": _SHA256, "summary_sha256": _SHA256, "manifest_sha256": _SHA256},
        "project.import_pentest": {**_fields("operations_imported candidates_created legacy_findings_seen unmapped_findings", _COUNT),
            "operation_ids": _Many(_handle("operation")), **_fields("operation_mapping ambiguous_legacy_ids skipped_operations source_hashes limitations"),
            "source_modified": _BOOL, "verification_inherited": _BOOL}})
    for name in ("tool.probe", "tool.sqlmap", "tool.yakit_replay", "tool.tscanplus_request", "tool.tscanplus_results",
                 "tool.tscanplus_summary", "tool.tscanplus_routes", "tool.inspect"):
        result[name] = run
    result["test.run"] = {
        "outcome": _enum("observed", "supported", "refuted", "inconclusive", "effect_unknown"),
        "run": {**_fields("id status mode error evaluation effect evidence_ids"), "id": _TEXT,
                "status": _enum("prepared", "claimed", "dispatch_started", "response_saved", "effect_unknown",
                                "evaluation_pending", "evaluated", "published", "failed", "cancelled", "interrupted"),
                "effect": {"unknown": _BOOL, "reconciled": _BOOL, "kind": _enum("read_only", "test_resource_write", "unknown")},
                "evidence_ids": _Many(_handle("evidence"))},
        "finding": dict(result["finding.record"]),
        "coverage_delta": {**_fields("tested finding_created family"), "tested": _COUNT, "finding_created": _BOOL},
        "replayed": _BOOL, "requires_reconciliation": _BOOL, "notice": _TEXT,
    }
    result["test.inspect"] = {**_fields("private_capsule_available control_count"), "recipe": _TEXT, "run": _TEXT}
    result["campaign.status"] = {
        "campaign": _TEXT, "universe": _TEXT, "dimensions": _TEXT, "family_matrix": _TEXT,
        "route_matrix": _TEXT, "consumer_matrix": _TEXT, "known_case_matrix": _TEXT,
        "known_case_summary": _TEXT, "tool_yield": _TEXT, "finding_summary": _TEXT,
        "delivery": _TEXT, "unplanned_family_count": _COUNT, "unregistered_route_count": _COUNT,
        "open_hypothesis_count": _COUNT, "open_gap_count": _COUNT, "capabilities": _TEXT,
        "next_action": _TEXT}
    result["report.matrix"] = {
        "campaign_id": _TEXT, "universe": _TEXT, "dimensions": _TEXT, "family_matrix": _TEXT,
        "route_matrix": _TEXT, "consumer_matrix": _TEXT, "known_case_matrix": _TEXT,
        "known_case_summary": _TEXT, "tool_yield": _TEXT, "finding_summary": _TEXT,
        "delivery": _TEXT, "denominators": _TEXT, "computed_by": _TEXT}
    result["tool.artifact"] = {**_fields("content name trust finding_status"), "run_id": _handle("run"),
                                **_fields("offset limit total_chars next_offset", _COUNT), "usable_for_confirmation": _BOOL}
    error = {"code": _enum(*_ERROR_CODES), "message": _TEXT, "details": {**_fields("field step_id reason missing_prerequisites"), "action": action,
        "next_action": action, "help_action": action, "help_input": {"name": action}, "continuation": continuation,
        "test_family": family, "framing_issue": _enum("utf8_bom", "invalid_multipart"),
        "reason_code": _enum("not_configured", "backend_mismatch", "overescaped_path", "not_absolute", "file_missing",
                             "wrong_filename", "invalid_path", "source_input_mismatch", "consumption_chain_required"),
        "execution_backend": _enum("native", "wsl"), "path_field": _enum("sqlmap_path", "yak_path"), "configured": _BOOL,
        "input_template": {"backend": _enum("all", "native", "wsl")},
        "repair": _enum("rewrite_utf8_without_bom", "rebuild_exact_multipart"),
        "oracle_type": _enum("baseline", "authorization", "semantic_negative", "extraction", "sql_metadata", "error_channel", "state_invariant", "state_transition"),
        "required_fields": _Many(_TEXT),
        "completion": completion, "checkpoint_action": action, "stop_policy": _enum("exhaustion_only"),
        "progress_export": {"action": action, "input": {"stage": _enum("draft")}},
        "run_id": _handle("run"), "operation_id": _handle("operation"), "obligation_id": _handle("obligation"),
        "evidence_id": _handle("evidence"), "candidate_id": _handle("candidate"), "steps": _Many(checkpoint_step),
        "requests_sent": _COUNT, "requests_replayed": _COUNT}}
    visited = set()

    def privacy_controls(shape):
        if isinstance(shape, dict):
            if id(shape) in visited:
                return
            visited.add(id(shape))
            for child in list(shape.values()):
                privacy_controls(child)
            shape.update({key: _Rule("true") for key in ("url_redacted", "path_redacted", "locator_requires_binding", "native_input_requires_binding")})
            shape["requestable"] = _Rule("false")
        elif isinstance(shape, _Many):
            privacy_controls(shape.item)

    for shape in result.values():
        privacy_controls(shape)
    privacy_controls(error)
    return result, error


_ACTION_SCHEMAS = None
_ERROR_SCHEMA = None


def publish(project, action, result, *, minted=None):
    global _ACTION_SCHEMAS, _ERROR_SCHEMA
    if _ACTION_SCHEMAS is None:
        _ACTION_SCHEMAS, _ERROR_SCHEMA = _schemas()
    schema = _ACTION_SCHEMAS.get(action, {})
    if action == "run.inspect" and isinstance(result, dict) and result.get("kind") == "browser":
        schema = {**schema, **_ACTION_SCHEMAS["browser.visit"], "id": _handle("run"),
                  "status": _enum("running", "interrupted", "succeeded", "failed"),
                  **_record_timestamps("run", "started_at finished_at completed_at")}
    return PublicationContext(project, minted=minted).metadata(result, schema=schema)


def publish_report_summary(project, summary, *, extra_secrets=(), files=None):
    """Publish the engine-built disk summary, not arbitrary source or target trees."""
    global _ACTION_SCHEMAS, _ERROR_SCHEMA
    if _ACTION_SCHEMAS is None:
        _ACTION_SCHEMAS, _ERROR_SCHEMA = _schemas()
    context = PublicationContext(project, extra_secrets=extra_secrets)
    finding = dict(_ACTION_SCHEMAS["finding.record"])
    proof = {**_fields("channel source metadata_type input_location input_selector response_selector recovered_value observed_change "
                       "expression source_reference witness marker consumer_url limitations content_selector resource_selector schema_branch runtime_marker"),
             "operation_id": _handle("operation"), "obligation_id": _handle("obligation"), "tool_run_id": _handle("run"),
             "visit_id": _handle("page_visit"), "runtime_visit_id": _handle("page_visit"),
             "normal_runtime_visit_id": _handle("page_visit"), "read_operation_id": _handle("operation"),
             "resource_id": _handle("resource"), "readback_evidence_ids": _Many(_handle("evidence")),
             "binding_version": _COUNT, "mechanism": _enum("stored_api_consumer"),
             "operation_signature": _digest("S"), "read_operation_signature": _digest("S"),
             "input_signature": _digest("I"), "resource_signature": _digest("RS"),
             "artifact_sha256": _SHA256, "normal_artifact_sha256": _SHA256,
             "consumption_signature": _digest("XCHAIN"),
             "identity": {"actor_id": _handle("actor"), "session_id": _handle("session"), "session_generation": _COUNT},
             "viewer_identity": {"actor_id": _handle("actor"), "session_id": _handle("session"), "session_generation": _COUNT},
             **{name: _handle("evidence") for name in ("baseline_evidence_id", "recovery_evidence_id", "negative_evidence_id",
                                                      "control_evidence_id", "injection_evidence_id", "before_evidence_id",
                                                      "action_evidence_id", "after_evidence_id", "attack_evidence_id")}}
    finding["proof"] = proof
    coverage = {**_ACTION_SCHEMAS["report.coverage"], "findings": _Many(finding)}
    group = {"current": _COUNT, "historical": _COUNT,
             "by_severity": _Many({"severity": finding["severity"], "count": _COUNT, "findings": _Many(finding)}),
             "by_category": _Many({"category": _TEXT, "count": _COUNT}), "historical_findings": _Many(finding)}
    step = {**_fields("role url captured_at source_artifact source_sha256 response_sha256 request_body_excerpt response_excerpt "
                      "request_file body_file http_request curl placeholders unavailable_reason subject roles resource registered_inputs"),
            "number": _COUNT, "method": _ACTION_SCHEMAS["surface.register"]["method"], "status_code": _Rule("http_status"),
            "evidence_id": _handle("evidence"), "operation_id": _handle("operation"), "run_id": _handle("run"),
            "actor_id": _handle("actor"), "session_id": _handle("session"), "resource_id": _handle("resource"),
            "session_generation": _COUNT, "auth_mode": _ACTION_SCHEMAS["http.capture"]["auth_mode"],
            **_fields("request_body_truncated response_truncated body_redacted request_template_available response_body_available state_changing", _BOOL),
            "response_observables": _Many({**_fields("selector observed_excerpt source"), "truncated": _BOOL, "sensitive_value_present": _BOOL})}
    step["curl"] = {"posix": _TEXT, "powershell": _TEXT}
    sqlmap = {**_fields("reason parameter input_location input_selector request_file recorded_profile commands scope expected_recorded_metadata note"),
              "available": _BOOL, "manual_only": _Rule("true"), "executed_by_report": _Rule("false"),
              "baseline_evidence_id": _handle("evidence"), "tool_run_id": _handle("run"), "request_method": step["method"],
              "metadata_type": _enum("database", "current_user"),
              "commands": {"posix": _TEXT, "powershell": _TEXT}}
    detail = {**_fields("prerequisites limitations decision_reason unavailable_reason"), "available": _BOOL, "partial": _BOOL, "metadata_only": _BOOL,
              "manual_only": _Rule("true"), "executed_by_report": _Rule("false"), "steps": _Many(step), "sqlmap": sqlmap,
              "evidence_ids": _Many(_handle("evidence")),
              "oracle_type": _enum("baseline", "authorization", "semantic_negative", "state_invariant", "state_transition",
                                   "extraction", "error_channel", "sql_metadata", "analyst_review", "analyst_runtime")}
    details = summary.get("reproduction") if isinstance(summary, dict) else None
    reproduction = {identity: detail for identity in details or {} if context.bound_handle("finding", identity)}
    schema = {**_ACTION_SCHEMAS["report.build"], "format_version": _COUNT, "language": _enum("zh-CN"),
              "project_id": _TEXT, "generated_at": _TEXT, "scope": {"target": _TEXT, "scope": _Many(_TEXT), "exclude": _Many(_TEXT)},
              "coverage": coverage, "finding_groups": group, "operation_metadata": _Many(_ACTION_SCHEMAS["surface.register"]),
              "verification_assurance": _ACTION_SCHEMAS["report.build"]["verification_assurance"],
              "unverified_candidates": _COUNT, "browser_coverage": _ACTION_SCHEMAS["page.coverage"],
              "external_tools": _Many(_ACTION_SCHEMAS["tool.inspect"]), "reproduction": reproduction,
              "reproduction_metadata_only": _BOOL, "reproduction_warnings": _TEXT,
              "artifacts": _Many({"path": _TEXT, "sha256": _TEXT, "size_bytes": _TEXT})}
    public = context.metadata(summary, schema=schema)
    # A complete packet must come from validated generated bytes. Metadata
    # redaction may change protocol tokens, and caller-supplied packets do not
    # acquire a captured binding merely by appearing in the source summary.
    if isinstance(public, dict):
        for projected in (public.get("reproduction") or {}).values():
            if not isinstance(projected, dict):
                continue
            for target in projected.get("steps") or []:
                if isinstance(target, dict):
                    target.pop("http_request", None)
    prepared = files if isinstance(files, dict) else {}
    known_files = {}
    for path, data in prepared.items():
        if not isinstance(path, str) or not isinstance(data, bytes):
            raise EngineError("publication_failed", "A generated report artifact has an invalid local shape")
        if path == "reproduction/README.md":
            known_files[path] = data
            continue
        match = re.fullmatch(r"reproduction/(F-[a-f0-9]{24,32})/([0-9]{2})-(E-[a-f0-9]{24,32})\.(http|json|xml|body)", path)
        if match is None or not context.bound_handle("finding", match[1]) or not context.bound_handle("evidence", match[3]):
            raise EngineError("publication_failed", "A generated report artifact escaped staging or does not bind to the private ledger")
        owner = project.get("finding", match[1])
        decision = project.get("decision", owner.get("decision_id"), required=False)
        ordered = decision.get("evidence_ids", []) if decision else []
        number = int(match[2])
        if not 1 <= number <= len(ordered) or ordered[number - 1] != match[3]:
            raise EngineError("publication_failed", "A generated report artifact does not bind to its recorded step")
        known_files[path] = data
    if isinstance(public, dict) and isinstance(summary, dict):
        from datetime import datetime
        from hashlib import sha256

        generated = summary.get("generated_at")
        if isinstance(generated, str):
            try:
                stamp = datetime.fromisoformat(generated)
            except ValueError:
                pass
            else:
                if stamp.tzinfo is not None:
                    public["generated_at"] = generated
        for original, sanitized in zip(summary.get("artifacts", []), public.get("artifacts", [])):
            if not isinstance(original, dict) or not isinstance(sanitized, dict):
                continue
            path = original.get("path")
            data = known_files.get(path)
            if data is not None and original.get("sha256") == sha256(data).hexdigest() \
                    and type(original.get("size_bytes")) is int and original["size_bytes"] == len(data):
                sanitized.update(path=path, sha256=sha256(data).hexdigest(), size_bytes=len(data))
        for identity, original in (details or {}).items():
            sanitized = public.get("reproduction", {}).get(identity)
            if not context.bound_handle("finding", identity) or not isinstance(original, dict) or not isinstance(sanitized, dict):
                continue
            owner = project.get("finding", identity)
            decision = project.get("decision", owner.get("decision_id"), required=False)
            ordered = decision.get("evidence_ids", []) if decision else []
            for source, target in zip(original.get("steps", []), sanitized.get("steps", [])):
                number = source.get("number") if isinstance(source, dict) else None
                if type(number) is not int or not 1 <= number <= len(ordered) or not isinstance(target, dict):
                    continue
                evidence = project.get("evidence", ordered[number - 1], required=False)
                if not evidence or not context.bound_handle("evidence", evidence["id"]):
                    continue
                target["evidence_id"] = evidence["id"]
                for key, kind in (("operation_id", "operation"), ("run_id", "run"), ("actor_id", "actor"),
                                  ("session_id", "session"), ("resource_id", "resource")):
                    if context.bound_handle(kind, evidence.get(key)):
                        target[key] = evidence[key]
                if context._typed(evidence.get("artifact_path"), _Rule("path")):
                    target["source_artifact"] = evidence["artifact_path"]
                    target["source_sha256"] = evidence["sha256"]
                try:
                    from base64 import b64decode
                    artifact = project.read_artifact(evidence)
                    target["response_sha256"] = sha256(b64decode(artifact["response"]["body_base64"], validate=True)).hexdigest()
                except (EngineError, OSError, ValueError, TypeError, KeyError):
                    pass
                stem = "reproduction/" + identity + "/" + f"{number:02d}-" + evidence["id"]
                if stem + ".http" in known_files:
                    target["request_file"] = stem + ".http"
                for extension in ("json", "xml", "body"):
                    if stem + "." + extension in known_files:
                        target["body_file"] = stem + "." + extension
                        break
                if target.get("request_file") in known_files and target.get("request_template_available") is True:
                    _reproduction_request(project, target, evidence, known_files)
            original_sql, public_sql = original.get("sqlmap"), sanitized.get("sqlmap")
            if isinstance(original_sql, dict) and isinstance(public_sql, dict):
                public_sql.pop("commands", None)
                public_sql.pop("metadata_type", None)
                metadata_type = (decision.get("proof") or {}).get("metadata_type") if decision else None
                if metadata_type in {"database", "current_user"}:
                    public_sql["metadata_type"] = metadata_type
                if public_sql.get("available") is True:
                    _reproduction_sqlmap(project, public_sql, decision, identity,
                                         known_files, sanitized.get("steps", []))
    return public


def _reproduction_request(project, target, evidence, files):
    """Restore the complete packet and compatibility commands from bound bytes."""
    from .reproduction import _commands
    from urllib.parse import urlsplit

    data = files[target["request_file"]]
    head, separator, body = data.partition(b"\r\n\r\n")
    try:
        request_text = data.decode("utf-8", errors="strict")
        lines = head.decode("utf-8", errors="strict").split("\r\n")
        method, path, version = lines[0].split(" ")
        headers = {}
        for line in lines[1:]:
            name, value = line.split(":", 1)
            if name.lower() in headers or re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) is None \
                    or any(character in value for character in "\r\n\x00"):
                raise ValueError()
            headers[name.lower()] = value.strip()
        artifact = project.read_artifact(evidence)
        original = urlsplit(artifact["request"]["url"])
        if not separator or version != "HTTP/1.1" or method != artifact["request"]["method"] \
                or not path.startswith("/") or any(character in path for character in "\r\n\x00") \
                or original.scheme not in {"http", "https"} or headers.get("host") != original.netloc:
            raise ValueError()
        length = headers.get("content-length")
        if length is not None and (not length.isdecimal() or int(length) != len(body)):
            raise ValueError()
    except (EngineError, OSError, UnicodeError, ValueError, KeyError, TypeError) as exc:
        raise EngineError("publication_failed", "A generated request file lacks a safe recorded binding") from exc
    url = original.scheme + "://" + headers["host"] + path
    args = ["--http1.1", "--globoff", "--path-as-is", "--request", method, "--url", url,
            "--connect-timeout", "5", "--max-time", "15", "--max-redirs", "0", "--noproxy", "*", "--proto", "=http,https"]
    for name, value in headers.items():
        if name not in {"host", "content-length", "transfer-encoding", "connection", "accept-encoding"}:
            args += ["--header", name + ": " + value]
    if body:
        body_file = target.get("body_file")
        if body_file not in files or files[body_file] != body:
            raise EngineError("publication_failed", "A generated request body lacks a matching safe file reference")
        args += ["--data-binary", "@" + body_file]
    target.update(url=url, http_request=request_text, curl=_commands(args))


def _reproduction_sqlmap(project, target, decision, finding_id, files, steps):
    """Build SQL commands only from the recorded baseline and its safe packet."""
    from base64 import b64encode
    import shlex
    from .reproduction import _component, _manual_sql_parameter

    def unavailable(reason):
        target.update(available=False, reason=reason)
        target.pop("commands", None)

    target.pop("commands", None)
    target.pop("metadata_type", None)
    proof = (decision or {}).get("proof") or {}
    metadata_type = proof.get("metadata_type")
    if not isinstance(metadata_type, str) or metadata_type not in {"database", "current_user"} \
            or proof.get("channel") == "behavioural_diff":
        unavailable("缺少已绑定的数据库元信息证明；不能将写侧行为或任意请求作为只读 SQL 复核。")
        return
    target["metadata_type"] = metadata_type
    baseline_id = proof.get("baseline_evidence_id") or proof.get("control_evidence_id")
    ordered = (decision or {}).get("evidence_ids") or []
    if not isinstance(baseline_id, str) or not isinstance(ordered, list) or ordered.count(baseline_id) != 1:
        unavailable("缺少证明明确绑定的正常 SQL 请求；不能用首个或攻击请求代替基线。")
        return
    number = ordered.index(baseline_id) + 1
    request_file = "reproduction/" + finding_id + "/" + f"{number:02d}-" + baseline_id + ".http"
    baseline_step = next((step for step in steps if isinstance(step, dict)
                          and step.get("number") == number and step.get("evidence_id") == baseline_id
                          and step.get("request_file") == request_file), None)
    data = files.get(request_file)
    if baseline_step is None or not isinstance(data, bytes) \
            or not isinstance(baseline_step.get("http_request"), str) \
            or baseline_step["http_request"].encode("utf-8") != data:
        unavailable("正常 SQL 请求缺少已验证的完整 HTTP 文件；不生成 sqlmap 命令。")
        return
    baseline = project.get("evidence", baseline_id, required=False)
    if not baseline:
        unavailable("正常 SQL 请求已无法绑定原始证据。")
        return
    obligation = project.get("obligation", decision.get("obligation_id"), required=False) \
        if decision.get("obligation_id") else {}
    run_id = proof.get("tool_run_id")
    recorded = {}
    if run_id:
        try:
            from .external import inspect as inspect_tool
            run = project.get("run", run_id)
            inspected = inspect_tool(project, {"run_id": run_id})
            if inspected.get("integrity") != "valid" or not inspected.get("usable_for_confirmation") \
                    or inspected.get("adapter") != "sqlmap" or inspected.get("action") != "metadata" \
                    or inspected.get("status") != "succeeded" or inspected.get("exit_code") != 0 \
                    or inspected.get("metadata_only") is not True:
                raise ValueError("The SQL execution no longer has a current immutable binding")
            recorded = project.read_artifact(run).get("execution") or {}
        except (EngineError, OSError, ValueError, KeyError, TypeError):
            unavailable("历史 sqlmap 参数或执行血缘不可校验；不重建命令。")
            return
    sources = [proof, obligation or {}, recorded]
    locations = [source["input_location"] for source in sources if source.get("input_location") is not None]
    selectors = [source["input_selector"] for source in sources if source.get("input_selector") is not None]
    if not locations or not selectors or not all(isinstance(value, str) for value in locations + selectors) \
            or any(value != locations[0] for value in locations) \
            or any(value != selectors[0] for value in selectors) or locations[0] not in {"query", "body"} \
            or not isinstance(selectors[0], str) or not selectors[0] \
            or any(source.get("operation_id") is not None and source.get("operation_id") != baseline.get("operation_id")
                   for source in [decision, *sources]):
        unavailable("SQL 输入位置、选择器或操作绑定缺失或不一致；不猜测 sqlmap 参数。")
        return
    try:
        # The packet has passed _reproduction_request. Recheck its final field
        # names after redaction instead of assuming the original -p still fits.
        head, separator, body = data.partition(b"\r\n\r\n")
        lines = head.decode("utf-8").split("\r\n")
        request = {"method": lines[0].split(" ", 1)[0], "url": baseline_step["url"],
                   "headers": dict(line.split(":", 1) for line in lines[1:]),
                   "body_base64": b64encode(body).decode("ascii")}
        parameter = _manual_sql_parameter(project, {"evidence_id": baseline_id, "resource_id": baseline.get("resource_id")},
                                          locations[0], selectors[0], request=request)
        if recorded.get("tool_parameter") is not None and recorded["tool_parameter"] != parameter:
            raise ValueError("The recorded parameter differs from the safe baseline")
    except (EngineError, OSError, UnicodeError, ValueError, KeyError, TypeError):
        unavailable("正常 HTTP 文件中的 SQL 输入缺失、受保护或不唯一；无法绑定可用的 sqlmap -p 参数。")
        return
    target.update(parameter=parameter, baseline_evidence_id=baseline_id, request_file=request_file,
                  request_method=request["method"], metadata_type=metadata_type,
                  input_location=locations[0], input_selector=selectors[0],
                  manual_only=True, executed_by_report=False)
    target.pop("reason", None)
    args = ["-r", request_file, "-p", parameter, "--batch", "--level=1", "--risk=1", "--threads=1", "--technique=BEU",
            "--timeout=5", "--retries=0", "--ignore-redirects", "--ignore-proxy", "--disable-coloring",
            "--output-dir=sqlmap-results/" + _component(finding_id, "F"), "--fresh-queries"]
    if request["url"].startswith("https://"):
        args += ["--force-ssl"]
    dbms = recorded.get("dbms")
    if dbms in {"MySQL", "PostgreSQL", "Microsoft SQL Server", "Oracle", "SQLite"}:
        args += ["--dbms=" + dbms]
    if dbms == "SQLite":
        from .external import SQLITE_DATABASE_QUERY
        args += ["--sql-query=" + SQLITE_DATABASE_QUERY]
    else:
        args += ["--current-db", "--current-user"]
    target["commands"] = {"posix": 'python3 -X utf8 "$AWA_SQLMAP_PATH" ' + shlex.join(args),
                          "powershell": "& 'python' '-X' 'utf8' $env:AWA_SQLMAP_PATH " +
                          " ".join("'" + item.replace("'", "''") + "'" for item in args)}


EXECUTION_ACTIONS = frozenset({"http.capture", "identity.verify", "scenario.run", "browser.visit", "browser.probe", "tool.probe",
    "tool.sqlmap", "tool.yakit_replay", "tool.tscanplus_request", "tool.tscanplus_results", "tool.tscanplus_summary", "tool.tscanplus_routes"})
OFFLINE_MUTATIONS = frozenset({"project.update", "project.import_pentest", "surface.register", "surface.batch", "surface.import",
    "surface.declare_consumer", "identity.actor", "identity.session", "identity.resource", "browser.import_mcp", "page.register",
    "page.adopt", "page.function", "page.mark", "plan.build", "plan.disposition", "plan.checkpoint", "plan.review", "plan.finalize",
    "candidate.link", "candidate.dismiss", "candidate.reopen", "run.recover", "assessment.evaluate", "finding.record", "finding.bind", "finding.update"})


def _persisted_run(project, action, args, previous, result=None, error=None, *, claimed=()):
    from .engine import stable

    expected = {"scenario.run": "scenario", "scenario.preflight": "scenario", "http.capture": "http", "http.preflight": "http",
                "identity.verify": "http", "browser.visit": "browser"}.get(action)
    if expected is None and action.startswith("tool.") and action in EXECUTION_ACTIONS:
        expected = "external_tool"
    if expected is None:
        return None
    candidates = []
    if isinstance(result, dict):
        candidates.extend(result.get(key) for key in ("run_id", "id"))
    if isinstance(error, EngineError) and isinstance(error.details, dict):
        candidates.append(error.details.get("run_id"))
    candidates.extend(reversed(claimed))
    context = PublicationContext.__new__(PublicationContext)
    context.project, context.minted, context._records = project, {}, {}
    for identity in candidates:
        if not context.bound_handle("run", identity):
            continue
        row = project.get("run", identity, required=False)
        if row.get("kind") != expected:
            continue
        prefix = "SC" if expected == "scenario" else "RUN"
        prior = args.get("idempotency_key") and identity == stable(prefix, args["idempotency_key"])
        if identity not in claimed and not prior:
            continue
        if expected == "http" and row.get("operation_id") != args.get("operation_id"):
            continue
        if expected == "scenario" and row.get("spec_signature") != stable("SPEC", args.get("scenario")):
            continue
        return row
    return None


def _execution_status(row):
    status = row.get("status")
    return status if isinstance(status, str) and status in {"running", "interrupted", "succeeded", "failed"} else "unknown"


def _recovery_error(project, action, args, previous, error, *, result=None, claimed=()):
    row = _persisted_run(project, action, args, previous, result=result, error=error, claimed=claimed)
    code = error.code if isinstance(error, EngineError) and isinstance(error.code, str) \
        and error.code in {"browser_redaction_context", "credential_header_names"} else "publication_failed"
    details = {"publication_status": "unavailable", "automatic_replay_allowed": False}
    if row is not None:
        details.update(run_id=row["id"], execution_status=_execution_status(row),
                       outcome_persisted=True, next_action="run.inspect", requests_replayed=0)
        message = "Public metadata could not be safely published. The recorded execution remains persisted; use run.inspect and inspect its evidence/checkpoints before any new request. Do not automatically replay."
    else:
        message = "Public metadata could not be safely published; restore the required local redaction context and inspect project checkpoints. Do not automatically replay."
    return EngineError(code, message, details)


def _public_error(project, action, args, previous, error, *, claimed=()):
    global _ACTION_SCHEMAS, _ERROR_SCHEMA
    if _ACTION_SCHEMAS is None:
        _ACTION_SCHEMAS, _ERROR_SCHEMA = _schemas()
    try:
        context = PublicationContext(project)
        value = context.metadata({"code": error.code, "message": str(error), "details": error.details}, schema=_ERROR_SCHEMA)
        code = value.get("code")
        if not isinstance(code, str) or re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,99}", code) is None:
            code = "engine_error"
        details = value.get("details") if isinstance(value.get("details"), dict) else {}
        row = _persisted_run(project, action, args, previous, error=error, claimed=claimed)
        if row is not None:
            details.update(run_id=row["id"], execution_status=_execution_status(row),
                           outcome_persisted=True, next_action="run.inspect", automatic_replay_allowed=False)
        elif "run_id" in details:
            details.pop("run_id")
        return EngineError(code, value["message"], details)
    except Exception as exc:
        return _recovery_error(project, action, args, previous, exc, claimed=claimed)


def invoke(project, action, args, handler):
    """Offline writes can roll back; dispatched traffic must retain its checkpoints."""
    from .contracts import validate_action_args

    previous = {row["id"] for row in project.list("run")} if action in EXECUTION_ACTIONS else set()
    try:
        # Validate before any handler, including before a network claim/dispatch.
        PublicationContext(project)
    except Exception as exc:
        raise _recovery_error(project, action, args, previous, exc) from exc
    result = None
    minted = {}
    claimed = []
    original_id = project.id
    original_claim = project.claim

    def mint(prefix):
        identity = original_id(prefix)
        kind = {"ACT": "actor", "SES": "session", "RES": "resource", "PG": "page"}.get(prefix)
        if prefix == "FN" and action == "page.function":
            kind = "function"
        if kind:
            minted.setdefault(kind, set()).add(identity)
            with project.transaction():
                project.connection.execute("INSERT OR IGNORE INTO metadata(key,value) VALUES(?,?)",
                                           ("publication_generated_handle:" + kind + ":" + identity, "engine-generated-v1"))
        return identity

    def claim(run):
        saved = original_claim(run)
        claimed.append(saved["id"])
        return saved

    def execute():
        nonlocal result
        validate_action_args(action, args)
        result = handler(project, action, args)
        try:
            return publish(project, action, result, minted=minted)
        except Exception as exc:
            raise _recovery_error(project, action, args, previous, exc, result=result, claimed=claimed) from exc

    project.id = mint
    project.claim = claim
    try:
        if action in OFFLINE_MUTATIONS:
            with project.transaction():
                return execute()
        return execute()
    except EngineError as exc:
        if isinstance(exc.details, dict) and exc.details.get("publication_status") == "unavailable":
            raise
        raise _public_error(project, action, args, previous, exc, claimed=claimed) from exc
    except KeyError as exc:
        error = EngineError("argument_missing", "A required action argument or local record field is missing; inspect action.help for this action.",
                            {"field": str(exc).strip("'"), "action": action, "help_action": "action.help", "help_input": {"name": action}})
        raise _public_error(project, action, args, previous, error, claimed=claimed) from exc
    except (TypeError, ValueError, OSError) as exc:
        error = EngineError("invalid_input", "Wrong argument shape or unavailable local resource; inspect action.help for this action.")
        raise _public_error(project, action, args, previous, error, claimed=claimed) from exc
    except Exception as exc:
        error = EngineError("engine_error", "Operation failed; inspect project checkpoints before any new request.")
        raise _public_error(project, action, args, previous, error, claimed=claimed) from exc
    finally:
        project.id = original_id
        project.claim = original_claim
