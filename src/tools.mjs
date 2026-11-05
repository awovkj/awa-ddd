/** Grouped native tools. All actions dispatch through the same bounded bridge. */
import { HarnessError } from '@deepseek-ai/dsh-llm';
import { invokeEngine, resolveConfig, redactActionResult, safeErrorText, safeErrorDetails, compactContinuation, BridgeError, ENGINE_DISPATCH_UNCERTAIN } from './bridge.mjs';
import { ACTION_GROUPS, V2_ACTION_GROUPS, READ_ACTIONS } from './actions.mjs';
import { GUIDANCE } from './tool-guidance.mjs';

export const MAX_RENDER_BYTES = 24 * 1024;
const BROWSER_SUMMARY_FIELDS = ['required_total', 'assisted_total', 'call_needed_total', 'invoke_now_total',
  'blocked_total', 'native_unsupported_total', 'followup_total', 'task_total'];
const PARAMETER_SUMMARY_FIELDS = ['parameter_total', 'cell_total', 'typed_tested_total', 'untested_total', 'observed_total',
  'variant_observed_total', 'needs_controls_total', 'unobserved_total', 'consumer_review_total', 'observations_limited_total'];
const HELP_HINT = 'Help: awa_project action.help input:{name:"<action>"} (no project_id). Put action-specific fields inside input, not at top level.';
const DETAIL_HINTS = Object.freeze({
  'project.status': 'Page project.status entities with offset/limit and methods with method_offset/method_limit; use surface.inspect for operation detail.',
  'plan.build': 'Use plan.next for the next ready tasks, or page plan.list with offset/limit.',
  'plan.list': 'Follow next_offset using plan.list; plan.next returns a short prioritized queue.',
  'plan.next': 'Request the next short plan.next page; inspect browser_testing.stage/call_needed/invoke_now before execution. Required and assisted both mandate needed Playwright work, but capture_controls/prepare/blocked are not permission to skip prerequisites; qualified existing material is reviewed offline without replay.',
  'plan.audit': 'Follow next_offset for the complete closure checklist; unresolved work is not a security finding or an exclusion.',
  'plan.checkpoint': 'Inspect continuation and persist actual progress after each round; no_progress_rounds requires a changed hypothesis or evidence review, not repeated requests.',
  'plan.review': 'Administrative review does not close a security obligation, candidate or running execution. Recheck plan.audit and continuation.',
  'plan.finalize': 'Only reason:completed after strict registered-scope exhaustion is accepted. Budget/user/authorization/blocked declarations cannot authorize automatic stopping. Preserve interrupted work as a checkpoint and draft; a current validated finalization_id is required for report.build stage:final.',
  'finding.list': 'Page finding.list with offset/limit to inspect complete redacted finding records.',
  'report.coverage': 'Follow next_offset using report.coverage; report.build exports the complete local snapshot.',
  'surface.list': 'Follow next_offset using surface.list, or call surface.inspect with operation_id.',
  'surface.recon': 'Use section and offset/limit to inspect the information profile and collection gaps. Both prepare and aggregate are offline; fingerprints and collection entries are not proof or target-traffic permission.',
  'candidate.list': 'Follow next_offset using candidate.list, or call candidate.inspect with candidate_id.',
  'tool.artifact': 'Follow next_offset using tool.artifact; raw bytes remain in the protected local artifact.',
  'tool.inspect': 'Use tool.artifact for bounded redacted stdout/stderr/traffic/result pages.',
  'tool.tscanplus_request': 'Inspect the saved run/tool artifact before any retry. Tool output remains unverified; interrupted POST effects require fixture reconciliation, never automatic replay.',
  'tool.tscanplus_results': 'Inspect saved result artifacts and candidate.list/inspect for ingested clues. Remote query_results has no offset pagination; never scan or execute route suggestions to recover omitted results.',
  'tool.tscanplus_summary': 'Inspect the saved result artifact for the bounded project summary. Counts are scanner database claims, not completed coverage or permission to execute suggested work.',
  'tool.tscanplus_routes': 'Inspect candidate.list/inspect and the saved redacted result artifact. The local limit is not remote pagination; route suggestions remain untrusted clues and are never executed.',
});

const PAGE_FIELDS = Object.freeze({
  'project.status': ['actors', 'sessions', 'runs'],
  'surface.list': ['operations'], 'surface.inspect': ['inputs'], 'surface.recon': ['items'], 'candidate.list': ['candidates'],
  'plan.build': ['obligation_items'], 'plan.list': ['gaps'], 'plan.next': ['work_items'],
  'plan.audit': ['checklist'], 'assessment.prepare': ['items'], 'finding.list': ['findings'], 'report.coverage': ['gaps'],
});
const PAGE_FILTERS = ['operation_id', 'obligation_id', 'finding_id', 'evidence_id', 'evidence_ids',
  'run_id', 'name', 'method', 'auth', 'status', 'kind', 'mode', 'section', 'current', 'lifecycle_status', 'include_blocked'];
const PARAMETER_FILTERS = ['any', 'untested', 'observed', 'needs_controls', 'tested', 'consumer_review'];
// Python's canonical JSON is sorted by key. Alphabetical truncation used to keep
// descriptions while dropping work_items and the action/identity/fixture gates.
const ROOT_PRIORITY = ['continuation', 'work_items', 'checklist', 'completion', 'offset', 'limit', 'next_offset',
  'queue_total', 'checklist_total', 'ready_total', 'review_total', 'blocked_total', 'requests_sent',
  'browser_testing_summary', 'parameter_coverage_summary', 'review_followups', 'review_followup_total',
  'category_matrix', 'security_coverage', 'parameter_coverage', 'obligation_items', 'operations', 'inputs',
  'method_coverage', 'findings', 'candidates', 'items', 'gaps', 'next_action', 'source', 'summary', 'hypothesis_entry',
  'automatic_execution_allowed', 'decisions_created', 'profile_is_security_evidence', 'completion_claim_allowed', 'unknown_surface_exhausted'];
const TASK_PRIORITY = ['id', 'gap_id', 'obligation_id', 'operation_id', 'obligation_kind', 'kind', 'input_location',
  'input_selector', 'schema_branch', 'test_family', 'hypothesis_family', 'queue_status', 'status', 'suggested_action',
  'next_action', 'input_template', 'missing_prerequisites', 'required_experiment_fields', 'execution_blocked',
  'control_candidate_review_required', 'controls_are_candidates_only', 'evidence_review_required',
  'positive_machine_adapter', 'preparation_state', 'control_candidate_required_values', 'schema_branch_requires_binding',
  'control_candidate_evidence_ids', 'control_review_blockers', 'scenario_run_ids', 'evidence_ids', 'help_input',
  'assessment_action', 'assessment_template', 'oracle_options',
  'assessment_followup_action', 'browser_testing', 'preparation_actions', 'actor_id', 'baseline_actor_id',
  'session_id', 'resource_id', 'finding_id', 'decision_id', 'method', 'url'];
const HYPOTHESIS_PRIORITY = ['id', 'operation_id', 'security_property', 'input_location', 'input_selector', 'schema_branch',
  'source', 'hint_only', 'requestable', 'usable_for_confirmation', 'observations_are_property_proof',
  'next_action', 'input_template', 'help_input', 'missing_context', 'suggested_test_families',
  'observed_evidence_ids', 'inference_basis', 'controls_zh', 'label_zh'];
const BROWSER_PRIORITY = ['requirement', 'must_call_playwright', 'stage', 'call_needed', 'invoke_now',
  'execution_blocked', 'native_supported', 'native_input_requires_binding', 'required_input_fields',
  'native_visit_input', 'provider_route', 'unsupported_capabilities', 'existing_observation'];
const COMPLETION_PRIORITY = ['status', 'registered_scope_only', 'open_obligations', 'open_security_obligations',
  'unassessed_observations', 'unlinked_analyst_findings', 'orphan_browser_visits', 'unresolved_candidates',
  'pages_unvisited', 'functions_untriggered', 'unreconciled_runs', 'unrecorded_confirmations', 'failed_partial_tools',
  'limited_ownership_sampling', 'applicability_review_total', 'scope_reduction_review_total'];
const ATOMIC_TASK_FIELDS = new Set(['input_template', 'native_visit_input', 'help_input',
  'assessment_template', 'required_experiment_fields', 'missing_prerequisites', 'required_input_fields',
  'evidence_ids', 'control_candidate_evidence_ids', 'preparation_actions', 'existing_observation',
  'oracle_template', 'required_fields', 'evidence_order', 'conditional_fields', 'control_review_blockers', 'scenario_run_ids',
  'missing_context', 'suggested_test_families', 'observed_evidence_ids', 'controls_zh', 'hypothesis_entry', 'summary']);
const EXACT_TASK_FIELDS = new Set(['id', 'gap_id', 'obligation_id', 'operation_id', 'input_location', 'input_selector',
  'schema_branch', 'test_family', 'hypothesis_family', 'suggested_action', 'next_action', 'queue_status',
  'actor_id', 'baseline_actor_id', 'session_id', 'resource_id']);
const TASK_ARRAYS = new Set(['work_items', 'checklist', 'review_followups', 'obligation_items', 'preparation_actions']);

function sameJson(left, right) {
  if (left === right) return true;
  if (left === null || right === null || typeof left !== 'object' || typeof right !== 'object') return false;
  if (Array.isArray(left)) return Array.isArray(right) && left.length === right.length
    && left.every((value, index) => sameJson(value, right[index]));
  if (Array.isArray(right)) return false;
  const keys = Object.keys(left);
  return keys.length === Object.keys(right).length
    && keys.every(key => Object.hasOwn(right, key) && sameJson(left[key], right[key]));
}

function projectionPriority(path, node) {
  if (!path.length) return ROOT_PRIORITY;
  if (path.at(-1) === 'browser_testing') return BROWSER_PRIORITY;
  if (path.at(-1) === 'completion') return COMPLETION_PRIORITY;
  if (path.at(-1) === 'source') return node?.kind === 'registered_operation'
    ? ['kind', 'operation_id', 'context_trust', 'operation_signature'] : ['operation_id', 'obligation_id', 'finding_id', 'evidence_id'];
  if (path.at(-1) === '*' && TASK_ARRAYS.has(path.at(-2))) return TASK_PRIORITY;
  if (path.at(-1) === '*' && path.at(-2) === 'items' && typeof node?.security_property === 'string'
      && typeof node?.operation_id === 'string') return HYPOTHESIS_PRIORITY;
  if (path.at(-1) === '*' && path.at(-2) === 'items' && typeof node?.obligation_id === 'string'
      && typeof node?.operation_id === 'string') return TASK_PRIORITY;
  if (path.at(-1) === '*' && path.at(-2) === 'oracle_options') {
    return ['oracle_type', 'oracle_template', 'evidence_order', 'required_fields', 'conditional_fields', 'can_confirm', 'help_input'];
  }
  if (path.at(-1) === '*' && ['category_matrix', 'by_family'].includes(path.at(-2))) {
    return ['test_family', 'status', 'total', 'evaluated', 'open', 'blocked', 'not_applicable',
      'declared_inputs', 'untraced_inputs', 'ratio', 'proof_channels', 'label_zh'];
  }
  if (path.at(-1) === '*' && path.at(-2) === 'items' && path.at(-3) === 'parameter_coverage') {
    return [...TASK_PRIORITY, 'typed_tested', 'parameter_coverage_id', 'observation_count', 'variant_observation_count'];
  }
  if (path.at(-1) === 'parameter_coverage') return ['summary', 'offset', 'limit', 'next_offset', 'total', 'filter', 'items'];
  return [];
}

function projectResult(node, limits, path = [], depth = 0) {
  if (depth > 8) return '[nested detail omitted]';
  const field = path.at(-1);
  // A bounded executable template or prerequisite list stays exact. If it is
  // too large, recovery is required rather than presenting an altered request.
  if (node !== undefined && ATOMIC_TASK_FIELDS.has(field)
      && Buffer.byteLength(JSON.stringify(node), 'utf8') <= 4096) return node;
  if (typeof node === 'string') {
    const bound = EXACT_TASK_FIELDS.has(field) ? Math.max(limits.string, 2048) : limits.string;
    return node.length > bound ? node.slice(0, bound) + ` [${node.length - bound} characters omitted]` : node;
  }
  if (Array.isArray(node)) {
    // These fixed family summaries describe twelve independent categories.
    const bound = ['category_matrix', 'by_family'].includes(field) ? Math.max(12, limits.array) : limits.array;
    const items = node.slice(0, bound).map(child => projectResult(child, limits, [...path, '*'], depth + 1));
    if (node.length > items.length) items.push({ render_omitted_items: node.length - items.length });
    return items;
  }
  if (node === null || typeof node !== 'object') return node;
  const priority = projectionPriority(path, node);
  const rank = new Map(priority.map((key, index) => [key, index]));
  const entries = Object.entries(node).sort(([left], [right]) => (rank.get(left) ?? Infinity) - (rank.get(right) ?? Infinity));
  const result = Object.create(null);
  let omitted = 0;
  for (const [key, child] of entries) {
    // Essential gates do not compete with descriptive fields for the key cap.
    if ((!rank.has(key) && Object.keys(result).length >= limits.keys) || key.length > 160) { omitted++; continue; }
    result[key] = projectResult(child, limits, [...path, key], depth + 1);
  }
  if (omitted) result.render_omitted_fields = omitted;
  if (priority === TASK_PRIORITY && (TASK_PRIORITY.filter(key => key !== 'browser_testing')
      .some(key => Object.hasOwn(node, key) && !sameJson(result[key], node[key]))
      || node.browser_testing && BROWSER_PRIORITY.some(key => Object.hasOwn(node.browser_testing, key)
        && !sameJson(result.browser_testing?.[key], node.browser_testing[key])))) {
    result.render_actionable = false;
  }
  return result;
}

function compactBrowserSummary(value) {
  const result = Object.create(null);
  if (!value || typeof value !== 'object' || Array.isArray(value)) return result;
  for (const key of BROWSER_SUMMARY_FIELDS) {
    if (Number.isSafeInteger(value[key]) && value[key] >= 0) result[key] = value[key];
  }
  return result;
}

function compactParameterSummary(value) {
  const result = Object.create(null);
  if (!value || typeof value !== 'object' || Array.isArray(value)) return result;
  for (const key of PARAMETER_SUMMARY_FIELDS) {
    if (Number.isSafeInteger(value[key]) && value[key] >= 0) result[key] = value[key];
  }
  if (value.observation_is_testing === false) result.observation_is_testing = false;
  return result;
}

function renderControls(data) {
  const result = Object.create(null);
  if (!data || typeof data !== 'object' || Array.isArray(data)) return result;
  const continuation = compactContinuation(data.continuation);
  if (continuation) result.continuation = continuation;
  if (Object.hasOwn(data, 'browser_testing_summary')) {
    result.browser_testing_summary = compactBrowserSummary(data.browser_testing_summary);
  }
  if (data.parameter_coverage_summary || data.parameter_coverage?.summary) {
    result.parameter_coverage_summary = compactParameterSummary(data.parameter_coverage_summary ?? data.parameter_coverage.summary);
  }
  for (const key of ['offset', 'limit', 'next_offset', 'method_offset', 'method_next_offset',
    'actor_next_offset', 'session_next_offset', 'run_next_offset']) {
    if (data[key] === null || (Number.isSafeInteger(data[key]) && data[key] >= 0)) result[key] = data[key];
  }
  return result;
}

function pageRecovery(args, data, projected, limits) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return undefined;
  const originalInput = args?.input && typeof args.input === 'object' && !Array.isArray(args.input) ? args.input : {};
  const filters = Object.create(null);
  const requiredOriginalFilters = [];
  for (const key of PAGE_FILTERS) {
    if (!Object.hasOwn(originalInput, key)) continue;
    const value = originalInput[key];
    if (typeof value === 'boolean') filters[key] = value;
    else if (typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$/.test(value)
      && safeErrorText(value, 160) === value) filters[key] = value;
    else requiredOriginalFilters.push(key);
  }
  const filterRequirements = requiredOriginalFilters.length ? { required_original_filters: requiredOriginalFilters } : {};
  const offsetOf = (key, fallback = 0) => Number.isSafeInteger(data[key]) && data[key] >= 0
    ? data[key] : Number.isSafeInteger(originalInput[key]) && originalInput[key] >= 0 ? originalInput[key] : fallback;
  // Keeping every row does not mean its selectors, controls or nested fields survived.
  const omitted = fields => fields.filter(key => Array.isArray(data[key]) && data[key].length > 0 &&
    !sameJson(data[key], projected?.[key]));
  const cursorOf = key => Number.isSafeInteger(data[key]) && data[key] >= 0 ? data[key] : null;
  const parameters = data.parameter_coverage;
  const hasParameters = ['plan.next', 'plan.audit'].includes(args?.action) && parameters && typeof parameters === 'object';
  const parameterStatus = originalInput.parameter_status ?? parameters?.filter;
  const parameterRequirements = hasParameters && !PARAMETER_FILTERS.includes(parameterStatus) ? ['parameter_status'] : [];
  const parameterOffset = Number.isSafeInteger(parameters?.offset) && parameters.offset >= 0 ? parameters.offset
    : Number.isSafeInteger(originalInput.parameter_offset) && originalInput.parameter_offset >= 0 ? originalInput.parameter_offset : 0;
  const parameterBase = hasParameters ? { parameter_offset: parameterOffset, parameter_limit: 1,
    ...(PARAMETER_FILTERS.includes(parameterStatus) ? { parameter_status: parameterStatus } : {}) } : {};
  const pages = [];
  const addArrayRecovery = (fields, source, baseInput, limitField, currentLimit, next, extra = {}) => {
    if (!fields.length) return;
    const requested = Number.isSafeInteger(currentLimit) && currentLimit >= 1 ? currentLimit : Infinity;
    const retry = fields.filter(key => source[key].length > 1 && requested > 1);
    if (retry.length) {
      const smaller = Math.max(1, Math.min(limits.array, requested - 1,
        ...retry.map(key => source[key].length - 1)));
      pages.push({ action: args.action, fields: retry, ...extra,
        input: { ...baseInput, [limitField]: smaller }, canonical_next_offset: next });
    }
    const detail = fields.filter(key => !retry.includes(key));
    if (detail.length) {
      // Repeating limit:1 cannot recover an oversized single row; inspect details instead.
      pages.push({ action: args.action, fields: detail, ...extra,
        retry_same_page: false, projection_limit: 'single_record',
        current_offset: baseInput[extra.cursor_field ?? (limitField === 'method_limit' ? 'method_offset' : 'offset')],
        detail_action: { action: 'action.help', input: { name: args.action } },
        canonical_next_offset: next });
    }
  };
  const fields = omitted(PAGE_FIELDS[args?.action] ?? []);
  addArrayRecovery(fields, data, { ...filters, offset: offsetOf('offset'), ...parameterBase }, 'limit',
    data.limit ?? originalInput.limit, cursorOf('next_offset'),
    parameterRequirements.length ? { required_original_filters: [...requiredOriginalFilters, ...parameterRequirements] } : filterRequirements);
  const methods = omitted(['method_coverage']);
  if (methods.length && ['project.status', 'report.coverage', 'plan.list'].includes(args?.action)) {
    addArrayRecovery(methods, data, { ...filters, offset: offsetOf('offset'), limit: 1,
      method_offset: offsetOf('method_offset') }, 'method_limit', data.method_limit ?? originalInput.method_limit,
    cursorOf('method_next_offset'), filterRequirements);
  }
  if (args?.action === 'tool.artifact' && typeof data.content === 'string' && projected?.content !== data.content) {
    pages.push({ action: args.action, fields: ['content'], ...filterRequirements,
      input: { ...filters, offset: offsetOf('offset'), limit: Math.max(1, limits.string) },
      canonical_next_offset: cursorOf('next_offset') });
  }
  if (['plan.next', 'plan.audit'].includes(args?.action) && parameters && Array.isArray(parameters.items)
      && parameters.items.length && !sameJson(parameters.items, projected?.parameter_coverage?.items)) {
    const required = [...requiredOriginalFilters, ...parameterRequirements];
    const parameterSource = { 'parameter_coverage.items': parameters.items };
    addArrayRecovery(['parameter_coverage.items'], parameterSource,
      { ...filters, offset: offsetOf('offset'), limit: 1,
        ...parameterBase }, 'parameter_limit',
      parameters.limit ?? originalInput.parameter_limit,
      Number.isSafeInteger(parameters.next_offset) && parameters.next_offset >= 0 ? parameters.next_offset : null,
      { cursor_field: 'parameter_offset', ...(required.length ? { required_original_filters: required } : {}) });
  }
  if (!pages.length) return undefined;
  let combined;
  if (pages.length > 1 && pages.every(page => page.input && page.retry_same_page !== false)) {
    const input = Object.assign(Object.create(null), ...pages.map(page => page.input));
    for (const key of ['limit', 'method_limit', 'parameter_limit']) {
      const limits = pages.map(page => page.input[key]).filter(value => Number.isSafeInteger(value) && value >= 1);
      if (limits.length) input[key] = Math.min(...limits);
    }
    const required = [...new Set(pages.flatMap(page => page.required_original_filters ?? []))];
    combined = { combined_input: input, ...(required.length ? { combined_required_original_filters: required } : {}) };
  }
  return { before_next_offset: true, pages, ...combined,
    note: 'Use combined_input when present, or pages[].input, to re-fetch CURRENT offsets with all independent limits bounded before canonical next_offset. retry_same_page:false requires detail_action, not an identical retry. Inputs with required_original_filters are incomplete; reapply those and combined_required_original_filters before dispatch. Changed or omitted records have not been reviewed; render_actionable:false templates must not be executed.' };
}

/** The rc.3 SDK persists only HarnessError name/code; recovery JSON stays in its message. */
export function asHostError(error) {
  const code = typeof error?.code === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,95}$/.test(error.code)
    ? error.code : 'ENGINE_FAILED';
  let details;
  try { details = safeErrorDetails(error?.details); }
  catch { /* Invalid arbitrary error metadata never becomes a second failure. */ }
  const message = safeErrorText(error instanceof Error ? error.message : 'Assessment action failed.');
  const result = new HarnessError(message + (details ? '\nRecovery: ' + JSON.stringify(details) : ''), code);
  result.name = 'AwaDddError';
  if (details) result.details = details;
  return result;
}

/** Presentation is bounded independently of the canonical, credential-free result. */
export function renderToolResult(args, value) {
  const safe = { ok: value.ok, data: redactActionResult(args?.action, value.data) };
  if (safe.data && typeof safe.data === 'object' && !Array.isArray(safe.data)
    && Object.hasOwn(safe.data, 'browser_testing_summary')) {
    safe.data = { ...safe.data, browser_testing_summary: compactBrowserSummary(safe.data.browser_testing_summary) };
  }
  if (safe.data && typeof safe.data === 'object' && !Array.isArray(safe.data)) {
    if (Object.hasOwn(safe.data, 'parameter_coverage_summary')) {
      safe.data = { ...safe.data, parameter_coverage_summary: compactParameterSummary(safe.data.parameter_coverage_summary) };
    }
    if (safe.data.parameter_coverage?.summary) {
      safe.data = { ...safe.data, parameter_coverage: { ...safe.data.parameter_coverage,
        summary: compactParameterSummary(safe.data.parameter_coverage.summary) } };
    }
  }
  const full = JSON.stringify(safe);
  if (Buffer.byteLength(full, 'utf8') <= MAX_RENDER_BYTES) return [{ type: 'text', text: full }];
  const controls = renderControls(safe.data);
  const hint = DETAIL_HINTS[args?.action] ?? 'Request a smaller page or inspect the referenced protected local artifact. Use action.help for available detail actions.';
  for (const limits of [{ array: 20, string: 1200, keys: 40 }, { array: 5, string: 500, keys: 24 },
    { array: 2, string: 120, keys: 12 }, { array: 1, string: 80, keys: 0 }]) {
    const data = projectResult(safe.data, limits);
    // Stop controls and cursors must survive regardless of field insertion order.
    if (data && typeof data === 'object' && !Array.isArray(data)) Object.assign(data, controls);
    const recovery = pageRecovery(args, safe.data, data, limits);
    const rendered = JSON.stringify({ ok: safe.ok, data,
      render_truncated: true, render_note: 'This is a bounded presentation, not the complete result or a coverage claim.',
      ...(recovery ? { render_recovery: recovery } : {}),
      next_action: recovery ? 'Follow render_recovery at the current offset before next_offset. ' + hint : hint });
    if (Buffer.byteLength(rendered, 'utf8') <= MAX_RENDER_BYTES) return [{ type: 'text', text: rendered }];
  }
  const recovery = pageRecovery(args, safe.data, controls, { array: 1, string: 120 });
  return [{ type: 'text', text: JSON.stringify({ ok: safe.ok, data: controls, render_truncated: true,
    render_note: 'Result is too large to present; no records were discarded from the canonical result.',
    ...(recovery ? { render_recovery: recovery } : {}),
    next_action: recovery ? 'Follow render_recovery at the current offset before next_offset. ' + hint : hint }) }];
}

export const GROUPS = Object.freeze([{ name: 'awa_project',
    description: 'Create or inspect local evidence-driven assessments; legacy imports remain unverified, and credentials stay private.',
    fields: 'action.help: name (omit for catalog). project.create: project_id,target,scope,exclude,allow_mutation:false. project.list: no project_id. project.status: offset/limit (default 10),method_offset/method_limit. project.update: allow_mutation/exclude,never recreate for permissions. project.import_pentest: absolute read-only source_path.' },
  { name: 'awa_surface',
    description: 'Discover and register exact operations/inputs offline. Source declarations, scores and same-named JS sinks never prove runtime behavior.',
    fields: 'surface.recon: mode:prepare|aggregate (default prepare),section:overview|technologies|functions|clues|collection,offset,limit:1..50(default10). Prepare collection first; aggregate saves an offline information baseline,not proof. No target traffic or auto-registration. surface.import: path,format:openapi|javascript|har|artex|sarif|assessment_hints,base_url (unverified clues). surface.register/batch: exact operations with url/method/auth/inputs; batch:1..50,no retry. Inputs need location/selector/consumer/test_families/schema_branch; unknown sinks stay review and families independent. surface.list: offset/limit,method/auth. surface.inspect: operation_id. surface.declare_consumer: operation_id,input_location,input_selector,consumer,test_families/schema_branch.' },
  { name: 'awa_identity',
    description: 'Separate server-verified actors/sessions/tenants/resources. Private credentials never cross origins; labels alone do not verify identity.',
    fields: 'identity.actor: subject,roles,actor_id,label,tenant_id; declare only server-verifiable values. identity.session: actor_id,session_id,absolute headers_file,ttl_seconds:1..86400. Renewal needs only session_id,renew:true; never resend credentials to renew. identity.verify: session_id,operation_id,subject_selector,roles_selector/tenant_selector (JSON Pointers). identity.resource: owner_actor_id,operation_id,external_id,request_binding:{location:path|query|body,selector},resource_id,state. IDs cannot be rebound.' },
  { name: 'awa_browser',
    description: 'Must use real Playwright for required and materially assisted browser testing. Prefer actual host MCP,then native fallback; preserve scope/write guards and provenance. Calls alone are not vulnerability proof.',
    fields: GUIDANCE.awa_browser },
  { name: 'awa_candidate',
    description: 'Review unresolved import/parser clues. Candidates and ordinary links are provenance,never security evidence or automatic coverage closure.',
    fields: 'candidate.list: status:unverified|linked|dismissed|any,kind,offset,limit. candidate.inspect: candidate_id. candidate.link: candidate_id,operation_id,exact input_location/input_selector; optional proof_decision_ids reviews only precisely bound hints with current accepted proof,not scores/baselines/client sinks. candidate.dismiss: candidate_id,reason,basis:outside_scope|duplicate_operation; duplicate also needs operation_id and exact source/current typed coverage. Reason alone stays review; mutable excludes cannot prove scope exclusion. candidate.reopen: candidate_id,reason. Changes revalidate history; no target traffic.' },
  { name: 'awa_plan',
    description: 'Prioritize actual tests and offline review with a persisted exhaustion-only contract. Required/assisted browser work is mandatory; empty pages,findings or drafts never prove completion.',
    fields: GUIDANCE.awa_plan },
  { name: 'awa_execute',
    description: 'Execute scoped HTTP/scenarios with immutable evidence. Preflight is offline; recover persisted runs after timeout,never automatically replay unknown writes.',
    fields: 'http.preflight/http.capture: operation_id,concrete url,session_id,resource_id,non-auth headers,body OR body_base64 OR body_file (raw,max 1MiB),timeout:>0..60 seconds,max_bytes,idempotency_key. anonymous_cookie is public non-identity state only. Writes need allow_mutation,effect:test_resource_write and exact fixture; only declared query/body-free state_scope:actor self-state may use a verified actor. scenario.preflight/scenario.run: scenario.steps with id,operation_id,capture fields; use help for concurrency/extract/assertions. run.inspect: run_id. run.recover: stale_seconds (default 300,min 60),no replay.' },
  { name: 'awa_assess',
    description: 'Evaluate exact typed controls and current evidence lineage. Record supported findings; raw HTTP,private credentials and weak proofs never become public confirmation.',
    fields: GUIDANCE.awa_assess },
  { name: 'awa_report',
    description: 'Export Chinese evidence-backed reports/redacted reproduction without target traffic. The supported awaited host turn-stopping guard cannot retract streamed text or override real aborts; normal turn end is not completion.',
    fields: 'report.coverage: offset/limit; follow render_recovery before next_offset. report.build: output_dir,stage:draft(default)|final. Draft success never authorizes stopping. Final needs current strict completed finalization_id. Preserve interruptions as unfinished checkpoint/draft. HTTP steps: full redacted packets and .http files for Yakit Web Fuzzer/Burp Suite Repeater. Replace placeholders; set host/port/HTTPS; update Content-Length after edits. SQLi adds bound sqlmap -r/-p commands with --current-db/--current-user. Export sends no requests.' },
  { name: 'awa_external',
    description: 'Discover local Yakit/sqlmap and loopback TscanPlus. Persist controlled execution and unverified results; never automatically execute scanner/route suggestions.',
    fields: GUIDANCE.awa_external },
].map(group => Object.freeze({ ...group, actions: ACTION_GROUPS[group.name] })));

/** 2.0 groups: six tools, about twenty actions, discovered instead of guessed. */
export const V2_GROUPS = Object.freeze([
  { name: 'awa_campaign',
    description: 'Run a persistent, source-bound assessment campaign. Universe first, hypotheses second, tests third; delivery never equals exhaustion unless the evidence gate proves it.',
    fields: 'campaign.start: objective,max_rounds,confirm_migration (no target request). campaign.status: campaign_id. campaign.next: campaign_id,limit:1..25(default3) returns complete public recipe references and preparation rows. campaign.checkpoint: label. campaign.finish: reason:completed|partial_accepted,accepted_by,explanation; partial_accepted never grants exhaustion. campaign.migrate: apply,confirm projects legacy decisions as legacy_evaluation,never a synthetic TestRun. campaign.rollback: ledger_id.' },
  { name: 'awa_recon',
    description: 'Build a source-bound Universe and import known cases, routes and capability readiness. Unknown surface remains explicit; imported hints never become proof.',
    fields: 'recon.snapshot: save. recon.import: kind:known_cases|assessment_hints|routes,path,source_group,track:import|hint_assisted|blind. recon.routes: path,offset,limit parses nested/dynamic/lazy/alias/catch-all statically. recon.hypotheses: status,family,operation_id,source_kind,offset,limit. recon.capabilities: installed/configured/catalog_verified/profile_supported/authorized/ready; no target traffic.' },
  { name: 'awa_test',
    description: 'One durable test entry: prepare, execute scoped controls, save evidence, evaluate the declared oracle and return coverage delta. Unknown writes are effect_unknown, never replayed.',
    fields: 'test.run: campaign_id,recipe_id OR hypothesis_id,mode:observe|test|verify,idempotency_key,variables (declared data only),worker_id. Write requires allow_mutation + effect:test_resource_write + frozen fixture. test.run_browser: mode:xss_evaluate with real consumer/visit/evidence IDs. test.run_scenario: scenario. test.run_external / test.record_external produce unverified provenance only. test.inspect: run_id OR recipe_id.' },
  { name: 'awa_review',
    description: 'Accept reviewed detection under a structured contract, bind current machine proof, or disposition a hypothesis with concrete prerequisites. Reviewed detection is not machine proof.',
    fields: 'review.finding: hypothesis_id,run_id,control_groups,observation,consumer_point,source_trust,reviewer,proof_scope,material. Agent-recorded reviewers cannot self-declare human approval. review.bind: finding_id,run_id,reviewer,reason. review.disposition: hypothesis_id,status:blocked|not_applicable|ready,prerequisite,applicability_basis,evidence_ids. review.evidence: review_id OR run_id. N/A needs business-fact evidence and never counts as tested.' },
  { name: 'awa_report',
    description: 'Export five separate coverage dimensions with denominators, 12-family/route/consumer/known-case matrices, and Chinese evidence-backed reports. No single percentage.',
    fields: 'report.matrix: campaign_id. report.build: output_dir,stage:draft|final,campaign_id; final only for completed exhaustion authority. report.compare: campaign_ids (up to two, like units only).' },
  { name: 'awa_admin',
    description: 'Low-frequency project, identity, resource and help operations. Private credentials never cross origins; labels alone do not verify identity.',
    fields: 'project.create/list/status/update; identity.actor/session/verify/resource; action.help. Identity values must be server-verifiable; sessions bind exact actors and origins.' },
].map(group => Object.freeze({ ...group, actions: V2_ACTION_GROUPS[group.name] })));

export function toolDefinitions(defineTool, config = {}, invoke = invokeEngine, ownerSignal, options = {}) {
  const settings = resolveConfig(config);
  const groups = settings.assessmentModel === 'v2' ? V2_GROUPS : GROUPS;
  const helpGroup = settings.assessmentModel === 'v2' ? 'awa_admin' : 'awa_project';
  return groups.map(group => defineTool({
    name: group.name,
    description: group.description,
    timeoutMs: settings.timeoutMs,
    parameters: {
      action: { type: 'string', enum: group.actions, required: true, description: 'Exact group action. Help uses ' + helpGroup + ' action.help input:{name:"<action>"}.' },
      project_id: { type: 'string', description: 'Project ID; required except action.help,runtime.probe,project.list. Creation may supply input.project_id.' },
      input: { type: 'object', additionalProperties: true, description: `Help: ${helpGroup} action.help input:{name:"<action>"} (no project_id). Put action-specific fields inside input, not at top level. ` + group.fields },
    },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: {
        ok: { type: 'boolean', const: true, required: true }, data: { type: 'json', required: true },
      } },
      render: renderToolResult,
    },
    isConcurrencySafe: args => READ_ACTIONS.has(args.action),
    async execute(args, exec) {
      try {
        if (!group.actions.includes(args.action)) throw new BridgeError('UNKNOWN_ACTION', 'Action is not supported by this tool group.');
        if (Object.keys(args).some(key => !['action', 'project_id', 'input'].includes(key))) {
          throw new BridgeError('MISPLACED_ARGUMENTS', 'Action-specific fields belong inside input (for example input.limit), not at the tool top level.');
        }
        const input = args.input === undefined ? {} : args.input;
        if (input === null || typeof input !== 'object' || Array.isArray(input)) throw new BridgeError('INVALID_ARGUMENTS', 'input must be an object.');
        if (args.project_id !== undefined && input.project_id !== undefined && args.project_id !== input.project_id) {
          throw new BridgeError('PROJECT_MISMATCH', 'project_id and input.project_id must identify the same assessment.');
        }
        const payload = { ...input, ...(args.project_id !== undefined ? { project_id: args.project_id } : {}) };
        const callerSignal = exec?.signal;
        const signal = ownerSignal && callerSignal ? AbortSignal.any([callerSignal, ownerSignal]) : ownerSignal ?? callerSignal;
        const references = {};
        for (const field of ['operation_id', 'obligation_id', 'evidence_id', 'finding_id', 'decision_id', 'candidate_id',
          'page_visit_id', 'run_id', 'checklist_id', 'session_id', 'resource_id', 'input_location', 'input_selector', 'schema_branch']) {
          if (typeof payload[field] === 'string' && payload[field].length <= 200) references[field] = payload[field];
        }
        if (payload.schema_branch === null) references.schema_branch = null;
        if (Array.isArray(payload.evidence_ids) && payload.evidence_ids.length <= 25
          && payload.evidence_ids.every(identity => typeof identity === 'string' && identity.length <= 200)) {
          references.evidence_ids = Object.freeze([...payload.evidence_ids]);
        }
        for (const field of ['offset', 'limit']) {
          if (Number.isSafeInteger(payload[field]) && payload[field] >= 0) references[field] = payload[field];
        }
        const invocation = Object.freeze({ action: args.action, project_id: payload.project_id, input: Object.freeze(references),
          agent: exec?.agent, callerSignal, signal });
        const observe = async event => {
          if (typeof options?.observer !== 'function') return;
          try { await options.observer(Object.freeze({ ...event, invocation })); }
          catch { console.error('[awa-ddd] optional host-continuation observer failed; the engine outcome is preserved.'); }
        };
        await observe({ phase: 'start' });
        try {
          const value = await invoke(settings, args.action, payload, { signal });
          const failureCode = typeof value?.error?.code === 'string' && /^[A-Za-z0-9_:-]{1,80}$/.test(value.error.code)
            ? value.error.code : undefined;
          await observe({ phase: 'success', ok: value?.ok === true, ...(failureCode ? { failure_code: failureCode } : {}) });
          return value;
        } catch (error) {
          const runPattern = args.action === 'scenario.run' ? /^SC-[A-Za-z0-9_-]+$/ : /^RUN-[A-Za-z0-9_-]+$/;
          const failureCode = typeof error?.code === 'string' && /^[A-Za-z0-9_:-]{1,80}$/.test(error.code)
            ? error.code : 'tool_failure';
          await observe({ phase: 'failure', claimed_run: typeof error?.details?.run_id === 'string'
            && runPattern.test(error.details.run_id), dispatch_uncertain: error?.[ENGINE_DISPATCH_UNCERTAIN] === true,
            failure_code: failureCode });
          throw error;
        }
      } catch (error) { throw asHostError(error); }
    },
  }));
}
