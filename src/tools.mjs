/** Grouped native tools. All actions dispatch through the same bounded bridge. */
import { HarnessError } from '@deepseek-ai/dsh-llm';
import { invokeEngine, resolveConfig, redactActionResult, safeErrorText, safeErrorDetails, compactContinuation, BridgeError, ENGINE_DISPATCH_UNCERTAIN } from './bridge.mjs';
import { ACTION_GROUPS, READ_ACTIONS } from './actions.mjs';
import { GUIDANCE } from './tool-guidance.mjs';

export const MAX_RENDER_BYTES = 24 * 1024;
const BROWSER_SUMMARY_FIELDS = ['required_total', 'assisted_total', 'call_needed_total', 'invoke_now_total',
  'blocked_total', 'native_unsupported_total', 'followup_total', 'task_total'];
const HELP_HINT = 'Put every action-specific field inside input; misplaced top-level fields are rejected. For exact required fields, enums and examples call awa_project action.help with input:{name:"<action>"}; it needs no project_id.';
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
  'surface.list': ['operations'], 'surface.inspect': ['inputs'], 'candidate.list': ['candidates'],
  'plan.build': ['obligation_items'], 'plan.list': ['gaps'], 'plan.next': ['work_items'],
  'plan.audit': ['checklist'], 'finding.list': ['findings'], 'report.coverage': ['gaps'],
});
const PAGE_FILTERS = ['operation_id', 'run_id', 'name', 'method', 'auth', 'status', 'kind', 'current', 'lifecycle_status', 'include_blocked'];

function compactBrowserSummary(value) {
  const result = Object.create(null);
  if (!value || typeof value !== 'object' || Array.isArray(value)) return result;
  for (const key of BROWSER_SUMMARY_FIELDS) {
    if (Number.isSafeInteger(value[key]) && value[key] >= 0) result[key] = value[key];
  }
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
  const omitted = fields => fields.filter(key => Array.isArray(data[key]) && data[key].length > 0 &&
    (!Array.isArray(projected?.[key]) || projected[key].some(item => item?.render_omitted_items > 0)));
  const cursorOf = key => Number.isSafeInteger(data[key]) && data[key] >= 0 ? data[key] : null;
  const pages = [];
  const fields = omitted(PAGE_FIELDS[args?.action] ?? []);
  if (fields.length) pages.push({ action: args.action, fields, ...filterRequirements,
    input: { ...filters, offset: offsetOf('offset'), limit: Math.max(1, limits.array) },
    canonical_next_offset: cursorOf('next_offset') });
  const methods = omitted(['method_coverage']);
  if (methods.length && ['project.status', 'report.coverage', 'plan.list'].includes(args?.action)) {
    pages.push({ action: args.action, fields: methods, ...filterRequirements,
      input: { ...filters, offset: offsetOf('offset'), limit: 1,
        method_offset: offsetOf('method_offset'), method_limit: Math.max(1, limits.array) },
      canonical_next_offset: cursorOf('method_next_offset') });
  }
  if (args?.action === 'tool.artifact' && typeof data.content === 'string' && projected?.content !== data.content) {
    pages.push({ action: args.action, fields: ['content'], ...filterRequirements,
      input: { ...filters, offset: offsetOf('offset'), limit: Math.max(1, limits.string) },
      canonical_next_offset: cursorOf('next_offset') });
  }
  if (!pages.length) return undefined;
  return { before_next_offset: true, pages,
    note: 'Re-fetch the CURRENT offset with these smaller limits and original filters/entity references before following canonical next_offset. Inputs with required_original_filters are incomplete: reapply those original values before dispatch. Omitted records have not been reviewed.' };
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
  const full = JSON.stringify(safe);
  if (Buffer.byteLength(full, 'utf8') <= MAX_RENDER_BYTES) return [{ type: 'text', text: full }];
  const controls = renderControls(safe.data);
  const project = (node, limits, depth = 0) => {
    if (depth > 8) return '[nested detail omitted]';
    if (typeof node === 'string') return node.length > limits.string
      ? node.slice(0, limits.string) + ` [${node.length - limits.string} characters omitted]` : node;
    if (Array.isArray(node)) {
      const items = node.slice(0, limits.array).map(child => project(child, limits, depth + 1));
      if (node.length > items.length) items.push({ render_omitted_items: node.length - items.length });
      return items;
    }
    if (node === null || typeof node !== 'object') return node;
    const result = Object.create(null);
    const entries = Object.entries(node);
    let omitted = 0;
    for (const [key, child] of entries) {
      if (Object.keys(result).length >= limits.keys || key.length > 160) { omitted++; continue; }
      result[key] = project(child, limits, depth + 1);
    }
    if (omitted) result.render_omitted_fields = omitted;
    return result;
  };
  const hint = DETAIL_HINTS[args?.action] ?? 'Request a smaller page or inspect the referenced protected local artifact. Use action.help for available detail actions.';
  for (const limits of [{ array: 20, string: 1200, keys: 40 }, { array: 5, string: 500, keys: 24 },
    { array: 2, string: 120, keys: 12 }]) {
    const data = project(safe.data, limits);
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

export const GROUPS = Object.freeze([
  { name: 'awa_project',
    description: 'Create and inspect an evidence-driven security assessment. Legacy imports remain unverified candidates; source projects and credentials are not modified or copied.',
    fields: 'action.help: optional name (exact action; omit for catalog), no project_id. project.create: project_id,target, scope (authorized URL array), exclude, allow_mutation:false. project.list: no project_id. project.status: bounded overview; entities use offset/limit (default 10); methods use method_offset/method_limit. project.update: allow_mutation and/or exclude; never recreate to change permissions. project.import_pentest: source_path (absolute read-only legacy directory).' },
  { name: 'awa_surface',
    description: 'Discover and register business operations and exact inputs from local API specifications, JavaScript AST, captured traffic or audit artifacts. Source declarations do not prove runtime behavior. Declaring an input consumer is the only step that turns an input_review gap into an executable input_test.',
    fields: 'surface.import: absolute path, format:openapi|javascript|har|artex|sarif, optional base_url. surface.register: operation:{url,method,auth,inputs,...}; inputs may declare test_families:[sql_injection,xss,ssrf,xxe,path_traversal,command_injection,template_injection,deserialization,file_upload,business_logic,generic]. Each explicitly declared family has a separate obligation; names alone never prove a sink. Fixture-free self-state writes require explicit state_scope:actor, concrete HTTP path and no actual query/body. surface.batch: operations (1..50 operation records); per-item success/error, no automatic retry. surface.list: offset/limit and optional filters; surface.inspect: operation_id, includes currently evaluated gap states rather than stale stored labels. surface.declare_consumer: operation_id,input_location,input_selector,consumer (concrete sink), optional test_families/schema_branch; ambiguous schema branches require exact selection. No action sends target traffic.' },
  { name: 'awa_identity',
    description: 'Keep actors, sessions, tenants and resources separate. Session credentials are private; labels alone do not verify identity. Verified sessions cannot forward headers to another origin, even if that origin is also in scope. Same-role actors retain distinct session records.',
    fields: 'identity.actor: subject (server identity), roles, optional actor_id,label,tenant_id. identity.session: actor_id, optional session_id, headers_file (preferred absolute JSON file), ttl_seconds:1..86400. renew:true extends the same session without credential/generation changes; TTL expiry does not invalidate historical proof. identity.verify: session_id,operation_id,subject_selector and optional roles_selector/tenant_selector JSON Pointers. identity.resource: owner_actor_id,operation_id,external_id,request_binding:{location:path|query|body,selector}, optional resource_id,state; body selectors support JSON Pointer, JSON key or multipart field.' },
  { name: 'awa_browser',
    description: 'Must use real Playwright for required and materially assisted browser testing: DOM/XSS,client routes/state,browser security constraints and beneficial UI/login/upload/business workflows. First discover the host Playwright MCP provider and preserve actual observations; only the native fallback probes locally before browser.visit. Local unavailability does not negate host MCP. Keep scope/write guards and provenance; browser calls alone never confirm vulnerabilities or replace backend evidence.',
    fields: GUIDANCE.awa_browser },
  { name: 'awa_candidate',
    description: 'Work the unresolved-discovery ledger. Candidates are clues from imports and parsing, never evidence: linking records lineage to an operation without closing any coverage obligation.',
    fields: 'candidate.list: project_id, optional status (unverified/linked/dismissed/any, default unverified), kind, offset, limit (1..500, default 50); follow next_offset. candidate.inspect: candidate_id, returns the source record and its linked operation, never private closure context. candidate.link: candidate_id, operation_id, optional input_location and input_selector together (the input must already be registered on that operation); the candidate URL must equal the operation URL. candidate.dismiss: candidate_id, reason (required), optional basis:outside_scope|duplicate_operation; duplicate_operation also requires operation_id. Reason-only/legacy dismissals remain actionable candidate review, not exhaustion. The engine revalidates concrete declared-scope exclusion (not mutable excludes), or exact ordinary route/method/protocol/input/schema plus current typed security coverage; dynamic sources, scanner findings or a baseline alone cannot establish duplicate closure. Source/scope/evidence changes reopen review without changing history. candidate.reopen: candidate_id, reason (required); follow the generated audit template to trace unverified exclusions. Dismissal/linking never creates security evidence or changes coverage denominators.' },
  { name: 'awa_plan',
    description: 'Build shared obligations, browser_testing requirements and a persisted exhaustion-only continuation contract. Required and assisted both mandate needed Playwright work; stage/invoke_now preserve control preparation and offline review. The projection is not execution or proof. Empty queues, findings, elapsed time and successful drafts never authorize stopping. Unknown inputs, missing identities and invalid evidence remain visible; only strict completed finalization permits automatic stopping.',
    fields: GUIDANCE.awa_plan },
  { name: 'awa_execute',
    description: 'Execute scoped HTTP captures and explicit business scenarios, recording immutable evidence and resource state. Requests must belong to the configured project scope. After a timeout recover the recorded run before retrying a state-changing operation.',
    fields: 'http.preflight/http.capture: operation_id, optional session_id,resource_id,concrete url, non-authentication headers, body OR body_base64 OR body_file (raw regular local file,max 1MiB), timeout,max_bytes,idempotency_key. Preflight is offline and does not dispatch or claim a run. anonymous_cookie: public non-identity state only, mutually exclusive with session_id. Writes need allow_mutation AND effect:test_resource_write AND an unambiguously bound resource; only query-free/body-free concrete operation.state_scope:actor requests may use a verified actor instead. scenario.preflight/scenario.run: scenario:{steps:[{id,operation_id,...captureFields,concurrent:2..40,extract,assertions}]}, 1..25 steps and max 200 attempts, optional idempotency_key; ${stepId.variableName} references are checked offline, dynamic values remain unresolved until run. run.inspect: run_id. run.recover: stale_seconds (default 300,min 60), no replay. After timeout inspect checkpoints before retrying writes.' },
  { name: 'awa_assess',
    description: 'Evaluate observations with typed controls, record supported findings and inspect evidence metadata. Stale identities or invalid evidence cannot close coverage; summaries omit raw HTTP and credentials.',
    fields: GUIDANCE.awa_assess },
  { name: 'awa_report',
    description: 'Export a Chinese evidence-backed report and redacted reproduction bundle using the plan evaluator. Default drafts are not stop permission; final delivery requires current strict completed exhaustion. Report generation never sends target traffic. The supported awaited host turn-stopping guard can steer the same normally closing turn; it cannot retract streamed text or override real abort/termination.',
    fields: 'report.coverage: offset (default 0),limit:1..100 (default 25); follow render_recovery before next_offset when a page is shortened. report.build: optional output_dir (local directory), stage:draft (default)|final. Draft success never authorizes stopping. Final requires finalization_id from a strict completed plan.finalize bound to the current snapshot/checkpoint, complete coverage and zero ready/review/blocked/unresolved tasks; partial or inconsistent stops are rejected before material preparation, never exported as final-partial. Actual user/host interruption preserves checkpoint and draft only. Any resumed material change requires a fresh checkpoint/finalization. Chinese report/summary, manifest digests, redacted HTTP/body files and PowerShell/POSIX curl plus bounded sqlmap templates. Replace credential/test-resource placeholders before authorized manual replay; generated commands are not executed. Withdrawn/superseded findings remain historical without new attack templates.' },
  { name: 'awa_external',
    description: 'Discover local Yakit/sqlmap and loopback TscanPlus MCP. Persist scoped HTTP replay, local result retrieval, bounded project summaries and unverified route candidates. Never execute generic TscanPlus scans, POC, cracking or route suggestions. Tool output stays unverified until independent accepted evidence supports a typed decision.',
    fields: GUIDANCE.awa_external },
].map(group => Object.freeze({ ...group, actions: ACTION_GROUPS[group.name] })));

export function toolDefinitions(defineTool, config = {}, invoke = invokeEngine, ownerSignal, options = {}) {
  const settings = resolveConfig(config);
  return GROUPS.map(group => defineTool({
    name: group.name,
    description: group.description,
    timeoutMs: settings.timeoutMs,
    parameters: {
      action: { type: 'string', enum: group.actions, required: true, description: 'Exact action from this tool group.' },
      project_id: { type: 'string', description: 'Assessment project ID: lowercase letters, digits, hyphen or underscore, maximum 64 characters. Required except action.help, runtime.probe and project.list; creation may supply it in input.' },
      input: { type: 'object', additionalProperties: true, description: group.fields + ' ' + HELP_HINT },
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
        const invocation = Object.freeze({ action: args.action, project_id: payload.project_id,
          agent: exec?.agent, callerSignal, signal });
        const observe = async event => {
          if (typeof options?.observer !== 'function') return;
          try { await options.observer(Object.freeze({ ...event, invocation })); }
          catch { console.error('[awa-ddd] optional host-continuation observer failed; the engine outcome is preserved.'); }
        };
        await observe({ phase: 'start' });
        try {
          const value = await invoke(settings, args.action, payload, { signal });
          await observe({ phase: 'success', ok: value?.ok === true });
          return value;
        } catch (error) {
          const runPattern = args.action === 'scenario.run' ? /^SC-[A-Za-z0-9_-]+$/ : /^RUN-[A-Za-z0-9_-]+$/;
          await observe({ phase: 'failure', claimed_run: typeof error?.details?.run_id === 'string'
            && runPattern.test(error.details.run_id), dispatch_uncertain: error?.[ENGINE_DISPATCH_UNCERTAIN] === true });
          throw error;
        }
      } catch (error) { throw asHostError(error); }
    },
  }));
}
