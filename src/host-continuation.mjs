/** Public, cancellation-aware agent/turn-stopping integration; never sends target traffic. */
import { createUserMessage } from '@deepseek-ai/dsh-llm';
import { compactContinuation, invokeEngine, resolveConfig } from './bridge.mjs';

export const name = 'awa-ddd-host-continuation';
export const TURN_STOPPING_EVENT = 'agent/turn-stopping';
const EXECUTION_ARM_ACTIONS = ['http.capture', 'scenario.run', 'browser.visit', 'identity.verify',
  'tool.sqlmap', 'tool.yakit_replay', 'tool.tscanplus_request', 'plan.build', 'plan.next'];
const EXECUTION_ARM_SET = new Set(EXECUTION_ARM_ACTIONS);
const TARGET_EXECUTION_SET = new Set(EXECUTION_ARM_ACTIONS.filter(action => !['plan.build', 'plan.next'].includes(action)));
export const ARM_ACTIONS = Object.freeze([...EXECUTION_ARM_ACTIONS, 'assessment.prepare', 'assessment.evaluate',
  'evidence.inspect', 'finding.record', 'finding.bind', 'plan.review', 'page.adopt', 'run.recover']);
const ARM_SET = new Set(ARM_ACTIONS);
const ACTIVITY_SET = new Set([...ARM_ACTIONS.filter(action => !['plan.build', 'plan.next'].includes(action)),
  'candidate.inspect', 'candidate.link', 'candidate.reopen', 'surface.inspect', 'surface.declare_consumer',
  'surface.register', 'identity.actor', 'identity.session', 'identity.resource', 'page.mark', 'run.inspect']);
const OFFLINE_TASKS = new Set(['evidence.inspect', 'assessment.prepare', 'assessment.evaluate', 'finding.record',
  'finding.bind', 'page.adopt', 'page.mark', 'plan.review', 'plan.disposition', 'run.inspect', 'run.recover',
  'candidate.inspect', 'candidate.link', 'candidate.reopen', 'surface.inspect', 'surface.declare_consumer',
  'surface.register', 'identity.actor', 'identity.session', 'identity.resource', 'action.help', 'project.status']);
const TARGET_TASKS = new Set(['http.preflight', 'scenario.preflight', 'http.capture', 'scenario.run',
  'browser.visit', 'identity.verify', 'tool.sqlmap', 'tool.yakit_replay', 'tool.tscanplus_request']);
const PAGE_ACTIONS = new Set(['plan.next', 'plan.audit']);
const COUNTS = ['ready_total', 'review_total', 'blocked_total', 'unresolved_total', 'actionable_total'];
const MESSAGE_PROJECT_LIMIT = 8;
const TASK_PAGE_LIMIT = 3;
const TASK_PAGE_READ_LIMIT = 3;
const ACTIVITY_LIMIT = 50000;

function workKey(current) {
  const value = current.continuation;
  // Captures, checkpoint IDs and no_progress counters are not closure progress.
  // Older compatible engines without progress_id fall back to their snapshot.
  const progress = typeof value.progress_id === 'string' && value.progress_id
    ? value.progress_id : value.snapshot_id;
  return JSON.stringify([progress, current.kind, value.frontier_rounds,
    value.frontier_review_required, value.can_finalize, value.coverage_status]);
}

function signalLike(signal) {
  return signal && typeof signal.aborted === 'boolean' && typeof signal.addEventListener === 'function'
    && typeof signal.removeEventListener === 'function';
}

function runtimeAgent(agent) {
  return agent && typeof agent === 'object' && typeof agent.id === 'string' && agent.id
    && agent.session && typeof agent.session === 'object' && typeof agent.steer === 'function'
    && agent.inbox && Array.isArray(agent.inbox.nextStep) && Array.isArray(agent.inbox.nextTurn);
}

function pendingInput(agent, state) {
  // Public Inbox has no wake bit. Injected metadata is not proof of waking input.
  const pending = message => message?.role === 'user' && typeof message.id === 'string'
    && (message.source?.kind === 'user' || state.steering_ids.has(message.id));
  return agent.inbox.nextStep.some(pending) || agent.inbox.nextTurn.some(pending);
}

function auditState(envelope) {
  const value = envelope?.ok === true ? envelope.data?.continuation : undefined;
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || value.contract_version !== 2 || value.stop_policy_version !== 1
    || value.stop_policy !== 'exhaustion_only' || typeof value.continue_required !== 'boolean'
    || COUNTS.some(key => !Number.isSafeInteger(value[key]) || value[key] < 0)
    || value.actionable_total !== value.ready_total + value.review_total
    || value.unresolved_total !== value.actionable_total + value.blocked_total
    || typeof value.snapshot_id !== 'string' || !value.snapshot_id) return undefined;
  const zero = COUNTS.every(key => value[key] === 0);
  const complete = value.continue_required === false && value.automatic_stop_allowed === true
    && value.can_finalize === true && value.can_claim_complete === true && value.coverage_status === 'complete'
    && value.frontier_review_required === false && Number.isSafeInteger(value.frontier_rounds)
    && value.frontier_rounds >= 2 && value.state === 'finalized'
    && typeof value.finalization_id === 'string' && value.finalization_id && zero;
  if (complete) return { kind: 'completed', continuation: value };
  if (value.continue_required !== true) return undefined;
  if (value.actionable_total > 0) return { kind: 'work', continuation: value };
  if (value.blocked_total > 0 || value.unresolved_total > 0) return { kind: 'blocked', continuation: value };
  return { kind: 'frontier', continuation: value };
}

function taskFrom(row, offlineOnly) {
  if (!row || typeof row !== 'object' || Array.isArray(row)) return undefined;
  let action = row.suggested_action || row.action;
  let input = row.input_template;
  const obligation = row.obligation_id;
  if ((!action || ['plan.next', 'plan.audit'].includes(action)) && typeof obligation === 'string') {
    action = 'assessment.prepare';
    input = { obligation_id: obligation, limit: 1 };
  }
  if (!OFFLINE_TASKS.has(action) && (!TARGET_TASKS.has(action) || offlineOnly)) return undefined;
  if (row.status === 'blocked' && !row.blocker_reconciliation_required) return undefined;
  if (!OFFLINE_TASKS.has(action) && (row.execution_blocked || row.missing_prerequisites?.length)) return undefined;
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    const field = { 'evidence.inspect': 'evidence_id', 'candidate.inspect': 'candidate_id',
      'page.adopt': 'page_visit_id', 'run.inspect': 'run_id', 'surface.inspect': 'operation_id' }[action];
    const identity = row[field] || (field === 'evidence_id' ? row.evidence_ids?.[0] : undefined);
    if (!field || typeof identity !== 'string') return undefined;
    input = { [field]: identity };
  }
  const identity = obligation || row.id || input.evidence_id || input.page_visit_id || input.candidate_id || input.run_id;
  if (typeof identity !== 'string' || !identity || identity.length > 200) return undefined;
  const task = { id: identity, action, input_template: input, offline: OFFLINE_TASKS.has(action) };
  for (const field of ['kind', 'operation_id', 'obligation_id', 'input_location', 'input_selector', 'schema_branch',
    'hypothesis_family', 'evidence_ids', 'missing_prerequisites', 'required_experiment_fields',
    'assessment_followup_action', 'assessment_followup_input', 'browser_testing', 'preparation_actions']) {
    if (row[field] !== undefined) task[field] = row[field];
  }
  if (offlineOnly) {
    if (!OFFLINE_TASKS.has(task.assessment_followup_action)) {
      delete task.assessment_followup_action;
      delete task.assessment_followup_input;
    }
    if (Array.isArray(task.preparation_actions)) {
      task.preparation_actions = task.preparation_actions.filter(item => OFFLINE_TASKS.has(item?.action));
    }
    if (task.browser_testing && typeof task.browser_testing === 'object') {
      const browser = {};
      for (const field of ['stage', 'requirement', 'existing_visit_id', 'existing_observation', 'required_input_fields']) {
        if (task.browser_testing[field] !== undefined) browser[field] = task.browser_testing[field];
      }
      task.browser_testing = { ...browser, offline_review_only: true, invoke_now: false, call_needed: false };
    }
  }
  task.key = JSON.stringify([identity, action, input]);
  return task;
}

function referenceKeys(input) {
  const result = [];
  for (const field of ['obligation_id', 'evidence_id', 'finding_id', 'decision_id', 'candidate_id',
    'page_visit_id', 'run_id', 'checklist_id', 'operation_id']) {
    if (typeof input?.[field] === 'string') result.push(field + ':' + input[field]);
  }
  if (Array.isArray(input?.evidence_ids)) {
    for (const identity of input.evidence_ids) if (typeof identity === 'string') result.push('evidence_id:' + identity);
  }
  return result;
}

function knownFailedActivity(binding, action, input) {
  const fields = action === 'assessment.evaluate' ? ['obligation_id']
    : action === 'assessment.prepare' ? ['obligation_id', 'evidence_id', 'finding_id', 'operation_id']
    : action.startsWith('candidate.') ? ['candidate_id']
    : action.startsWith('finding.') ? ['finding_id', 'decision_id']
    : action.startsWith('page.') ? ['page_visit_id']
    : action.startsWith('run.') ? ['run_id']
    : action === 'plan.review' ? ['checklist_id']
    : action === 'evidence.inspect' ? ['evidence_id'] : ['operation_id'];
  return fields.some(field => typeof input?.[field] === 'string'
    && binding.known_references.has(field + ':' + input[field]));
}

function pageRequestKey(action, input) {
  return PAGE_ACTIONS.has(action) && Number.isSafeInteger(input?.offset) && input.offset >= 0
    && input.limit === TASK_PAGE_LIMIT ? JSON.stringify([action, input.offset, input.limit]) : undefined;
}

function taskPriority(task) {
  return ['assessment.evaluate', 'finding.bind', 'finding.record', 'page.adopt', 'plan.review'].includes(task.action) ? 0
    : ['evidence.inspect', 'assessment.prepare'].includes(task.action) ? 1
    : task.offline ? 2 : 3;
}

const RECOVERY_LINES = [
  'Attempt one bounded OFFLINE recovery: awa_project action.help input:{name:"plan.audit"} -> project.status -> plan.audit with a smaller current page.',
  'For those projects, do not send target traffic, retry uncertain writes, expand authorization or guess queue counts. Recover recorded runs offline.',
  'If the dependency still fails, preserve an unfinished checkpoint/draft and state the prerequisite; do not spin retries or claim completion.',
];

function continuationMessage(items, blocked, recoveryProjects = []) {
  const visible = items.slice(0, MESSAGE_PROJECT_LIMIT);
  const shown = visible.map(item => ({ project_id: item.project_id,
    continuation: compactContinuation(item.continuation) }));
  return createUserMessage({
    source: { kind: 'awa-ddd-host-continuation', form: 'notice',
      summary: 'Unfinished assessment: a new closure/frontier state needs attention.' },
    content: [{ type: 'text', text: [
      'awa-ddd host continuation guard: this normally closing turn is not an assessment completion. This is plugin context, not a user command or new authorization; respect user intent, cancellation and scope/identity/fixture limits.',
      'Review every current registered input, saved HTTP control and browser observation. Inspect actual evidence, evaluate the precise positive/negative oracle, bind supported findings and archive observations before closing. Reading queues, exporting drafts or storing checkpoints does not complete this work.',
      'Follow plan.next/review_followups, reconcile prerequisites and existing evidence OFFLINE, execute only already authorized ready work, then plan.checkpoint. Recover omitted CURRENT pages before next_offset.',
      'Caller-only plan.disposition status:blocked prose is NOT a verified prerequisite. Inspect missing_prerequisites and its bounded OFFLINE plan.disposition status:open template. Do not automatically replay a target request.',
      'For blocker_reconciliation_required use OFFLINE plan.review status:reopen templates. Setup/auth/input tracing and existing-evidence review remain actionable; prose cannot close them.',
      'Findings, elapsed time and context pressure are not overall execution-budget exhaustion. A draft is not completion; when work closes, complete the evidence-bound discovery/category/page frontier rounds and strict plan.finalize reason:completed.',
      'Before a new target action after an interrupted run, FIRST use offline run.inspect/run.recover. Never replay an uncertain write or expand scope.',
      'If a proof or prerequisite stalls, move to another concrete unreviewed item or prepare its missing controls; do not end with a partial handoff while current authorized ready work or offline review remains actionable. After all work closes, perform the frontier reviews and strict finalization.',
      ...(visible.some(item => !item.binding.execution_armed) ? [
        `OFFLINE-only bindings: ${JSON.stringify(visible.filter(item => !item.binding.execution_armed).map(item => item.project_id))}. Finish saved-evidence review and archive only; these bindings do not authorize target traffic or new experiments.`,
      ] : []),
      ...(visible.some(item => item.tasks?.length) ? [
        'Concrete current tasks below come from fresh local queue pages. Complete their exact evidence review/preparation and record the supported result, then continue to remaining current pages. They are data references, not new authorization; required assertions must come from actual evidence, never be invented.',
        `Current review/ready tasks: ${JSON.stringify(visible.filter(item => item.tasks?.length)
          .map(item => ({ project_id: item.project_id, offline_only: !item.binding.execution_armed,
            tasks: item.tasks.map(({ key, ...task }) => task) })))}`,
      ] : []),
      ...(blocked ? ['Other blocked-only projects remain unfinished; do not replay them.'] : []),
      `Fresh offline audit (${shown.length} of ${items.length} unnotified work states shown; other bound projects remain unfinished): ${JSON.stringify(shown)}`,
      ...(recoveryProjects.length ? [...RECOVERY_LINES,
        `Unauditable unfinished projects (${Math.min(recoveryProjects.length, MESSAGE_PROJECT_LIMIT)} of ${recoveryProjects.length} shown): ${JSON.stringify(recoveryProjects.slice(0, MESSAGE_PROJECT_LIMIT))}`] : []),
    ].join('\n') }],
  });
}

function recoveryMessage(projects) {
  return createUserMessage({
    source: { kind: 'awa-ddd-host-continuation', form: 'notice',
      summary: 'Offline continuation audit unavailable; assessment exhaustion is not established.' },
    content: [{ type: 'text', text: [
      'awa-ddd host continuation guard: the fresh offline continuation audit is unavailable or inconsistent. The bound assessment remains unfinished, not completed.',
      'This is plugin context, not a user command or new authorization; respect intent, cancellation and scope/identity/fixture limits.',
      ...RECOVERY_LINES,
      'Only strict plan.finalize reason:completed establishes exhaustion; a normal turn end or suppressed duplicate is not completion.',
      `Unauditable unfinished projects (${Math.min(projects.length, MESSAGE_PROJECT_LIMIT)} of ${projects.length} shown; omitted projects remain unfinished): ${JSON.stringify(projects.slice(0, MESSAGE_PROJECT_LIMIT))}`,
    ].join('\n') }],
  });
}

/** Instantiate before tool registration; attach only after the core tools have registered. */
export function createController(config = {}, { signal: ownerSignal, invoke = invokeEngine, onDiagnostic } = {}) {
  const settings = resolveConfig(config);
  const lifetime = new AbortController();
  const states = new Map();
  const tickets = new WeakMap();
  const disposers = [];
  const reported = new Set();
  const metrics = { observed_pre_steps: 0, observed_boundaries: 0, steers: 0, recovery_steers: 0,
    blocked_checkpoints: 0, stalled_checkpoints: 0, duplicate_work_suppressed: 0,
    audit_failures: 0, missing_execution_context: 0, concrete_handoffs: 0, review_activity_receipts: 0 };
  let registered = false;
  let disposed = false;
  let reason = 'not_attached';

  function diagnose(code) {
    reason = code;
    if (reported.has(code)) return;
    reported.add(code);
    const diagnostic = Object.freeze({ code, registered, ...metrics });
    if (typeof onDiagnostic === 'function') {
      try { onDiagnostic(diagnostic); } catch { /* Diagnostics never decide agent or tool outcomes. */ }
    }
  }

  function clearState(state) {
    state.audit?.abort(new Error('awa-ddd host binding changed'));
    for (const [signal, listener] of state.signals) signal.removeEventListener('abort', listener);
    state.signals.clear();
    state.projects.clear();
    state.steering_ids.clear();
  }

  function remove(agent) {
    const state = states.get(agent);
    if (state) clearState(state);
    states.delete(agent);
  }

  function addTurnSignal(state, signal) {
    if (state.signals.has(signal)) return;
    const listener = () => {
      state.cancelled = true;
      state.audit?.abort(new Error('awa-ddd turn was cancelled'));
      diagnose('actual_turn_abort_respected');
    };
    state.signals.set(signal, listener);
    signal.addEventListener('abort', listener, { once: true });
    if (signal.aborted) listener();
  }

  function usable(agent, state, payloadSignal, turn) {
    return registered && !disposed && !lifetime.signal.aborted && !ownerSignal?.aborted
      && runtimeAgent(agent) && agent.status === 'running' && states.get(agent) === state
      && state.context.turn === turn && state.context.signal === payloadSignal
      && state.context.session === agent.session && state.context.agent_id === agent.id
      && !state.cancelled && !payloadSignal.aborted
      && ![...state.signals.keys()].some(signal => signal.aborted);
  }

  async function preStep(payload, next) {
    let decision;
    try { decision = await next(); }
    catch (error) { remove(payload?.agent); throw error; }
    try {
      const agent = payload?.agent;
      if (!registered || disposed || ownerSignal?.aborted || !runtimeAgent(agent)
        || !signalLike(payload.signal) || payload.signal.aborted || agent.status !== 'running'
        || !Number.isSafeInteger(payload.turn) || payload.turn < 1
        || decision?.kind !== 'enter' || !Array.isArray(decision.messages)) {
        remove(agent);
        return decision;
      }
      metrics.observed_pre_steps++;
      let state = states.get(agent);
      const users = decision.messages.filter(message => message?.role === 'user'
        && message.source?.kind === 'user' && typeof message.id === 'string');
      const userId = users.at(-1)?.id;
      // Only admitted live input changes intent; tool output and replayed source_meta are never inputs here.
      if (!state || state.context.turn !== payload.turn || state.context.signal !== payload.signal
        || state.context.session !== agent.session || state.context.agent_id !== agent.id
        || userId && userId !== state.context.user_id) {
        if (state) clearState(state);
        state = { context: { turn: payload.turn, signal: payload.signal, session: agent.session,
          agent_id: agent.id, user_id: userId }, cancelled: false, projects: new Map(), signals: new Map(),
          steering_ids: new Set(), audit: null };
        states.set(agent, state);
        addTurnSignal(state, payload.signal);
      }
      for (const message of decision.messages) state.steering_ids.delete(message?.id);
    } catch { diagnose('public_step_context_unavailable'); }
    return decision;
  }

  function observe(event) {
    if (!registered || disposed || ownerSignal?.aborted || !event?.invocation) return;
    const invocation = event.invocation;
    if (event.phase === 'start') {
      const agent = invocation.agent;
      const state = states.get(agent);
      const arm = ARM_SET.has(invocation.action);
      const bound = state?.projects.get(invocation.project_id);
      const pageKey = pageRequestKey(invocation.action, invocation.input);
      if (!arm && !(bound && (ACTIVITY_SET.has(invocation.action) || bound.pending_pages.has(pageKey)))) return;
      if (!runtimeAgent(agent) || !state || !signalLike(invocation.callerSignal)
        || !signalLike(invocation.signal) || !usable(agent, state, state.context.signal, state.context.turn)) {
        metrics.missing_execution_context++;
        diagnose('public_execution_context_unavailable');
        return;
      }
      // The bridge owns these per-tool signals until settlement; they never cancel the whole turn.
      if (invocation.callerSignal.aborted || invocation.signal.aborted) return;
      if (typeof invocation.project_id !== 'string'
        || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(invocation.project_id)) return;
      tickets.set(invocation, { state, agent, project_id: invocation.project_id, arm });
      return;
    }
    const ticket = tickets.get(invocation);
    tickets.delete(invocation);
    if (!ticket || !usable(ticket.agent, ticket.state, ticket.state.context.signal, ticket.state.context.turn)) return;
    const settled = event.phase === 'success' && event.ok === true;
    const uncertain = event.phase === 'failure' && (event.claimed_run === true || event.dispatch_uncertain === true);
    if (ticket.arm && (settled || uncertain) && !ticket.state.projects.has(ticket.project_id)) ticket.state.projects.set(ticket.project_id,
      { blocked_snapshot: null, recovery_notified: false, observed_key: null,
        notified_keys: new Set(), stalled_keys: new Set(), execution_armed: EXECUTION_ARM_SET.has(invocation.action),
        activities: new Set(), activity_version: 0, task_states: new Map(), known_references: new Set(),
        pending_pages: new Map() });
    const binding = ticket.state.projects.get(ticket.project_id);
    if (!binding) return;
    if ((settled || uncertain) && TARGET_EXECUTION_SET.has(invocation.action)) binding.execution_armed = true;
    const pageKey = pageRequestKey(invocation.action, invocation.input);
    const pageProgress = binding.pending_pages.get(pageKey);
    const recoveredPage = settled && typeof pageProgress === 'string' && pageProgress === binding.observed_key;
    if (recoveredPage) binding.pending_pages.delete(pageKey);
    if (recoveredPage || ACTIVITY_SET.has(invocation.action) && (settled || uncertain
      || event.phase === 'failure' && knownFailedActivity(binding, invocation.action, invocation.input))) {
      const key = JSON.stringify([invocation.action, invocation.input || {}, ...(recoveredPage ? [pageProgress] : [])]);
      if (!binding.activities.has(key) && binding.activities.size < ACTIVITY_LIMIT) {
        binding.activities.add(key);
        binding.activity_version++;
        metrics.review_activity_receipts++;
      }
    }
  }

  async function currentTasks(project_id, binding, key, current, signal, stillUsable) {
    const previous = binding.task_states.get(key) || {
      queue_offset: 0, review_offset: 0, last_activity: -1, attempted: false, issued: false, shown: new Set(),
    };
    if (previous.attempted && binding.activity_version <= previous.last_activity) return undefined;
    const next = { ...previous, shown: new Set(previous.shown), attempted: true,
      last_activity: binding.activity_version };
    const candidates = [];
    const pageRecoveries = [];
    for (const [action, field, cursor] of [['plan.next', 'work_items', 'queue_offset'], ['plan.audit', 'checklist', 'review_offset']]) {
      for (let page = 0; page < TASK_PAGE_READ_LIMIT; page++) {
        if (!stillUsable()) return undefined;
        let envelope;
        try {
          envelope = await invoke(settings, action, { project_id, offset: next[cursor], limit: TASK_PAGE_LIMIT,
            ...(action === 'plan.next' ? { parameter_limit: 1 } : {}) }, { signal });
        } catch {
          if (!stillUsable() || signal.aborted) return undefined;
          break;
        }
        if (!stillUsable()) return undefined;
        const fresh = auditState(envelope);
        if (!fresh) break;
        if (fresh.kind === 'completed') return { project_id, completed: true };
        const freshKey = workKey(fresh);
        if (freshKey !== key) return !binding.notified_keys.has(freshKey)
          ? { project_id, ...fresh, binding, key: freshKey } : undefined;
        current = fresh;
        const data = envelope.data;
        if (!Array.isArray(data[field]) || data[field].length > TASK_PAGE_LIMIT) break;
        const before = candidates.length;
        for (const row of [...data[field], ...(action === 'plan.next' && Array.isArray(data.review_followups)
          ? data.review_followups.slice(0, TASK_PAGE_LIMIT) : [])]) {
          const task = taskFrom(row, !binding.execution_armed);
          if (!task) continue;
          for (const reference of [...referenceKeys(task), ...referenceKeys(task.input_template)]) {
            if (binding.known_references.size < ACTIVITY_LIMIT) binding.known_references.add(reference);
          }
          if (!next.shown.has(task.key)) candidates.push(task);
        }
        const total = data[action === 'plan.next' ? 'queue_total' : 'checklist_total'];
        const following = Number.isSafeInteger(total) && Number.isSafeInteger(data.next_offset)
          && data.next_offset > next[cursor] && data.next_offset < total ? data.next_offset : 0;
        next[cursor] = following;
        if (candidates.length > before || !following) break;
        if (page === TASK_PAGE_READ_LIMIT - 1) {
          const recovery = { id: 'page:' + action + ':' + following, action, offline: true, pagination_recovery: true,
            input_template: { offset: following, limit: TASK_PAGE_LIMIT },
            required_experiment_fields: ['Read this exact current page, inspect its saved material and follow the supported review/preparation actions; a page read does not close a security obligation.'] };
          recovery.key = pageRequestKey(action, recovery.input_template);
          if (!next.shown.has(recovery.key)) pageRecoveries.push(recovery);
        }
      }
    }
    const unique = new Map();
    for (const task of candidates.sort((a, b) => taskPriority(a) - taskPriority(b))) {
      if (!unique.has(task.key)) unique.set(task.key, task);
    }
    const tasks = [...unique.values(), ...pageRecoveries].slice(0, TASK_PAGE_LIMIT);
    if (!tasks.length) {
      // Keep a validated cursor even when a page contains only blocked or
      // already handed-off rows, without retrying on a zero-tool tail.
      binding.task_states.set(key, next);
      return undefined;
    }
    return { project_id, ...current, binding, key, tasks, task_state: next };
  }

  function includeFreshCheckpoint(state, project_id, binding, envelope, work) {
    const updated = auditState(envelope);
    if (updated?.kind === 'completed') { state.projects.delete(project_id); return; }
    if (updated?.kind !== 'work' && updated?.kind !== 'frontier') return;
    const key = workKey(updated);
    // A concurrent worker may make genuine progress while the checkpoint awaits.
    if (!binding.notified_keys.has(key)) {
      binding.observed_key = key;
      binding.pending_pages.clear();
      binding.known_references.clear();
      binding.recovery_notified = false;
      work.push({ project_id, ...updated, binding, key });
    }
  }

  async function turnStopping(payload) {
    const agent = payload?.agent;
    const state = states.get(agent);
    if (!state || !signalLike(payload?.signal) || !Number.isSafeInteger(payload.turn)
      || !usable(agent, state, payload.signal, payload.turn) || pendingInput(agent, state)
      || state.audit || !state.projects.size) return;
    metrics.observed_boundaries++;
    const control = new AbortController();
    state.audit = control;
    const signal = AbortSignal.any([payload.signal, lifetime.signal, control.signal,
      ...(ownerSignal ? [ownerSignal] : []), ...state.signals.keys()]);
    const work = [];
    const recovery = [];
    let blocked = 0;
    try {
      for (const [project_id, binding] of state.projects) {
        if (!usable(agent, state, payload.signal, payload.turn) || pendingInput(agent, state)) return;
        let current;
        try { current = auditState(await invoke(settings, 'plan.audit', { project_id, offset: 0, limit: 1 }, { signal })); }
        catch {
          if (signal.aborted || !usable(agent, state, payload.signal, payload.turn)) return;
          metrics.audit_failures++;
          diagnose('audit_unavailable_unfinished');
          if (!binding.recovery_notified) recovery.push({ project_id, binding });
          continue;
        }
        if (!usable(agent, state, payload.signal, payload.turn) || pendingInput(agent, state)) return;
        if (!current) {
          metrics.audit_failures++;
          diagnose('audit_contract_unavailable_unfinished');
          if (!binding.recovery_notified) recovery.push({ project_id, binding });
          continue;
        }
        if (current.kind === 'completed') { state.projects.delete(project_id); continue; }
        const key = workKey(current);
        if (binding.observed_key !== key) {
          if (!binding.notified_keys.has(key)) binding.recovery_notified = false;
          binding.observed_key = key;
          binding.pending_pages.clear();
          binding.known_references.clear();
        }
        if (current.kind === 'blocked') {
          blocked++;
          diagnose('blocked_only_unfinished');
          if (binding.blocked_snapshot !== key) {
            binding.blocked_snapshot = key;
            try {
              const checkpoint = await invoke(settings, 'plan.checkpoint', { project_id,
                label: 'Host boundary: blocked work remains unfinished; no target replay' }, { signal });
              if (!usable(agent, state, payload.signal, payload.turn) || pendingInput(agent, state)) return;
              if (checkpoint?.ok !== true) { diagnose('blocked_checkpoint_unavailable_unfinished'); continue; }
              metrics.blocked_checkpoints++;
              includeFreshCheckpoint(state, project_id, binding, checkpoint, work);
            } catch {
              if (signal.aborted || !usable(agent, state, payload.signal, payload.turn)) return;
              diagnose('blocked_checkpoint_unavailable_unfinished');
            }
          }
          continue;
        }
        if (binding.notified_keys.has(key)) {
          metrics.duplicate_work_suppressed++;
          diagnose('no_progress_handoff_suppressed_unfinished');
          if (!binding.stalled_keys.has(key)) {
            binding.stalled_keys.add(key);
            try {
              const checkpoint = await invoke(settings, 'plan.checkpoint', { project_id,
                label: 'Host boundary: unchanged closure progress; assessment remains unfinished' }, { signal });
              if (!usable(agent, state, payload.signal, payload.turn) || pendingInput(agent, state)) return;
              if (checkpoint?.ok === true) {
                metrics.stalled_checkpoints++;
                includeFreshCheckpoint(state, project_id, binding, checkpoint, work);
              }
              else diagnose('stalled_checkpoint_unavailable_unfinished');
            } catch {
              if (signal.aborted || !usable(agent, state, payload.signal, payload.turn)) return;
              diagnose('stalled_checkpoint_unavailable_unfinished');
            }
          }
          if (!usable(agent, state, payload.signal, payload.turn) || pendingInput(agent, state)) return;
          if (!state.projects.has(project_id) || work.some(item => item.project_id === project_id)) continue;
          const handoff = await currentTasks(project_id, binding, key, current, signal,
            () => usable(agent, state, payload.signal, payload.turn) && !pendingInput(agent, state));
          if (handoff?.completed) state.projects.delete(project_id);
          else if (handoff) work.push(handoff);
          continue;
        }
        work.push({ project_id, ...current, binding, key });
      }
      if ((!work.length && !recovery.length) || !usable(agent, state, payload.signal, payload.turn)
        || pendingInput(agent, state)) return;
      // steer is synchronous: no await separates the final cancellation check from inbox publication.
      // Unnotified projects retain precedence over corrective pages from others.
      work.sort((a, b) => Boolean(a.tasks) - Boolean(b.tasks));
      const projects = recovery.map(item => item.project_id);
      const message = work.length ? continuationMessage(work, blocked, projects) : recoveryMessage(projects);
      state.steering_ids.add(message.id);
      agent.steer(message);
      // Only shown projects were handed off; omitted projects get their next page.
      for (const item of work.slice(0, MESSAGE_PROJECT_LIMIT)) {
        if (item.binding.observed_key !== item.key) {
          item.binding.observed_key = item.key;
          item.binding.pending_pages.clear();
          item.binding.known_references.clear();
        }
        item.binding.notified_keys.add(item.key);
        if (item.tasks) {
          for (const task of item.tasks) {
            item.task_state.shown.add(task.key);
            if (task.pagination_recovery) item.binding.pending_pages.set(task.key, item.key);
          }
          item.task_state.last_activity = item.binding.activity_version;
          item.task_state.issued = true;
          item.binding.task_states.set(item.key, item.task_state);
          metrics.concrete_handoffs++;
        }
      }
      for (const item of recovery.slice(0, MESSAGE_PROJECT_LIMIT)) item.binding.recovery_notified = true;
      metrics.steers++;
      if (recovery.length) metrics.recovery_steers++;
      diagnose(work.length ? 'current_work_steered' : 'offline_recovery_steered_unfinished');
    } catch {
      if (!signal.aborted && usable(agent, state, payload.signal, payload.turn)) diagnose('steering_unavailable_unfinished');
    } finally {
      if (state.audit === control) state.audit = null;
    }
  }

  function dispose() {
    if (disposed) return;
    disposed = true;
    registered = false;
    lifetime.abort(new Error('awa-ddd host continuation disposed'));
    for (const state of states.values()) clearState(state);
    states.clear();
    for (const detach of disposers.splice(0).reverse()) {
      try { detach(); } catch { /* Optional hook teardown cannot affect assessment tool disposal. */ }
    }
    ownerSignal?.removeEventListener('abort', dispose);
    reason = 'disposed';
  }

  function attach(ctx) {
    if (disposed || registered) return status();
    if (typeof ctx?.on !== 'function') { diagnose('public_hook_unavailable'); return status(); }
    try {
      for (const [event, callback] of [
        ['agent/pre-step', preStep], [TURN_STOPPING_EVENT, turnStopping],
        ['agent/status', payload => { if (payload?.status === 'idle') remove(payload.agent); }],
        ['agent/disposed', payload => remove(payload?.agent)],
      ]) {
        const detach = ctx.on(event, callback);
        if (typeof detach === 'function') disposers.push(detach);
      }
      registered = true;
      reason = 'public_hook_registered';
      if (!ownerSignal && typeof ctx.effect === 'function') ctx.effect(() => dispose);
    } catch {
      for (const detach of disposers.splice(0).reverse()) { try { detach(); } catch {} }
      registered = false;
      diagnose('public_hook_registration_failed');
    }
    return status();
  }

  function status() {
    return Object.freeze({ registered, disposed, reason, active_agents: [...states.values()].filter(state => state.projects.size).length,
      cancelled_agents: [...states.values()].filter(state => state.cancelled).length,
      bound_projects: [...states.values()].reduce((count, state) => count + state.projects.size, 0), ...metrics });
  }

  if (ownerSignal) {
    if (!signalLike(ownerSignal)) throw new TypeError('Host continuation requires a real lifecycle AbortSignal');
    ownerSignal.addEventListener('abort', dispose, { once: true });
    if (ownerSignal.aborted) dispose();
  }
  return Object.freeze({ observe, attach, dispose, status, preStep, turnStopping });
}

export function apply(ctx, config = {}, options = {}) {
  const controller = createController(config, options);
  controller.attach(ctx);
  return controller;
}
