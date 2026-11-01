/** Public, cancellation-aware agent/turn-stopping integration; never sends target traffic. */
import { createUserMessage } from '@deepseek-ai/dsh-llm';
import { compactContinuation, invokeEngine, resolveConfig } from './bridge.mjs';

export const name = 'awa-ddd-host-continuation';
export const TURN_STOPPING_EVENT = 'agent/turn-stopping';
export const ARM_ACTIONS = Object.freeze(['http.capture', 'scenario.run', 'browser.visit', 'identity.verify',
  'tool.sqlmap', 'tool.yakit_replay', 'tool.tscanplus_request', 'plan.build', 'plan.next']);
const ARM_SET = new Set(ARM_ACTIONS);
const COUNTS = ['ready_total', 'review_total', 'blocked_total', 'unresolved_total', 'actionable_total'];
const MESSAGE_PROJECT_LIMIT = 8;

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

const RECOVERY_LINES = [
  'For unauditable projects, exhaustion is NOT established. Attempt one bounded OFFLINE recovery: action.help for plan.audit -> project.status -> plan.audit at the current offset with a smaller page. Preserve an unfinished checkpoint/draft when available.',
  'For those projects, do not send target traffic, retry uncertain writes, expand authorization or guess queue counts. Inspect/recover any recorded interrupted run offline and reconcile immutable existing evidence before considering an authorized retry.',
  'If the same offline dependency failure persists, retain the unfinished binding and report the needed prerequisite; do not spin identical error retries or label it completed, user_stop or budget_exhausted.',
];

function continuationMessage(items, blocked, recoveryProjects = []) {
  const shown = items.slice(0, MESSAGE_PROJECT_LIMIT).map(item => ({ project_id: item.project_id,
    continuation: compactContinuation(item.continuation) }));
  return createUserMessage({
    source: { kind: 'awa-ddd-host-continuation', form: 'notice',
      summary: 'Current authorized assessment work or strict exhaustion review remains.' },
    content: [{ type: 'text', text: [
      'awa-ddd host continuation guard: this normally closing turn is not an assessment completion.',
      'This is plugin-sourced context, not a user command or new authorization. Respect the current user intent, actual cancellation and existing scope/identity/fixture limits.',
      'Continue ALL current authorized ready AND review work for successfully audited projects: plan.audit -> plan.next/review_followups -> OFFLINE prerequisite/disposition/evidence reconciliation -> scoped execution only when current prerequisites permit -> plan.checkpoint. Recover omitted CURRENT pages before following next_offset.',
      'Caller-only plan.disposition status:blocked prose is NOT a verified unavailable prerequisite. If the current queue exposes blocked-disposition reconciliation, FIRST inspect its actual obligation and missing_prerequisites, then use its bounded OFFLINE plan.disposition status:open template. Do not automatically replay a target request or override actual scope/identity/fixture/browser prerequisites.',
      'Likewise, administrative plan.review status:blocked does not prove valid existing material is unavailable. Follow current blocker_reconciliation_required items with their OFFLINE plan.review status:reopen templates before reviewing the source; never replace evidence reconciliation with caller prose.',
      'Setup/auth/input tracing and existing-evidence review remain actionable review work; declaring them blocked or citing no_progress is not reconciliation or completion.',
      'Findings, elapsed time, request counts, context pressure, a single step output-token ceiling and caller-declared budgets are not overall execution-budget exhaustion. Do not invent budget_exhausted/user_stop/authorization_boundary exits.',
      'If no execution/review work remains, complete the evidence-bound discovery/category/page frontier rounds, then obtain the current strict plan.finalize reason:completed. A draft or can_finalize alone is not a finalized assessment.',
      'Before any new target action after an interrupted/unknown run, FIRST use offline run.inspect/run.recover and reconcile its recorded evidence. Never replay an uncertain write or expand scope.',
      'Stalled/no_progress_rounds requires a different bounded hypothesis, existing-evidence reconciliation or repaired prerequisites, never endless duplicate traffic.',
      ...(blocked ? ['Other bound projects have blocked-only work retained as unfinished checkpoints; do not replay them or label them completed.'] : []),
      `Fresh offline audit (${shown.length} of ${items.length} bound projects shown; omitted projects remain unfinished): ${JSON.stringify(shown)}`,
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
      'This is plugin-sourced context, not a user command or new authorization. Respect the current user intent, actual cancellation and existing scope/identity/fixture limits.',
      ...RECOVERY_LINES,
      'Only a successful current strict plan.finalize reason:completed can establish assessment exhaustion. Do not invent an overall execution budget or override an actual abort/termination.',
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
    blocked_checkpoints: 0, audit_failures: 0, missing_execution_context: 0 };
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
      if (!ARM_SET.has(invocation.action)) return;
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
      tickets.set(invocation, { state, agent, project_id: invocation.project_id });
      return;
    }
    const ticket = tickets.get(invocation);
    tickets.delete(invocation);
    if (!ticket || !(event.phase === 'success' && event.ok === true || event.phase === 'failure'
      && (event.claimed_run === true || event.dispatch_uncertain === true))
      || !usable(ticket.agent, ticket.state, ticket.state.context.signal, ticket.state.context.turn)) return;
    if (!ticket.state.projects.has(ticket.project_id)) ticket.state.projects.set(ticket.project_id,
      { blocked_snapshot: null, recovery_notified: false });
  }

  async function turnStopping(payload) {
    const agent = payload?.agent;
    const state = states.get(agent);
    if (!state || !signalLike(payload?.signal) || !Number.isSafeInteger(payload.turn)
      || !usable(agent, state, payload.signal, payload.turn) || pendingInput(agent, state) || !state.projects.size) return;
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
        binding.recovery_notified = false;
        if (current.kind === 'completed') { state.projects.delete(project_id); continue; }
        if (current.kind === 'blocked') {
          blocked++;
          diagnose('blocked_only_unfinished');
          if (binding.blocked_snapshot !== current.continuation.snapshot_id) {
            binding.blocked_snapshot = current.continuation.snapshot_id;
            try {
              const checkpoint = await invoke(settings, 'plan.checkpoint', { project_id,
                label: 'Host boundary: blocked work remains unfinished; no target replay' }, { signal });
              if (!usable(agent, state, payload.signal, payload.turn) || pendingInput(agent, state)) return;
              if (checkpoint?.ok !== true) { diagnose('blocked_checkpoint_unavailable_unfinished'); continue; }
              metrics.blocked_checkpoints++;
              const updated = auditState(checkpoint);
              if (updated?.kind === 'work' || updated?.kind === 'frontier') work.push({ project_id, ...updated });
            } catch {
              if (signal.aborted || !usable(agent, state, payload.signal, payload.turn)) return;
              diagnose('blocked_checkpoint_unavailable_unfinished');
            }
          }
          continue;
        }
        work.push({ project_id, ...current });
      }
      if ((!work.length && !recovery.length) || !usable(agent, state, payload.signal, payload.turn)
        || pendingInput(agent, state)) return;
      // steer is synchronous: no await separates the final cancellation check from inbox publication.
      const projects = recovery.map(item => item.project_id);
      const message = work.length ? continuationMessage(work, blocked, projects) : recoveryMessage(projects);
      state.steering_ids.add(message.id);
      agent.steer(message);
      for (const item of recovery) item.binding.recovery_notified = true;
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
