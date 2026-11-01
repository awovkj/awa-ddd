import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { basename, join, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';
import { createServer } from 'node:http';
import { Context } from '@deepseek-ai/cordis';
import { Session } from '@deepseek-ai/dsh-session';
import { agentEvents } from '@deepseek-ai/dsh-agent';
import { createUserMessage } from '@deepseek-ai/dsh-llm';
import { defineTool } from '@deepseek-ai/dsh-tools';
import { ARM_ACTIONS, TURN_STOPPING_EVENT, apply, createController } from '../src/host-continuation.mjs';
import { BridgeError, invokeEngine } from '../src/bridge.mjs';
import { toolDefinitions } from '../src/tools.mjs';

const config = { workspace: join(tmpdir(), 'awa-host-continuation-fixture') };
const user = text => createUserMessage({ source: { kind: 'user' }, content: [{ type: 'text', text }] });

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function audit(overrides = {}) {
  return { ok: true, data: { continuation: { contract_version: 2, stop_policy: 'exhaustion_only',
    stop_policy_version: 1, continue_required: true, automatic_stop_allowed: false, can_finalize: false,
    can_claim_complete: false, frontier_review_required: true, frontier_rounds: 0,
    ready_total: 98, review_total: 134, actionable_total: 232, blocked_total: 149, unresolved_total: 381,
    no_progress_rounds: 0, snapshot_id: 'CS-fixture', checkpoint_id: null, finalization_id: null,
    state: 'continue', coverage_status: 'partial', next_action: 'plan.next', ...overrides } } };
}

function finalAudit() {
  return audit({ continue_required: false, automatic_stop_allowed: true, can_finalize: true,
    can_claim_complete: true, frontier_review_required: false, frontier_rounds: 2,
    ready_total: 0, review_total: 0, actionable_total: 0, blocked_total: 0, unresolved_total: 0,
    coverage_status: 'complete', state: 'finalized', finalization_id: 'FN-real-fixture' });
}

function agent(id, sessionId = id) {
  const session = Session.create(sessionId);
  const steered = [];
  const inbox = { nextStep: [], nextTurn: [] };
  return { id, session, status: 'running', inbox, steered,
    steer(message) { steered.push(message); inbox.nextStep.push(message); },
    followup() { assert.fail('followup cannot veto the current turn'); },
    inject() { assert.fail('non-waking context is not a turn-stopping veto'); } };
}

function fakeContext() {
  const handlers = new Map();
  return { handlers,
    on(name, callback) {
      if (!handlers.has(name)) handlers.set(name, []);
      handlers.get(name).push(callback);
      return () => handlers.set(name, handlers.get(name).filter(item => item !== callback));
    },
    async step(payload, decision) {
      let next = async () => decision;
      for (const handler of [...(handlers.get('agent/pre-step') ?? [])].reverse()) {
        const inner = next;
        next = () => handler(payload, inner);
      }
      return next();
    },
    async stopping(payload) {
      for (const handler of handlers.get(TURN_STOPPING_EVENT) ?? []) await handler(payload);
    },
    emit(name, payload) { for (const handler of handlers.get(name) ?? []) handler(payload); },
  };
}

function setup({ query = async () => audit(), runner = async () => ({ ok: true, data: {} }), settings = config } = {}) {
  const ctx = fakeContext();
  const lifetime = new AbortController();
  const diagnostics = [];
  const calls = [];
  const controller = createController(settings, { signal: lifetime.signal,
    invoke: async (...args) => { calls.push(args); return query(...args); },
    onDiagnostic: value => diagnostics.push(value) });
  controller.attach(ctx);
  const definitions = toolDefinitions(defineTool, settings, runner, lifetime.signal, { observer: controller.observe });
  const frames = new Map();
  return { ctx, controller, lifetime, diagnostics, calls, definitions,
    async step(subject, { turn = 1, messages = [user('Assess only the authorized fixture.')], signal = new AbortController().signal } = {}) {
      frames.set(subject, { agent: subject, turn, step: 1, signal });
      subject.inbox.nextStep.length = 0;
      const decision = { kind: 'enter', messages };
      assert.equal(await ctx.step(frames.get(subject), decision), decision);
      return signal;
    },
    async call(subject, action, project_id = 'project-a', input = {}, callerSignal = frames.get(subject)?.signal) {
      const tool = definitions.find(item => item.parameters.properties.action.enum.includes(action));
      return tool.execute({ action, ...(project_id ? { project_id } : {}), input }, { agent: subject, signal: callerSignal });
    },
    stop(subject, override = {}) { return ctx.stopping({ ...frames.get(subject), ...override }); },
  };
}

async function offlineSdkFixture(project_id, body, { expectedRequests = 0, expectedRunTotal = 0,
  expectedUnassessed = 0, extraActions = [], responseDelayMs = 0, captureTimeoutMs } = {}) {
  const prefix = 'awa-host-cordis-engine-';
  const workspace = await mkdtemp(join(tmpdir(), prefix));
  const settings = { workspace, timeoutMs: 15000 };
  let requests = 0;
  const server = createServer((_request, response) => {
    requests++;
    response.writeHead(200, { 'content-type': 'application/json' });
    if (responseDelayMs) setTimeout(() => response.end('{"fixture":true}'), responseDelayMs);
    else response.end('{"fixture":true}');
  });
  const lifetime = new AbortController();
  const turn = new AbortController();
  const ctx = new Context();
  const calls = [];
  const actions = [];
  const controller = createController(settings, { signal: lifetime.signal,
    invoke: async (...args) => { calls.push(args); return invokeEngine(...args); } });
  const definitions = toolDefinitions(defineTool, settings,
    async (...args) => {
      actions.push(args[1]);
      if (args[1] === 'http.capture' && captureTimeoutMs) return invokeEngine({ ...args[0], timeoutMs: captureTimeoutMs }, ...args.slice(1));
      return invokeEngine(...args);
    }, lifetime.signal,
    { observer: controller.observe });
  controller.attach(ctx);
  const subject = agent('runtime-' + project_id);
  const events = agentEvents(ctx, subject);
  let step = 0;
  try {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    const base = `http://127.0.0.1:${server.address().port}`;
    const fixture = { settings, base, subject, controller, calls, actions, turn, lifetime,
      get requests() { return requests; },
      async enter(messages = [user('Assess only this finite authorized loopback fixture.')]) {
        subject.inbox.nextStep.length = 0;
        const decision = { kind: 'enter', messages };
        assert.equal(await events.waterfall('agent/pre-step', { turn: 1, step: ++step, signal: turn.signal, messages },
          async () => decision), decision);
      },
      async call(action, input = {}) {
        const definition = definitions.find(item => item.parameters.properties.action.enum.includes(action));
        return definition.execute({ action, project_id, input }, { agent: subject, signal: turn.signal });
      },
      stop() { return events.serial(TURN_STOPPING_EVENT, { turn: 1, signal: turn.signal }); },
    };
    await fixture.call('project.create', { target: base });
    await fixture.enter();
    await body(fixture);
    assert.equal(requests, expectedRequests, 'only the declared fixture request occurs; offline reconciliation never replays it');
    const state = await fixture.call('project.status');
    assert.equal(state.data.run_total, expectedRunTotal, 'only the declared fixture runs are claimed');
    assert.equal(state.data.completion.unassessed_observations, expectedUnassessed);
    assert.ok([...actions, ...calls.map(call => call[1])].every(action =>
      ['project.create', 'project.status', 'surface.register', 'surface.inspect', 'plan.build', 'plan.next',
        'plan.disposition', 'plan.audit', 'plan.checkpoint', 'http.preflight', ...extraActions].includes(action)));
  } finally {
    controller.dispose();
    if (server.listening) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    const absolute = resolve(workspace);
    assert.ok(absolute.startsWith(resolve(tmpdir()) + sep) && basename(absolute).startsWith(prefix));
    await rm(absolute, { recursive: true, force: true });
  }
}

test('public SDK declares the awaited stopping seam and identified-message helper', async () => {
  const root = new URL('../node_modules/@deepseek-ai/', import.meta.url);
  const types = await readFile(new URL('dsh-agent/lib/types/runtime-types.d.ts', root), 'utf8');
  assert.match(types, /'agent\/turn-stopping'\(this: Scoped<Agent>, payload: \{[\s\S]*?signal: AbortSignal;[\s\S]*?\}\): Promise<void> \| void/);
  assert.match(types, /fresh steering runs another step/);
  assert.match(types, /steer\(message: UserMessage\): void/);
  const message = createUserMessage({ source: { kind: 'awa-ddd-host-continuation' }, content: [{ type: 'text', text: 'fixture' }] });
  assert.equal(message.role, 'user');
  assert.equal(typeof message.id, 'string');
  assert.ok(Object.isFrozen(message));
});

test('actual Cordis/agentEvents serial dispatch awaits the guard without starting a host', async () => {
  const ctx = new Context();
  const lifetime = new AbortController();
  const waiting = deferred();
  const controller = apply(ctx, config, { signal: lifetime.signal, invoke: () => waiting.promise });
  const subject = agent('public-sdk-agent');
  const signal = new AbortController().signal;
  const events = agentEvents(ctx, subject);
  try {
    await events.waterfall('agent/pre-step', { turn: 1, step: 1, signal, messages: [user('Fixture assessment')] },
      async () => ({ kind: 'enter', messages: [user('Fixture assessment')] }));
    const tools = toolDefinitions(defineTool, config, async () => ({ ok: true, data: {} }), lifetime.signal,
      { observer: controller.observe });
    await tools.find(item => item.name === 'awa_plan').execute({ action: 'plan.next', project_id: 'project-a' }, { agent: subject, signal });
    let settled = false;
    const stopping = events.serial(TURN_STOPPING_EVENT, { turn: 1, signal }).then(() => { settled = true; });
    await Promise.resolve();
    assert.equal(settled, false);
    waiting.resolve(audit());
    await stopping;
    assert.equal(subject.steered.length, 1);
  } finally { controller.dispose(); }
});

test('the first real failed scenario SC handle binds unfinished work and steers without replay', async () => {
  await offlineSdkFixture('first-failed-scenario', async fixture => {
    const operation = (await fixture.call('surface.register', { url: fixture.base + '/fixture', method: 'GET', auth: 'public',
      inputs: [{ name: 'q', location: 'query', consumer: 'business_input', test_families: ['generic'] }] })).data;
    assert.equal(fixture.controller.status().bound_projects, 0);
    let runId;
    await assert.rejects(fixture.call('scenario.run', { scenario: { steps: [{ id: 'read-once', operation_id: operation.id,
      assertions: [{ selector: '/fixture', equals: false }] }] } }), error => {
      assert.equal(error.code, 'scenario_assertion');
      runId = error.details.run_id;
      assert.match(runId, /^SC-[A-Za-z0-9_-]+$/);
      return true;
    });
    assert.equal(fixture.requests, 1);
    assert.equal(fixture.controller.status().bound_projects, 1);
    const inspected = (await fixture.call('run.inspect', { run_id: runId })).data;
    assert.equal(inspected.id, runId);
    assert.equal(inspected.status, 'failed');
    await fixture.stop();
    assert.equal(fixture.requests, 1);
    assert.equal(fixture.subject.steered.length, 1);
    assert.equal(fixture.subject.steered[0].source.kind, 'awa-ddd-host-continuation');
    assert.match(fixture.subject.steered[0].content[0].text, /offline run\.inspect\/run\.recover/);
    assert.deepEqual(fixture.calls.map(call => call[1]), ['plan.audit']);
  }, { expectedRequests: 1, expectedRunTotal: 2, expectedUnassessed: 1, extraActions: ['scenario.run', 'run.inspect'] });
});

test('failed run handles must match the actual arming action kind', async () => {
  for (const [action, run_id] of [['scenario.run', 'RUN-wrong-kind'], ['http.capture', 'SC-wrong-kind']]) {
    const h = setup({ runner: async () => { throw new BridgeError('FIXTURE_FAILURE', 'Owned fixture failure', { run_id }); } });
    const subject = agent('wrong-' + action);
    await h.step(subject);
    await assert.rejects(h.call(subject, action));
    await h.stop(subject);
    assert.equal(h.controller.status().bound_projects, 0);
    assert.equal(h.calls.length, 0);
    assert.equal(subject.steered.length, 0);
    h.controller.dispose();
  }
});

test('the first real bridge timeout retains binding without a returned run handle and never replays', async () => {
  await offlineSdkFixture('first-uncertain-timeout', async fixture => {
    const operation = (await fixture.call('surface.register', { url: fixture.base + '/fixture', method: 'GET', auth: 'public',
      inputs: [{ name: 'q', location: 'query', consumer: 'business_input', test_families: ['generic'] }] })).data;
    assert.equal(fixture.controller.status().bound_projects, 0);
    await assert.rejects(fixture.call('http.capture', { operation_id: operation.id }), error => error.code === 'ENGINE_TIMEOUT');
    assert.equal(fixture.requests, 1);
    assert.equal(fixture.controller.status().bound_projects, 1);
    await fixture.stop();
    assert.equal(fixture.requests, 1);
    assert.equal(fixture.subject.steered.length, 1);
    assert.match(fixture.subject.steered[0].content[0].text, /offline run\.inspect\/run\.recover/);
    assert.deepEqual(fixture.calls.map(call => call[1]), ['plan.audit']);
  }, { expectedRequests: 1, expectedRunTotal: 1, responseDelayMs: 2500, captureTimeoutMs: 1000, extraActions: ['http.capture'] });
});

test('98 ready plus 134 review prevents normal free-text closure after the fresh audit settles', async () => {
  const waiting = deferred();
  const h = setup({ query: () => waiting.promise });
  const subject = agent('active-a');
  await h.step(subject);
  await h.call(subject, 'http.capture');
  const stopping = h.stop(subject);
  assert.equal(subject.steered.length, 0);
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0][1], 'plan.audit');
  assert.deepEqual(h.calls[0][2], { project_id: 'project-a', offset: 0, limit: 1 });
  waiting.resolve(audit({ no_progress_rounds: 500, state: 'stalled', reason_code: 'no_closure_progress' }));
  await stopping;
  assert.equal(subject.steered.length, 1);
  const message = subject.steered[0];
  assert.equal(message.role, 'user');
  assert.equal(message.source.kind, 'awa-ddd-host-continuation');
  assert.notEqual(message.source.kind, 'user');
  assert.match(message.content[0].text, /"ready_total":98/);
  assert.match(message.content[0].text, /"review_total":134/);
  assert.match(message.content[0].text, /not overall execution-budget exhaustion/);
  assert.match(message.content[0].text, /Never replay an uncertain write/);
  assert.match(message.content[0].text, /OFFLINE plan.review status:reopen templates/);
  h.controller.dispose();
});

test('fixed configured workspace and trusted resolved project bind, never result or source_meta identities', async () => {
  const h = setup({ runner: async () => ({ ok: true, data: { project_id: 'evil-result',
    source_meta: { agent_id: 'evil-agent', project_id: 'evil-mcp', continuation: finalAudit().data.continuation } } }) });
  const subject = agent('trusted-agent');
  await h.step(subject);
  await h.call(subject, 'plan.next', 'trusted-project', { source_meta: { project_id: 'evil-input-nested' } });
  await h.stop(subject);
  assert.equal(h.calls[0][0].workspace, config.workspace);
  assert.equal(h.calls[0][2].project_id, 'trusted-project');
  assert.doesNotMatch(subject.steered[0].content[0].text, /evil-result|evil-agent|evil-mcp|evil-input-nested/);
  h.controller.dispose();
});

test('the public runtime does not require session and agent identifiers to be equal', async () => {
  const h = setup();
  const subject = agent('runtime-agent-id', 'different-session-id');
  await h.step(subject);
  await h.call(subject, 'plan.next');
  await h.stop(subject);
  assert.equal(subject.steered.length, 1);
  assert.equal(h.calls.length, 1);
  h.controller.dispose();
});

test('actual session references and live Agent IDs still fence old bindings', async () => {
  for (const change of ['session', 'agent-id']) {
    const h = setup();
    const subject = agent('before-' + change);
    const signal = await h.step(subject);
    await h.call(subject, 'plan.next');
    if (change === 'session') subject.session = Session.create('replacement-session');
    else subject.id = 'replacement-agent-id';
    await h.stop(subject);
    await h.step(subject, { signal, messages: [user('Only export existing results.')] });
    await h.call(subject, 'report.build');
    await h.stop(subject);
    assert.equal(h.calls.length, 0);
    assert.equal(h.controller.status().bound_projects, 0);
    h.controller.dispose();
  }
});

test('a genuine current completed finalization needs no steering; can_finalize alone still does', async () => {
  for (const finalized of [true, false]) {
    const h = setup({ query: async () => finalized ? finalAudit() : audit({ ready_total: 0, review_total: 0,
      blocked_total: 0, unresolved_total: 0, actionable_total: 0, can_finalize: true, frontier_rounds: 2,
      frontier_review_required: false, coverage_status: 'complete' }) });
    const subject = agent('final-' + finalized);
    await h.step(subject);
    await h.call(subject, 'plan.next');
    await h.stop(subject);
    assert.equal(subject.steered.length, finalized ? 0 : 1);
    assert.equal(h.controller.status().bound_projects, finalized ? 0 : 1);
    h.controller.dispose();
  }
});

test('closed work without the two complete frontier rounds is continued offline, not called exhaustion', async () => {
  const h = setup({ query: async () => audit({ ready_total: 0, review_total: 0, actionable_total: 0,
    blocked_total: 0, unresolved_total: 0, coverage_status: 'complete', frontier_rounds: 0 }) });
  const subject = agent('frontier-needed');
  await h.step(subject);
  await h.call(subject, 'assessment.evaluate');
  assert.equal(h.controller.status().bound_projects, 0, 'standalone evidence review does not arm target testing');
  await h.call(subject, 'plan.next');
  await h.stop(subject);
  assert.equal(subject.steered.length, 1);
  assert.match(subject.steered[0].content[0].text, /complete the evidence-bound discovery\/category\/page frontier/);
  h.controller.dispose();
});

test('help, old project status, report-only, import and pause checkpoint calls never arm testing', async () => {
  const h = setup();
  const subject = agent('report-only');
  await h.step(subject, { messages: [user('Read and export historical results only; do not test.')] });
  for (const action of ['action.help', 'project.status', 'report.build', 'plan.audit', 'plan.checkpoint',
    'browser.import_mcp', 'project.import_pentest', 'finding.list']) await h.call(subject, action);
  await h.stop(subject);
  assert.equal(h.calls.length, 0);
  assert.equal(subject.steered.length, 0);
  assert.equal(h.controller.status().bound_projects, 0);
  h.controller.dispose();
});

test('no real exec.agent or no admitted public step context safely degrades', async () => {
  const h = setup();
  const subject = agent('unobserved-step');
  await h.definitions.find(item => item.name === 'awa_execute').execute({ action: 'http.capture', project_id: 'project-a' },
    { signal: new AbortController().signal });
  await h.call(subject, 'plan.next', 'project-a', {}, new AbortController().signal);
  await h.ctx.stopping({ agent: subject, turn: 1, signal: new AbortController().signal });
  assert.equal(h.calls.length, 0);
  assert.equal(h.controller.status().bound_projects, 0);
  assert.equal(h.controller.status().missing_execution_context, 2);
  assert.equal(h.diagnostics.at(-1).code, 'public_execution_context_unavailable');
  h.controller.dispose();
});

test('a settled tool signal abort is not whole-turn cancellation or budget exhaustion', async () => {
  const h = setup();
  const subject = agent('old-execution-cancel');
  const turn = await h.step(subject);
  const execution = new AbortController();
  await h.call(subject, 'plan.next', 'project-a', {}, execution.signal);
  execution.abort(new Error('actual caller cancel'));
  assert.equal(turn.aborted, false);
  await h.stop(subject);
  assert.equal(h.calls.length, 1);
  assert.equal(subject.steered.length, 1);
  assert.equal(h.controller.status().cancelled_agents, 0);
  h.controller.dispose();
});

test('a settled passive tool timeout cannot suppress already armed assessment work', async () => {
  const h = setup();
  const subject = agent('passive-execution-cancel');
  await h.step(subject);
  await h.call(subject, 'plan.next');
  const passive = new AbortController();
  await h.call(subject, 'report.build', 'project-a', {}, passive.signal);
  passive.abort();
  await h.stop(subject);
  assert.equal(h.calls.length, 1);
  assert.equal(subject.steered.length, 1);
  assert.equal(h.controller.status().cancelled_agents, 0);
  h.controller.dispose();
});

test('cancellation while audit is awaited never publishes steering or wakes a later turn', async () => {
  for (const kind of ['turn', 'owner', 'disposed-agent']) {
    const waiting = deferred();
    const h = setup({ query: () => waiting.promise });
    const subject = agent('cancel-race-' + kind);
    const turn = new AbortController();
    await h.step(subject, { signal: turn.signal });
    const execution = new AbortController();
    await h.call(subject, 'http.capture', 'project-a', {}, execution.signal);
    const stopping = h.stop(subject);
    assert.equal(h.calls.length, 1);
    if (kind === 'turn') turn.abort();
    else if (kind === 'owner') h.lifetime.abort();
    else h.ctx.emit('agent/disposed', { agent: subject });
    assert.equal(h.calls[0][3].signal.aborted, true);
    waiting.resolve(audit());
    await stopping;
    assert.equal(subject.steered.length, 0, kind);
    h.controller.dispose();
  }
});

test('an independently settled tool signal cannot cancel a subsequently awaited audit', async () => {
  const waiting = deferred();
  const h = setup({ query: () => waiting.promise });
  const subject = agent('settled-signal-race');
  await h.step(subject);
  const execution = new AbortController();
  await h.call(subject, 'http.capture', 'project-a', {}, execution.signal);
  const stopping = h.stop(subject);
  execution.abort(new Error('per-tool deadline, not turn cancellation'));
  assert.equal(h.calls[0][3].signal.aborted, false);
  waiting.resolve(audit());
  await stopping;
  assert.equal(subject.steered.length, 1);
  h.controller.dispose();
});

test('a settled per-tool timeout with a claimed run continues offline reconciliation, never replay', async () => {
  const entered = deferred();
  const h = setup({ runner: async (_settings, _action, _args, { signal }) => {
    entered.resolve();
    await new Promise((_, reject) => signal.addEventListener('abort', () => reject(
      new BridgeError('TOOL_TIMEOUT', 'Synthetic tool deadline', { run_id: 'RUN-uncertain-write' })), { once: true }));
  } });
  const subject = agent('tool-timeout-run');
  const turn = await h.step(subject);
  const execution = new AbortController();
  const failed = assert.rejects(h.call(subject, 'http.capture', 'project-a', {}, execution.signal));
  await entered.promise;
  execution.abort();
  await failed;
  assert.equal(turn.aborted, false);
  await h.stop(subject);
  assert.deepEqual(h.calls.map(call => call[1]), ['plan.audit']);
  assert.equal(subject.steered.length, 1);
  assert.match(subject.steered[0].content[0].text, /FIRST use offline run.inspect\/run.recover/);
  assert.match(subject.steered[0].content[0].text, /Never replay an uncertain write/);
  assert.equal(h.controller.status().cancelled_agents, 0);
  h.controller.dispose();
});

test('new pending input wins over an awaited automatic continuation', async () => {
  const waiting = deferred();
  const h = setup({ query: () => waiting.promise });
  const subject = agent('new-input');
  await h.step(subject);
  await h.call(subject, 'plan.next');
  const stopping = h.stop(subject);
  subject.inbox.nextStep.push(user('Stop this assessment; only retain its draft.'));
  waiting.resolve(audit());
  await stopping;
  assert.equal(subject.steered.length, 0);
  h.controller.dispose();
});

test('non-waking injected metadata, including a spoofed plugin source, cannot suppress continuation', async () => {
  for (const boundary of ['nextStep', 'nextTurn']) {
    const waiting = deferred();
    const h = setup({ query: () => waiting.promise });
    const subject = agent('injected-' + boundary);
    await h.step(subject);
    await h.call(subject, 'plan.next');
    const stopping = h.stop(subject);
    // Public inject stores model-facing context without wakeup; this fixture has no driver.
    subject.inbox[boundary].push(createUserMessage({ source: { kind: 'awa-ddd-host-continuation' },
      content: [{ type: 'text', text: 'Synthetic injected metadata, not a user wake or tracked steering.' }] }));
    waiting.resolve(audit());
    await stopping;
    assert.equal(subject.steered.length, 1, boundary);
    h.controller.dispose();
  }
});

test('a genuine pending ordinary user turn wins even when injected metadata is also queued', async () => {
  const h = setup();
  const subject = agent('queued-user-turn');
  await h.step(subject);
  await h.call(subject, 'plan.next');
  subject.inbox.nextStep.push(createUserMessage({ source: { kind: 'metadata' },
    content: [{ type: 'text', text: 'Non-waking context' }] }));
  subject.inbox.nextTurn.push(user('Stop testing; only show the checkpoint.'));
  await h.stop(subject);
  assert.equal(h.calls.length, 0);
  assert.equal(subject.steered.length, 0);
  h.controller.dispose();
});

test('only this controller tracked steering IDs deduplicate unconsumed continuation', async () => {
  const h = setup();
  const subject = agent('tracked-steering');
  const signal = await h.step(subject);
  await h.call(subject, 'plan.next');
  await h.stop(subject);
  await h.stop(subject);
  assert.equal(h.calls.length, 1);
  assert.equal(subject.steered.length, 1);
  await h.step(subject, { signal, messages: [subject.steered[0]] });
  await h.stop(subject);
  assert.equal(h.calls.length, 2);
  assert.equal(subject.steered.length, 2);
  h.controller.dispose();
});

test('admitted new user intent clears old project bindings even inside the same turn', async () => {
  const h = setup();
  const subject = agent('changed-intent');
  const signal = await h.step(subject);
  await h.call(subject, 'http.capture');
  await h.step(subject, { signal, messages: [user('Pause testing and only export a draft.')] });
  await h.call(subject, 'plan.checkpoint');
  await h.call(subject, 'report.build');
  await h.stop(subject);
  assert.equal(h.calls.length, 0);
  assert.equal(subject.steered.length, 0);
  h.controller.dispose();
});

test('old-turn work and same-id replacement agents cannot inherit continuation authority', async () => {
  const h = setup();
  const original = agent('shared-id');
  const oldSignal = await h.step(original);
  await h.call(original, 'plan.next');
  await h.step(original, { turn: 2 });
  await h.stop(original, { turn: 1, signal: oldSignal });
  await h.stop(original);
  const replacement = agent('shared-id');
  await h.step(replacement, { turn: 2 });
  await h.stop(replacement);
  assert.equal(h.calls.length, 0);
  assert.equal(original.steered.length, 0);
  assert.equal(replacement.steered.length, 0);
  h.controller.dispose();
});

test('agent A and B only audit their own explicitly used projects, never workspace inventories', async () => {
  const h = setup();
  const a = agent('agent-a');
  const b = agent('agent-b');
  await h.step(a);
  await h.step(b);
  await h.call(a, 'http.capture', 'project-a');
  await h.call(b, 'scenario.run', 'project-b');
  await h.stop(a);
  assert.deepEqual(h.calls.map(call => call[2].project_id), ['project-a']);
  assert.equal(b.steered.length, 0);
  await h.stop(b);
  assert.deepEqual(h.calls.map(call => call[2].project_id), ['project-a', 'project-b']);
  assert.ok(h.calls.every(call => call[1] === 'plan.audit'));
  h.controller.dispose();
});

test('switching projects within one intent does not silently discard earlier unfinished work', async () => {
  const h = setup({ query: async (_settings, _action, args) => args.project_id === 'finished' ? finalAudit() : audit() });
  const subject = agent('several-projects');
  await h.step(subject);
  await h.call(subject, 'plan.next', 'unfinished');
  await h.call(subject, 'plan.next', 'finished');
  await h.stop(subject);
  assert.deepEqual(h.calls.map(call => call[2].project_id), ['unfinished', 'finished']);
  assert.equal(subject.steered.length, 1);
  assert.match(subject.steered[0].content[0].text, /unfinished/);
  assert.equal(h.controller.status().bound_projects, 1);
  h.controller.dispose();
});

test('real unavailable write authorization/fixture checkpoints unfinished work once without target replay', async () => {
  await offlineSdkFixture('genuine-blocked', async h => {
    const operation = await h.call('surface.register', { url: h.base + '/requires-write-fixture', method: 'POST', auth: 'public',
      inputs: [{ name: 'q', location: 'body', consumer: 'fixture_predicate', test_families: ['generic'] }] });
    await h.call('plan.build');
    const next = await h.call('plan.next', { include_blocked: true, limit: 25 });
    assert.equal(next.data.continuation.actionable_total, 0);
    assert.equal(next.data.continuation.ready_total, 0);
    assert.equal(next.data.continuation.review_total, 0);
    assert.equal(next.data.continuation.blocked_total, 2);
    assert.equal(next.data.requests_sent, 0);
    assert.deepEqual(next.data.review_followups, []);
    assert.ok(next.data.work_items.every(row => row.status === 'open' && row.queue_status === 'blocked'
      && row.missing_prerequisites.includes('project_allow_mutation')
      && row.missing_prerequisites.includes('matching_test_resource_or_declared_actor_state')));
    await assert.rejects(h.call('http.preflight', { operation_id: operation.data.id, effect: 'test_resource_write' }),
      error => error.code === 'operation_effect');
    await h.stop();
    await h.stop();
    assert.deepEqual(h.calls.map(call => call[1]), ['plan.audit', 'plan.checkpoint', 'plan.audit']);
    assert.equal(h.subject.steered.length, 0);
    assert.equal(h.controller.status().blocked_checkpoints, 1);
    assert.equal(h.controller.status().bound_projects, 1, 'unfinished binding is retained, not completed');
  });
});

test('real Cordis serial plus Python engine cannot close after caller-blocking every actually ready task', async () => {
  await offlineSdkFixture('caller-blocked', async h => {
    await h.call('surface.register', { url: h.base + '/items', method: 'GET', auth: 'public',
      inputs: [{ name: 'q', location: 'query', consumer: 'fixture_predicate', test_families: ['generic'] }] });
    await h.call('plan.build');
    const before = await h.call('plan.next', { include_blocked: true, limit: 25 });
    assert.equal(before.data.ready_total, 2);
    assert.equal(before.data.continuation.review_total, 0);
    assert.ok(before.data.work_items.every(row => row.queue_status === 'ready' && !row.missing_prerequisites.length));
    for (const row of before.data.work_items) await h.call('plan.disposition', { obligation_id: row.obligation_id,
      status: 'blocked', reason: 'Synthetic caller-only unavailable claim; no objective prerequisite changed.' });
    const after = await h.call('plan.next', { limit: 25 });
    await h.stop();
    assert.equal(h.subject.steered.length, 1, 'the awaited serial stopping boundary receives same-turn steering');
    assert.deepEqual(h.calls.map(call => call[1]), ['plan.audit']);
    assert.equal(after.data.requests_sent, 0);
    assert.equal(after.data.continuation.ready_total, 0);
    assert.equal(after.data.continuation.review_total, 2);
    assert.equal(after.data.continuation.actionable_total, 2);
    assert.equal(after.data.continuation.blocked_total, 0);
    assert.equal(after.data.work_items.length, before.data.work_items.length);
    assert.ok(after.data.work_items.every(row => row.queue_status === 'review'
      && row.status === 'blocked' && row.declared_status === 'blocked' && row.underlying_queue_status === 'ready'
      && row.blocker_reconciliation_required === true && row.execution_blocked === true
      && row.suggested_action === 'plan.disposition' && row.input_template.status === 'open'));
    assert.match(h.subject.steered[0].content[0].text, /"review_total":2/);
    assert.match(h.subject.steered[0].content[0].text, /Caller-only plan.disposition status:blocked prose is NOT/);
    assert.match(h.subject.steered[0].content[0].text, /bounded OFFLINE plan.disposition status:open template/);
    assert.match(h.subject.steered[0].content[0].text, /Do not automatically replay a target request/);
    assert.equal(h.controller.status().blocked_checkpoints, 0, 'caller prose is not an objective blocked-only checkpoint');
    await h.enter([h.subject.steered[0]]);
    for (const row of after.data.work_items) await h.call(row.suggested_action, row.input_template);
    const reopened = await h.call('plan.next', { limit: 25 });
    assert.equal(reopened.data.ready_total, 2);
    assert.equal(reopened.data.requests_sent, 0);
    assert.equal(h.requests, 0, 'reopening disposition does not replay or pre-authorize the target');
  });
});

test('real setup/auth/input review survives caller-blocked prose and offline reopening', async () => {
  await offlineSdkFixture('blocked-setup-review', async h => {
    await h.call('surface.register', { url: h.base + '/unknown-policy', method: 'GET', auth: 'unknown',
      inputs: [{ name: 'opaque', location: 'query' }] });
    await h.call('plan.build');
    const before = await h.call('plan.next', { limit: 25 });
    const kinds = ['auth_review', 'input_review'];
    assert.deepEqual(before.data.work_items.map(row => row.obligation_kind).sort(), kinds);
    for (const row of before.data.work_items) await h.call('plan.disposition', { obligation_id: row.obligation_id,
      status: 'blocked', reason: 'Synthetic setup pause prose cannot erase actionable offline tracing.' });
    const after = await h.call('plan.next', { limit: 25 });
    await h.stop();
    assert.equal(h.subject.steered.length, 1);
    assert.equal(after.data.continuation.review_total, 2);
    assert.equal(after.data.continuation.blocked_total, 1, 'the unknown-policy access prerequisite stays genuinely blocked');
    assert.deepEqual(after.data.work_items.map(row => row.obligation_kind).sort(), kinds);
    assert.ok(after.data.work_items.every(row => row.queue_status === 'review' && row.underlying_queue_status === 'review'
      && row.blocker_reconciliation_required === true && row.execution_blocked === true
      && row.suggested_action === 'plan.disposition' && row.input_template.status === 'open'));
    assert.match(h.subject.steered[0].content[0].text, /Setup\/auth\/input tracing and existing-evidence review remain actionable/);
    await h.enter([h.subject.steered[0]]);
    for (const row of after.data.work_items) await h.call(row.suggested_action, row.input_template);
    const reopened = await h.call('plan.next', { limit: 25 });
    assert.deepEqual(reopened.data.work_items.map(row => row.suggested_action).sort(), ['surface.declare_consumer', 'surface.register']);
    assert.equal(reopened.data.continuation.ready_total, 0);
    assert.equal(reopened.data.continuation.review_total, 2);
    assert.equal(reopened.data.continuation.blocked_total, 1);
    assert.equal(reopened.data.requests_sent, 0);
  });
});

test('ordinary failed preflight does not arm a nonexistent project; a claimed interrupted run does', async () => {
  for (const claimed of [false, true]) {
    const h = setup({ runner: async () => { throw new BridgeError('fixture_failure', 'Fixture failed', claimed ? { run_id: 'RUN-owned-fixture' } : undefined); } });
    const subject = agent('failed-' + claimed);
    await h.step(subject);
    await assert.rejects(h.call(subject, 'http.capture'));
    await h.stop(subject);
    assert.equal(h.calls.length, claimed ? 1 : 0);
    assert.equal(subject.steered.length, claimed ? 1 : 0);
    h.controller.dispose();
  }
});

test('a rejected pre-step is not overridden; a late old invocation cannot re-arm after user intent changes', async () => {
  const waiting = deferred();
  const h = setup({ runner: () => waiting.promise });
  const subject = agent('rejected-and-late');
  const signal = await h.step(subject);
  const running = h.call(subject, 'http.capture');
  await h.step(subject, { signal, messages: [user('No further testing.')] });
  waiting.resolve({ ok: true, data: {} });
  await running;
  await h.stop(subject);
  assert.equal(h.calls.length, 0);
  const rejected = { kind: 'reject' };
  assert.equal(await h.ctx.step({ agent: subject, turn: 1, step: 2, signal }, rejected), rejected);
  await h.stop(subject);
  assert.equal(subject.steered.length, 0);
  h.controller.dispose();
});

test('missing or failing public hook registration is observable and leaves all tool definitions usable', async () => {
  for (const ctx of [{}, { on() { throw new Error('Authorization: Bearer synthetic-private-registration-value'); } }]) {
    const diagnostics = [];
    const controller = apply(ctx, config, { onDiagnostic: value => diagnostics.push(value) });
    assert.equal(controller.status().registered, false);
    assert.match(controller.status().reason, /public_hook_unavailable|public_hook_registration_failed/);
    assert.doesNotMatch(JSON.stringify(diagnostics), /synthetic-private-registration-value/);
    const tools = toolDefinitions(defineTool, config, async () => ({ ok: true, data: {} }), undefined, { observer: controller.observe });
    assert.equal(tools.length, 10);
    await tools[0].execute({ action: 'project.list' }, {});
    controller.dispose();
  }
});

test('optional observer failures never hide an already-persisted engine outcome or leak diagnostics', async () => {
  const errors = [];
  const original = console.error;
  console.error = text => errors.push(text);
  try {
    const tools = toolDefinitions(defineTool, config, async () => ({ ok: true, data: { run_id: 'RUN-persisted' } }), undefined,
      { observer() { throw new Error('synthetic-private-observer-value'); } });
    const value = await tools.find(item => item.name === 'awa_execute').execute({ action: 'http.capture', project_id: 'project-a' }, {});
    assert.equal(value.data.run_id, 'RUN-persisted');
  } finally { console.error = original; }
  assert.equal(errors.length, 2);
  assert.doesNotMatch(errors.join('\n'), /synthetic-private-observer-value/);
});

test('offline audit failure publishes one safe recovery step per failure episode, not false exhaustion', async () => {
  for (const query of [async () => { throw new Error('synthetic-private-audit-value'); },
    async () => finalAudit().data, async () => audit({ continue_required: false, automatic_stop_allowed: true }),
    async () => { const value = finalAudit(); value.data.continuation.state = 'draft'; return value; },
    async () => audit({ unresolved_total: 1 }),
    async () => { const value = finalAudit(); value.data.continuation.stop_policy_version = 0; return value; }]) {
    const h = setup({ query });
    const subject = agent('bad-audit');
    const signal = await h.step(subject);
    await h.call(subject, 'plan.next');
    await h.stop(subject);
    assert.equal(subject.steered.length, 1);
    assert.match(subject.steered[0].content[0].text, /bounded OFFLINE recovery/);
    assert.match(subject.steered[0].content[0].text, /do not send target traffic, retry uncertain writes/);
    assert.doesNotMatch(subject.steered[0].content[0].text, /"ready_total"|"review_total"|synthetic-private-audit-value/);
    await h.step(subject, { signal, messages: [subject.steered[0]] });
    await h.stop(subject);
    assert.equal(subject.steered.length, 1, 'a persistent identical failure cannot spin more recovery steering');
    assert.equal(h.controller.status().bound_projects, 1);
    assert.equal(h.controller.status().audit_failures, 2);
    assert.equal(h.controller.status().recovery_steers, 1);
    assert.match(h.controller.status().reason, /audit_.*unfinished/);
    assert.doesNotMatch(JSON.stringify(h.diagnostics), /synthetic-private-audit-value/);
    h.controller.dispose();
  }
});

test('a successful fresh audit resets the bounded offline recovery episode', async () => {
  let unavailable = true;
  const h = setup({ query: async () => {
    if (unavailable) throw new Error('synthetic failure');
    return audit();
  } });
  const subject = agent('recovered-audit');
  const signal = await h.step(subject);
  await h.call(subject, 'plan.next');
  await h.stop(subject);
  await h.step(subject, { signal, messages: [subject.steered[0]] });
  unavailable = false;
  await h.stop(subject);
  await h.step(subject, { signal, messages: [subject.steered[1]] });
  unavailable = true;
  await h.stop(subject);
  assert.equal(subject.steered.length, 3);
  assert.equal(h.controller.status().recovery_steers, 2);
  assert.equal(h.controller.status().bound_projects, 1);
  h.controller.dispose();
});

test('actual cancellation takes precedence over a late unavailable audit recovery', async () => {
  for (const kind of ['turn', 'owner']) {
    const waiting = deferred();
    const h = setup({ query: () => waiting.promise });
    const subject = agent('audit-error-cancel-' + kind);
    const turn = new AbortController();
    await h.step(subject, { signal: turn.signal });
    await h.call(subject, 'plan.next');
    const stopping = h.stop(subject);
    if (kind === 'turn') turn.abort();
    else h.lifetime.abort();
    waiting.reject(new Error('synthetic-private-audit-value'));
    await stopping;
    assert.equal(subject.steered.length, 0);
    assert.equal(h.controller.status().audit_failures, 0);
    h.controller.dispose();
  }
});

test('an unavailable project receives offline-only recovery alongside other freshly audited work', async () => {
  const h = setup({ query: async (_settings, _action, args) => {
    if (args.project_id === 'unavailable') throw new Error('synthetic-private-audit-value');
    return audit();
  } });
  const subject = agent('mixed-audit');
  await h.step(subject);
  await h.call(subject, 'plan.next', 'known-ready');
  await h.call(subject, 'plan.next', 'unavailable');
  await h.stop(subject);
  assert.equal(subject.steered.length, 1);
  assert.match(subject.steered[0].content[0].text, /"ready_total":98/);
  assert.match(subject.steered[0].content[0].text, /Unauditable unfinished projects.*unavailable/);
  assert.match(subject.steered[0].content[0].text, /For those projects, do not send target traffic/);
  assert.doesNotMatch(subject.steered[0].content[0].text, /synthetic-private-audit-value/);
  assert.equal(h.controller.status().bound_projects, 2);
  h.controller.dispose();
});

test('only explicit testing actions arm; old four-argument toolDefinitions API is unchanged', async () => {
  assert.ok(ARM_ACTIONS.includes('plan.next'));
  assert.ok(ARM_ACTIONS.includes('http.capture'));
  assert.equal(ARM_ACTIONS.includes('report.build'), false);
  let called = 0;
  const tools = toolDefinitions(defineTool, config, async () => { called++; return { ok: true, data: {} }; }, undefined);
  await tools[0].execute({ action: 'project.list' }, {});
  assert.equal(called, 1);
});

test('real packaged-engine audit uses only a fresh temporary project and sends no target traffic', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'awa-host-guard-offline-'));
  const settings = { workspace, timeoutMs: 10000 };
  const h = setup({ settings, query: invokeEngine, runner: invokeEngine });
  try {
    await invokeEngine(settings, 'project.create', { project_id: 'offline', target: 'http://fixture.invalid' });
    await invokeEngine(settings, 'surface.register', { project_id: 'offline', url: 'http://fixture.invalid/items', method: 'GET',
      auth: 'public', inputs: [{ name: 'q', location: 'query' }] });
    const subject = agent('offline-runtime');
    await h.step(subject);
    await h.call(subject, 'plan.next', 'offline');
    await h.stop(subject);
    assert.equal(subject.steered.length, 1);
    assert.deepEqual(h.calls.map(call => call[1]), ['plan.audit']);
    const state = await invokeEngine(settings, 'project.status', { project_id: 'offline' });
    assert.equal(state.data.run_total, 0);
    assert.equal(state.data.completion.unassessed_observations, 0);
    assert.equal(state.data.continuation.continue_required, true);
  } finally {
    h.controller.dispose();
    const absolute = resolve(workspace);
    assert.ok(absolute.startsWith(resolve(tmpdir()) + sep) && basename(absolute).startsWith('awa-host-guard-offline-'));
    await rm(absolute, { recursive: true, force: true });
  }
});
