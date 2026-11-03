import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createUserMessage } from '@deepseek-ai/dsh-llm';
import { createController, TURN_STOPPING_EVENT } from '../src/host-continuation.mjs';

function continuation(overrides = {}) {
  return {
    contract_version: 2, stop_policy_version: 1, stop_policy: 'exhaustion_only',
    continue_required: true, automatic_stop_allowed: false, can_finalize: false,
    can_claim_complete: false, frontier_review_required: true, frontier_rounds: 0,
    ready_total: 95, review_total: 484, blocked_total: 836,
    actionable_total: 579, unresolved_total: 1415, no_progress_rounds: 0,
    snapshot_id: 'CS-offline-stall-fixture', progress_id: 'PR-offline-stall-fixture',
    checkpoint_id: 'CP-offline-fixture', finalization_id: null,
    state: 'continue', coverage_status: 'partial', next_action: 'plan.next',
    ...overrides,
  };
}

function fixture() {
  const handlers = new Map();
  const calls = [];
  const notices = [];
  const lifetime = new AbortController();
  const turn = new AbortController();
  let current = continuation();
  let step = 0;
  const subject = {
    id: 'offline-stall-agent', session: { id: 'offline-stall-session' }, status: 'running',
    inbox: { nextStep: [], nextTurn: [] },
    steer(message) { notices.push(message); this.inbox.nextStep.push(message); },
    followup() { assert.fail('stall reconciliation must not start another turn'); },
  };
  const ctx = {
    on(event, callback) {
      const items = handlers.get(event) ?? [];
      items.push(callback);
      handlers.set(event, items);
      return () => handlers.set(event, items.filter(item => item !== callback));
    },
  };
  const controller = createController({ workspace: join(tmpdir(), 'awa-offline-stall-replay') }, {
    signal: lifetime.signal,
    invoke: async (_settings, action, args) => {
      assert.ok(['plan.audit', 'plan.checkpoint'].includes(action), 'only offline engine actions are invoked');
      assert.equal(args.project_id, 'offline-stall-project');
      calls.push({ action, args });
      if (action === 'plan.checkpoint') current = { ...current, checkpoint_id: 'CP-offline-stall-retained' };
      return { ok: true, data: { continuation: { ...current } } };
    },
  });
  controller.attach(ctx);
  const frame = () => ({ agent: subject, turn: 1, step, signal: turn.signal });

  return {
    subject, controller, calls, notices, turn,
    get current() { return current; },
    update(values) { current = { ...current, ...values }; },
    async enter(messages = subject.inbox.nextStep.splice(0)) {
      step++;
      const decision = { kind: 'enter', messages };
      let next = async () => decision;
      for (const handler of [...(handlers.get('agent/pre-step') ?? [])].reverse()) {
        const inner = next;
        next = () => handler(frame(), inner);
      }
      assert.equal(await next(), decision);
    },
    settle(action = 'plan.next') {
      // Public observer events are synthetic; no tool, server or target is executed.
      const invocation = { action, project_id: 'offline-stall-project', agent: subject,
        callerSignal: turn.signal, signal: new AbortController().signal };
      controller.observe({ phase: 'start', invocation });
      controller.observe({ phase: 'success', invocation, ok: true });
    },
    async stop() {
      for (const handler of handlers.get(TURN_STOPPING_EVENT) ?? []) await handler(frame());
    },
    dispose() { controller.dispose(); lifetime.abort(); },
  };
}

const user = text => createUserMessage({ source: { kind: 'user' }, content: [{ type: 'text', text }] });

function assertUnfinished(h) {
  assert.equal(h.current.continue_required, true);
  assert.equal(h.current.automatic_stop_allowed, false);
  assert.equal(h.current.can_finalize, false);
  assert.equal(h.current.can_claim_complete, false);
  assert.equal(h.current.finalization_id, null);
  assert.equal(h.controller.status().bound_projects, 1);
  assert.ok(h.calls.every(call => ['plan.audit', 'plan.checkpoint'].includes(call.action)));
  assert.ok(h.notices.every(message => message.source.kind === 'awa-ddd-host-continuation'));
}

test('536 unchanged boundaries including a 427-step zero-tool tail cannot create a host feedback loop', async () => {
  const h = fixture();
  try {
    await h.enter([user('Assess only the authorized offline fixture.')]);
    for (let boundary = 0; boundary < 536; boundary++) {
      if (boundary > 0) await h.enter();
      if (boundary < 109) h.settle('plan.next');
      await h.stop();
    }
    assert.equal(h.notices.length, 1, 'unchanged closure progress receives only the initial continuation notice');
    assert.equal(h.calls.filter(call => call.action === 'plan.checkpoint').length, 1,
      'the repeated boundary retains one unfinished checkpoint rather than manufacturing progress');
    assertUnfinished(h);
  } finally { h.dispose(); }
});

test('raw capture snapshot churn is not closure progress and does not rearm repeated notices', async () => {
  const h = fixture();
  try {
    await h.enter([user('Assess only the authorized offline fixture.')]);
    h.settle();
    await h.stop();
    for (let observation = 1; observation <= 12; observation++) {
      await h.enter();
      h.update({ snapshot_id: `CS-offline-raw-observation-${observation}` });
      h.settle('http.capture');
      await h.stop();
    }
    assert.equal(h.notices.length, 1, 'raw observations cannot defeat progress-based host deduplication');
    assert.ok(h.calls.filter(call => call.action === 'plan.checkpoint').length <= 1);
    assertUnfinished(h);
  } finally { h.dispose(); }
});

test('genuine closure progress can rearm continuation without granting completion', async () => {
  const h = fixture();
  try {
    await h.enter([user('Assess only the authorized offline fixture.')]);
    h.settle();
    await h.stop();
    await h.enter();
    h.update({ snapshot_id: 'CS-offline-new-closure', progress_id: 'PR-offline-new-closure' });
    h.settle();
    await h.stop();
    assert.equal(h.notices.length, 2);
    assertUnfinished(h);
  } finally { h.dispose(); }
});

test('frontier review progress can rearm the same snapshot while finalization is still required', async () => {
  const h = fixture();
  try {
    h.update({ ready_total: 0, review_total: 0, blocked_total: 0, actionable_total: 0, unresolved_total: 0 });
    await h.enter([user('Review the exhausted fixture frontier without sending requests.')]);
    h.settle();
    await h.stop();
    await h.enter();
    h.update({ frontier_rounds: 1, checkpoint_id: 'CP-offline-frontier-round-one' });
    h.settle();
    await h.stop();
    await h.enter();
    h.update({ frontier_rounds: 2, checkpoint_id: 'CP-offline-frontier-round-two', can_finalize: true });
    h.settle();
    await h.stop();
    assert.equal(h.notices.length, 3, 'each actual frontier round is distinct from duplicate no-progress callbacks');
    assert.equal(h.current.continue_required, true);
    assert.equal(h.current.automatic_stop_allowed, false);
    assert.equal(h.current.can_claim_complete, false);
    assert.equal(h.current.finalization_id, null);
    assert.equal(h.controller.status().bound_projects, 1);
    assert.ok(h.calls.every(call => ['plan.audit', 'plan.checkpoint'].includes(call.action)));
  } finally { h.dispose(); }
});

test('actual turn cancellation takes priority after an unchanged stalled boundary', async () => {
  const h = fixture();
  try {
    await h.enter([user('Assess only the authorized offline fixture.')]);
    h.settle();
    await h.stop();
    await h.enter();
    await h.stop();
    const before = { calls: h.calls.length, notices: h.notices.length };
    h.turn.abort(new Error('Actual fixture user cancellation'));
    await h.stop();
    assert.equal(h.calls.length, before.calls);
    assert.equal(h.notices.length, before.notices);
    assertUnfinished(h);
  } finally { h.dispose(); }
});

test('a new report-only user intent clears the old stalled host binding', async () => {
  const h = fixture();
  try {
    await h.enter([user('Assess only the authorized offline fixture.')]);
    h.settle();
    await h.stop();
    await h.enter();
    await h.stop();
    await h.enter([user('Do not test; explain the existing report only.')]);
    const before = { calls: h.calls.length, notices: h.notices.length };
    await h.stop();
    assert.equal(h.calls.length, before.calls);
    assert.equal(h.notices.length, before.notices);
    assert.equal(h.controller.status().bound_projects, 0);
    assert.equal(h.current.continue_required, true, 'new user intent is not proof of exhaustion');
    assert.equal(h.current.automatic_stop_allowed, false);
  } finally { h.dispose(); }
});
