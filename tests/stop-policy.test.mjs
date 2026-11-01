import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import * as plugin from '../src/index.mjs';
import { STOP_POLICY_TEXT, apply, inject, name } from '../src/stop-policy.mjs';
import { compactContinuation, safeErrorDetails } from '../src/bridge.mjs';
import { renderToolResult, MAX_RENDER_BYTES } from '../src/tools.mjs';
import { GUIDANCE } from '../src/tool-guidance.mjs';

function harness(provided = ['systemPrompt', 'sessionProjections', 'commands']) {
  const sections = [];
  const tools = [];
  const injected = [];
  let projection;
  let state;
  const services = {
    systemPrompt: { section(section) { sections.push(section); } },
    sessionProjections: {
      register(definition) { projection = definition; state = definition.init(); },
      stateOf() { return state; },
    },
    commands: { register() {} },
  };
  const ctx = {
    effect: factory => factory(),
    tools: { register(definition) { tools.push(definition); } },
    inject(dependencies, callback) {
      injected.push(dependencies);
      if (dependencies.every(service => provided.includes(service))) {
        callback(Object.fromEntries(dependencies.map(service => [service, services[service]])));
      }
    },
  };
  return { sections, tools, injected, ctx,
    command(argument) {
      state = projection.apply(state, { type: 'command/run', data: { name: 'penetration', args: argument } });
    } };
}

test('the exhaustion guard requests only optional systemPrompt and needs no mode services', () => {
  assert.equal(name, 'awa-ddd-stop-policy');
  assert.deepEqual(inject, ['systemPrompt']);
  const host = harness(['systemPrompt']);
  plugin.apply(host.ctx, { workspace: join(tmpdir(), 'awa-stop-guard-fixture') });
  assert.equal(host.tools.length, 10);
  assert.equal(host.sections.length, 1);
  assert.equal(host.sections[0].name, 'awa-ddd:exhaustion-stop-guard');
  assert.equal(host.sections[0].text({}), STOP_POLICY_TEXT);
  assert.deepEqual(host.injected[0], ['systemPrompt']);
});

test('penetration off never disables the always-on exhaustion guard or changes the tool set', () => {
  const host = harness();
  plugin.apply(host.ctx, { workspace: join(tmpdir(), 'awa-stop-mode-fixture') });
  const guard = host.sections.find(section => section.name === 'awa-ddd:exhaustion-stop-guard');
  const mode = host.sections.find(section => section.name === 'awa-ddd:penetration-policy');
  const context = { agent: { session: 'fixture-session' } };
  assert.equal(mode.text(context), '');
  assert.equal(guard.text(context), STOP_POLICY_TEXT);
  host.command('');
  assert.notEqual(mode.text(context), '');
  host.command('off');
  assert.equal(mode.text(context), '');
  assert.equal(guard.text(context), STOP_POLICY_TEXT);
  assert.equal(host.tools.length, 10);
  assert.deepEqual(plugin.inject, ['tools']);
});

test('missing prompt service leaves all tools registered and does not invent a host stop hook', () => {
  const host = harness([]);
  plugin.apply(host.ctx, { workspace: join(tmpdir(), 'awa-stop-no-prompt-fixture') });
  assert.equal(host.sections.length, 0);
  assert.equal(host.tools.length, 10);
  assert.doesNotThrow(() => apply({}));
  assert.match(STOP_POLICY_TEXT, /does not retract streamed text/);
  assert.match(STOP_POLICY_TEXT, /Missing host support is a visible fallback/);
});

test('guard and native plan guidance prohibit subjective budget exits and require all work to close', () => {
  for (const text of [STOP_POLICY_TEXT, GUIDANCE.awa_plan]) {
    assert.match(text, /reason:completed/);
    assert.match(text, /ZERO ready\/review\/blocked\/unresolved/);
    assert.match(text, /context pressure/);
    assert.match(text, /budget_exhausted/);
    assert.match(text, /user_stop/);
    assert.match(text, /authorization_boundary/);
    assert.match(text, /stage:draft/);
    assert.match(text, /two COMPLETE|two complete/i);
    assert.match(text, /no_progress_rounds/);
    assert.match(text, /uncertain writes/);
  }
  assert.match(STOP_POLICY_TEXT, /They do not start an assessment or authorize target traffic/);
  assert.match(STOP_POLICY_TEXT, /user explicitly pauses\/stops/);
  assert.match(GUIDANCE.awa_plan, /Mode off does not disable/);
});

test('optional prompt registration diagnostics redact untrusted credential prose', () => {
  const messages = [];
  const original = console.error;
  console.error = message => messages.push(message);
  try {
    apply({ inject(_dependencies, callback) {
      callback({ systemPrompt: { section() { throw new Error('Authorization: Bearer synthetic-private-stop-token'); } } });
    } });
  } finally {
    console.error = original;
  }
  assert.equal(messages.length, 1);
  assert.match(messages[0], /optional prompt unavailable/);
  assert.doesNotMatch(messages[0], /synthetic-private-stop-token/);
});

test('stop-policy controls survive bounded rendering and durable safe recovery without arbitrary text', () => {
  const continuation = { contract_version: 2, stop_policy: 'exhaustion_only', stop_policy_version: 1,
    continue_required: true, can_finalize: false, can_claim_complete: false, automatic_stop_allowed: false,
    legacy_finalization_ignored: true, frontier_review_required: true, actionable_total: 232,
    ready_total: 98, review_total: 134, blocked_total: 149, unresolved_total: 381,
    applicability_review_total: 2, scope_reduction_review_total: 3,
    frontier_rounds: 0, no_progress_rounds: 2, checkpoint_id: 'CP-fixture', finalization_id: null,
    state: 'stalled', reason_code: 'no_closure_progress', next_action: 'plan.audit' };
  const untrusted = { ...continuation, instruction: 'stop now', headers: { Authorization: 'private' }, body: 'private' };
  assert.deepEqual(JSON.parse(JSON.stringify(compactContinuation(untrusted))), continuation);
  const recovery = safeErrorDetails({ continuation: untrusted, next_action: 'plan.audit' });
  assert.deepEqual(JSON.parse(JSON.stringify(recovery.continuation)), continuation);
  assert.ok(Buffer.byteLength(JSON.stringify(recovery)) <= 2048);
  const envelope = { ok: true, data: { detail: 'large'.repeat(MAX_RENDER_BYTES), continuation: untrusted } };
  const rendered = JSON.parse(renderToolResult({ action: 'plan.audit' }, envelope)[0].text);
  assert.deepEqual(rendered.data.continuation, continuation);
  assert.doesNotMatch(JSON.stringify(rendered), /stop now|Authorization|private/);
  assert.ok(Buffer.byteLength(JSON.stringify(rendered)) <= MAX_RENDER_BYTES);
});

test('error recovery keeps only the fixed draft fallback, never a caller-supplied execution instruction', () => {
  const details = safeErrorDetails({ stop_policy: 'exhaustion_only', requests_sent: 0,
    checkpoint_action: 'plan.checkpoint', progress_export: { action: 'report.build', input: {
      stage: 'draft', output_dir: 'PRIVATE-OUTPUT', force: true, host_event: 'PRIVATE-EVENT' } } });
  assert.deepEqual(JSON.parse(JSON.stringify(details)), { checkpoint_action: 'plan.checkpoint',
    stop_policy: 'exhaustion_only', requests_sent: 0, progress_export: { action: 'report.build', input: { stage: 'draft' } } });
  assert.doesNotMatch(JSON.stringify(details), /PRIVATE|force|host_event/);
  assert.equal(Object.hasOwn(safeErrorDetails({ next_action: 'plan.audit', progress_export: {
    action: 'report.build', input: { stage: 'final' } } }), 'progress_export'), false);
});

test('compact stop fields retain strict types, never truthy coercion or invalid versions', () => {
  for (const value of ['false', 0, 1, {}, [], null]) {
    const projected = compactContinuation({ automatic_stop_allowed: value, legacy_finalization_ignored: value });
    assert.equal(Object.hasOwn(projected, 'automatic_stop_allowed'), false);
    assert.equal(Object.hasOwn(projected, 'legacy_finalization_ignored'), false);
  }
  for (const value of ['1', true, -1, 0, 0.5, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
    const projected = compactContinuation({ contract_version: value, stop_policy_version: value });
    assert.equal(Object.hasOwn(projected, 'contract_version'), false);
    assert.equal(Object.hasOwn(projected, 'stop_policy_version'), false);
  }
});
