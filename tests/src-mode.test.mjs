import test from 'node:test';
import assert from 'node:assert/strict';
import { join, resolve, relative, isAbsolute } from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtemp, rm } from 'node:fs/promises';
import { assessmentArguments, resolveConfig, invokeEngine, redactResult, safeErrorDetails } from '../src/bridge.mjs';
import { ACTION_GROUPS, V2_ACTION_GROUPS, READ_ACTIONS } from '../src/actions.mjs';
import { toolDefinitions } from '../src/tools.mjs';
import { createController, srcProjection, SRC_POLICY_TEXT } from '../src/src-mode.mjs';

const settings = { workspace: join(tmpdir(), 'awa-src-host-test') };
const command = args => ({ type: 'command/run', data: { name: 'src', args } });

function harness(config = {}, provided = ['sessionProjections', 'systemPrompt', 'commands']) {
  const sections = [];
  const commands = [];
  const projections = [];
  const states = new Map();
  const services = {
    sessionProjections: {
      register(projection) { projections.push(projection); },
      stateOf(session, key) { return states.get(session)?.get(key) ?? srcProjection.init(); },
    },
    systemPrompt: { section(section) { sections.push(section); } },
    commands: { register(definition) { commands.push(definition); } },
  };
  const controller = createController(config);
  controller.attach({ inject(dependencies, callback) {
    if (dependencies.every(service => provided.includes(service))) callback(services);
  } });
  return { controller, sections, commands, projections,
    replay(session, event) {
      if (!states.has(session)) states.set(session, new Map());
      for (const projection of projections) {
        const current = states.get(session).get(projection.key) ?? projection.init();
        states.get(session).set(projection.key, projection.apply(current, event));
      }
    } };
}

test('SRC preference replays independently, keeps sessions isolated, and status/rejected commands do not mutate it', () => {
  const host = harness();
  assert.equal(host.projections.length, 1);
  assert.equal(host.commands[0].name, 'src');
  host.replay('first', command('on'));
  assert.equal(host.controller.modeForAgent({ session: 'first' }), 'src');
  assert.equal(host.controller.modeForAgent({ session: 'second' }), 'assessment');
  for (const argument of ['status', 'yes', 'OFF', undefined, {}]) host.replay('first', command(argument));
  assert.equal(host.controller.modeForAgent({ session: 'first' }), 'src');
  assert.deepEqual(host.commands[0].handler({ agent: { session: 'first' }, rawInput: 'status' }),
    { kind: 'success', text: 'SRC mode on.' });
  assert.match(host.sections[0].text({ agent: { session: 'first' } }), /有直接、可复核证据即停止/);
  assert.equal(host.sections[0].text({ agent: { session: 'second' } }), '');
  host.replay('first', command('off'));
  assert.equal(host.controller.modeForAgent({ session: 'first' }), 'assessment');
});

test('configured SRC survives preference off and absent optional services', () => {
  for (const provided of [[], ['systemPrompt'], ['sessionProjections', 'systemPrompt', 'commands']]) {
    const host = harness({ assessmentMode: 'src' }, provided);
    host.replay('first', command('off'));
    assert.equal(host.controller.modeForAgent({ session: 'first' }), 'src');
  }
  assert.equal(resolveConfig({ ...settings, assessmentMode: 'src' }).assessmentMode, 'src');
  assert.throws(() => resolveConfig({ ...settings, assessmentMode: 'unrestricted' }), { code: 'INVALID_CONFIG' });
});

test('SRC is forwarded as a hard project match, not a prompt-only selection', async () => {
  const host = harness();
  host.replay('first', command(''));
  const calls = [];
  const tools = toolDefinitions(value => value, settings, async (config, action, args) => {
    calls.push({ config, action, args });
    return { ok: true, data: { requests_sent: 0 } };
  }, undefined, { assessmentModeFor: host.controller.modeForAgent });
  const project = tools.find(tool => tool.name === 'awa_project');
  const execution = { agent: { session: 'first' } };
  await project.execute({ action: 'project.create', input: { project_id: 'src-project', target: 'https://example.test/app/' } }, execution);
  assert.equal(calls[0].config.assessmentMode, 'src');
  assert.deepEqual(calls[0].args, { project_id: 'src-project', target: 'https://example.test/app/',
    assessment_mode: 'src', allow_mutation: false, required_assessment_mode: 'src' });
  const execute = tools.find(tool => tool.name === 'awa_execute');
  await execute.execute({ action: 'http.capture', project_id: 'src-project', input: { operation_id: 'OP-1' } }, execution);
  assert.equal(calls[1].args.required_assessment_mode, 'src');
  await assert.rejects(project.execute({ action: 'project.create', input: { target: 'https://example.test/', assessment_mode: 'assessment' } }, execution),
    { code: 'ASSESSMENT_MODE_MISMATCH' });
  await assert.rejects(project.execute({ action: 'project.create', input: { target: 'https://example.test/', allow_mutation: true } }, execution),
    { code: 'SRC_MUTATION_FORBIDDEN' });
  assert.equal(calls.length, 2, 'rejected downgrade/write arguments never dispatch');
});

test('ordinary assessments retain their payload; explicit SRC creation remains bounded', () => {
  const original = { project_id: 'project', target: 'https://example.test/' };
  assert.equal(assessmentArguments(resolveConfig(settings), 'project.create', original), original);
  assert.deepEqual(assessmentArguments(resolveConfig(settings), 'project.create', { ...original, assessment_mode: 'src' }),
    { ...original, assessment_mode: 'src', allow_mutation: false });
  assert.throws(() => assessmentArguments(resolveConfig({ ...settings, assessmentMode: 'src' }), 'project.update',
    { project_id: 'project', required_assessment_mode: 'assessment' }), { code: 'ASSESSMENT_MODE_MISMATCH' });
  assert.deepEqual(JSON.parse(JSON.stringify(safeErrorDetails({ assessment_mode: 'src', operation_id: 'OP-1',
    decision_id: 'DEC-1', evidence_ids: ['EV-1'], requests_sent: 0, next_action: 'evidence.inspect' }))),
    { next_action: 'evidence.inspect', operation_id: 'OP-1', decision_id: 'DEC-1', assessment_mode: 'src', requests_sent: 0, evidence_ids: ['EV-1'] });
});

test('integration stays offline and reachable in both model catalogs, with read-only exports and scoped import guidance', async () => {
  for (const assessmentModel of ['v1', 'v2']) {
    const calls = [];
    const tools = toolDefinitions(value => value, { ...settings, assessmentModel }, async (_config, action, args) => {
      calls.push({ action, args });
      return { ok: true, data: { import_id: 'IMPORT-1', requests_sent: 0 } };
    });
    const group = tools.find(tool => tool.name === (assessmentModel === 'v1' ? 'awa_project' : 'awa_admin'));
    const exchange = { schema: 'dsh-purge-awa/v1', engagement: { id: '1', name: 'Scope', mode: 'src' },
      candidates: [{ external_id: 'vuln-1', method: 'GET', url: 'https://example.test/app/', source_status: 'confirmed' }] };
    await group.execute({ action: 'integration.import', project_id: 'project', input: { exchange } }, {});
    assert.deepEqual(calls[0], { action: 'integration.import', args: { project_id: 'project', exchange } });
    assert.equal(group.isConcurrencySafe({ action: 'integration.import' }), false);
    assert.equal(group.isConcurrencySafe({ action: 'integration.export' }), true);
    assert.match(group.parameters.input.description, /unverified/);
  }
  assert.equal(ACTION_GROUPS.awa_project.includes('integration.import'), true);
  assert.equal(V2_ACTION_GROUPS.awa_admin.includes('integration.export'), true);
  assert.equal(READ_ACTIONS.has('integration.export'), true);
  assert.doesNotMatch(JSON.stringify(redactResult({ candidates: [{ request: { Authorization: 'private-token' }, response: { body: 'private-body' } }] })), /private-/);
  for (const boundary of ['unverified', 'required_assessment_mode:src', 'allow_mutation:false', 'WebShell', 'checkpoint']) {
    assert.ok(SRC_POLICY_TEXT.includes(boundary), boundary);
  }
});

test('the real Python bridge persists SRC and rejects old-project active calls and mode updates before target execution', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'awa-src-bridge-'));
  const assessment = { workspace, timeoutMs: 10000 };
  const src = { ...assessment, assessmentMode: 'src' };
  try {
    await invokeEngine(assessment, 'project.create', { project_id: 'legacy', target: 'https://example.test/app/' });
    await invokeEngine(src, 'project.create', { project_id: 'src-project', target: 'https://example.test/app/' });
    const status = await invokeEngine(src, 'project.status', { project_id: 'src-project' });
    assert.equal(status.data.config.assessment_mode, 'src');
    assert.equal(status.data.config.allow_mutation, false);
    await assert.rejects(invokeEngine(src, 'http.capture', { project_id: 'legacy', operation_id: 'OP-never-executed' }),
      { code: 'assessment_mode_mismatch' });
    await assert.rejects(invokeEngine(src, 'project.update', { project_id: 'src-project', assessment_mode: 'assessment' }),
      { code: 'assessment_mode_immutable' });
    await assert.rejects(invokeEngine(src, 'project.update', { project_id: 'src-project', allow_mutation: true }),
      { code: 'src_write_denied' });
    await assert.rejects(invokeEngine(src, 'tool.sqlmap', { project_id: 'src-project', operation_id: 'OP-never-executed',
      url: 'https://example.test/app/' }), { code: 'src_action_denied' });
  } finally {
    const target = resolve(workspace);
    const delta = relative(resolve(tmpdir()), target);
    assert.ok(!isAbsolute(delta) && delta !== '..' && !delta.startsWith('..') && target.startsWith(join(resolve(tmpdir()), 'awa-src-bridge-')),
      'cleanup stays inside the freshly created temporary fixture directory');
    await rm(target, { recursive: true, force: true });
  }
});

test('real v1/v2 integration imports are idempotent, redacted and unverified even when external status says confirmed', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'awa-src-exchange-'));
  const secret = 'SYNTHETIC-PRIVATE-EXCHANGE-SECRET';
  try {
    for (const assessmentModel of ['v1', 'v2']) {
      const config = { workspace, assessmentModel, assessmentMode: 'src', timeoutMs: 10000 };
      const project_id = 'exchange-' + assessmentModel;
      const group = toolDefinitions(value => value, config).find(tool => tool.name === (assessmentModel === 'v1' ? 'awa_project' : 'awa_admin'));
      await group.execute({ action: 'project.create', input: { project_id, target: 'https://example.test/app/' } }, {});
      const exchange = { schema: 'dsh-purge-awa/v1', engagement: { id: 'rt-123', name: 'Fixture', mode: 'src' },
        candidates: [{ external_id: 'vuln:1', url: 'https://example.test/app/?q=hello', method: 'GET',
          title: `External claim ${secret}`, source_status: 'confirmed', evidence_refs: ['http:1'] }],
        http_evidence: [{ external_id: 'http:1', url: 'https://example.test/app/?q=hello', method: 'GET', status_code: 200,
          request: { headers: { Authorization: `Bearer ${secret}` } }, response: { body: secret } }] };
      const first = await group.execute({ action: 'integration.import', project_id, input: { exchange } }, {});
      const repeated = await group.execute({ action: 'integration.import', project_id, input: { exchange } }, {});
      assert.equal(first.data.requests_sent, 0);
      assert.equal(first.data.usable_for_confirmation, false);
      assert.equal(first.data.import_id, repeated.data.import_id);
      assert.equal(first.data.counts.created, 1);
      assert.equal(repeated.data.counts.created, 0);
      const output = await group.execute({ action: 'integration.export', project_id, input: { import_id: first.data.import_id, offset: 0, limit: 10 } }, {});
      assert.equal(output.data.schema, 'dsh-purge-awa/v1');
      assert.equal(output.data.requests_sent, 0);
      assert.equal(output.data.candidates[0].status, 'unverified');
      assert.equal(output.data.candidates[0].usable_for_confirmation, false);
      assert.equal(output.data.candidates[0].url, 'https://example.test/app/');
      assert.equal(output.data.candidates[0].decisions.length, 0);
      assert.equal(output.data.candidates[0].findings.length, 0);
      assert.doesNotMatch(JSON.stringify(output), new RegExp(secret));
      await assert.rejects(group.execute({ action: 'integration.import', project_id, input: { exchange: {
        ...exchange, candidates: [{ external_id: 'vuln:2', url: 'https://outside.test/', method: 'GET' }], http_evidence: [] } } }, {}),
      { code: 'out_of_scope' });
    }
  } finally {
    const target = resolve(workspace);
    const delta = relative(resolve(tmpdir()), target);
    assert.ok(!isAbsolute(delta) && !delta.startsWith('..') && target.startsWith(join(resolve(tmpdir()), 'awa-src-exchange-')));
    await rm(target, { recursive: true, force: true });
  }
});
