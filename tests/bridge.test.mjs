import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  invokeEngine, resolveConfig, validateRequest, validateJson, redactResult, safeErrorText, safeErrorDetails,
  PACKAGE_ROOT, MAX_REQUEST_BYTES, MAX_JSON_DEPTH, ACTIONS, ENGINE_DISPATCH_UNCERTAIN, ENGINE_DISPATCH_PHASE,
} from '../src/bridge.mjs';

const config = { workspace: join(tmpdir(), 'awa-ddd-bridge-test-state'), timeoutMs: 5000 };

function synthetic(source, inspect = () => {}) {
  return (executable, argv, options) => {
    inspect(executable, argv, options);
    return spawn(process.execPath, ['-e', source], options);
  };
}

function syntheticIpc({ phases = [], output = '{"ok":true,"data":{}}', exitCode = 0, hold = false } = {},
  inspect = () => {}) {
  const source = `
    const { createHash } = require('node:crypto');
    const { writeSync } = require('node:fs');
    let input = '';
    let started = false;
    process.stdin.setEncoding('utf8');
    const run = () => {
      if (started) return;
      started = true;
      const newline = input.indexOf('\\n');
      const wire = newline >= 0 ? input.slice(0, newline + 1) : input;
      const request = JSON.parse(wire);
      const nonce = process.env.AWA_DDD_REQUEST_NONCE;
      if (typeof nonce !== 'string' || !/^[a-f0-9]{64}$/.test(nonce)) process.exit(3);
      const requestHash = createHash('sha256').update(wire, 'utf8').digest('hex');
      let seq = 0;
      for (const spec of ${JSON.stringify(phases)}) {
        if (spec.plain !== undefined) {
          writeSync(2, spec.plain + '\\n');
          continue;
        }
        if (spec.malformed === true) {
          writeSync(2, '{"schema":"awa-ddd-ipc/v1","nonce":"' + nonce + '","phase":\\n');
          continue;
        }
        seq += 1;
        const phase = spec.phase;
        const receipt = {
          schema: spec.schema ?? 'awa-ddd-ipc/v1',
          nonce: spec.nonce ?? nonce,
          phase,
          seq: spec.seq ?? seq,
        };
        if (phase === 'accepted' || phase === 'dispatch') {
          receipt.action = spec.action ?? request.action;
          receipt.request_hash = spec.request_hash ?? requestHash;
        }
        if (phase === 'dispatch') {
          receipt.run_id = spec.run_id ?? 'RUN-ipc-fixture';
          receipt.dispatch_hash = spec.dispatch_hash ?? 'd'.repeat(64);
        }
        Object.assign(receipt, spec.extra || {});
        for (const key of spec.omit || []) delete receipt[key];
        writeSync(2, JSON.stringify(receipt) + '\\n');
      }
      if (${hold}) {
        setInterval(() => {}, 1000);
      } else if (${output === null ? 'true' : 'false'}) {
        process.exit(${exitCode});
      } else {
        process.stdout.write(${JSON.stringify(output)}, () => process.exit(${exitCode}));
      }
    };
    process.stdin.on('data', chunk => {
      input += chunk;
      if (input.includes('\\n')) run();
    });
    process.stdin.on('end', run);
  `;
  return synthetic(source, inspect);
}

test('configuration separates state from code and accepts an executable path, never a shell command', () => {
  assert.notEqual(resolveConfig().workspace, PACKAGE_ROOT);
  assert.throws(() => resolveConfig({ workspace: PACKAGE_ROOT }), { code: 'INVALID_CONFIG' });
  assert.throws(() => resolveConfig({ workspace: 'relative' }), { code: 'INVALID_CONFIG' });
  assert.throws(() => resolveConfig({ timeoutMs: 0 }), { code: 'INVALID_CONFIG' });
  assert.throws(() => resolveConfig({ pythonExecutable: '' }), { code: 'INVALID_CONFIG' });
  assert.equal(resolveConfig().executionBackend, 'native');
  assert.equal(resolveConfig().wslDistribution, 'kali-linux');
  for (const bad of [{ executionBackend: 'shell' }, { wslDistribution: '--exec' },
    { wslDistribution: 'kali-linux --exec bash' }, { wslPythonExecutable: 'python3 -c code' },
    { wslPythonExecutable: '-c' }, { wslPythonExecutable: '/usr/bin/python3\n' }]) {
    assert.throws(() => resolveConfig(bad), { code: 'INVALID_CONFIG' });
  }
});

test('candidate closure source context stays private even in unexpected bridge output', () => {
  const source = 'synthetic-private-candidate-source';
  const value = { candidate_closure_context: { opaque: source },
    nested: [{ 'Candidate-Closure-Context': { opaque: source } }],
    candidate_closure: { version: 1, basis: 'outside_scope' } };
  const result = redactResult(value);
  assert.equal(result.candidate_closure_context, '[redacted]');
  assert.equal(result.nested[0]['Candidate-Closure-Context'], '[redacted]');
  assert.equal(Object.getPrototypeOf(result.candidate_closure), null);
  assert.deepEqual({ ...result.candidate_closure }, value.candidate_closure);
  assert.doesNotMatch(JSON.stringify(result), new RegExp(source));
});

test('the bridge rejects non-JSON values instead of changing oracle or request semantics', () => {
  const values = [NaN, Infinity, -Infinity, undefined, () => {}, Symbol('private'), 1n,
    new Date(), new Map(), new Set(), Buffer.from('private'), Object.create({ inherited: true }),
    new Proxy({}, {}), { toJSON: () => ({ changed: true }) }];
  for (const value of values) {
    assert.throws(() => validateRequest('action.help', { nested: [value] }), { code: 'INVALID_ARGUMENTS' });
  }
  const hole = Array(1);
  const extra = []; extra.custom = true;
  const symbolKey = { [Symbol('hidden')]: true };
  const hidden = {}; Object.defineProperty(hidden, 'hidden', { value: true });
  let accessed = false;
  const accessor = { get unsafe() { accessed = true; return 'not JSON'; } };
  for (const value of [hole, extra, symbolKey, hidden, accessor]) {
    assert.throws(() => validateJson(value), { code: 'INVALID_ARGUMENTS' });
  }
  assert.equal(accessed, false, 'validation never executes a getter');
  let deep = null;
  for (let index = 0; index <= MAX_JSON_DEPTH; index++) deep = { child: deep };
  assert.throws(() => validateJson(deep), { code: 'INVALID_ARGUMENTS' });
  const shared = Object.assign(Object.create(null), { value: 'UTF-8: 中文', boolean: false, number: 0 });
  const valid = { one: shared, two: shared, array: [null, true, 1.5, ''] };
  assert.equal(validateJson(valid), valid, 'shared references are not mistaken for circular references');
  assert.deepEqual(JSON.parse(validateRequest('action.help', { name: 'http.preflight' })).args,
    { name: 'http.preflight' });
  assert.doesNotThrow(() => validateRequest('runtime.probe', {}));
});

test('isolated UTF-16 surrogates in JSON strings or keys fail before dispatch without changing valid emoji or binary data', () => {
  for (const value of ['\uD800', '\uDC00', 'prefix\uD800suffix', '\uDC00\uDC00']) {
    for (const args of [{ value }, { nested: { [value]: 'value' } }, { nested: [value] }]) {
      assert.throws(() => validateRequest('action.help', args), { code: 'INVALID_ARGUMENTS' });
    }
  }
  const args = { value: '\uD83D\uDD12\u4e2d\u6587', body_base64: Buffer.from([0xff, 0xfe, 0x00, 0xd8]).toString('base64') };
  assert.deepEqual(JSON.parse(validateRequest('action.help', args)).args, args);
  let starts = 0;
  assert.throws(() => invokeEngine(config, 'action.help', { value: '\uD800' }, {
    spawnProcess() { starts += 1; throw new Error('unexpected spawn'); },
  }), { code: 'INVALID_ARGUMENTS' });
  assert.equal(starts, 0);
});

test('unknown actions, traversal IDs and oversized input are rejected before process creation', () => {
  assert.throws(() => validateRequest('shell.run', {}), { code: 'UNKNOWN_ACTION' });
  assert.throws(() => validateRequest('project.status', {}), { code: 'PROJECT_REQUIRED' });
  assert.throws(() => validateRequest('project.status', { project_id: '../other' }), { code: 'INVALID_PROJECT_ID' });
  assert.throws(() => validateRequest('project.create', { body: 'x'.repeat(MAX_REQUEST_BYTES) }), { code: 'INPUT_TOO_LARGE' });
  const cycle = {}; cycle.cycle = cycle;
  assert.throws(() => validateRequest('project.create', cycle), { code: 'INVALID_ARGUMENTS' });
});

test('the packaged Python help catalog exactly matches native action enums without a project or network', async () => {
  const result = await invokeEngine(config, 'action.help', {});
  assert.equal(result.data.action_count, ACTIONS.length);
  assert.deepEqual(Object.values(result.data.groups).flat().sort(), [...ACTIONS].sort());
  const help = await invokeEngine(config, 'action.help', { name: 'http.capture' });
  assert.equal(help.data.action, 'http.capture');
  assert.equal(help.data.project_required, true);
  assert.match(help.data.fields.headers, /non-authentication/);
  assert.match(help.data.fields.body_base64, /base64/);
  assert.match(help.data.fields.body_file, /exact bytes/);
});

test('real child bridge accepts a current partial checkpoint without granting completion', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'awa-ddd-partial-bridge-'));
  const realConfig = { workspace, timeoutMs: 15000 };
  const projectId = 'partial-e2e';
  try {
    await invokeEngine(realConfig, 'project.create', {
      project_id: projectId, target: 'http://fixture.invalid',
    });
    await invokeEngine(realConfig, 'surface.register', {
      project_id: projectId, url: 'http://fixture.invalid/items?q=fixture', method: 'GET', auth: 'public',
      inputs: [{ name: 'q', location: 'query', consumer: 'business_input', test_families: ['generic'] }],
    });
    const checkpoint = await invokeEngine(realConfig, 'plan.checkpoint', {
      project_id: projectId, label: 'Bounded partial fixture',
    });
    const input = {
      project_id: projectId, checkpoint_id: checkpoint.data.checkpoint.id,
      accepted_by: 'fixture-owner',
      explanation: 'Current partial evidence is deliverable while review work remains.',
    };
    const accepted = await invokeEngine(realConfig, 'plan.accept_partial', input);
    const repeated = await invokeEngine(realConfig, 'plan.accept_partial', input);
    assert.match(accepted.data.partial_acceptance.id, /^CA-[a-f0-9]{64}$/);
    assert.equal(repeated.data.partial_acceptance.id, accepted.data.partial_acceptance.id);
    assert.equal(accepted.data.partial_acceptance.can_claim_complete, false);
    assert.equal(accepted.data.partial_acceptance.automatic_stop_allowed, false);
    assert.equal(accepted.data.partial_acceptance.continue_required, true);
    assert.equal(accepted.data.continuation.continue_required, true);
    assert.equal(accepted.data.continuation.can_claim_complete, false);
    assert.equal(accepted.data.continuation.partial_acceptance_id, accepted.data.partial_acceptance.id);
    await assert.rejects(invokeEngine(realConfig, 'plan.finalize', {
      project_id: projectId, checkpoint_id: checkpoint.data.checkpoint.id,
      reason: 'partial_accepted', explanation: 'Delivery must remain partial', reviewer: 'fixture-reviewer',
    }), { code: 'stop_reason' });
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test('argv is fixed, shell is disabled, and payload punctuation is carried only in JSON stdin', async () => {
  const value = '$() & ; `echo ignored`\n"quoted"';
  const spawnProcess = synthetic("let s='';process.stdin.on('data',c=>s+=c);process.stdin.on('end',()=>{const p=JSON.parse(s);process.stdout.write(JSON.stringify({ok:true,data:{action:p.action,value:p.args.value}}))})",
    (executable, argv, options) => {
      assert.equal(options.shell, false);
      assert.equal(options.windowsHide, true);
      assert.equal(options.cwd, PACKAGE_ROOT);
      assert.deepEqual(argv.slice(-4), ['-m', 'awa_ddd', '--workspace', config.workspace]);
      assert.ok(!argv.includes(value));
      assert.equal(typeof executable, 'string');
    });
  const result = await invokeEngine(config, 'project.create', { value }, { spawnProcess });
  assert.equal(result.data.value, value);
});

test('sensitive data is removed from the canonical result, not just the rendered text', async () => {
  const raw = { ok: true, data: { id: 'E1', status_code: 200, nested: { Authorization: 'secret-a', body_base64: 'secret-b' },
    request: { headers: { Cookie: 'secret-c' } }, response: { body: 'secret-d' } } };
  const result = await invokeEngine(config, 'project.list', {}, {
    spawnProcess: synthetic(`process.stdin.resume();process.stdin.on('end',()=>process.stdout.write(${JSON.stringify(JSON.stringify(raw))}))`),
  });
  assert.equal(result.data.id, 'E1');
  assert.equal(result.data.status_code, 200);
  assert.doesNotMatch(JSON.stringify(result), /secret-[abcd]/);
  assert.equal(redactResult({ headers: { authorization: 'secret' } }).headers, '[redacted]');
  assert.doesNotMatch(JSON.stringify(redactResult({ anonymous_cookie: 'private-jar', api_token: 'private-api',
    nested: { client_secret: 'private-client', id_token: 'private-id' } })), /private-/);
});

test('the process protocol preserves UTF-8 and rejects invalid byte sequences', async () => {
  const payload = '中文与 emoji \u{1F512}';
  const result = await invokeEngine(config, 'action.help', { value: payload }, {
    spawnProcess: synthetic("let text='';process.stdin.setEncoding('utf8');process.stdin.on('data',c=>text+=c);process.stdin.on('end',()=>process.stdout.write(JSON.stringify({ok:true,data:JSON.parse(text).args})))"),
  });
  assert.equal(result.data.value, payload);
  let invalidBytesWritten = false;
  await assert.rejects(invokeEngine(config, 'project.list', {}, {
    spawnProcess(executable, argv, options) {
      const child = synthetic("process.stdin.resume();process.stdin.on('end',()=>{process.stdout.write(Buffer.concat([Buffer.from('{\"ok\":true,\"data\":\"'),Buffer.from([0xff]),Buffer.from('\"}')]))})")(executable, argv, options);
      child.stdout.on('data', chunk => { if (chunk.includes(0xff)) invalidBytesWritten = true; });
      return child;
    },
  }), { code: 'INVALID_RESPONSE' });
  assert.equal(invalidBytesWritten, true, 'this regression sends malformed UTF-8, not a syntax-error empty response');
});

test('UTF-8 JSON bytes cannot smuggle isolated surrogates or overflowing numbers into response data', async () => {
  for (const text of ['{"ok":true,"data":{"value":"\\ud800"}}',
    '{"ok":true,"data":{"\\udc00":"value"}}', '{"ok":true,"data":{"value":1e309}}']) {
    await assert.rejects(invokeEngine(config, 'project.list', {}, {
      spawnProcess: synthetic(`process.stdin.resume();process.stdin.on('end',()=>process.stdout.write(${JSON.stringify(text)}))`),
    }), { code: 'INVALID_RESPONSE' });
  }
});

test('WSL uses fixed argv, a selected distribution and one UTF-8 request without a shell',
  { skip: process.platform !== 'win32' }, async () => {
    const source = "let input='';process.stdin.setEncoding('utf8');process.stdin.on('data',c=>{input+=c;const i=input.indexOf('\\n');if(i>=0){const request=JSON.parse(input.slice(0,i));process.stdout.write(JSON.stringify({ok:true,data:{value:request.args.value}}),()=>process.exit(0))}})";
    const result = await invokeEngine({ ...config, executionBackend: 'wsl', wslDistribution: 'kali-linux',
      wslPythonExecutable: '/usr/bin/python3' }, 'action.help', { value: '中文' }, {
      spawnProcess: synthetic(source, (executable, argv, options) => {
        assert.equal(executable, 'wsl.exe');
        assert.deepEqual(argv, ['--distribution', 'kali-linux', '--cd', PACKAGE_ROOT, '--exec', '/usr/bin/python3',
          '-E', '-s', '-X', 'utf8', '-B', '-m', 'awa_ddd.wsl_runner', '--workspace', config.workspace,
          '--deadline-ms', String(config.timeoutMs)]);
        assert.equal(options.shell, false);
        assert.equal(options.windowsHide, true);
      }),
    });
    assert.equal(result.data.value, '中文');
  });

test('WSL cancellation sends CANCEL and waits for the owned supervisor to close',
  { skip: process.platform !== 'win32' }, async () => {
    const controller = new AbortController();
    let closed = false;
    let frames = '';
    let child;
    const source = "let input='';let first=false;process.stdin.setEncoding('utf8');process.stdin.on('data',c=>{input+=c;let i;while((i=input.indexOf('\\n'))>=0){const line=input.slice(0,i);input=input.slice(i+1);if(!first){JSON.parse(line);first=true}else if(line==='CANCEL'){process.stdout.write(JSON.stringify({ok:true,data:{control:'CANCEL'}}),()=>process.exit(0))}}});process.stdin.on('end',()=>process.exit(2))";
    const result = invokeEngine({ ...config, executionBackend: 'wsl' }, 'runtime.probe', {}, {
      signal: controller.signal,
      spawnProcess(executable, argv, options) {
        child = synthetic(source)(executable, argv, options);
        child.stdout.on('data', chunk => { frames += chunk; });
        child.on('close', () => { closed = true; });
        setTimeout(() => {
          assert.equal(child.stdin.writableEnded, false, 'WSL control pipe stays open after dispatch');
          controller.abort();
        }, 150);
        return child;
      },
    });
    await assert.rejects(result, { code: 'ABORTED' });
    assert.equal(closed, true);
    assert.match(frames, /CANCEL/);
  });

test('WSL deadlines use the supervisor control channel instead of pretending a client kill is Linux cleanup',
  { skip: process.platform !== 'win32' }, async () => {
    let frames = '';
    const source = "let text='';process.stdin.setEncoding('utf8');process.stdin.on('data',c=>{text+=c;if(text.includes('\\nCANCEL\\n'))process.stdout.write('CANCEL acknowledged',()=>process.exit(0))})";
    await assert.rejects(invokeEngine({ ...config, executionBackend: 'wsl', timeoutMs: 1000 }, 'runtime.probe', {}, {
      spawnProcess(executable, argv, options) {
        const child = synthetic(source)(executable, argv, options);
        child.stdout.on('data', chunk => { frames += chunk; });
        return child;
      },
    }), { code: 'ENGINE_TIMEOUT' });
    assert.match(frames, /CANCEL acknowledged/);
  });

test('engine error codes are preserved without publishing stderr', async () => {
  const source = "process.stdin.resume();process.stdin.on('end',()=>{process.stderr.write('private diagnostic');process.stdout.write(JSON.stringify({ok:false,error:{code:'identity_unverified',message:'Verify this actor first'}}));process.exitCode=2})";
  await assert.rejects(invokeEngine(config, 'project.list', {}, { spawnProcess: synthetic(source) }),
    error => error.code === 'identity_unverified' && error.message === 'Verify this actor first');
});

test('engine errors preserve bounded safe recovery metadata without credential or raw response leaks', async () => {
  const raw = { ok: false, error: { code: 'resource_binding',
    message: "Expected {'auth_token': 'private-token'} actual={'password':'private-password'}; URL https://private-user:private-pass@example.invalid/item?token=private-query#private-fragment; Cookie: private-cookie", 
    details: { action: 'http.capture', field: 'resource_id', run_id: 'RUN-1', operation_id: 'OP-1', next_action: 'run.inspect',
      help_action: 'action.help', help_input: { name: 'http.capture', headers: 'private-headers' }, raw: 'private-http',
      response: { body: 'private-body' }, token: 'private-detail' } } };
  await assert.rejects(invokeEngine(config, 'project.list', {}, {
    spawnProcess: synthetic(`process.stdin.resume();process.stdin.on('end',()=>{process.stdout.write(${JSON.stringify(JSON.stringify(raw))});process.exitCode=2})`),
  }), error => {
    assert.equal(error.code, 'resource_binding');
    assert.equal(error.details.run_id, 'RUN-1');
    assert.equal(error.details.next_action, 'run.inspect');
    assert.deepEqual(error.details.help_input, { name: 'http.capture' });
    assert.ok(Buffer.byteLength(JSON.stringify(error.details), 'utf8') <= 2048);
    assert.doesNotMatch(error.message + JSON.stringify(error.details), /private-/);
    return true;
  });
  const redacted = safeErrorText('Bearer private-bearer Basic cHJpdmF0ZTpiYXNlNjQ= auth_token=private-auth api_token=private-api; eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature');
  assert.doesNotMatch(redacted, /private-|cHJpdmF0Z|eyJhbGci/);
});

test('finalization rejection retains compact continuation through the actual process bridge', async () => {
  const continuation = { continue_required: true, can_finalize: false, can_claim_complete: false,
    frontier_review_required: true, actionable_total: 4, ready_total: 1, review_total: 3, blocked_total: 0,
    no_progress_rounds: 2, frontier_rounds: 0, unresolved_total: 4, state: 'stalled',
    reason_code: 'no_closure_progress', next_action: 'plan.audit', snapshot_id: 'CS-' + 'a'.repeat(64),
    progress_id: 'PR-' + 'b'.repeat(64), checkpoint_id: 'CP-' + 'c'.repeat(32), finalization_id: null,
    coverage_status: 'partial' };
  const raw = { ok: false, error: { code: 'continue_required', message: 'Review work remains',
    details: { next_action: 'plan.next', continuation: { ...continuation,
      headers: { Authorization: 'private-header' }, body: 'private-body', instruction: 'private-instruction' } } } };
  await assert.rejects(invokeEngine(config, 'plan.finalize', { project_id: 'p', checkpoint_id: continuation.checkpoint_id,
    reason: 'completed', explanation: 'Fixture finalization', reviewer: 'fixture-reviewer' }, {
    spawnProcess: synthetic(`process.stdin.resume();process.stdin.on('end',()=>{process.stdout.write(${JSON.stringify(JSON.stringify(raw))});process.exitCode=2})`),
  }), error => {
    assert.equal(error.code, 'continue_required');
    assert.deepEqual(JSON.parse(JSON.stringify(error.details.continuation)), continuation);
    assert.equal(error.details.next_action, 'plan.next');
    assert.ok(Buffer.byteLength(JSON.stringify(error.details), 'utf8') <= 2048);
    assert.doesNotMatch(JSON.stringify(error.details), /private-|instruction/);
    return true;
  });
});

test('oversized recovery prioritizes typed continuation while keeping the entire payload under 2 KiB', () => {
  const original = { next_action: 'plan.audit', run_id: 'RUN-' + 'r'.repeat(196), operation_id: 'O-' + 'o'.repeat(198),
    action: 'a'.repeat(200), field: 'f'.repeat(200), help_action: 'h'.repeat(200),
    resource_id: 'R-' + 'r'.repeat(198), evidence_id: 'E-' + 'e'.repeat(198), obligation_id: 'OB-' + 'o'.repeat(197),
    continuation: { continue_required: true, can_finalize: false, can_claim_complete: false,
      actionable_total: 5, ready_total: 2, review_total: 3, blocked_total: 0, unresolved_total: 5,
      state: '中'.repeat(1000), reason_code: '中'.repeat(1000), next_action: '中'.repeat(1000),
      coverage_status: '中'.repeat(1000), snapshot_id: 'CS-' + 'a'.repeat(64),
      progress_id: 'PR-' + 'b'.repeat(64), checkpoint_id: 'CP-' + 'c'.repeat(32), finalization_id: null,
      token: 'private-token', arbitrary_text: 'private-text' }, body: 'private-body' };
  const before = JSON.stringify(original);
  const details = safeErrorDetails(original);
  assert.ok(Buffer.byteLength(JSON.stringify(details), 'utf8') <= 2048);
  assert.equal(details.continuation.continue_required, true);
  assert.equal(details.continuation.can_finalize, false);
  assert.equal(details.continuation.actionable_total, 5);
  assert.equal(details.continuation.snapshot_id, original.continuation.snapshot_id);
  assert.equal(details.continuation.checkpoint_id, original.continuation.checkpoint_id);
  assert.equal(details.next_action, 'plan.audit');
  assert.doesNotMatch(JSON.stringify(details), /private-/);
  assert.equal(JSON.stringify(original), before);
});

test('success-shaped output with a failed exit cannot become success', async () => {
  await assert.rejects(invokeEngine(config, 'project.list', {}, {
    spawnProcess: synthetic("process.stdin.resume();process.stdin.on('end',()=>{process.stdout.write('{\"ok\":true,\"data\":{}}');process.exitCode=1})"),
  }), { code: 'ENGINE_FAILED' });
});

test('extra stdout, malformed envelopes and missing Python produce explicit errors', async () => {
  for (const text of ['log\n{"ok":true,"data":{}}', '{"ok":true}', '{"data":{}}']) {
    await assert.rejects(invokeEngine(config, 'project.list', {}, {
      spawnProcess: synthetic(`process.stdin.resume();process.stdin.on('end',()=>process.stdout.write(${JSON.stringify(text)}))`),
    }), { code: 'INVALID_RESPONSE' });
  }
  await assert.rejects(invokeEngine({ ...config, pythonExecutable: join(tmpdir(), 'awa-ddd-no-such-python-executable') }, 'project.list', {}),
    { code: 'PYTHON_START_FAILED' });
});

test('IPC phases distinguish a read before dispatch from an unproven or dispatched write', async () => {
  await assert.rejects(invokeEngine(config, 'project.list', {}, {
    spawnProcess: syntheticIpc({ phases: [{ phase: 'startup' }], output: 'not-json' }),
  }), error => {
    assert.equal(error.code, 'INVALID_RESPONSE');
    assert.equal(error[ENGINE_DISPATCH_PHASE], 'started');
    assert.notEqual(error[ENGINE_DISPATCH_UNCERTAIN], true);
    return true;
  });
  await assert.rejects(invokeEngine(config, 'http.capture', { project_id: 'fixture' }, {
    spawnProcess: syntheticIpc({ phases: [{ phase: 'startup' }], output: 'not-json' }),
  }), error => {
    assert.equal(error.code, 'INVALID_RESPONSE');
    assert.equal(error[ENGINE_DISPATCH_PHASE], 'started');
    assert.equal(error[ENGINE_DISPATCH_UNCERTAIN], true);
    return true;
  });
  await assert.rejects(invokeEngine(config, 'http.capture', { project_id: 'fixture' }, {
    spawnProcess: syntheticIpc({ phases: [{ phase: 'startup' }, { phase: 'accepted' }], output: null, exitCode: 2 }),
  }), error => {
    assert.equal(error[ENGINE_DISPATCH_PHASE], 'accepted');
    assert.equal(error[ENGINE_DISPATCH_UNCERTAIN], true);
    return true;
  });
  await assert.rejects(invokeEngine(config, 'project.list', {}, {
    spawnProcess: syntheticIpc({ phases: [{ phase: 'startup' }, { phase: 'accepted' }, { phase: 'dispatch' }],
      output: null, exitCode: 2 }),
  }), error => {
    assert.equal(error[ENGINE_DISPATCH_PHASE], 'dispatched');
    assert.equal(error[ENGINE_DISPATCH_UNCERTAIN], true);
    return true;
  });
});

test('mode-dependent storage mutations retain uncertainty through the serialized bridge request', async () => {
  for (const [action, args, uncertain] of [
    ['project.migrate', { project_id: 'fixture', mode: 'apply', confirm: true }, true],
    ['project.migrate', { project_id: 'fixture', mode: 'dry_run' }, false],
    ['project.projection', { project_id: 'fixture', mode: 'rebuild' }, true],
    ['project.projection', { project_id: 'fixture', mode: 'compare' }, false],
  ]) {
    await assert.rejects(invokeEngine(config, action, args, {
      spawnProcess: syntheticIpc({ phases: [{ phase: 'startup' }], output: 'not-json' }),
    }), error => {
      assert.equal(error.code, 'INVALID_RESPONSE');
      assert.equal(error[ENGINE_DISPATCH_PHASE], 'started');
      assert.equal(error[ENGINE_DISPATCH_UNCERTAIN] === true, uncertain,
        `${action}:${args.mode} must derive uncertainty from the parsed request arguments`);
      return true;
    });
  }
});

test('valid IPC receipts are nonce-scoped, hash the exact newline-delimited request and tolerate private diagnostics', async () => {
  const nonces = [];
  const result = await invokeEngine(config, 'project.create', { project_id: 'fixture', target: 'http://fixture.invalid' }, {
    spawnProcess: syntheticIpc({
      phases: [{ plain: 'private ordinary diagnostic' }, { phase: 'startup' }, { plain: 'between receipts' },
        { phase: 'accepted' }, { phase: 'dispatch' }],
    }, (_executable, _argv, options) => nonces.push(options.env.AWA_DDD_REQUEST_NONCE)),
  });
  assert.equal(result.ok, true);
  assert.deepEqual(JSON.parse(JSON.stringify(result.data)), {});
  assert.match(nonces[0], /^[a-f0-9]{64}$/);
  await invokeEngine(config, 'project.list', {}, {
    spawnProcess: syntheticIpc({ phases: [{ phase: 'startup' }] },
      (_executable, _argv, options) => nonces.push(options.env.AWA_DDD_REQUEST_NONCE)),
  });
  assert.notEqual(nonces[0], nonces[1], 'each invocation receives a fresh nonce');
});

test('facade execution accepts only its actual nested dispatch receipts and preserves multiple attempts', async () => {
  const result = await invokeEngine(config, 'scenario.run', {
    project_id: 'fixture',
    scenario: { steps: [] },
  }, {
    spawnProcess: syntheticIpc({ phases: [
      { phase: 'startup' },
      { phase: 'accepted' },
      { phase: 'dispatch', action: 'http.capture', run_id: 'RUN-first' },
      { phase: 'dispatch', action: 'http.capture', run_id: 'RUN-second',
        dispatch_hash: 'e'.repeat(64) },
    ] }),
  });
  assert.equal(result.ok, true);
  await assert.rejects(invokeEngine(config, 'scenario.run', {
    project_id: 'fixture',
    scenario: { steps: [] },
  }, {
    spawnProcess: syntheticIpc({ phases: [
      { phase: 'startup' },
      { phase: 'accepted' },
      { phase: 'dispatch', action: 'project.status' },
    ] }),
  }), { code: 'ENGINE_IPC_INVALID' });
});

test('browser and sqlmap preserve provider and request-slot receipts under exact request binding', async () => {
  for (const [action, args] of [
    ['browser.visit', { project_id: 'fixture', url: 'http://fixture.invalid/' }],
    ['tool.sqlmap', { project_id: 'fixture', operation_id: 'OP-fixture', url: 'http://fixture.invalid/' }],
  ]) {
    const result = await invokeEngine(config, action, args, {
      spawnProcess: syntheticIpc({ phases: [
        { phase: 'startup' },
        { phase: 'accepted' },
        { phase: 'dispatch', action, run_id: 'RUN-provider',
          dispatch_hash: 'd'.repeat(64) },
        { phase: 'dispatch', action, run_id: 'RUN-provider',
          dispatch_hash: 'e'.repeat(64) },
      ] }),
    });
    assert.equal(result.ok, true);
    await assert.rejects(invokeEngine(config, action, args, {
      spawnProcess: syntheticIpc({ phases: [
        { phase: 'startup' },
        { phase: 'accepted' },
        { phase: 'dispatch', action, run_id: 'RUN-provider',
          dispatch_hash: 'd'.repeat(64) },
        { phase: 'dispatch', action, run_id: 'RUN-provider',
          dispatch_hash: 'd'.repeat(64) },
      ] }),
    }), { code: 'ENGINE_IPC_INVALID' });
  }
});

test('IPC rejects forged, reordered, duplicated and malformed live-nonce receipts', async () => {
  const invalid = [
    [{ phase: 'startup', schema: 'awa-ddd-ipc/v2' }],
    [{ phase: 'startup', seq: 2 }],
    [{ phase: 'startup' }, { phase: 'startup' }],
    [{ phase: 'accepted' }],
    [{ phase: 'startup' }, { phase: 'accepted', action: 'project.status' }],
    [{ phase: 'startup' }, { phase: 'accepted', request_hash: '0'.repeat(64) }],
    [{ phase: 'startup' }, { phase: 'accepted', extra: { untrusted: true } }],
    [{ phase: 'startup' }, { phase: 'accepted' }, { phase: 'accepted' }],
    [{ phase: 'startup' }, { phase: 'accepted' }, { phase: 'dispatch', dispatch_hash: 'sha256:' + 'd'.repeat(64) }],
    [{ phase: 'startup' }, { phase: 'accepted' }, { phase: 'dispatch' }, { phase: 'dispatch' }],
    [{ malformed: true }],
  ];
  for (const phases of invalid) {
    await assert.rejects(invokeEngine(config, 'project.list', {}, {
      spawnProcess: syntheticIpc({ phases }),
    }), { code: 'ENGINE_IPC_INVALID' });
  }
  const replayed = await invokeEngine(config, 'project.list', {}, {
    spawnProcess: syntheticIpc({ phases: [{ phase: 'startup', nonce: '0'.repeat(64) }] }),
  });
  assert.equal(replayed.ok, true);
  assert.deepEqual(JSON.parse(JSON.stringify(replayed.data)), {},
    'an unrelated nonce is ordinary private stderr');
});

test('backend envelopes cannot self-grant or erase trusted dispatch proof', async () => {
  await assert.rejects(invokeEngine(config, 'project.list', {}, {
    spawnProcess: syntheticIpc({
      phases: [{ phase: 'startup' }, { phase: 'accepted' }, { phase: 'dispatch' }],
      output: JSON.stringify({ ok: false, error: { code: 'arguments', message: 'Backend rejection',
        details: { engine_dispatch_phase: 'not_started', engine_dispatch_uncertain: false } } }),
      exitCode: 2,
    }),
  }), error => {
    assert.equal(error.code, 'arguments');
    assert.equal(error[ENGINE_DISPATCH_PHASE], 'dispatched', 'backend fields cannot rewrite bridge proof');
    assert.equal(error[ENGINE_DISPATCH_UNCERTAIN], true,
      'a structured backend error cannot erase an already dispatched outcome');
    return true;
  });
  await assert.rejects(invokeEngine(config, 'project.list', {}, {
    spawnProcess: syntheticIpc({ phases: [{ phase: 'startup' }],
      output: JSON.stringify({ ok: false, error: { code: 'arguments', message: 'Preflight failed',
        details: { engine_dispatch_phase: 'dispatched', engine_dispatch_uncertain: true } } }),
      exitCode: 2 }),
  }), error => {
    assert.equal(error[ENGINE_DISPATCH_PHASE], 'started');
    assert.notEqual(error[ENGINE_DISPATCH_UNCERTAIN], true);
    return true;
  });
});

test('WSL forwards the request nonce to the Linux supervisor and trusts only its forwarded receipts',
  { skip: process.platform !== 'win32' }, async () => {
    let forwardedNonce;
    await assert.rejects(invokeEngine({ ...config, executionBackend: 'wsl' }, 'project.list', {}, {
      spawnProcess: syntheticIpc({
        phases: [{ phase: 'startup' }, { phase: 'accepted' }, { phase: 'dispatch' }],
        output: null,
        exitCode: 2,
      }, (_executable, _argv, options) => {
        forwardedNonce = options.env.AWA_DDD_REQUEST_NONCE;
        assert.match(forwardedNonce, /^[a-f0-9]{64}$/);
        assert.ok(options.env.WSLENV.split(':').includes('AWA_DDD_REQUEST_NONCE/u'));
      }),
    }), error => {
      assert.equal(error[ENGINE_DISPATCH_PHASE], 'dispatched');
      assert.equal(error[ENGINE_DISPATCH_UNCERTAIN], true);
      return true;
    });
    assert.match(forwardedNonce, /^[a-f0-9]{64}$/);
  });

test('cancellation before dispatch starts no child', async () => {
  const controller = new AbortController(); controller.abort();
  let starts = 0;
  await assert.rejects(invokeEngine(config, 'project.list', {}, {
    signal: controller.signal, spawnProcess() { starts += 1; throw new Error('unexpected spawn'); },
  }), { code: 'ABORTED_BEFORE_DISPATCH' });
  assert.equal(starts, 0);
});

test('cancellation waits for the owned process to close and cannot publish a late success', async () => {
  const controller = new AbortController();
  let closed = false;
  const source = "process.stdin.resume();setTimeout(()=>process.stdout.write('{\"ok\":true,\"data\":{}}'),2000);setInterval(()=>{},1000)";
  const result = invokeEngine(config, 'project.list', {}, {
    signal: controller.signal,
    spawnProcess(executable, argv, options) {
      const child = synthetic(source)(executable, argv, options);
      child.on('close', () => { closed = true; });
      setTimeout(() => controller.abort(), 100);
      return child;
    },
  });
  await assert.rejects(result, { code: 'ABORTED' });
  assert.equal(closed, true);
});

test('bridge enforces its own deadline even without the dsh timeout policy', async () => {
  await assert.rejects(invokeEngine({ ...config, timeoutMs: 1000 }, 'project.list', {}, {
    spawnProcess: synthetic('process.stdin.resume();setInterval(()=>{},1000)'),
  }), { code: 'ENGINE_TIMEOUT' });
});

test('an input pipe failure terminates the owned child instead of disabling the deadline', async () => {
  let closed = false;
  let child;
  let watchdog;
  let forcedCleanup = false;
  try {
    await assert.rejects(invokeEngine({ ...config, timeoutMs: 1000 }, 'project.list', {}, {
      spawnProcess(executable, argv, options) {
        child = synthetic('process.stdin.resume();setInterval(()=>{},1000)')(executable, argv, options);
        child.on('close', () => { closed = true; });
        watchdog = setTimeout(() => { forcedCleanup = true; child.kill('SIGKILL'); }, 3000);
        setTimeout(() => child.stdin.emit('error', new Error('synthetic input pipe failure')), 50);
        return child;
      },
    }), { code: 'ENGINE_IO_ERROR' });
    assert.equal(closed, true);
    assert.equal(forcedCleanup, false);
  } finally {
    clearTimeout(watchdog);
    // Keep this fault-injection regression bounded even if termination regresses.
    if (child && !closed) child.kill('SIGKILL');
  }
});

test('stdout and diagnostic budgets terminate excessive output', async () => {
  await assert.rejects(invokeEngine(config, 'project.list', {}, {
    spawnProcess: synthetic("process.stdin.resume();process.stdout.write('x'.repeat(5*1024*1024));setInterval(()=>{},1000)"),
  }), { code: 'OUTPUT_TOO_LARGE' });
  await assert.rejects(invokeEngine(config, 'project.list', {}, {
    spawnProcess: synthetic("process.stdin.resume();process.stderr.write('x'.repeat(128*1024));setInterval(()=>{},1000)"),
  }), { code: 'DIAGNOSTICS_TOO_LARGE' });
});
