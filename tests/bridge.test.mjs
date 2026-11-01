import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  invokeEngine, resolveConfig, validateRequest, validateJson, redactResult, safeErrorText, safeErrorDetails,
  PACKAGE_ROOT, MAX_REQUEST_BYTES, MAX_JSON_DEPTH, ACTIONS, ENGINE_DISPATCH_UNCERTAIN,
} from '../src/bridge.mjs';

const config = { workspace: join(tmpdir(), 'awa-ddd-bridge-test-state'), timeoutMs: 5000 };

function synthetic(source, inspect = () => {}) {
  return (executable, argv, options) => {
    inspect(executable, argv, options);
    return spawn(process.execPath, ['-e', source], options);
  };
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

test('only bridge-owned uncertain outcomes carry dispatch uncertainty, never backend assertions', async () => {
  await assert.rejects(invokeEngine(config, 'project.list', {}, {
    spawnProcess: synthetic("process.stdin.resume();process.stdin.on('end',()=>process.stdout.write('not-json'))"),
  }), error => {
    assert.equal(error.code, 'INVALID_RESPONSE');
    assert.equal(error[ENGINE_DISPATCH_UNCERTAIN], true);
    return true;
  });
  await assert.rejects(invokeEngine(config, 'project.list', {}, {
    spawnProcess: synthetic("process.stdin.resume();process.stdin.on('end',()=>{process.stdout.write(JSON.stringify({ok:false,error:{code:'arguments',message:'Preflight failed',details:{engine_dispatch_uncertain:true}}}));process.exitCode=2})"),
  }), error => {
    assert.equal(error.code, 'arguments');
    assert.notEqual(error[ENGINE_DISPATCH_UNCERTAIN], true);
    return true;
  });
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
