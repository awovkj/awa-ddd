import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { basename, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';
import { invokeEngine, MAX_REQUEST_BYTES, PACKAGE_ROOT } from '../src/bridge.mjs';

const cli = join(PACKAGE_ROOT, 'scripts', 'invoke-request.mjs');
const helper = join(PACKAGE_ROOT, 'scripts', 'Invoke-AwaDdd.ps1');

function run(executable, argv, cwd) {
  return new Promise((fulfill, reject) => {
    const child = spawn(executable, argv, { cwd, shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout = [];
    const stderr = [];
    const timer = setTimeout(() => child.kill('SIGKILL'), 15000);
    child.stdout.on('data', data => stdout.push(data));
    child.stderr.on('data', data => stderr.push(data));
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', code => {
      clearTimeout(timer);
      fulfill({ code, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr) });
    });
  });
}

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'awa-request-file-test-'));
  t.after(async () => {
    const target = resolve(directory);
    const delta = relative(resolve(tmpdir()), target);
    assert.ok(delta && !isAbsolute(delta) && delta !== '..' && !delta.startsWith(`..${sep}`));
    assert.ok(basename(target).startsWith('awa-request-file-test-'));
    await rm(target, { recursive: true, force: true });
  });
  return { directory, workspace: join(directory, 'state'), input: join(directory, 'request.json'), output: join(directory, 'result.json') };
}

function parse(raw) {
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
}

test('request-file CLI writes byte-exact UTF-8 without BOM and still prints the same envelope', async t => {
  const f = await fixture(t);
  await invokeEngine({ workspace: f.workspace, timeoutMs: 5000 }, 'project.create', {
    project_id: 'unicode-file', target: 'http://fixture.invalid/', scope: ['http://fixture.invalid/'],
  });
  await writeFile(f.input, JSON.stringify({ action: 'identity.actor', args: {
    project_id: 'unicode-file', actor_id: 'unicode-actor', subject: '\u6d4b\u8bd5\u4e3b\u4f53', label: '\u4e2d\u6587 \uD83D\uDD12', roles: [],
  } }), 'utf8');
  const result = await run(process.execPath, [cli, '--request-file', f.input, '--workspace', f.workspace, '--output-file', f.output], f.directory);
  assert.equal(result.code, 0, result.stderr.toString('utf8'));
  const output = await readFile(f.output);
  assert.deepEqual(output, result.stdout);
  assert.notDeepEqual([...output.subarray(0, 3)], [0xef, 0xbb, 0xbf]);
  assert.equal(parse(output).ok, true);
  assert.equal(parse(output).data.label, '\u4e2d\u6587 \uD83D\uDD12');
});

test('invalid request bytes and isolated JSON surrogates produce valid UTF-8 error result files', async t => {
  const f = await fixture(t);
  for (const [index, raw, code] of [[0, Buffer.from([0xff, 0xfe, 0x41, 0x00]), 'REQUEST_FILE'],
    [1, Buffer.from('{"action":"project.create","args":{"label":"\\ud800"}}'), 'INVALID_ARGUMENTS']]) {
    await writeFile(f.input, raw);
    const output = join(f.directory, `error-${index}.json`);
    const result = await run(process.execPath, [cli, '--request-file', f.input, '--workspace', f.workspace, '--output-file', output], f.directory);
    assert.equal(result.code, 2);
    assert.deepEqual(await readFile(output), result.stdout);
    assert.equal(parse(result.stdout).ok, false);
    assert.equal(parse(result.stdout).error.code, code);
  }
});

test('existing output paths and the request file are never overwritten or used after dispatch', async t => {
  const f = await fixture(t);
  const request = JSON.stringify({ action: 'project.create', args: {
    project_id: 'never-created', target: 'http://fixture.invalid/', scope: ['http://fixture.invalid/'],
  } });
  await writeFile(f.input, request, 'utf8');
  await writeFile(f.output, 'keep-existing-result', 'utf8');
  for (const output of [f.input, f.output]) {
    const before = await readFile(output);
    const result = await run(process.execPath, [cli, '--request-file', f.input, '--workspace', f.workspace, '--output-file', output], f.directory);
    assert.equal(result.code, 2);
    assert.equal(parse(result.stdout).error.code, 'RESULT_FILE');
    assert.deepEqual(await readFile(output), before);
  }
  const result = await run(process.execPath, [cli, '--request-file', f.input, '--workspace', f.workspace, '--output-file', join(f.directory, 'new-result.json')], f.directory);
  assert.equal(result.code, 0, 'rejected output paths never created or partially modified the project');
});

test('missing request files emit generic structured errors without publishing their path', async t => {
  const f = await fixture(t);
  const secretPath = join(f.directory, 'credential-secret-missing.json');
  const result = await run(process.execPath, [cli, '--request-file', secretPath, '--output-file', f.output], f.directory);
  assert.equal(result.code, 2);
  assert.equal(parse(result.stdout).error.code, 'REQUEST_FILE');
  assert.doesNotMatch(result.stdout.toString('utf8'), /credential-secret/);
  assert.deepEqual(await readFile(f.output), result.stdout);
});

test('oversized files and devices fail closed before engine dispatch instead of reading without a bound', async t => {
  const f = await fixture(t);
  await writeFile(f.input, Buffer.alloc(MAX_REQUEST_BYTES + 1, 0x20));
  const oversized = await run(process.execPath, [cli, '--request-file', f.input, '--output-file', f.output], f.directory);
  assert.equal(oversized.code, 2);
  assert.equal(parse(oversized.stdout).error.code, 'REQUEST_FILE');
  const device = process.platform === 'win32' ? 'NUL' : '/dev/zero';
  const output = join(f.directory, 'device-error.json');
  const result = await run(process.execPath, [cli, '--request-file', device, '--output-file', output], f.directory);
  assert.equal(result.code, 2);
  assert.equal(parse(result.stdout).error.code, 'REQUEST_FILE');
  assert.deepEqual(await readFile(output), result.stdout);
});

test('PowerShell 5.1 helper writes UTF-8 files and preserves structured file errors',
  { skip: process.platform !== 'win32' }, async t => {
    const f = await fixture(t);
    await invokeEngine({ workspace: f.workspace, timeoutMs: 5000 }, 'project.create', {
      project_id: 'unicode-helper', target: 'http://fixture.invalid/', scope: ['http://fixture.invalid/'],
    });
    const input = join(f.directory, '\u4e2d\u6587 request $(); &.json');
    const output = join(f.directory, '\u4e2d\u6587 result $(); &.json');
    await writeFile(input, JSON.stringify({ action: 'identity.actor', args: {
      project_id: 'unicode-helper', actor_id: 'unicode-actor', subject: '\u6d4b\u8bd5\u4e3b\u4f53', label: '\u4e2d\u6587 \uD83D\uDD12', roles: [],
    } }), 'utf8');
    const args = ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', helper,
      '-RequestFile', input, '-Workspace', f.workspace, '-OutputFile', output];
    const result = await run('powershell.exe', args, f.directory);
    assert.equal(result.code, 0, result.stderr.toString('utf8'));
    assert.equal(parse(await readFile(output)).data.label, '\u4e2d\u6587 \uD83D\uDD12');
    assert.deepEqual(result.stdout, await readFile(output));
    const errorOutput = join(f.directory, 'helper-error.json');
    const error = await run('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', helper,
      '-RequestFile', join(f.directory, 'missing.json'), '-OutputFile', errorOutput], f.directory);
    assert.equal(error.code, 2);
    assert.equal(parse(await readFile(errorOutput)).error.code, 'REQUEST_FILE');
  });
