import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { once } from 'node:events';
import { invokeEngine, validateRequest } from '../src/bridge.mjs';


function requestHash(action, args) {
  return createHash('sha256')
    .update(Buffer.from(validateRequest(action, args) + '\n', 'utf8'))
    .digest('hex');
}


function observeChildren(records) {
  return (executable, argv, options) => {
    const record = {
      executable,
      argv: [...argv],
      options: {
        cwd: options.cwd,
        shell: options.shell,
        windowsHide: options.windowsHide,
      },
      receipts: [],
    };
    records.push(record);
    const child = spawn(executable, argv, options);
    let pending = Buffer.alloc(0);
    child.stderr.on('data', chunk => {
      pending = Buffer.concat([pending, chunk]);
      let newline;
      while ((newline = pending.indexOf(0x0a)) >= 0) {
        const line = pending.subarray(0, newline).toString('utf8');
        pending = pending.subarray(newline + 1);
        try {
          const receipt = JSON.parse(line);
          if (receipt?.schema === 'awa-ddd-ipc/v1') {
            record.receipts.push(receipt);
          }
        } catch {
          // Ordinary diagnostics remain private; invokeEngine owns validation.
        }
      }
    });
    return child;
  };
}


test('real Bridge child binds startup/accepted/dispatch to one loopback request', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'awa-bridge-dispatch-e2e-'));
  const settings = { workspace, timeoutMs: 30000 };
  const requests = [];
  const server = createServer((request, response) => {
    requests.push({
      method: request.method,
      url: request.url,
      host: request.headers.host,
    });
    const body = Buffer.from('{"fixture":true}', 'utf8');
    response.writeHead(200, {
      'content-type': 'application/json',
      'content-length': String(body.length),
    });
    response.end(body);
  });

  try {
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const base = `http://127.0.0.1:${server.address().port}`;
    const projectId = 'bridge-dispatch-e2e';

    const created = await invokeEngine(settings, 'project.create', {
      project_id: projectId,
      target: base,
      scope: [base],
    });
    assert.equal(created.data.project_id, projectId);
    assert.equal(requests.length, 0, 'project creation sends no target traffic');

    const operation = await invokeEngine(settings, 'surface.register', {
      project_id: projectId,
      url: base + '/fixture',
      method: 'GET',
      auth: 'public',
    });
    assert.match(operation.data.id, /^O-[a-f0-9]{24}$/);
    assert.equal(requests.length, 0, 'operation registration sends no target traffic');

    const captureArgs = {
      project_id: projectId,
      operation_id: operation.data.id,
    };
    const expectedRequestHash = requestHash('http.capture', captureArgs);
    const children = [];
    const captured = await invokeEngine(
      settings,
      'http.capture',
      captureArgs,
      { spawnProcess: observeChildren(children) },
    );

    assert.equal(children.length, 1);
    const child = children[0];
    assert.equal(child.options.shell, false);
    assert.equal(child.options.windowsHide, true);
    assert.deepEqual(child.argv.slice(-4), [
      '-m', 'awa_ddd', '--workspace', workspace,
    ]);
    assert.deepEqual(
      child.receipts.map(receipt => receipt.phase),
      ['startup', 'accepted', 'dispatch'],
    );
    assert.deepEqual(
      child.receipts.map(receipt => receipt.seq),
      [1, 2, 3],
    );
    const accepted = child.receipts[1];
    const dispatched = child.receipts[2];
    assert.equal(accepted.action, 'http.capture');
    assert.equal(accepted.request_hash, expectedRequestHash);
    assert.equal(dispatched.action, 'http.capture');
    assert.equal(dispatched.request_hash, expectedRequestHash);
    assert.match(dispatched.run_id, /^RUN-[A-Za-z0-9_-]+$/);
    assert.match(dispatched.dispatch_hash, /^[a-f0-9]{64}$/);
    assert.equal(captured.data.run_id, dispatched.run_id);
    assert.equal(captured.data.complete, true);

    assert.equal(requests.length, 1, 'the capture must hit the target exactly once');
    assert.equal(requests[0].method, 'GET');
    assert.equal(requests[0].url, '/fixture');
    assert.equal(requests[0].host, new URL(base).host);
    assert.equal(new URL(base).origin, base);

    const inspected = await invokeEngine(settings, 'run.inspect', {
      project_id: projectId,
      run_id: captured.data.run_id,
    });
    assert.equal(inspected.data.status, 'succeeded');
    assert.equal(inspected.data.dispatch_attempted, true);
    assert.match(inspected.data.dispatch_id, /^DSP-[a-f0-9]{64}$/);
    assert.equal(requests.length, 1, 'offline inspection must not replay the request');
  } finally {
    if (server.listening) {
      await new Promise((accept, reject) => {
        server.close(error => error ? reject(error) : accept());
      });
    }
    const absolute = resolve(workspace);
    assert.ok(absolute.startsWith(resolve(tmpdir()) + sep));
    await rm(absolute, { recursive: true, force: true });
  }
});
