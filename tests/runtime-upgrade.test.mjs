import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { defineTool } from '@deepseek-ai/dsh-tools';
import * as plugin from '../src/index.mjs';
import {
  invokeEngine, resolveConfig, BridgeError, ENGINE_DISPATCH_UNCERTAIN,
  TRUSTED_SQLMAP_ENV, TRUSTED_YAK_ENV, BROWSER_TLS_ENV,
} from '../src/bridge.mjs';
import { toolDefinitions } from '../src/tools.mjs';

const workspace = join(tmpdir(), 'awa-runtime-upgrade-node-tests');

function syntheticChild(inspect) {
  return (executable, argv, options) => {
    inspect(options.env);
    return spawn(process.execPath, ['-e', `
      let input = '';
      process.stdin.on('data', chunk => { input += chunk; });
      process.stdin.on('end', () => process.stdout.write('{"ok":true,"data":{}}'));
    `], options);
  };
}

test('administrator tool/TLS config is explicit, normalized and idempotent', () => {
  const defaults = plugin.Config({});
  assert.equal(defaults.trustedSqlmapPath, '');
  assert.equal(defaults.trustedYakPath, '');
  assert.equal(defaults.browserIgnoreHTTPSErrors, false);
  const schemaConfigured = plugin.Config({ trustedSqlmapPath: { path: '/admin/sqlmap.py' },
    trustedYakPath: '/opt/yak', browserIgnoreHTTPSErrors: true });
  assert.deepEqual(schemaConfigured.trustedSqlmapPath, { path: '/admin/sqlmap.py', sha256: '' });
  assert.equal(schemaConfigured.browserIgnoreHTTPSErrors, true);
  assert.equal(resolveConfig({ workspace }).browserIgnoreHTTPSErrors, false);
  const digest = 'a'.repeat(64);
  const resolved = resolveConfig({ workspace,
    trustedSqlmapPath: { path: 'C:/admin/sqlmap.py', sha256: digest },
    trustedYakPath: '/opt/yak', browserIgnoreHTTPSErrors: true });
  assert.deepEqual(resolved.trustedSqlmapPath, { path: 'C:/admin/sqlmap.py', sha256: digest });
  assert.deepEqual(resolved.trustedYakPath, { path: '/opt/yak', sha256: '' });
  assert.equal(resolved.browserIgnoreHTTPSErrors, true);
  assert.deepEqual(resolveConfig(resolved), resolved);
  for (const config of [
    { trustedSqlmapPath: { path: 'C:/admin/sqlmap.py', sha256: 'not-a-digest' } },
    { trustedYakPath: { path: '/opt/yak', sha256: 'INVALID' } },
    { browserIgnoreHTTPSErrors: 'true' },
  ]) assert.throws(() => resolveConfig({ workspace, ...config }), { code: 'INVALID_CONFIG' });
});

test('bridge passes only private admin settings and strips dangerous inherited environment', async () => {
  const saved = new Map();
  for (const key of ['NODE_OPTIONS', 'PYTHONPATH', 'HTTPS_PROXY', TRUSTED_SQLMAP_ENV, TRUSTED_YAK_ENV, BROWSER_TLS_ENV]) {
    saved.set(key, process.env[key]);
  }
  const observed = [];
  try {
    process.env.NODE_OPTIONS = '--require ./missing-injection.cjs';
    process.env.PYTHONPATH = '/tmp/model-controlled';
    process.env.HTTPS_PROXY = 'http://proxy.invalid';
    process.env[TRUSTED_SQLMAP_ENV] = '{"path":"/inherited/sqlmap.py"}';
    process.env[TRUSTED_YAK_ENV] = '{"path":"/inherited/yak"}';
    process.env[BROWSER_TLS_ENV] = '1';
    const digest = 'b'.repeat(64);
    await invokeEngine({ workspace,
      trustedSqlmapPath: { path: 'C:/admin/sqlmap.py', sha256: digest },
      trustedYakPath: '/opt/yak', browserIgnoreHTTPSErrors: true,
    }, 'project.list', {}, { spawnProcess: syntheticChild(env => observed.push(env)) });
    await invokeEngine({ workspace }, 'project.list', {}, {
      spawnProcess: syntheticChild(env => observed.push(env)) });
  } finally {
    for (const [key, value] of saved) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
  assert.equal(observed.length, 2);
  const [configured, unconfigured] = observed;
  assert.deepEqual(JSON.parse(configured[TRUSTED_SQLMAP_ENV]),
    { path: 'C:/admin/sqlmap.py', sha256: 'b'.repeat(64) });
  assert.deepEqual(JSON.parse(configured[TRUSTED_YAK_ENV]), { path: '/opt/yak', sha256: '' });
  assert.equal(configured[BROWSER_TLS_ENV], '1');
  for (const key of ['NODE_OPTIONS', 'PYTHONPATH', 'HTTPS_PROXY']) assert.equal(configured[key], undefined);
  for (const key of [TRUSTED_SQLMAP_ENV, TRUSTED_YAK_ENV, BROWSER_TLS_ENV]) {
    assert.equal(unconfigured[key], undefined, 'inherited private settings require explicit host config');
  }
});

test('scenario.run and test.run_scenario both preserve SC run identity and dispatch uncertainty', async () => {
  for (const [assessmentModel, groupName, action] of [
    ['v1', 'awa_execute', 'scenario.run'], ['v2', 'awa_test', 'test.run_scenario'],
  ]) {
    const events = [];
    const error = new BridgeError('tool_timeout', 'fixture timeout', { run_id: 'SC-runtime-upgrade' });
    Object.defineProperty(error, ENGINE_DISPATCH_UNCERTAIN, { value: true });
    const definitions = toolDefinitions(defineTool, { workspace, assessmentModel }, async () => { throw error; },
      undefined, { observer: event => { events.push(event); } });
    const tool = definitions.find(item => item.name === groupName);
    await assert.rejects(tool.execute({ action, project_id: 'p', input: { scenario: { steps: [] } } }, {}));
    const failure = events.find(event => event.phase === 'failure');
    assert.equal(failure.claimed_run, true);
    assert.equal(failure.dispatch_uncertain, true);
  }
});
