/** AWA-DDD 2.0 surface: six groups, model switch, no legacy action leakage by default. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { toolDefinitions, GROUPS, V2_GROUPS } from '../src/tools.mjs';
import { ACTION_GROUPS, V2_ACTION_GROUPS, ALL_ACTIONS } from '../src/actions.mjs';
import { resolveConfig, validateRequest } from '../src/bridge.mjs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const workspace = join(tmpdir(), 'awa-v2-plugin-test');
const config = { workspace };
const defineTool = definition => definition;

test('default surface remains the ten legacy groups', () => {
  const definitions = toolDefinitions(defineTool, config);
  assert.equal(definitions.length, 10);
  assert.equal(GROUPS.flatMap(group => group.actions).length, 63);
});

test('v2 mode registers six groups and only v2 actions', () => {
  const definitions = toolDefinitions(defineTool, { ...config, assessmentModel: 'v2' });
  assert.equal(definitions.length, 6);
  assert.deepEqual(definitions.map(definition => definition.name).sort(), Object.keys(V2_ACTION_GROUPS).sort());
  const actions = definitions.flatMap(definition => definition.parameters.action.enum);
  assert.equal(actions.length, new Set(actions).size);
  assert.ok(actions.includes('campaign.start'));
  assert.ok(actions.includes('test.run'));
  assert.ok(!actions.includes('http.capture'), 'legacy write facade is not exposed in v2 mode');
});

test('bridge validates v2 actions but rejects unknown ones', () => {
  assert.doesNotThrow(() => validateRequest('campaign.start', { project_id: 'p' }));
  assert.doesNotThrow(() => validateRequest('test.run', { project_id: 'p', campaign_id: 'C' }));
  assert.throws(() => validateRequest('shell.run', {}), { code: 'UNKNOWN_ACTION' });
});

test('assessmentModel config is validated and survives resolution', () => {
  assert.equal(resolveConfig({ ...config, assessmentModel: 'v2' }).assessmentModel, 'v2');
  assert.throws(() => resolveConfig({ ...config, assessmentModel: 'v3' }), { code: 'INVALID_CONFIG' });
});
