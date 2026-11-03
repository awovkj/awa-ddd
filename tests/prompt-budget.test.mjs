import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { defineTool } from '@deepseek-ai/dsh-tools';
import { ACTIONS, PACKAGE_ROOT } from '../src/bridge.mjs';
import { toolDefinitions } from '../src/tools.mjs';
import { STOP_POLICY_TEXT } from '../src/stop-policy.mjs';
import { apply as applyMode } from '../src/mode.mjs';

const bytes = value => Buffer.byteLength(value, 'utf8');

function modePrompt() {
  let section;
  applyMode({ inject(_dependencies, callback) {
    callback({ sessionProjections: { register() {}, stateOf: () => ({ active: true }) },
      systemPrompt: { section(value) { section = value; } }, commands: { register() {} } });
  } });
  return section.text({ agent: { session: 'fixture' } });
}

test('always-present schemas and enabled policy fit the measured 25 KB context budget', () => {
  const definitions = toolDefinitions(defineTool, { workspace: join(tmpdir(), 'awa-prompt-budget') });
  const schemas = JSON.stringify(definitions.map(({ name, description, parameters }) => ({ name, description, parameters })));
  const size = { schemas: bytes(schemas), stop: bytes(STOP_POLICY_TEXT), mode: bytes(modePrompt()) };
  assert.ok(size.schemas <= 20000, JSON.stringify(size));
  assert.ok(size.stop <= 2200, JSON.stringify(size));
  assert.ok(size.mode <= 4000, JSON.stringify(size));
  assert.ok(size.schemas + size.stop + size.mode <= 25000, JSON.stringify(size));
  assert.equal(ACTIONS.length, 63);
  assert.deepEqual(definitions.flatMap(tool => tool.parameters.properties.action.enum).sort(), [...ACTIONS].sort());
  assert.match(modePrompt(), /\u5148 surface\.recon \u7edf\u7b79\u4fe1\u606f/);
});

test('every tool places the only help entrance before its action-specific field description', () => {
  const definitions = toolDefinitions(defineTool, { workspace: join(tmpdir(), 'awa-help-selection') });
  for (const tool of definitions) {
    assert.match(tool.parameters.properties.action.description, /awa_project action\.help input:\{name:"<action>"\}/);
    assert.ok(tool.parameters.properties.input.description.startsWith(
      'Help: awa_project action.help input:{name:"<action>"}'), tool.name);
    assert.equal(tool.parameters.properties.action.enum.includes('action.help'), tool.name === 'awa_project');
  }
});

test('the loaded skill stays bounded while detailed contracts remain available on demand', async () => {
  const skill = await readFile(join(PACKAGE_ROOT, 'skills', 'awa-ddd', 'SKILL.md'), 'utf8');
  assert.ok(bytes(skill) <= 10 * 1024, `Skill is ${bytes(skill)} bytes; load detailed docs only when needed.`);
  assert.match(skill, /action\.help/);
  assert.match(skill, /Playwright/);
  assert.match(skill, /checkpoint/);
});
