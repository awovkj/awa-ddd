import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { z } from 'zod';
import { MAX_JSON_NODES, validateJson } from '../src/bridge.mjs';

test('the development SDK uses fixed Zod without vendoring another host SDK', async () => {
  const manifest = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
  const lock = JSON.parse(await readFile(new URL('../package-lock.json', import.meta.url), 'utf8'));
  assert.equal(manifest.overrides.zod, '4.6.6');
  assert.equal(lock.packages['node_modules/zod'].version, '4.6.6');
  assert.equal(lock.packages['node_modules/zod'].dev, true);
  assert.equal(manifest.devDependencies['@deepseek-ai/dsh-tools'], '0.2.1-rc.3');
  assert.equal(manifest.devDependencies['@deepseek-ai/dsh-llm'], '0.2.1-rc.3');
  assert.ok(Object.keys(manifest.dependencies).every(name => !name.startsWith('@deepseek-ai/')));
  assert.ok(Object.hasOwn(manifest.peerDependencies, '@deepseek-ai/dsh-tools'));
  assert.ok(Object.hasOwn(manifest.peerDependencies, '@deepseek-ai/dsh-llm'));
  assert.ok(manifest.files.includes('!**/node_modules/**'));
});

test('patched constrained collections reject excess length before parsing every element', () => {
  let transformed = 0;
  const schema = z.array(z.string().transform(value => { transformed++; return value; })).max(1);
  const result = schema.safeParse(Array(10001).fill('synthetic-fixture'));
  assert.equal(result.success, false);
  assert.equal(result.error.issues[0].code, 'too_big');
  assert.equal(transformed, 0);
  assert.equal(schema.safeParse(['valid']).success, true);
  assert.equal(transformed, 1);
});

test('JSON breadth limits precede descriptor allocation for oversized arrays and objects', () => {
  const values = [Array(MAX_JSON_NODES + 1).fill(0),
    Object.fromEntries(Array.from({ length: MAX_JSON_NODES + 1 }, (_, index) => ['key' + index, null]))];
  for (const value of values) {
    const original = Object.getOwnPropertyDescriptors;
    let inspected = false;
    Object.getOwnPropertyDescriptors = object => {
      if (object === value) {
        inspected = true;
        throw new Error('An oversized collection reached descriptor allocation');
      }
      return original(object);
    };
    try {
      assert.throws(() => validateJson(value), { code: 'INVALID_ARGUMENTS' });
      assert.equal(inspected, false);
    } finally {
      Object.getOwnPropertyDescriptors = original;
    }
  }
  assert.deepEqual(validateJson({ rows: [0, false, null, 'valid'] }), { rows: [0, false, null, 'valid'] });
});
