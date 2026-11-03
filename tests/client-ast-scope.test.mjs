import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const helper = fileURLToPath(new URL('../src/parse-js.mjs', import.meta.url));
const root = fileURLToPath(new URL('../', import.meta.url));

function parse(source) {
  const result = spawnSync(process.execPath, [helper], {
    input: JSON.stringify({source}), encoding: 'utf8', cwd: root, shell: false,
    timeout: 15000, maxBuffer: 2 * 1024 * 1024,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0);
  const value = JSON.parse(result.stdout);
  assert.ok(!value.limitations.some(row => row.code === 'javascript_analysis_budget_or_input_error'));
  return value;
}

test('nested, default and rest variable patterns shadow browser and request globals', () => {
  for (const declaration of [
    'const {fetch, location, window} = fixture;',
    'const {client: {fetch, location, window}} = fixture;',
    'const [fetch, [location, window]] = fixture;',
    'const {fetch = fallback, location = fallback, window = fallback} = fixture;',
    'const {fetch, location, ...window} = fixture;',
    'const [fetch, location, ...window] = fixture;',
  ]) {
    const value = parse(declaration + "fetch('/ghost'); location.assign(input.redirect); window.location.href = input.redirect;");
    assert.deepEqual(value.operations, [], declaration);
    assert.deepEqual(value.candidates, [], declaration);
    assert.deepEqual(value.client_sinks, [], declaration);
  }
});

test('destructuring binds target identifiers, not property keys', () => {
  const value = parse("const {fetch: localFetch, location: localLocation, window: localWindow} = fixture; fetch('/actual'); window.location.href = input.redirect; location.replace(input.return_url);");
  assert.deepEqual(value.operations.map(row => row.url), ['/actual']);
  assert.deepEqual(value.client_sinks.map(row => row.sink), ['location.href', 'location.replace']);
});

test('innerHTML binding-pattern keys are not render-object sinks', () => {
  const value = parse([
    'const {innerHTML: local} = fixture;',
    'function localRender({innerHTML: data}) { return data; }',
    'const vnode = {innerHTML: item.description};',
  ].join('\n'));
  assert.equal(value.client_sinks.length, 1);
  assert.equal(value.client_sinks[0].sink, 'innerHTML.object_property');
  assert.equal(value.client_sinks[0].source_line, 3);
  assert.deepEqual(value.client_sinks[0].referenced_fields, ['description']);
});

test('destructured document, self, globalThis and axios remain local unknowns', () => {
  const value = parse("const {document, self, globalThis, axios} = fixture; document.location.assign(input.redirect); self.location.replace(input.redirect); globalThis.location.href = input.redirect; axios.post('/ghost', {});");
  assert.deepEqual(value.operations, []);
  assert.deepEqual(value.client_sinks, []);
});

test('catch identifiers and nested patterns fence their own bodies only', () => {
  const value = parse([
    "try { throw null; } catch (fetch) { fetch('/ghost'); }",
    'try { throw null; } catch (window) { window.location.href = input.redirect; }',
    "try { throw null; } catch ({fetch, nested: {location} = {}, ...window}) { fetch('/ghost'); location.assign(input.redirect); window.location.href = input.redirect; }",
    "fetch('/actual'); location.assign(input.actual);",
  ].join('\n'));
  assert.deepEqual(value.operations.map(row => row.url), ['/actual']);
  assert.deepEqual(value.client_sinks.map(row => row.referenced_fields), [['actual']]);
});

test('for declarations have loop-local bindings including nested and rest patterns', () => {
  const value = parse([
    "for (let fetch = callback; check; increment) { fetch('/ghost'); }",
    "for (const {fetch, nested: {location}} of rows) { fetch('/ghost'); location.assign(input.redirect); }",
    "for (const [fetch, ...window] of rows) { fetch('/ghost'); window.location.href = input.redirect; }",
    'for (let window in rows) window.location.assign(input.redirect);',
    "fetch('/actual'); window.location.href = input.actual;",
  ].join('\n'));
  assert.deepEqual(value.operations.map(row => row.url), ['/actual']);
  assert.deepEqual(value.client_sinks.map(row => row.referenced_fields), [['actual']]);
});

test('var patterns hoist to their function or program, never a neighboring function', () => {
  const value = parse([
    "function local() { fetch('/ghost-before'); { var {fetch, location} = fixture; } location.assign(input.ghost); }",
    "function localLoop() { location.assign(input.ghost); for (var location of rows) location.replace(input.ghost); }",
    "fetch('/actual'); location.assign(input.actual);",
  ].join('\n'));
  assert.deepEqual(value.operations.map(row => row.url), ['/actual']);
  assert.deepEqual(value.client_sinks.map(row => row.referenced_fields), [['actual']]);
  const program = parse("{ var [fetch, location] = fixture; } fetch('/ghost'); location.assign(input.ghost);");
  assert.deepEqual(program.operations, []);
  assert.deepEqual(program.client_sinks, []);
});

test('switch bindings share cases but do not shadow the discriminant or outside scope', () => {
  const value = parse([
    "switch (fetch('/discriminant')) { case 1: const fetch = callback; fetch('/ghost'); break; default: fetch('/ghost'); }",
    "fetch('/actual');",
  ].join('\n'));
  assert.deepEqual(value.operations.map(row => row.url), ['/discriminant', '/actual']);
});

test('local same-name writes cannot invalidate unrelated global aliases', () => {
  const value = parse([
    'const request = fetch; const loc = window.location;',
    'function local(fetch, window, location) { fetch = callback; window.location = fixture; location.assign = callback; }',
    "request('/actual'); loc.assign(input.redirect); location.replace(input.return_url);",
  ].join('\n'));
  assert.deepEqual(value.operations.map(row => row.url), ['/actual']);
  assert.deepEqual(value.client_sinks.map(row => row.sink), ['location.assign', 'location.replace']);
});

test('plain, pattern and loop reassignments cannot lend stale request aliases', () => {
  for (const source of [
    "fetch = callback; fetch('/ghost'); window.fetch('/ghost');",
    "({fetch} = fixture); fetch('/ghost'); globalThis.fetch('/ghost');",
    "for (fetch of callbacks) fetch('/ghost'); fetch('/ghost');",
    "const request = fetch; request = callback; request('/ghost');",
    "fetch('/ghost-before'); fetch = callback;",
  ]) {
    const value = parse(source);
    assert.deepEqual(value.operations, [], source);
  }
});

test('global namespace and const-alias method writes invalidate shared request clients', () => {
  for (const source of [
    "window.fetch = callback; fetch('/ghost'); globalThis.fetch('/ghost');",
    "globalThis['fetch'] = callback; fetch('/ghost'); window.fetch('/ghost');",
    "const root = window; root.fetch = callback; fetch('/ghost');",
    "const api = axios; api.post = callback; axios.post('/ghost', {}); window.axios.post('/ghost', {});",
  ]) assert.deepEqual(parse(source).operations, [], source);
});

test('navigation binding, object and method replacement stays review-only across browser aliases', () => {
  for (const source of [
    'location = fixture; location.assign(input.redirect); window.location.assign(input.redirect);',
    '({location} = fixture); document.location.replace(input.redirect);',
    'window.location = fixture; location.assign(input.redirect); globalThis.location.href = input.redirect;',
    'window.location.assign = callback; location.assign(input.redirect); self.location.assign(input.redirect);',
    'const loc = window.location; loc.assign = callback; location.assign(input.redirect);',
    'delete window.location.replace; document.location.replace(input.redirect);',
    'window[key] = fixture; location.assign(input.redirect);',
    'for (location of rows) location.assign(input.redirect);',
  ]) {
    const value = parse(source);
    assert.deepEqual(value.client_sinks, [], source);
    assert.ok(value.limitations.some(row => row.code === 'client_navigation_target_requires_review'), source);
  }
});

test('href writes and unrelated properties do not erase genuine navigation sites', () => {
  const value = parse([
    'const loc = window.location; const root = window;',
    'root.unrelated = fixture;',
    'loc.href = input.first;',
    'root.location.href = input.second;',
    'location.assign(input.third);',
    'document.location.replace(input.fourth);',
  ].join('\n'));
  assert.deepEqual(value.client_sinks.map(row => row.sink), ['location.href', 'location.href', 'location.assign', 'location.replace']);
  assert.deepEqual(value.client_sinks.map(row => row.referenced_fields), [['first'], ['second'], ['third'], ['fourth']]);
});

test('many unrelated navigation properties retain the bounded sink ledger', () => {
  const writes = Array.from({length: 3000}, (_, index) => `location.unrelated${index} = fixture;`);
  const sinks = Array.from({length: 2001}, () => 'window.location.href = input.redirect;');
  const value = parse([...writes, ...sinks].join('\n'));
  assert.equal(value.client_sinks.length, 2000);
  assert.ok(value.limitations.some(row => row.code === 'client_sink_rows_truncated'));
  assert.ok(value.client_sinks.every(row => row.sink === 'location.href'));
});

test('const aliases of browser globals retain exact syntactic field provenance', () => {
  const value = parse([
    "axios.post('/audit', {description: form.description});",
    'const first = globalThis; const second = first; const loc = second.location;',
    'loc.replace(route.query.redirect);',
    'target.innerHTML = data.description;',
  ].join('\n'));
  assert.deepEqual(value.operations.map(row => row.url), ['/audit']);
  assert.deepEqual(value.client_sinks.map(row => row.referenced_fields), [['redirect'], ['description']]);
  assert.deepEqual(value.client_sinks.map(row => [row.source_line, row.source_column]), [[3, 1], [4, 1]]);
});

test('scope analysis never executes source or exports literal request and sink values', () => {
  const value = parse([
    'process.exit(91);',
    "throw new Error('SYNTHETIC_PRIVATE_SOURCE');",
    "fetch('/syntactic-only', {body: 'SYNTHETIC_PRIVATE_BODY'});",
    "target.innerHTML = 'SYNTHETIC_PRIVATE_HTML';",
  ].join('\n'));
  assert.deepEqual(value.operations.map(row => row.url), ['/syntactic-only']);
  assert.equal(value.client_sinks[0].value_kind, 'static');
  assert.doesNotMatch(JSON.stringify(value), /SYNTHETIC_PRIVATE/);
});
