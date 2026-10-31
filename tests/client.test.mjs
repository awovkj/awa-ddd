import test, { afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const live = new Set();
const ready = () => new Promise(resolve => setImmediate(resolve));
/** The DSH command RPC envelope: { ok, value: { commandId, result } }. */
const commandReply = result => ({ ok: true, value: { commandId: 'cmd-test', result } });
afterEach(() => { for (const harness of live) harness.dispose(); live.clear(); });

function harness(options = {}) {
  const nodes = new Map();
  const effects = [];
  const observers = [];
  const windowEvents = new Map();
  const documentEvents = new Map();
  const server = options.server ?? new Map();
  const calls = [];
  let session = 'session' in options ? options.session : 's-1';
  const registerEvent = (events, type, fn) => {
    if (!events.has(type)) events.set(type, new Set());
    events.get(type).add(fn);
  };
  const removeEvent = (events, type, fn) => events.get(type)?.delete(fn);
  const append = node => { if (node.id) nodes.set(node.id, node); return node; };
  const document = {
    body: { appendChild: append }, head: { appendChild: append },
    documentElement: { dataset: {} }, readyState: options.loading ? 'loading' : 'complete',
    getElementById: id => nodes.get(id) ?? null,
    querySelector: selector => selector === '[data-conversation-session]' && session
      ? { getAttribute: name => name === 'data-conversation-session' ? session : null } : null,
    addEventListener: (type, fn) => registerEvent(documentEvents, type, fn),
    removeEventListener: (type, fn) => removeEvent(documentEvents, type, fn),
    createElement(tag) {
      const attributes = new Map();
      const listeners = new Map();
      return {
        tagName: tag, id: '', textContent: '', title: '', className: '', dataset: {}, disabled: false,
        style: { cssText: '' },
        setAttribute: (name, value) => attributes.set(name, value),
        getAttribute: name => attributes.get(name),
        addEventListener: (type, fn) => listeners.set(type, fn),
        removeEventListener: (type, fn) => { if (listeners.get(type) === fn) listeners.delete(type); },
        remove() { if (nodes.get(this.id) === this) nodes.delete(this.id); },
        async click() { if (!this.disabled) await listeners.get('click')?.(); },
      };
    },
  };
  let definition;
  const window = {
    location: options.location ?? { pathname: '/', search: '' },
    __ModuleLoader__: { load: value => { definition = value; } },
    addEventListener: (type, fn) => registerEvent(windowEvents, type, fn),
    removeEventListener: (type, fn) => removeEvent(windowEvents, type, fn),
    MutationObserver: class {
      constructor(callback) { this.callback = callback; this.disconnected = false; observers.push(this); }
      observe() {}
      disconnect() { this.disconnected = true; }
    },
  };
  const source = readFileSync(join(ROOT, 'src', 'client.js'), 'utf8');
  new Function('window', 'document', 'console', source)(window, document, console);
  assert.ok(definition);
  const module = definition.factory(() => { throw new Error('The DOM client requires no React/slot modules.'); });
  const defaultExecute = async ({ sessionId, line }) => {
    if (line === '/penetration status') return commandReply({ kind: 'success',
      text: server.get(sessionId) ? 'Penetration mode on.' : 'Penetration mode off.' });
    if (line === '/penetration') server.set(sessionId, true);
    else if (line === '/penetration off') server.set(sessionId, false);
    else return commandReply({ kind: 'error', text: 'Usage error' });
    return commandReply({ kind: 'success', text: 'Command accepted.' });
  };
  const ctx = {
    effect(factory) { const cleanup = factory(); if (typeof cleanup === 'function') effects.push(cleanup); },
    locale: { register: () => () => {} },
    remote: options.noCommands ? {} : { commands: {
      async execute(sessionId, line, attachments) {
        const call = { sessionId, line, attachments }; calls.push(call);
        return options.execute ? options.execute(call, defaultExecute) : defaultExecute(call);
      },
    } },
    slots: { register() { throw new Error('A slot must never be registered.'); },
      inject() { throw new Error('A slot must never be injected.'); } },
  };
  const result = {
    module, definition, ctx, document, window, nodes, server, calls, observers,
    button: () => document.getElementById('awa-ddd-fallback-btn'),
    mutations: () => calls.filter(call => call.line !== '/penetration status'),
    setSession(value) { session = value; for (const observer of observers) if (!observer.disconnected) observer.callback(); },
    emit(type) { for (const fn of windowEvents.get(type) ?? []) fn(); },
    domReady() { document.readyState = 'complete'; for (const fn of documentEvents.get('DOMContentLoaded') ?? []) fn(); },
    dispose() { while (effects.length) effects.pop()(); },
  };
  live.add(result);
  module.apply(ctx);
  return result;
}

test('client module keeps the package-derived id and only required runtime services', () => {
  const h = harness();
  assert.equal(h.definition.id, 'awa-ddd/client');
  assert.equal(h.module.name, 'awa-ddd-penetration-mode');
  assert.deepEqual([...h.module.inject].sort(), ['locale', 'remote', 'remote.commands']);
  assert.equal(typeof h.module.apply, 'function');
});

test('the optional control mounts without React or any slot registration', async () => {
  const h = harness();
  await ready();
  assert.ok(h.button());
  assert.equal(h.button().textContent, '渗透模式');
  assert.equal(h.button().dataset.active, 'false');
});

test('clicks inspect the actual server projection before and after changing a session', async () => {
  const h = harness({ session: 'session-abc' });
  await ready();
  await h.button().click();
  assert.deepEqual(h.mutations(), [{ sessionId: 'session-abc', line: '/penetration', attachments: [] }]);
  assert.equal(h.button().textContent, '渗透模式 · 已启用');
  assert.equal(h.button().dataset.active, 'true');
  await h.button().click();
  assert.deepEqual(h.mutations()[1], { sessionId: 'session-abc', line: '/penetration off', attachments: [] });
  assert.equal(h.button().dataset.active, 'false');
  assert.ok(h.calls.filter(call => call.line === '/penetration status').length >= 5);
});

test('without a session the button explains instead of sending malformed host calls', async () => {
  const h = harness({ session: null });
  await h.button().click();
  assert.deepEqual(h.calls, []);
  assert.match(h.button().textContent, /请先打开一个会话/);
});

test('a missing command service has visible feedback without affecting host mounting', async () => {
  const h = harness({ noCommands: true });
  await ready();
  await h.button().click();
  assert.match(h.button().textContent, /宿主接口未就绪/);
  assert.notEqual(h.button().dataset.active, 'true');
});

test('host rejection does not falsely flip the displayed state', async () => {
  const h = harness({ execute: async () => ({ ok: false, error: { message: 'unknown command', code: 'E_CMD' } }) });
  await ready();
  await h.button().click();
  assert.match(h.button().textContent, /unknown command/);
  assert.notEqual(h.button().dataset.active, 'true');
});

test('a transport success containing a command error is still a failure', async () => {
  const h = harness({ execute: async (call, fallback) => call.line === '/penetration status'
    ? fallback(call) : commandReply({ kind: 'error', text: 'Command policy denied' }) });
  await ready();
  await h.button().click();
  assert.equal(h.button().dataset.active, 'false');
  assert.match(h.button().textContent, /Command policy denied/);
});

test('unknown or incomplete success shapes never establish mode truth', async () => {
  for (const reply of [undefined, { ok: true }, { ok: true, value: {} },
    commandReply({ kind: 'success', text: 'unverified state' }),
    { ok: true, value: { kind: 'success', text: 'legacy flat shape' } }]) {
    const h = harness({ execute: async () => reply });
    await ready();
    await h.button().click();
    assert.equal(h.button().dataset.active, 'unknown');
    assert.deepEqual(h.mutations(), []);
    assert.match(h.button().textContent, /切换失败/);
    h.dispose();
  }
});

test('reload reads server state instead of assuming that the mode is off', async () => {
  const server = new Map([['s-1', true]]);
  const first = harness({ server });
  await ready();
  assert.equal(first.button().dataset.active, 'true');
  first.dispose();
  const second = harness({ server });
  await ready();
  assert.equal(second.button().dataset.active, 'true');
  await second.button().click();
  assert.equal(second.mutations()[0].line, '/penetration off');
});

test('session changes never share displayed or toggled state', async () => {
  const h = harness({ session: 'a', server: new Map([['a', true], ['b', false]]) });
  await ready();
  assert.equal(h.button().dataset.active, 'true');
  h.setSession('b');
  await ready();
  assert.equal(h.button().dataset.active, 'false');
  await h.button().click();
  assert.equal(h.mutations()[0].sessionId, 'b');
  assert.equal(h.server.get('a'), true);
  h.setSession('a');
  await ready();
  await h.button().click();
  assert.equal(h.server.get('a'), false);
  assert.equal(h.server.get('b'), true);
});

test('clicks observe changes made through the slash command or another client', async () => {
  const h = harness();
  await ready();
  assert.equal(h.button().dataset.active, 'false');
  h.server.set('s-1', true);
  await h.button().click();
  assert.equal(h.mutations()[0].line, '/penetration off');
  assert.equal(h.server.get('s-1'), false);
});

test('rapid clicks are single-flight and the button becomes busy until completion', async () => {
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const h = harness({ execute: async (call, fallback) => {
    if (call.line === '/penetration') await gate;
    return fallback(call);
  } });
  await ready();
  const first = h.button().click();
  await ready();
  assert.equal(h.button().disabled, true);
  assert.equal(h.button().getAttribute('aria-busy'), 'true');
  await h.button().click();
  assert.equal(h.mutations().length, 1);
  release();
  await first;
  assert.equal(h.button().disabled, false);
  assert.equal(h.button().dataset.active, 'true');
});

test('switching sessions during a status query never dispatches to the old session', async () => {
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const h = harness({ session: 'a', execute: async (call, fallback) => {
    if (call.sessionId === 'a' && call.line === '/penetration status') await gate;
    return fallback(call);
  } });
  const pending = h.button().click();
  h.setSession('b');
  await ready();
  release();
  await pending;
  assert.deepEqual(h.mutations(), []);
  assert.equal(h.button().dataset.active, 'false');
});

test('URL session fallback and navigation changes still resolve the actual session', async () => {
  const h = harness({ session: null, location: { pathname: '/session/url-session', search: '' } });
  await ready();
  await h.button().click();
  assert.equal(h.mutations()[0].sessionId, 'url-session');
  h.window.location = { pathname: '/', search: '?session=query-session' };
  h.emit('popstate');
  await ready();
  await h.button().click();
  assert.equal(h.mutations()[1].sessionId, 'query-session');
});

test('disposal removes owned nodes and listeners and repeated disposal is harmless', async () => {
  const h = harness();
  await ready();
  const oldButton = h.button();
  h.dispose();
  h.dispose();
  assert.equal(h.button(), null);
  assert.equal(h.nodes.size, 0);
  assert.ok(h.observers.every(observer => observer.disconnected));
  const calls = h.calls.length;
  h.setSession('another');
  h.emit('popstate');
  await oldButton.click();
  assert.equal(h.calls.length, calls);
  h.module.apply(h.ctx);
  await ready();
  assert.notEqual(h.button(), oldButton);
});

test('disposal while a status read is pending prevents later state-changing commands', async () => {
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const h = harness({ execute: async (call, fallback) => { await gate; return fallback(call); } });
  const pending = h.button().click();
  h.dispose();
  release();
  await pending;
  assert.deepEqual(h.mutations(), []);
  assert.equal(h.button(), null);
});

test('disposing before DOM readiness cannot mount a stale control later', () => {
  const h = harness({ loading: true });
  assert.equal(h.button(), null);
  h.dispose();
  h.domReady();
  assert.equal(h.button(), null);
});

test('repeated application does not mount a duplicate button or extra status readers', async () => {
  const h = harness();
  h.module.apply(h.ctx);
  await ready();
  assert.equal([...h.nodes.values()].filter(node => node.tagName === 'button').length, 1);
  assert.equal(h.calls.length, 1);
  h.dispose();
  assert.equal(h.nodes.size, 0);
});
