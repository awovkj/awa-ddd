import test from 'node:test';
import assert from 'node:assert/strict';
import { penetrationProjection, apply, inject, name } from '../src/mode.mjs';

/**
 * Minimal Cordis-like context. `inject(deps, callback)` only runs the callback
 * when every named service is available — the same "skip, don't throw" contract
 * the real container uses, which is what makes the mode degrade cleanly.
 */
function harness({ provide = ['sessionProjections', 'systemPrompt', 'commands'] } = {}) {
  const log = { sections: [], projections: [], commands: [], injected: [] };
  const state = new Map();
  const services = {
    sessionProjections: {
      register(definition) { log.projections.push(definition); },
      // 用投影自身的 apply 重放事件，模拟宿主的事件日志语义。
      stateOf(session, key) {
        if (key !== penetrationProjection.key) return undefined;
        return state.get(session) ?? penetrationProjection.init();
      },
      applyEvent(event, session = 's1') {
        const current = state.get(session) ?? penetrationProjection.init();
        state.set(session, penetrationProjection.apply(current, event));
      },
    },
    systemPrompt: { section(definition) { log.sections.push(definition); } },
    commands: { register(definition) { log.commands.push(definition); } },
  };
  const ctx = {
    inject(deps, callback) {
      log.injected.push([...deps]);
      if (!deps.every(name => provide.includes(name))) return;
      const scope = {};
      for (const name of deps) scope[name] = services[name];
      callback(scope);
    },
  };
  apply(ctx);
  return { log, ctx: services, state };
}

const commandRun = args => ({ type: 'command/run', data: { name: 'penetration', args } });

test('mode module exports a named plugin identity and its required services', () => {
  assert.equal(name, 'awa-ddd-penetration-mode');
  assert.deepEqual([...inject].sort(), ['commands', 'sessionProjections', 'systemPrompt']);
});

test('registers exactly one projection, one prompt section and one command', () => {
  const { log } = harness();
  assert.equal(log.projections.length, 1);
  assert.equal(log.projections[0].key, 'penetration');
  assert.equal(log.sections.length, 1);
  assert.equal(log.sections[0].name, 'awa-ddd:penetration-policy');
  assert.equal(log.commands.length, 1);
  assert.equal(log.commands[0].name, 'penetration');
});

test('services are obtained through ctx.inject, never read off ctx directly', () => {
  // 回归：Cordis 对未 inject 的服务访问会抛
  // "cannot get property X without inject"，即使服务存在。
  const { log } = harness();
  assert.equal(log.injected.length, 1);
  assert.deepEqual([...log.injected[0]].sort(), ['commands', 'sessionProjections', 'systemPrompt']);
});

test('a host missing any mode service skips the mode instead of throwing', () => {
  for (const missing of ['sessionProjections', 'systemPrompt', 'commands']) {
    const provide = ['sessionProjections', 'systemPrompt', 'commands'].filter(name => name !== missing);
    const { log } = harness({ provide });
    assert.equal(log.injected.length, 1, 'the dependency is still declared');
    assert.equal(log.projections.length, 0, `no projection when ${missing} is absent`);
    assert.equal(log.sections.length, 0, `no prompt section when ${missing} is absent`);
    assert.equal(log.commands.length, 0, `no command when ${missing} is absent`);
  }
});

test('the projection is replayable from the event log alone', () => {
  const { ctx, log } = harness();
  const projection = log.projections[0];
  let state = projection.init();
  assert.equal(state.active, false, 'default is off');
  state = projection.apply(state, commandRun(''));
  assert.equal(state.active, true, 'bare command enters the mode');
  state = projection.apply(state, commandRun(' off '));
  assert.equal(state.active, false, 'off exits even with surrounding whitespace');
  // 无关事件不得改变状态。
  state = projection.apply(state, { type: 'message' });
  assert.equal(state.active, false);
  state = projection.apply(state, { type: 'command/run', data: { name: 'plan', args: '' } });
  assert.equal(state.active, false, 'other commands must not touch this projection');
  // 没有 args 的运行记录（例如回放边界）保持原状而不是翻转。
  state = projection.apply({ active: true }, { type: 'command/run', data: { name: 'penetration' } });
  assert.equal(state.active, true);
});

test('prompt section text is empty until the mode is on for that session', () => {
  const { log, ctx } = harness();
  const section = log.sections[0];
  assert.equal(section.text({ agent: { session: 's1' } }), '', 'off by default');
  assert.equal(section.text({ agent: undefined }), '', 'no agent means no section');
  ctx.sessionProjections.applyEvent(commandRun(''), 's1');
  assert.match(section.text({ agent: { session: 's1' } }), /Penetration mode/);
  // 另一个会话不受影响：状态按会话隔离。
  assert.equal(section.text({ agent: { session: 's2' } }), '');
});

test('active policy requires persisted progress and guarded finalization without claiming a host stop hook', () => {
  const { log, ctx } = harness();
  ctx.sessionProjections.applyEvent(commandRun(''), 's1');
  const text = log.sections[0].text({ agent: { session: 's1' } });
  assert.match(text, /plan\.checkpoint/);
  assert.match(text, /continue_required:true/);
  assert.match(text, /no_progress_rounds/);
  assert.match(text, /plan\.review/);
  assert.match(text, /plan\.finalize/);
  assert.match(text, /只允许 reason:completed/);
  assert.match(text, /budget_exhausted\/user_stop\/authorization_boundary\/blocked 都不能/);
  assert.match(text, /禁止以任何理由自动终止/);
  assert.match(text, /零 ready\/review\/blocked\/unresolved/);
  assert.match(text, /旧 partial 停止记录仅留历史/);
  assert.match(text, /渗透模式关闭也不放宽引擎硬门禁/);
  assert.match(text, /stage:draft/);
  assert.match(text, /finalization_id/);
  assert.match(text, /completed 必须满足 can_finalize、completion\.status:complete/);
  assert.match(text, /can_claim_complete 只授权成功收尾后的完成声明，不是调用前提/);
  assert.match(text, /agent\/turn-stopping 串行钩子/);
  assert.match(text, /不能撤回已输出文字/);
  assert.match(text, /实际消费页并完成成功业务交互/);
  assert.match(text, /全部 12 族/);
  assert.match(text, /tool\.probe adapter:tscanplus/);
  assert.match(text, /tool\.tscanplus_request/);
  assert.match(text, /tool\.tscanplus_results/);
  assert.match(text, /tool\.tscanplus_summary/);
  assert.match(text, /tool\.tscanplus_routes/);
  assert.match(text, /不回显 prompt\/hint/);
  assert.match(text, /limit 是本地预算/);
  assert.match(text, /不得用默认 MCP 桶/);
  assert.match(text, /route 自动执行/);
});

test('active policy mandates beneficial Playwright use with stage, provider and proof boundaries', () => {
  const { log, ctx } = harness();
  ctx.sessionProjections.applyEvent(commandRun(''), 's1');
  const text = log.sections[0].text({ agent: { session: 's1' } });
  assert.match(text, /required 或 assisted/);
  assert.match(text, /must_call_playwright:true/);
  assert.match(text, /assisted 表示有明显收益时也必须使用/);
  assert.match(text, /call_needed/);
  assert.match(text, /invoke_now/);
  assert.match(text, /review_existing 离线复核已有合格材料/);
  assert.match(text, /只有 native 回退路线先 browser\.probe/);
  assert.match(text, /本地不可用不能否定宿主 MCP/);
  for (const mechanism of ['CSRF/CORS', 'SameSite/HttpOnly/Secure', 'postMessage', 'OAuth/OIDC', '上传预览消费']) {
    assert.ok(text.includes(mechanism), mechanism);
  }
  assert.match(text, /宿主 tabs 不是隔离 context/);
  assert.match(text, /unsafe run_code 不是默认安全入口/);
  assert.match(text, /MCP 导入不绑定 session\/actor/);
  assert.match(text, /不能替代 authenticated XSS typed closure/);
  assert.match(text, /上传\/evaluate\/tab 输出不得伪装 click/);
  assert.match(text, /人工 evaluate\(alert\) 不算证明/);
  assert.match(text, /用户要求不测试或仅源码\/报告维护时不启动目标测试/);
});

test('the command handler validates input and does not mutate state itself', () => {
  const { log, ctx } = harness();
  const handler = log.commands[0].handler;
  const agent = { session: 's1' };
  assert.equal(handler({ agent, rawInput: '' }).kind, 'success');
  const rejected = handler({ agent, rawInput: 'yes' });
  assert.equal(rejected.kind, 'error');
  assert.match(rejected.text, /Usage: \/penetration/);
  // 状态只能由事件投影推进：handler 自身不写。
  assert.equal(ctx.sessionProjections.stateOf('s1', 'penetration').active, false);
  ctx.sessionProjections.applyEvent(commandRun(''), 's1');
  assert.equal(ctx.sessionProjections.stateOf('s1', 'penetration').active, true);
});

test('rejected arguments and status queries never change a replayed mode state', () => {
  for (const active of [true, false]) {
    for (const args of ['yes', 'OFF', 'status', {}, ['off'], null, 1, undefined]) {
      const state = { active };
      assert.equal(penetrationProjection.apply(state, commandRun(args)), state);
    }
  }
});

test('the read-only status command reports the actual session projection', () => {
  const { log, ctx } = harness();
  const handler = log.commands[0].handler;
  assert.deepEqual(handler({ agent: { session: 's1' }, rawInput: 'status' }),
    { kind: 'success', text: 'Penetration mode off.' });
  ctx.sessionProjections.applyEvent(commandRun(''), 's1');
  assert.deepEqual(handler({ agent: { session: 's1' }, rawInput: 'status' }),
    { kind: 'success', text: 'Penetration mode on.' });
  assert.deepEqual(handler({ agent: { session: 's2' }, rawInput: 'status' }),
    { kind: 'success', text: 'Penetration mode off.' });
  ctx.sessionProjections.applyEvent(commandRun('status'), 's1');
  assert.equal(ctx.sessionProjections.stateOf('s1', 'penetration').active, true);
});

test('a late optional-service registration failure remains isolated and redacted', () => {
  let callback;
  apply({ inject(_dependencies, ready) { callback = ready; } });
  const errors = [];
  const original = console.error;
  console.error = message => { errors.push(message); };
  try {
    assert.doesNotThrow(() => callback({ sessionProjections: {
      register() { throw new Error('auth_token=private-registration; service unavailable'); },
    } }));
  } finally { console.error = original; }
  assert.equal(errors.length, 1);
  assert.match(errors[0], /optional registration unavailable/);
  assert.doesNotMatch(errors[0], /private-registration/);
});
