import assert from 'node:assert/strict';
import test from 'node:test';
import { MAX_RENDER_BYTES, renderToolResult } from '../src/tools.mjs';

const render = (args, data) => {
  const value = { ok: true, data };
  const original = JSON.stringify(value);
  const [{ text }] = renderToolResult(args, value);
  assert.ok(Buffer.byteLength(text, 'utf8') <= MAX_RENDER_BYTES);
  assert.equal(JSON.stringify(value), original, 'the canonical result is immutable');
  return JSON.parse(text);
};

test('two rows with omitted inner fields recover at the current offset with a strictly smaller page', () => {
  const row = { obligation_id: 'OB-fixture',
    ...Object.fromEntries(Array.from({ length: 42 }, (_, index) => [`detail_${index}`, 'x'.repeat(500)])),
    required_input: { operation_id: 'O-fixture', selector: 'actual-field' } };
  const result = render({ action: 'plan.next', input: { offset: 10, limit: 2, include_blocked: false } },
    { offset: 10, limit: 2, next_offset: 12, work_items: [row, row],
      continuation: { continue_required: true, can_finalize: false, automatic_stop_allowed: false } });
  assert.equal(result.render_truncated, true);
  assert.equal(result.data.work_items.length, 2, 'retaining row count is not retaining full records');
  assert.equal(result.data.work_items[0].required_input, undefined);
  const recovery = result.render_recovery.pages.find(page => page.fields.includes('work_items'));
  assert.deepEqual(recovery.input, { include_blocked: false, offset: 10, limit: 1 });
  assert.equal(recovery.canonical_next_offset, 12);
  assert.equal(result.data.next_offset, 12);
  assert.equal(result.data.continuation.automatic_stop_allowed, false);
});

test('string and nested-array truncation need recovery even without a top-level row omission marker', () => {
  for (const row of [{ note: 'x'.repeat(30000) },
    { browser_testing: { observation_requirements: Array.from({ length: 30 }, () => 'x'.repeat(1000)) } }]) {
    const result = render({ action: 'plan.next', input: { offset: 4, limit: 3 } },
      { offset: 4, limit: 3, next_offset: 7, work_items: [row, row, row] });
    assert.equal(result.render_truncated, true);
    assert.ok(result.data.work_items.every(item => !Object.hasOwn(item, 'render_omitted_items')));
    const recovery = result.render_recovery.pages.find(page => page.fields.includes('work_items'));
    assert.equal(recovery.input.offset, 4);
    assert.ok(recovery.input.limit < 3);
    assert.equal(recovery.canonical_next_offset, 7);
  }
});

test('an oversized single row requires offline detail inspection, never an identical limit-one retry', () => {
  const result = render({ action: 'plan.audit', input: { offset: 9, limit: 1, operation_id: 'O-fixture' } },
    { offset: 9, limit: 1, next_offset: 10, checklist: [{ id: 'CL-fixture', note: 'x'.repeat(50000) }] });
  const recovery = result.render_recovery.pages.find(page => page.fields.includes('checklist'));
  assert.equal(result.render_recovery.before_next_offset, true);
  assert.equal(recovery.projection_limit, 'single_record');
  assert.equal(recovery.retry_same_page, false);
  assert.equal(recovery.current_offset, 9);
  assert.equal(recovery.input, undefined);
  assert.deepEqual(recovery.detail_action, { action: 'action.help', input: { name: 'plan.audit' } });
  assert.equal(recovery.canonical_next_offset, 10);
  assert.match(result.render_recovery.note, /not an identical retry/);
});

test('single parameter and method records retain independent detail-only cursor recovery', () => {
  const parameter = render({ action: 'plan.next', input: { parameter_offset: 30, parameter_limit: 1 } },
    { work_items: [], parameter_coverage: { items: [{ selector: 'field', note: 'x'.repeat(50000) }],
      offset: 30, limit: 1, next_offset: 31, filter: 'untested' } });
  const parameterRecovery = parameter.render_recovery.pages.find(page => page.cursor_field === 'parameter_offset');
  assert.equal(parameterRecovery.retry_same_page, false);
  assert.equal(parameterRecovery.current_offset, 30);
  assert.equal(parameterRecovery.input, undefined);
  assert.equal(parameterRecovery.canonical_next_offset, 31);

  const method = render({ action: 'project.status', input: { method_offset: 20, method_limit: 1 } },
    { method_coverage: [{ operation_id: 'O-fixture', note: 'x'.repeat(50000) }],
      method_offset: 20, method_limit: 1, method_next_offset: 21 });
  const methodRecovery = method.render_recovery.pages.find(page => page.fields.includes('method_coverage'));
  assert.equal(methodRecovery.retry_same_page, false);
  assert.equal(methodRecovery.current_offset, 20);
  assert.equal(methodRecovery.input, undefined);
  assert.equal(methodRecovery.canonical_next_offset, 21);
});

test('recon section recovery preserves hypotheses/functions, mode and information cursor', () => {
  for (const mode of ['prepare', 'aggregate']) {
    for (const section of ['functions', 'hypotheses']) {
      const result = render({ action: 'surface.recon', input: { mode, section, offset: 10, limit: 25 } },
        { mode, section, offset: 10, limit: 25, next_offset: 35,
          requests_sent: 0, items: Array.from({ length: 25 }, (_, index) => ({ id: `entry-${index}`, note: 'x'.repeat(5000) })) });
      const recovery = result.render_recovery.pages.find(page => page.fields.includes('items'));
      assert.equal(recovery.input.mode, mode);
      assert.equal(recovery.input.section, section);
      assert.equal(recovery.input.offset, 10);
      assert.ok(recovery.input.limit < 25);
      assert.equal(recovery.canonical_next_offset, 35);
      assert.equal(result.data.requests_sent, 0);
    }
  }
});
