import assert from 'node:assert/strict';
import test from 'node:test';
import { MAX_RENDER_BYTES, renderToolResult } from '../src/tools.mjs';

const rendered = (args, data) => JSON.parse(renderToolResult(args, { ok: true, data })[0].text);

test('oversized exact-input pages recover their own current cursor and retain full typed counts', () => {
  const summary = { parameter_total: 80, cell_total: 200, typed_tested_total: 20, untested_total: 180,
    observed_total: 50, variant_observed_total: 30, needs_controls_total: 20, unobserved_total: 100,
    consumer_review_total: 10, observations_limited_total: 0, observation_is_testing: false };
  const metadata = Object.fromEntries(Array.from({ length: 90 }, (_, i) => [`detail${i}`, 'description '.repeat(500)]));
  const data = { ...metadata, work_items: Array.from({ length: 25 }, (_, i) => ({ id: `OB-${i}`, note: 'control '.repeat(300) })),
    offset: 25, limit: 25, next_offset: 50,
    parameter_coverage: { summary, items: Array.from({ length: 25 }, (_, i) => ({
      id: `PC-${i.toString(16).padStart(24, '0')}`, input_selector: `field${i}`, test_family: 'generic',
      status: 'needs_controls', note: 'unassessed '.repeat(300), typed_tested: false })),
      total: 180, offset: 50, limit: 25, next_offset: 75, filter: 'untested' } };
  const args = { action: 'plan.next', input: { offset: 25, limit: 25, include_blocked: false,
    parameter_offset: 50, parameter_limit: 25, parameter_status: 'untested' } };
  const output = rendered(args, data);
  assert.ok(Buffer.byteLength(JSON.stringify(output), 'utf8') <= MAX_RENDER_BYTES);
  assert.equal(output.render_truncated, true);
  assert.deepEqual(output.data.parameter_coverage_summary, summary);
  const recovery = output.render_recovery.pages.find(page => page.cursor_field === 'parameter_offset');
  assert.ok(recovery);
  assert.deepEqual(recovery.fields, ['parameter_coverage.items']);
  assert.equal(recovery.input.parameter_offset, 50);
  assert.equal(recovery.input.parameter_status, 'untested');
  assert.equal(recovery.input.include_blocked, false);
  assert.ok(recovery.input.parameter_limit < 25);
  assert.equal(recovery.canonical_next_offset, 75);
  assert.equal(data.parameter_coverage.items.length, 25);
});

test('parameter summaries never coerce truthy strings, booleans or negative and unsafe counts', () => {
  const output = rendered({ action: 'plan.audit' }, { parameter_coverage: {
    summary: { parameter_total: '10', cell_total: -1, typed_tested_total: true, untested_total: 2,
      observed_total: Number.MAX_SAFE_INTEGER + 1, observation_is_testing: 'false', raw: 'not a counter' },
    items: [], offset: 0, limit: 10, total: 0, next_offset: null, filter: 'any' } });
  assert.deepEqual(output.data.parameter_coverage.summary, { untested_total: 2 });
});

test('unsafe original matrix filters are required without echoing their values or skipping a page', () => {
  const data = { parameter_coverage: { summary: { cell_total: 25, observation_is_testing: false },
    items: Array.from({ length: 25 }, () => ({ note: 'a'.repeat(3000) })),
    offset: 40, next_offset: 65, filter: 'any' } };
  const output = rendered({ action: 'plan.audit', input: { parameter_status: 'PRIVATE_FILTER_VALUE',
    operation_id: 'token=PRIVATE_OPERATION_VALUE' } }, data);
  const page = output.render_recovery.pages.find(row => row.cursor_field === 'parameter_offset');
  assert.equal(page.input.parameter_offset, 40);
  assert.ok(page.required_original_filters.includes('parameter_status'));
  assert.ok(page.required_original_filters.includes('operation_id'));
  assert.equal(page.input.parameter_status, undefined);
  assert.doesNotMatch(JSON.stringify(output.render_recovery), /PRIVATE_/);
});
