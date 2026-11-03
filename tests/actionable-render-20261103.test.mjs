import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { invokeEngine } from '../src/bridge.mjs';
import { MAX_RENDER_BYTES, renderToolResult } from '../src/tools.mjs';

const sorted = value => {
  if (Array.isArray(value)) return value.map(sorted);
  if (value === null || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b))
    .map(([key, child]) => [key, sorted(child)]));
};

function render(args, data) {
  const value = { ok: true, data: sorted(data) };
  const original = JSON.stringify(value);
  const [{ text }] = renderToolResult(args, value);
  assert.ok(Buffer.byteLength(text, 'utf8') <= MAX_RENDER_BYTES);
  assert.equal(JSON.stringify(value), original, 'rendering does not change the canonical record');
  return JSON.parse(text);
}

function work(id) {
  return {
    ...Object.fromEntries(Array.from({ length: 42 }, (_, i) => [`description_${i}`, 'explanation '.repeat(300)])),
    id, gap_id: id, obligation_id: id, obligation_kind: 'input_test', operation_id: 'O-fixture',
    input_location: 'query', input_selector: 'keyword', schema_branch: 'search', hypothesis_family: 'sql_injection',
    queue_status: 'review', suggested_action: 'assessment.prepare', execution_blocked: true,
    input_template: { obligation_id: id, evidence_ids: ['E-normal', 'E-variant', 'E-control'] },
    missing_prerequisites: ['accepted_sql_metadata_channel'],
    required_experiment_fields: ['Read the existing controls offline before selecting an accepted oracle.'],
    control_candidate_review_required: true,
    control_candidate_evidence_ids: ['E-normal', 'E-variant', 'E-control'],
    control_review_blockers: ['roles_unverified', 'actor_independence', 'declared_access_policy'],
    scenario_run_ids: ['SC-one', 'SC-two', 'SC-three'],
    browser_testing: { requirement: 'not_needed', must_call_playwright: false, stage: 'backend_controls',
      call_needed: false, invoke_now: false, execution_blocked: true, native_supported: false,
      required_input_fields: ['accepted_sql_metadata_channel'],
      notes: Array.from({ length: 40 }, () => 'browser explanation '.repeat(60)) },
  };
}

test('alphabetically sorted real queue shapes preserve actions, exact bindings and prerequisite gates', () => {
  const source = [work('OB-first'), work('OB-second')];
  const output = render({ action: 'plan.next', input: { offset: 7, limit: 2 } }, {
    blocked_sample: source,
    continuation: { continue_required: true, can_finalize: false, can_claim_complete: false, automatic_stop_allowed: false },
    completion: { status: 'partial', registered_scope_only: true, open_obligations: 386,
      open_security_obligations: 290, unassessed_observations: 38, unlinked_analyst_findings: 11,
      orphan_browser_visits: 5, unresolved_candidates: 0, pages_unvisited: 0, functions_untriggered: 0,
      unreconciled_runs: 0, unrecorded_confirmations: 0, failed_partial_tools: 0,
      limited_ownership_sampling: 0, applicability_review_total: 0, scope_reduction_review_total: 0 },
    offset: 7, limit: 2, next_offset: 9, work_items: source,
    parameter_coverage: { items: Array.from({ length: 10 }, (_, i) => ({ id: `PC-${i}`, input_selector: `field-${i}`,
      note: 'unassessed input '.repeat(300) })), offset: 20, limit: 10, next_offset: 30, filter: 'untested' },
  });
  assert.equal(output.render_truncated, true);
  assert.equal(output.data.work_items.length, 2, 'essential queue is retained before blocked examples and descriptions');
  for (let index = 0; index < 2; index++) {
    const row = output.data.work_items[index];
    for (const key of ['obligation_id', 'operation_id', 'input_location', 'input_selector', 'schema_branch',
      'hypothesis_family', 'queue_status', 'suggested_action', 'execution_blocked', 'control_candidate_review_required']) {
      assert.equal(row[key], source[index][key], key);
    }
    for (const key of ['input_template', 'required_experiment_fields', 'missing_prerequisites', 'control_candidate_evidence_ids',
      'control_review_blockers', 'scenario_run_ids']) {
      assert.deepEqual(row[key], sorted(source[index][key]), key);
    }
    for (const key of ['must_call_playwright', 'invoke_now', 'execution_blocked', 'native_supported', 'required_input_fields']) {
      assert.deepEqual(row.browser_testing[key], source[index].browser_testing[key], key);
    }
  }
  assert.equal(output.data.completion.open_obligations, 386);
  assert.equal(output.data.completion.scope_reduction_review_total, 0);
  assert.equal(output.data.continuation.automatic_stop_allowed, false);
  assert.equal(output.data.next_offset, 9);
  const page = output.render_recovery.pages.find(item => item.fields.includes('work_items'));
  assert.equal(page.input.offset, 7);
  assert.equal(page.input.limit, 1);
  assert.equal(page.input.parameter_offset, 20);
  assert.equal(page.input.parameter_limit, 1, 'main-page retry cannot request a default large parameter page');
});

test('combined recovery restores all independent current pages without echoing unsafe filters', () => {
  const output = render({ action: 'plan.next', input: { offset: 7, limit: 2,
    parameter_offset: 20, parameter_limit: 10, parameter_status: 'PRIVATE_FILTER', operation_id: 'token=PRIVATE_OP' } }, {
    work_items: [work('OB-one'), work('OB-two')], offset: 7, limit: 2, next_offset: 9,
    parameter_coverage: { items: Array.from({ length: 10 }, () => ({ note: 'value '.repeat(5000) })),
      offset: 20, limit: 10, next_offset: 30, filter: 'untested' },
  });
  assert.equal(output.render_recovery.combined_input.offset, 7);
  assert.equal(output.render_recovery.combined_input.parameter_offset, 20);
  assert.equal(output.render_recovery.combined_input.limit, 1);
  assert.equal(output.render_recovery.combined_input.parameter_limit, 1);
  assert.equal(output.render_recovery.combined_input.parameter_status, undefined);
  assert.deepEqual(output.render_recovery.combined_required_original_filters.sort(), ['operation_id', 'parameter_status']);
  assert.doesNotMatch(JSON.stringify(output.render_recovery), /PRIVATE_/);
});

test('all twelve category identities and current counts survive an oversized audit projection', () => {
  const families = ['access_control', 'sql_injection', 'xss', 'ssrf', 'xxe', 'path_traversal',
    'command_injection', 'template_injection', 'deserialization', 'file_upload', 'business_logic', 'generic'];
  const category_matrix = families.map((test_family, index) => ({ test_family, status: 'open', total: index + 1,
    evaluated: 0, open: index + 1, blocked: 0, not_applicable: 0, detail: 'context '.repeat(2000) }));
  const output = render({ action: 'plan.audit', input: { offset: 0, limit: 2 } }, {
    category_matrix, checklist: [work('CL-one'), work('CL-two')], offset: 0, limit: 2, next_offset: 2,
  });
  assert.deepEqual(output.data.category_matrix.map(row => row.test_family), families);
  assert.deepEqual(output.data.category_matrix.map(row => row.open), families.map((_, index) => index + 1));
  assert.equal(output.data.checklist[0].suggested_action, 'assessment.prepare');
});

test('an oversized executable binding is marked unusable and does not generate another limit-one retry', () => {
  const row = work('OB-large');
  row.input_template = { operation_id: 'O-fixture', consumer_url: 'http://fixture.invalid/' + 'segment'.repeat(3000) };
  const output = render({ action: 'plan.next', input: { offset: 4, limit: 1 } }, {
    work_items: [row], offset: 4, limit: 1, next_offset: 5,
  });
  assert.equal(output.data.work_items[0].render_actionable, false);
  const page = output.render_recovery.pages.find(item => item.fields.includes('work_items'));
  assert.equal(page.retry_same_page, false);
  assert.equal(page.input, undefined);
  assert.equal(output.render_recovery.combined_input, undefined);
});

test('offline preparation recovery retains its exact source and never silently replaces an evidence filter', () => {
  const row = work('OB-prepare');
  row.controls_are_candidates_only = true;
  row.evidence_review_required = true;
  row.positive_machine_adapter = false;
  const output = render({ action: 'assessment.prepare', input: { finding_id: 'F-source',
    evidence_ids: ['E-filtered'], offset: 3, limit: 2 } }, {
    source: { finding_id: 'F-source' }, items: [row, row], offset: 3, limit: 2, next_offset: 5,
    requests_sent: 0, decisions_created: 0, automatic_execution_allowed: false,
  });
  assert.deepEqual(output.data.source, { finding_id: 'F-source' });
  assert.equal(output.data.items[0].suggested_action, 'assessment.prepare');
  assert.equal(output.data.items[0].controls_are_candidates_only, true);
  assert.equal(output.data.items[0].positive_machine_adapter, false);
  assert.equal(output.data.automatic_execution_allowed, false);
  const recovery = output.render_recovery.pages.find(page => page.fields.includes('items'));
  assert.equal(recovery.input.finding_id, 'F-source');
  assert.equal(recovery.input.offset, 3);
  assert.equal(recovery.input.limit, 1);
  assert.deepEqual(recovery.required_original_filters, ['evidence_ids']);
  assert.equal(recovery.input.evidence_ids, undefined);
});

test('semantic key prioritization alone does not create a false current-page recovery loop', () => {
  const output = render({ action: 'plan.next', input: { offset: 4, limit: 2 } }, {
    ...Object.fromEntries(Array.from({ length: 45 }, (_, i) => [`description_${i}`, 'context '.repeat(500)])),
    work_items: [{ operation_id: 'O-fixture', obligation_id: 'OB-exact', input_selector: 'keyword',
      queue_status: 'ready', suggested_action: 'http.preflight', input_template: { operation_id: 'O-fixture' },
      browser_testing: { must_call_playwright: false, call_needed: false, invoke_now: false,
        stage: 'backend_controls', requirement: 'not_needed' } }],
    offset: 4, limit: 2, next_offset: null,
  });
  assert.equal(output.render_truncated, true);
  assert.equal(output.data.work_items[0].suggested_action, 'http.preflight');
  assert.equal(output.data.work_items[0].render_actionable, undefined);
  assert.equal(output.render_recovery, undefined, 'only explanations were omitted; complete queue keys were reordered');
});

test('large sorted security-property hints keep declared provenance, exact inputs and false proof authority', () => {
  const hypothesis = id => ({
    ...Object.fromEntries(Array.from({ length: 42 }, (_, i) => [`description_${i}`, 'context '.repeat(500)])),
    id, operation_id: 'O-declared', security_property: 'numeric_business_bounds',
    input_location: 'body', input_selector: '/amount', schema_branch: 'refund', label_zh: 'Business bounds',
    source: { kind: 'registered_operation', operation_id: 'O-declared', operation_signature: 'a'.repeat(64), context_trust: 'declared' },
    suggested_test_families: ['access_control', 'business_logic', 'generic'],
    observed_evidence_ids: ['E-one', 'E-two', 'E-three'], observations_are_property_proof: false,
    missing_context: ['normal_business_assertion', 'property_specific_controls', 'owned_test_fixture', 'state_readback'],
    controls_zh: ['Inspect the actual business limits and matching owned fixture.'],
    inference_basis: ['input_name'], hint_only: true, requestable: false, usable_for_confirmation: false,
    next_action: 'assessment.prepare', input_template: { obligation_id: 'OB-exact' }, help_input: { name: 'assessment.prepare' },
  });
  const entry = { action: 'surface.recon', input: { mode: 'aggregate', section: 'hypotheses', limit: 10 } };
  const output = render({ action: 'surface.recon', input: { mode: 'aggregate', section: 'hypotheses', offset: 7, limit: 2,
    headers: { Authorization: 'PRIVATE_ORIGINAL_HEADER' } } }, {
    items: [hypothesis('HYP-one'), hypothesis('HYP-two')], offset: 7, limit: 2, next_offset: 9,
    mode: 'aggregate', section: 'hypotheses', summary: { hypothesis_total: 29, hypothesis_limited: true },
    hypothesis_entry: entry, requests_sent: 0, automatic_execution_allowed: false,
    profile_is_security_evidence: false, completion_claim_allowed: false, unknown_surface_exhausted: false,
  });
  assert.equal(output.render_truncated, true);
  assert.equal(output.data.items.length, 2);
  for (const row of output.data.items) {
    assert.equal(row.source.kind, 'registered_operation');
    assert.equal(row.source.context_trust, 'declared');
    assert.equal(row.source.operation_signature, 'a'.repeat(64));
    assert.equal(row.hint_only, true);
    for (const flag of ['requestable', 'usable_for_confirmation', 'observations_are_property_proof']) assert.equal(row[flag], false);
    assert.equal(row.next_action, 'assessment.prepare');
    assert.equal(row.operation_id, 'O-declared');
    assert.equal(row.input_location, 'body');
    assert.equal(row.input_selector, '/amount');
    assert.equal(row.schema_branch, 'refund');
    assert.deepEqual(row.input_template, { obligation_id: 'OB-exact' });
    assert.deepEqual(row.missing_context, hypothesis('HYP-one').missing_context);
    assert.deepEqual(row.observed_evidence_ids, ['E-one', 'E-two', 'E-three']);
    assert.deepEqual(row.suggested_test_families, ['access_control', 'business_logic', 'generic']);
  }
  assert.deepEqual(output.data.hypothesis_entry, sorted(entry));
  assert.equal(output.data.summary.hypothesis_total, 29);
  assert.equal(output.data.automatic_execution_allowed, false);
  assert.equal(output.data.profile_is_security_evidence, false);
  assert.equal(output.data.completion_claim_allowed, false);
  assert.equal(output.data.unknown_surface_exhausted, false);
  const page = output.render_recovery.pages.find(item => item.fields.includes('items'));
  assert.deepEqual(page.input, { mode: 'aggregate', section: 'hypotheses', offset: 7, limit: 1 });
  assert.equal(page.canonical_next_offset, 9);
  assert.doesNotMatch(JSON.stringify(output.render_recovery), /PRIVATE_ORIGINAL_HEADER|Authorization/);
});

test('the actual Python queue returns bounded independent parameters and complete executable gates', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'awa-actionable-page-'));
  try {
    const config = { workspace };
    await invokeEngine(config, 'project.create', { project_id: 'paging', target: 'http://fixture.invalid' });
    await invokeEngine(config, 'surface.batch', { project_id: 'paging', operations: Array.from({ length: 4 }, (_, i) => ({
      url: `http://fixture.invalid/items-${i}`, method: 'GET', auth: 'public',
      inputs: ['keyword', 'page', 'sort'].map(name => ({ name, location: 'query', consumer: 'business_input',
        test_families: ['generic', 'business_logic'] })),
    })) });
    const value = await invokeEngine(config, 'plan.next', { project_id: 'paging', limit: 2 });
    assert.equal(value.data.requests_sent, 0, 'queue preparation is offline');
    assert.equal(value.data.parameter_coverage.limit, 2);
    const original = JSON.stringify(value);
    const [{ text }] = renderToolResult({ action: 'plan.next', input: { limit: 2 } }, value);
    const output = JSON.parse(text);
    assert.ok(Buffer.byteLength(text, 'utf8') <= MAX_RENDER_BYTES);
    for (let i = 0; i < value.data.work_items.length; i++) {
      const expected = value.data.work_items[i];
      const actual = output.data.work_items[i];
      for (const key of ['obligation_id', 'operation_id', 'suggested_action', 'queue_status', 'input_template',
        'required_experiment_fields', 'missing_prerequisites', 'execution_blocked']) {
        assert.deepEqual(actual[key], sorted(expected[key]), key);
      }
    }
    assert.equal(JSON.stringify(value), original);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});
