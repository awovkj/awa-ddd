/** Offline release smoke: pack, inspect, extract and execute the shipped entry. */
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { copyFile, lstat, mkdir, mkdtemp, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const validation = join(root, '.validation');
const pythonExecutable = process.env.AWA_DDD_PYTHON || (process.platform === 'win32' ? 'python' : 'python3');
const options = { cwd: root, shell: false, windowsHide: true, timeout: 60000, maxBuffer: 8 * 1024 * 1024 };
const recordPath = join(validation, 'package-check.json');
const runningRecordPath = join(validation, 'package-check.running.json');
const lockPath = join(validation, 'package-check.lock');
const archiveRoot = join(validation, 'archives');
const requestedRunId = process.env.AWA_RELEASE_RUN_ID || randomUUID();
const runId = requestedRunId;
const startedAt = new Date().toISOString();
const bundledResources = new Map([
  ['awa_ddd/resources/js_parser/manifest.json', '9cd41e076c3bcf2a4bc61bcfd52130d319b42354232d5d127c98ade42f614686'],
  ['awa_ddd/resources/js_parser/parse-js.mjs', '972badd3720729ad0336ab6d610576d2b748a8f38e7ed9c3a9cea4ba1da28210'],
  ['awa_ddd/resources/js_parser/vendor/acorn/LICENSE', '76a876cf886ff9be2a8b5e2e86514fed06223c8c9f0c1e9ee9606e93841e00b7'],
  ['awa_ddd/resources/js_parser/vendor/acorn/package.json', '04d6fecaafb5e3d20a38fc3b64fed84bb3830a7759a8c00400ebcb87331fec00'],
  ['awa_ddd/resources/js_parser/vendor/acorn/dist/acorn.mjs', '76254fc76529713b4dfd2532972d17a991ffd9aafeebb1f977445b5506b9fb0b'],
]);
const phases = [];
let currentPhase = 'initialize';
let phaseStartedAt = startedAt;

function beginPhase(name) {
  currentPhase = name;
  phaseStartedAt = new Date().toISOString();
}

function finishPhase(summary = null) {
  phases.push({
    name: currentPhase,
    started_at: phaseStartedAt,
    finished_at: new Date().toISOString(),
    result: 'passed',
    ...(summary ? { summary } : {}),
  });
}

function errorRecord(error) {
  return {
    code: String(error?.code || error?.name || 'PACKAGE_CHECK_FAILED'),
    message: String(error?.message || 'Package check failed.'),
    ...(Number.isInteger(error?.exitCode) ? { exit_code: error.exitCode } : {}),
    ...(Array.isArray(error?.errors) ? { nested_errors: error.errors.map(errorRecord) } : {}),
  };
}

async function atomicWriteJson(path, value) {
  const temporary = `${path}.${runId}.${process.pid}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, JSON.stringify(value, null, 2) + '\n', { flag: 'wx' });
    await rename(temporary, path);
  } catch (primary) {
    try {
      await rm(temporary, { force: true });
    } catch (cleanup) {
      throw new AggregateError([primary, cleanup], primary.message, { cause: primary });
    }
    throw primary;
  }
}

function failureRecord(error, stagePath = null, extras = {}) {
  return {
    schema_version: 1,
    run_id: runId,
    result: 'failed',
    phase: currentPhase,
    primary_error: errorRecord(error),
    cleanup_errors: (extras.cleanupErrors || []).map(item => ({
      surface: item.surface,
      error: errorRecord(item.error),
    })),
    dispose_error: extras.disposeError ? errorRecord(extras.disposeError) : null,
    phases,
    ...(stagePath ? { stage_path: stagePath } : {}),
    started_at: startedAt,
    finished_at: new Date().toISOString(),
  };
}

function assertLexicallyWithin(candidate, parent, allowEqual = false) {
  const candidateFull = resolve(candidate);
  const parentFull = resolve(parent);
  const delta = relative(parentFull, candidateFull);
  assert.ok(
    (allowEqual && delta === '') || (delta && delta !== '..' && !delta.startsWith(`..${sep}`) && !isAbsolute(delta)),
    `Path must stay below ${parentFull}: ${candidateFull}`,
  );
  return candidateFull;
}

async function assertNoLinkComponents(path, stopAt = root) {
  let cursor = resolve(path);
  const stop = resolve(stopAt);
  assertLexicallyWithin(cursor, stop, true);
  while (true) {
    try {
      const metadata = await lstat(cursor);
      assert.ok(!metadata.isSymbolicLink(), `Refusing symbolic-link path component: ${cursor}`);
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    if (cursor === stop) break;
    const parent = dirname(cursor);
    assert.notEqual(parent, cursor, `Path ancestry ended before ${stop}`);
    cursor = parent;
  }
}

async function assertRealPathWithin(candidate, parentReal, allowEqual = false, label = 'path') {
  const actual = await realpath(candidate);
  assertLexicallyWithin(actual, parentReal, allowEqual);
  assert.equal(resolve(actual), actual, `${label} must resolve to a canonical path.`);
  return actual;
}

async function assertRegularSource(path) {
  const full = assertLexicallyWithin(resolve(root, path), root);
  await assertNoLinkComponents(full, root);
  const metadata = await lstat(full);
  assert.ok(metadata.isFile() && !metadata.isSymbolicLink(), `Release source is not a regular file: ${path}`);
  const actual = await assertRealPathWithin(full, await realpath(root), false, 'release source');
  assert.equal(actual, full, `Release source must not be re-addressed through a link: ${path}`);
  return metadata;
}

async function shippedSourceManifest(files, installedRoot) {
  const rows = [];
  for (const path of [...files].sort()) {
    const original = resolve(root, path);
    await assertRegularSource(path);
    const sourceBytes = await readFile(original);
    const installedBytes = await readFile(join(installedRoot, path));
    const sourceDigest = createHash('sha256').update(sourceBytes).digest('hex');
    assert.equal(sourceBytes.length, installedBytes.length, `The extracted ${path} has a different byte length.`);
    assert.equal(sourceDigest, createHash('sha256').update(installedBytes).digest('hex'),
      `The extracted ${path} differs from the current release source.`);
    rows.push({ path, bytes: sourceBytes.length, sha256: sourceDigest });
  }
  return rows;
}

async function verifyUpgradeSmoke(dispatch, installedRoot, fixtureRoot, workspace) {
  const help = await dispatch('awa_project', 'action.help', { name: 'assessment.evaluate' }, null);
  const oracleKinds = ['authorization', 'baseline', 'error_channel', 'extraction', 'semantic_negative',
    'sql_metadata', 'state_invariant', 'state_transition'];
  assert.deepEqual(Object.keys(help.oracle_contracts).sort(), oracleKinds);
  for (const [kind, shape] of Object.entries(help.oracle_contracts)) {
    assert.equal(shape.example.type, kind);
    assert.ok(shape.required.includes('type'));
    assert.ok(shape.evidence_order.length > 0 && shape.constraints.length > 0);
  }
  assert.deepEqual(help.oracle_contracts.extraction.required_for_typed,
    ['test_family', 'expected_value', 'source_reference']);
  assert.equal(help.runtime_proof_entry.action, 'finding.record');
  assert.equal(help.oracle_contracts.analyst_runtime, undefined);
  const preparationHelp = await dispatch('awa_project', 'action.help', { name: 'assessment.prepare' }, null);
  assert.equal(preparationHelp.group, 'awa_assess');
  for (const field of ['obligation_id', 'finding_id', 'evidence_id', 'operation_id', 'evidence_ids', 'offset', 'limit']) {
    assert.equal(typeof preparationHelp.fields[field], 'string');
  }
  const bindingHelp = await dispatch('awa_project', 'action.help', { name: 'finding.bind' }, null);
  assert.equal(bindingHelp.group, 'awa_assess');
  assert.deepEqual(bindingHelp.required, ['finding_id', 'decision_id', 'reviewer', 'reason']);
  const runtimeBindingHelp = await dispatch('awa_project', 'action.help', { name: 'finding.record' }, null);
  assert.match(runtimeBindingHelp.fields.xss_consumption, /stored_api/);
  const consumerHelp = await dispatch('awa_project', 'action.help', { name: 'surface.declare_consumer' }, null);
  assert.match(consumerHelp.fields.schema_branch, /null/);

  // Keep new source-only hypotheses out of the existing release fixture's queue.
  const projectId = 'package-upgrade';
  const baseUrl = 'https://upgrade.invalid/';
  const call = (name, action, input = {}) => dispatch(name, action, input, projectId);
  await call('awa_project', 'project.create', { target: baseUrl, scope: [baseUrl] });
  const definitionPath = join(fixtureRoot, 'upgrade-definition.json');
  await writeFile(definitionPath, JSON.stringify({ version: 'fixture-v1', maxScore: 1,
    vulns: [['/api/search', [['keyword', 'GET']], 'SQL\u6ce8\u5165', 1]] }));
  const nativeHints = await call('awa_surface', 'surface.import', {
    path: definitionPath, format: 'assessment_hints', base_url: baseUrl,
  });
  assert.deepEqual(nativeHints.operation_ids, []);
  assert.equal(nativeHints.candidates, 1);
  const exampleHints = await call('awa_surface', 'surface.import', {
    path: join(installedRoot, 'examples', 'assessment-hints.json'), format: 'assessment_hints', base_url: baseUrl,
  });
  assert.deepEqual(exampleHints.operation_ids, []);
  assert.equal(exampleHints.candidates, 3);
  const hints = await call('awa_candidate', 'candidate.list', { limit: 10 });
  assert.equal(hints.candidate_total, 4);
  assert.equal(hints.counts.unverified, 4);
  assert.deepEqual([...new Set(hints.candidates.map(candidate => candidate.kind))].sort(),
    ['answer_key_hint', 'assessment_hint']);
  for (const summary of hints.candidates) {
    const { candidate, operation } = await call('awa_candidate', 'candidate.inspect', { candidate_id: summary.id });
    assert.equal(operation, null);
    assert.equal(candidate.status, 'unverified');
    assert.equal(candidate.verification_level, 'hint_only');
    assert.equal(candidate.hints_only, true);
    assert.equal(candidate.independent_evidence_required, true);
    assert.equal(candidate.usable_for_confirmation, false);
    if (candidate.kind === 'answer_key_hint') {
      assert.equal(candidate.method ?? null, null, 'GET parameter location must not invent an HTTP method.');
      assert.equal(candidate.method_requires_binding, true);
    }
  }
  assert.equal((await call('awa_surface', 'surface.list')).operation_total, 0);
  await assert.rejects(call('awa_assess', 'finding.record', {
    title: 'Unproven package answer-key claim', category: 'sql_injection', impact: 'Not established',
    remediation: 'Obtain independent evidence', decision_id: hints.candidates[0].id,
  }), error => error.code === 'not_found');
  const findingsBeforeBinding = await call('awa_assess', 'finding.list');
  assert.equal(findingsBeforeBinding.finding_total, 0);
  await assert.rejects(call('awa_assess', 'finding.bind', {
    finding_id: hints.candidates[0].id, decision_id: hints.candidates[0].id,
    reviewer: 'package-offline-review', reason: 'A source-only candidate is not an existing finding or accepted typed proof.',
  }), error => error.code === 'not_found');
  assert.deepEqual(await call('awa_assess', 'finding.list'), findingsBeforeBinding,
    'Rejected binding cannot promote a source-only record or create a finding.');

  const javascriptPath = join(fixtureRoot, 'upgrade-client.js');
  await writeFile(javascriptPath, [
    "axios.post('/api/register', {shop_name: form.shop_name});",
    'target.innerHTML = item.shop_name;',
    "axios.get('/pay', {params: {redirect: route.query.redirect}});",
    "const destination = route.query.redirect ?? '/orders';",
    'window.location.href = destination;',
    "throw new Error('SOURCE_MUST_NOT_EXECUTE');",
    '',
  ].join('\n'));
  const javascript = await call('awa_surface', 'surface.import', {
    path: javascriptPath, format: 'javascript', base_url: baseUrl,
  });
  assert.equal(javascript.operation_ids.length, 2);
  const sinks = await call('awa_candidate', 'candidate.list', { kind: 'client_sink', limit: 10 });
  assert.equal(sinks.candidate_total, 2);
  const sinkNames = [];
  for (const summary of sinks.candidates) {
    const { candidate } = await call('awa_candidate', 'candidate.inspect', { candidate_id: summary.id });
    sinkNames.push(candidate.sink);
    assert.equal(candidate.status, 'unverified');
    assert.equal(candidate.verification_level, 'hint_only');
    assert.equal(candidate.hints_only, true);
    assert.equal(candidate.independent_evidence_required, true);
    assert.equal(candidate.taint_proven, false);
    assert.equal(candidate.consumer_declaration_allowed, false);
    assert.equal(candidate.usable_for_confirmation, false);
    assert.equal(candidate.binding_status, 'possible');
    assert.equal(candidate.possible_input_bindings.length, 1);
    const navigation = candidate.sink === 'location.href';
    const binding = candidate.possible_input_bindings[0];
    assert.equal(binding.matching_basis, 'same_bundle_field_name_only');
    assert.equal(binding.url, new URL(navigation ? 'pay' : 'api/register', baseUrl).href);
    assert.equal(binding.method, navigation ? 'GET' : 'POST');
    assert.equal(binding.input_location, navigation ? 'query' : 'body');
    assert.equal(binding.input_selector, navigation ? 'redirect' : '/shop_name');
    assert.deepEqual(candidate.referenced_fields, [navigation ? 'redirect' : 'shop_name']);
    assert.equal(candidate.source_column, 1);
    assert.equal(candidate.source_line, navigation ? 5 : 2);
    assert.doesNotMatch(JSON.stringify(candidate), /SOURCE_MUST_NOT_EXECUTE/);
  }
  assert.deepEqual(sinkNames.sort(), ['innerHTML.assignment', 'location.href']);
  for (const operationId of javascript.operation_ids) {
    const inspected = await call('awa_surface', 'surface.inspect', { operation_id: operationId });
    assert.ok(inspected.inputs.length > 0);
    assert.ok(inspected.inputs.every(input => input.consumer === 'unknown'));
    const prepared = await call('awa_assess', 'assessment.prepare', { operation_id: operationId, limit: 10 });
    assert.deepEqual(Object.keys(prepared.source), ['operation_id']);
    assert.equal(prepared.source.operation_id, operationId);
    assert.equal(prepared.requests_sent, 0);
    assert.equal(prepared.decisions_created, 0);
    assert.equal(prepared.automatic_execution_allowed, false);
    assert.equal(prepared.controls_are_candidates_only, true);
    assert.equal(prepared.source_evidence_total, 0);
    assert.deepEqual(prepared.evidence_reviews, []);
    assert.ok(prepared.items.every(item => item.operation_id === operationId
      && item.controls_are_candidates_only === true && item.control_candidate_evidence_ids.length === 0));
    for (const input of inspected.inputs) {
      const review = prepared.items.find(item => item.input_location === input.location
        && item.input_selector === input.selector && (item.schema_branch ?? null) === (input.schema_branch ?? null));
      assert.ok(review, 'The packaged preparation must retain the imported exact input selector.');
      assert.equal(review.obligation_kind, 'input_review');
      assert.equal(review.suggested_action, 'surface.declare_consumer');
      assert.equal(review.positive_machine_adapter, false);
    }
  }
  const openapiPath = join(fixtureRoot, 'upgrade-openapi.json');
  await writeFile(openapiPath, JSON.stringify({ openapi: '3.0.3', info: { title: 'Offline proof-preparation fixture', version: '1' },
    servers: [{ url: baseUrl }], paths: { '/health': { get: { security: [], responses: { 200: { description: 'ok' } } } } } }));
  const openapi = await call('awa_surface', 'surface.import', { path: openapiPath, format: 'openapi' });
  assert.equal(openapi.operation_ids.length, 1);
  const policyPreparation = await call('awa_assess', 'assessment.prepare', { operation_id: openapi.operation_ids[0] });
  assert.ok(policyPreparation.items.some(item => item.obligation_kind === 'auth_review'),
    'An imported specification does not establish the runtime access policy.');
  const publicOperation = await call('awa_surface', 'surface.register', {
    url: new URL('health', baseUrl).href, method: 'GET', auth: 'public',
  });
  assert.equal(publicOperation.id, openapi.operation_ids[0]);
  const publicPreparation = await call('awa_assess', 'assessment.prepare', { operation_id: openapi.operation_ids[0] });
  assert.deepEqual(Object.keys(publicPreparation.source), ['operation_id']);
  assert.equal(publicPreparation.source.operation_id, openapi.operation_ids[0]);
  assert.equal(publicPreparation.requests_sent, 0);
  assert.equal(publicPreparation.decisions_created, 0);
  assert.equal(publicPreparation.automatic_execution_allowed, false);
  assert.ok(publicPreparation.items.some(item => item.obligation_kind === 'baseline'
    && item.operation_id === openapi.operation_ids[0] && item.control_candidate_evidence_ids.length === 0));
  await call('awa_surface', 'surface.register', { url: new URL('parameters', baseUrl).href, method: 'GET', auth: 'public',
    inputs: Array.from({ length: 3 }, (_, index) => ({ name: `q${index}`, location: 'query',
      consumer: 'business_input', test_families: ['generic'] })),
  });
  const next = await call('awa_plan', 'plan.next', { offset: 999, limit: 1,
    parameter_offset: 1, parameter_limit: 2, parameter_status: 'untested' });
  assert.equal(next.requests_sent, 0);
  assert.deepEqual(next.work_items, []);
  const matrix = next.parameter_coverage;
  assert.equal(matrix.offset, 1);
  assert.equal(matrix.limit, 2);
  assert.equal(matrix.filter, 'untested');
  assert.ok(matrix.total >= 5);
  assert.equal(matrix.items.length, 2);
  assert.equal(matrix.next_offset, 3);
  assert.equal(matrix.summary.typed_tested_total, 0);
  assert.equal(matrix.summary.observed_total, 0);
  assert.equal(matrix.summary.observation_is_testing, false);
  assert.ok(matrix.items.every(item => item.typed_tested === false && item.observation_count === 0));
  const following = await call('awa_plan', 'plan.next', { offset: 0, limit: 1,
    parameter_offset: matrix.next_offset, parameter_limit: 2, parameter_status: 'untested' });
  assert.equal(following.parameter_coverage.offset, 3);
  assert.ok(following.parameter_coverage.items.every(item => !matrix.items.some(previous => previous.id === item.id)));
  const tested = await call('awa_plan', 'plan.next', { limit: 1, parameter_status: 'tested' });
  assert.equal(tested.parameter_coverage.total, 0);
  assert.deepEqual(tested.parameter_coverage.items, []);
  const consumerReview = await call('awa_plan', 'plan.audit', { offset: 999, limit: 1,
    parameter_offset: 0, parameter_limit: 1, parameter_status: 'consumer_review' });
  assert.equal(consumerReview.requests_sent, 0);
  assert.ok(consumerReview.parameter_coverage.total >= 2);
  assert.equal(consumerReview.parameter_coverage.items.length, 1);
  assert.equal(consumerReview.parameter_coverage.next_offset, 1);
  assert.equal(consumerReview.parameter_coverage.items[0].status, 'consumer_review');

  const multipart = await call('awa_surface', 'surface.register', {
    url: new URL('multipart-fixture', baseUrl).href, method: 'GET', auth: 'public',
  });
  const wire = Buffer.from('--PackageBoundary\r\nContent-Disposition: form-data; name="file"; filename="fixture.png"\r\n'
    + 'Content-Type: application/octet-stream\r\n\r\nPACKAGE_PRIVATE_BODY\r\n--PackageBoundary--\r\n', 'utf8');
  const bomWire = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), wire]);
  const bomPath = join(fixtureRoot, 'upgrade-multipart-bom.bin');
  await writeFile(bomPath, bomWire);
  const preflight = { operation_id: multipart.id, effect: 'read_only',
    headers: { 'Content-Type': 'multipart/form-data; boundary=PackageBoundary' } };
  await assert.rejects(call('awa_execute', 'http.preflight', { ...preflight, body_file: bomPath }), error => {
    assert.equal(error.code, 'multipart_framing');
    assert.equal(error.details.framing_issue, 'utf8_bom');
    assert.equal(error.details.repair, 'rewrite_utf8_without_bom');
    assert.equal(error.details.next_action, 'http.preflight');
    assert.doesNotMatch(JSON.stringify(error.details), /PACKAGE_PRIVATE_BODY|PackageBoundary/);
    return true;
  });
  assert.deepEqual(await readFile(bomPath), bomWire, 'Preflight must not silently repair or rewrite caller bytes.');
  const validPath = join(fixtureRoot, 'upgrade-multipart-valid.bin');
  await writeFile(validPath, wire);
  const valid = await call('awa_execute', 'http.preflight', { ...preflight, body_file: validPath });
  assert.equal(valid.ready, true);
  assert.equal(valid.requests_sent, 0);
  assert.equal(valid.body_bytes, wire.length);
  assert.equal((await call('awa_project', 'project.status')).run_total, 0);
  const { stdout } = await run(pythonExecutable, ['-E', '-s', '-X', 'utf8', '-B', '-c', String.raw`
import json, pathlib, sqlite3, sys
database = pathlib.Path(sys.argv[1]) / "projects" / sys.argv[2] / "assessment.sqlite3"
with sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True) as connection:
    counts = dict(connection.execute("SELECT kind, COUNT(*) FROM entities GROUP BY kind"))
print(json.dumps({kind: counts.get(kind, 0) for kind in ("run", "evidence", "decision", "finding")}))
`, workspace, projectId], options);
  const counts = JSON.parse(stdout);
  assert.deepEqual(counts, { run: 0, evidence: 0, decision: 0, finding: 0 });
  const srcId = 'package-src';
  const srcUrl = 'https://package-src.invalid/app';
  const srcCall = (name, action, input = {}) => dispatch(name, action, input, srcId);
  const srcCreated = await srcCall('awa_project', 'project.create', {
    target: srcUrl, scope: [srcUrl], assessment_mode: 'src', allow_mutation: false,
  });
  assert.equal(srcCreated.config.assessment_mode, 'src');
  const writeOperation = await srcCall('awa_surface', 'surface.register', {
    operation: { url: srcUrl + '/write', method: 'POST', auth: 'public' },
  });
  await assert.rejects(srcCall('awa_execute', 'http.capture', {
    operation_id: writeOperation.id, url: srcUrl + '/write', effect: 'read_only', idempotency_key: 'src-write-must-not-dispatch',
  }), error => error.code === 'src_write_denied');
  const exchange = { schema: 'dsh-purge-awa/v1', engagement: { id: 'package-source', mode: 'src' },
    candidates: [{ external_id: 'vuln-1', url: srcUrl + '/candidate', method: 'GET',
      title: 'Package scanner candidate', category: 'generic', source_status: 'confirmed' }] };
  const imported = await srcCall('awa_project', 'integration.import', { exchange });
  const reused = await srcCall('awa_project', 'integration.import', { exchange });
  assert.equal(imported.counts.created, 1);
  assert.equal(reused.counts.created, 0);
  assert.deepEqual(reused.candidate_ids, imported.candidate_ids);
  const exported = await srcCall('awa_project', 'integration.export', { import_id: imported.import_id });
  assert.equal(exported.candidates[0].status, 'unverified');
  assert.equal(exported.candidates[0].usable_for_confirmation, false);
  assert.deepEqual(exported.candidates[0].decisions, []);
  assert.equal((await srcCall('awa_project', 'project.status')).run_total, 0);
  return { oracle_discriminators: oracleKinds.length, assessment_hint_candidates: hints.candidate_total,
    client_sink_candidates: sinks.candidate_total, parameter_cells: matrix.summary.cell_total,
    typed_tested_parameters: matrix.summary.typed_tested_total, multipart_bom_error: 'multipart_framing',
    multipart_bom_repair: 'rewrite_utf8_without_bom', proof_preparation_operations: javascript.operation_ids.length + openapi.operation_ids.length,
    finding_bind_unproven_rejected: true, requests_sent: 0, decisions_created: 0, automatic_execution_allowed: false, entity_counts: counts,
    src_write_rejected_before_dispatch: true, src_exchange_idempotent: true, src_external_confirmation_ignored: true };
}

async function verifySourceInventorySmoke(dispatch, fixtureRoot) {
  const projectId = 'package-source-inventory';
  const baseUrl = 'https://source-package.invalid';
  const call = (name, action, input = {}) => dispatch(name, action, input, projectId);
  await call('awa_project', 'project.create', { target: baseUrl, assessment_mode: 'src' });
  const importHelp = await dispatch('awa_project', 'action.help', { name: 'surface.import' }, null);
  assert.match(importHelp.fields.format, /actuator_mappings/);
  assert.match(importHelp.fields.snapshot_id, /saved/);
  const sourcePath = join(fixtureRoot, 'source-mappings.json');
  const sourceBytes = JSON.stringify({ contexts: { fixture: { mappings: { dispatcherServlets: { dispatcher: [
    ...['/records', '/records/{record}', '/assets/**'].map(pattern => ({
      handler: 'fixture-only', details: { requestMappingConditions: { methods: ['GET'], patterns: [pattern] } },
    })),
  ] } } } } });
  await writeFile(sourcePath, sourceBytes);
  const preview = await call('awa_surface', 'surface.import', {
    path: sourcePath, format: 'actuator_mappings', base_url: baseUrl, mode: 'preview', limit: 1,
  });
  assert.equal(preview.result_total, 3);
  assert.equal(preview.results.length, 1);
  assert.deepEqual(preview.operation_ids, []);
  assert.deepEqual(preview.candidate_ids, []);
  assert.equal(preview.source_inventory.pending_import_total, 3);
  assert.equal(preview.requests_sent, 0);
  assert.equal((await call('awa_surface', 'surface.list')).operation_total, 0);
  const saved = await call('awa_surface', 'surface.sources', { snapshot_id: preview.snapshot_id, limit: 1 });
  assert.equal(saved.snapshot.sha256, createHash('sha256').update(sourceBytes).digest('hex'));
  assert.equal(saved.snapshot.inventory.mapping_total, 3);
  assert.equal(saved.snapshot_integrity, 'valid');
  // The reviewed snapshot must remain usable after the local file changes.
  await writeFile(sourcePath, JSON.stringify({ contexts: {} }));
  let input = { snapshot_id: preview.snapshot_id, mode: 'apply', offset: 0, limit: 1 };
  let applied;
  let pageCount = 0;
  while (input && pageCount < 3) {
    applied = await call('awa_surface', 'surface.import', input);
    assert.equal(applied.snapshot_id, preview.snapshot_id);
    assert.equal(applied.results.length, 1);
    assert.ok(applied.operation_ids.length + applied.candidate_ids.length <= 1);
    assert.equal(applied.requests_sent, 0);
    input = applied.next_input;
    pageCount++;
  }
  assert.equal(input, null);
  assert.equal(pageCount, 3);
  assert.equal(applied.next_action, 'surface.sources');
  assert.equal(applied.source_inventory.pending_import_total, 0);
  assert.equal((await call('awa_surface', 'surface.list')).operation_total, 2);
  assert.equal((await call('awa_candidate', 'candidate.list')).candidate_total, 1);
  const status = await call('awa_project', 'project.status');
  assert.equal(status.run_total, 0);
  assert.equal(status.source_inventory.known_not_registered_total, 1);
  assert.equal(status.completion.status, 'partial');
  assert.equal(status.continuation.can_finalize, false);
  assert.equal(status.source_inventory.site_wide_discovery_allowed, false);
  return { preview_rows: 3, apply_pages: pageCount, operations: 2, candidates: 1,
    exact_snapshot_ignores_file_changes: true, requests_sent: 0, can_finalize: false };
}

let stage;
let mainFailure;
let lockAcquired = false;
let disposeFailure = null;
let successRecord;
const cleanupErrors = [];

function addCleanupFailure(surface, error) {
  cleanupErrors.push({ surface, error });
}

try {
  assert.match(runId, /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/,
    'AWA_RELEASE_RUN_ID must be a safe 1-128 character path token.');
  await mkdir(validation, { recursive: true });
  const rootReal = await realpath(root);
  assertLexicallyWithin(validation, root);
  await assertNoLinkComponents(validation, root);
  await assertRealPathWithin(validation, rootReal, false, 'validation directory');
  await assertNoLinkComponents(lockPath, root);
  await writeFile(lockPath, JSON.stringify({
    schema_version: 1, run_id: runId, pid: process.pid, started_at: startedAt,
  }, null, 2) + '\n', { flag: 'wx' });
  lockAcquired = true;
  await assertNoLinkComponents(lockPath, root);

  // The running marker is written before any old result is invalidated. Consumers
  // must require result=passed, this exact run_id, and absence of the running marker.
  await assertNoLinkComponents(runningRecordPath, root);
  await writeFile(runningRecordPath, JSON.stringify({
    schema_version: 1, run_id: runId, result: 'running', started_at: startedAt,
  }, null, 2) + '\n', { flag: 'w' });
  await assertNoLinkComponents(runningRecordPath, root);
  await assertNoLinkComponents(recordPath, root);
  await rm(recordPath, { force: true });

  await mkdir(archiveRoot, { recursive: true });
  await assertNoLinkComponents(archiveRoot, root);
  await assertRealPathWithin(archiveRoot, await realpath(validation), false, 'archive root');
  stage = await mkdtemp(join(validation, 'package-smoke-'));
  await assertNoLinkComponents(stage, root);
  await assertRealPathWithin(stage, await realpath(validation), false, 'smoke stage');
  await writeFile(runningRecordPath, JSON.stringify({
    schema_version: 1, run_id: runId, result: 'running', started_at: startedAt,
    phase: currentPhase, stage_path: stage,
  }, null, 2) + '\n', { flag: 'w' });
} catch (error) {
  mainFailure = error;
}

if (!mainFailure) try {
  assert.ok(process.env.npm_execpath, 'Run this check with npm run pack:check.');
  finishPhase({ lock_acquired: true, running_marker_written: true, stage_created: true });
  beginPhase('npm-pack');
  const { stdout } = await run(process.execPath, [process.env.npm_execpath, 'pack', '--ignore-scripts', '--offline',
    '--json', '--cache', join(stage, 'cache'), '--pack-destination', stage], options);
  const packResults = JSON.parse(stdout);
  assert.equal(packResults.length, 1, 'npm pack JSON must contain exactly one package result.');
  const [packed] = packResults;
  assert.equal(packed.name, 'awa-ddd', 'npm pack returned an unexpected package name.');
  assert.ok(Array.isArray(packed.files) && packed.files.length > 0, 'npm pack returned no file manifest.');
  const packedPaths = packed.files.map(file => file.path);
  assert.equal(packedPaths.length, new Set(packedPaths).size, 'npm pack manifest contains duplicate paths');
  for (const file of packed.files) {
    assert.ok(Number.isInteger(file.size), `npm pack manifest has no integer size for ${file.path}.`);
    assert.ok(Number.isInteger(file.mode), `npm pack manifest has no integer mode for ${file.path}.`);
  }
  const files = new Set(packedPaths);
  assert.equal(basename(packed.filename), packed.filename, 'npm pack filename must be a basename.');
  const archive = assertLexicallyWithin(join(stage, packed.filename), stage);
  await assertNoLinkComponents(archive, root);
  await assertRealPathWithin(archive, await realpath(stage), false, 'npm archive');
  const required = ['package.json', 'cordis.patch.yml', 'README.md', 'LICENSE', 'pyproject.toml', 'setup.py',
    'icon.svg', 'locale/en.json', 'locale/zh.json',
    'src/index.mjs', 'src/bridge.mjs', 'src/tools.mjs', 'src/actions.mjs', 'src/tool-guidance.mjs',
    'src/parse-js.mjs', 'src/mode.mjs', 'src/src-mode.mjs', 'src/stop-policy.mjs', 'src/host-continuation.mjs', 'src/client.js',
    'scripts/invoke-request.mjs', 'scripts/Invoke-AwaDdd.ps1', 'skills/awa-ddd/SKILL.md',
    'docs/UPGRADE-20261029.md', 'docs/UPGRADE-20261030-ASSESSMENT.md', 'docs/UPGRADE-20261031.md', 'docs/UPGRADE-20261101.md',
    'docs/UPGRADE-20261102.md', 'docs/UPGRADE-20261102-LEAN.md', 'docs/SESSION-20261102-ADAAE1EF.md',
    'docs/UPGRADE-20261103.md', 'docs/SESSION-20261103-CFF22367.md',
    'docs/V2-ARCHITECTURE.md', 'docs/V2-MIGRATION.md', 'docs/V2-ACCEPTANCE.md', 'docs/SRC-MODE.md', 'docs/INTEGRATION-DSH-PURGE.md',
    'docs/REPRODUCTION.md', 'docs/REFACTOR-PLAN-20261121.md', 'docs/UPGRADE-20261121-SOURCE-LEDGER.md',
    'docs/UPGRADE-20261122-HARDENING.md', 'examples/assessment-hints.json',
    'docs/WINDOWS_WSL.md', 'docs/INTERNAL_CONTRACT.md', 'docs/HOST_CONTRACT.md', 'docs/PLAYWRIGHT_TESTING.md',
    ...['__init__', '__main__', 'store', 'engine', 'scope', 'transport', 'assessment', 'scenario',
      'discovery', 'source_inventory', 'importers', 'reporting_legacy', 'candidates', 'lineage', 'browser', 'browser_policy', 'external', 'contracts', 'continuation',
      'mcp_http', 'tscanplus',
      'workflow', 'runtime', 'wsl_runner', 'inputs', 'completeness', 'reproduction', 'publication',
      'parameter_coverage', 'oracle_contracts', 'assessment_hints', 'reconnaissance', 'recon_parsing',
      'assessment_preparation', 'finding_binding', 'security_hypotheses', 'v2api', 'assessment_mode', 'integration'].map(module => `awa_ddd/${module}.py`),
    ...['__init__', 'universe', 'hypothesis', 'test_recipe', 'test_run', 'finding', 'coverage_claim', 'campaign',
      'known_case', 'gap', 'review', 'common', 'repository'].map(module => `awa_ddd/domain/${module}.py`),
    ...['__init__', 'scheduler', 'known_cases', 'route_parser', 'hypotheses', 'coverage', 'campaign', 'migration'].map(module => `awa_ddd/planning/${module}.py`),
    ...['__init__', 'test_runner', 'browser_provider', 'external_provider', 'capabilities', 'fixtures',
      'oracle_profiles', 'recipe_builder', 'review_engine', 'fixture_api'].map(module => `awa_ddd/execution/${module}.py`),
    'awa_ddd/reporting/__init__.py', 'awa_ddd/reporting/matrix.py',
    'awa_ddd/resources/__init__.py',
    ...bundledResources.keys()];
  for (const file of required) assert.ok(files.has(file), `Release is missing ${file}`);
  for (const file of files) {
    const bundledResource = bundledResources.has(file);
    assert.ok(bundledResource || !/(?:^|\/)node_modules(?:\/|$)/.test(file),
      `Release contains an unapproved bundled Node.js module: ${file}`);
    if (file.startsWith('awa_ddd/resources/')) assert.ok(
      bundledResource || file === 'awa_ddd/resources/__init__.py',
      `Release contains an unapproved runtime resource: ${file}`);
    assert.doesNotMatch(file, /(?:^|\/)(?:\.validation|__pycache__|\.cache|\.pytest_cache|\.mypy_cache|\.ruff_cache|htmlcov|coverage|projects|tests|backups?)(?:\/|$)/);
    assert.doesNotMatch(file, /(?:\.py[co]|\.sqlite[^/]*|\.db(?:-wal|-shm|-journal)?|\.tgz|\.log|\.tmp|\.temp|\.bak|\.backup|\.orig|\.rej|~)$/i);
    const environment = /(?:^|\/)(?:\.env|[^/]+\.env)(?:\.[^/]*)?$/i.test(file);
    assert.ok(!environment || /\.(?:example|sample|template)$/i.test(file), `Release contains private environment configuration: ${file}`);
  }
  for (const [file, expectedDigest] of bundledResources) {
    const bytes = await readFile(join(root, file));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), expectedDigest,
      `Bundled runtime resource differs from its frozen SHA-256: ${file}`);
  }

  // HARD RULE: the archive must never vendor @deepseek-ai/*.
  // @deepseek-ai/dsh-tools holds module-level Symbols (TOOL_RUNTIME_SCHEDULER); a
  // second instance shadows the host's and every `ctx.tools[SYMBOL]` lookup misses,
  // which crashes session creation in the host. The SDK must always resolve to the
  // host's own copy, so it stays a peerDependency and is never shipped here.
  const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
  assert.equal(manifest.dependencies?.acorn, undefined,
    'Bundled Acorn must not also remain a direct npm runtime dependency.');
  for (const [name, range] of Object.entries(manifest.dependencies ?? {})) {
    assert.ok(!name.startsWith('@deepseek-ai/'),
      `dependencies must not include ${name}: shipping an SDK copy shadows the host's instance`);
  }
  for (const name of ['@deepseek-ai/dsh-tools', '@deepseek-ai/dsh-llm', '@deepseek-ai/schemastery', '@deepseek-ai/cordis']) {
    assert.ok(manifest.peerDependencies?.[name],
      `${name} must stay a peerDependency so the host supplies the single instance`);
  }
  finishPhase({ files: files.size, archive: packed.filename });
  beginPhase('archive-extract');
  const destination = join(stage, 'unpacked');
  await mkdir(destination);
  await assertNoLinkComponents(destination, root);
  await assertRealPathWithin(destination, await realpath(stage), false, 'archive extraction directory');
  // Manual extraction supports Python 3.10 and rejects links and every path escape.
  const extraction = await run(pythonExecutable, ['-E', '-s', '-X', 'utf8', '-B', '-c', String.raw`
import json, pathlib, sys, tarfile
base = pathlib.Path(sys.argv[2]).resolve()
files = []
total_size = 0
with tarfile.open(sys.argv[1], "r:gz") as archive:
    for member in archive.getmembers():
        name = pathlib.PurePosixPath(member.name)
        if name.is_absolute() or ".." in name.parts or not name.parts or name.parts[0] != "package":
            raise ValueError("Unexpected archive path")
        target = (base / pathlib.Path(*name.parts)).resolve()
        if not target.is_relative_to(base) or member.issym() or member.islnk():
            raise ValueError("Archive path escape or link")
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
        elif member.isfile():
            if member.size > 16 * 1024 * 1024:
                raise ValueError("Archive member exceeds budget")
            total_size += member.size
            if total_size > 256 * 1024 * 1024:
                raise ValueError("Archive exceeds total unpacked-size budget")
            relative = str(pathlib.PurePosixPath(*name.parts[1:]))
            if any(row["path"] == relative for row in files):
                raise ValueError("Duplicate archive file member")
            if len(files) >= 10000:
                raise ValueError("Archive exceeds member-count budget")
            files.append({
                "path": relative,
                "size": member.size,
                "mode": member.mode & 0o777,
            })
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as source:
                target.write_bytes(source.read())
        else:
            raise ValueError("Unsupported archive member")
print(json.dumps({"files": sorted(files, key=lambda row: row["path"]), "total_size": total_size}, separators=(",", ":")))
`, archive, destination], options);
  const extracted = JSON.parse(extraction.stdout);
  assert.deepEqual(extracted.files.map(file => file.path), [...files].sort(),
    'The tar member set must exactly equal the npm pack manifest.');
  const packEntries = new Map(packed.files.map(file => [file.path, file]));
  for (const extractedFile of extracted.files) {
    const packedFile = packEntries.get(extractedFile.path);
    assert.ok(packedFile, `Archive member is absent from the npm pack manifest: ${extractedFile.path}`);
    assert.equal(extractedFile.size, packedFile.size,
      `Archive member size differs from npm pack metadata: ${extractedFile.path}`);
    assert.equal(extractedFile.mode, packedFile.mode & 0o777,
      `Archive member mode differs from npm pack metadata: ${extractedFile.path}`);
  }
  assert.ok(Number.isInteger(extracted.total_size) && extracted.total_size <= 256 * 1024 * 1024,
    'Archive exceeds the total unpacked-size budget.');
  finishPhase({
    files: extracted.files.length,
    total_size: extracted.total_size,
    membership_exact: true,
  });
  beginPhase('package-smoke');

  // SDK dependencies resolve from the installed development host above stage;
  // application code and all Python modules come from the extracted archive.
  const installedRoot = join(destination, 'package');
  const publishedSource = await shippedSourceManifest(files, installedRoot);
  const plugin = await import(pathToFileURL(join(installedRoot, 'src', 'index.mjs')).href);
  const registered = [];
  const hooks = new Map();
  let dispose;
  const workspace = join(stage, 'state');
  plugin.apply({ effect(factory) { dispose = factory(); }, tools: { register(tool) { registered.push(tool); } },
    on(event, callback) {
      hooks.set(event, callback);
      return () => { if (hooks.get(event) === callback) hooks.delete(event); };
    } },
    { workspace, pythonExecutable, timeoutMs: 10000 });
  // Derive the expected group set from the packaged module instead of hard-coding a
  // count: a stale literal here silently fails the release check after any tool change.
  const { GROUPS } = await import(pathToFileURL(join(installedRoot, 'src', 'tools.mjs')).href);
  const { ACTIONS } = await import(pathToFileURL(join(installedRoot, 'src', 'actions.mjs')).href);
  assert.equal(registered.length, GROUPS.length);
  assert.deepEqual(registered.map(tool => tool.name), GROUPS.map(group => group.name));

  // The penetration-mode half must ship and declare its client entry.
  const installedManifest = JSON.parse(await readFile(join(installedRoot, 'package.json'), 'utf8'));
  assert.equal(installedManifest.name, manifest.name);
  assert.equal(installedManifest.version, manifest.version);
  assert.equal(packed.version, manifest.version);
  assert.equal(installedManifest.exports['./client'], './src/client.js');
  assert.equal(installedManifest.exports['./icon'], './icon.svg');
  assert.equal(installedManifest.exports['./locale/*.json'], './locale/*.json');
  assert.equal(installedManifest.dsh.client.platform, 'web');
  for (const locale of ['en', 'zh']) {
    const localized = JSON.parse(await readFile(join(installedRoot, 'locale', `${locale}.json`), 'utf8'));
    assert.ok(localized.meta?.title?.trim(), `Missing ${locale} plugin title`);
    assert.ok(localized.meta?.description?.trim(), `Missing ${locale} plugin description`);
    assert.equal(localized.meta.detail, undefined, 'The README fallback is intentional without a feature preview');
  }
  const icon = await readFile(join(installedRoot, 'icon.svg'), 'utf8');
  assert.ok(icon.includes('viewBox="0 0 36 36"') && !/<(?:script|image|foreignObject|style|text)\b/.test(icon),
    'The plugin icon must be a self-contained 36px SVG');

  // HARD RULE: the client bundle id must derive from the package name.
  // The host keys client factories by `stripClientSuffix(id)`, which removes only a
  // trailing "/client". Any other id makes a second load of the same bundle look like
  // a fresh registration, and the host throws "duplicate factory registration" at boot.
  const clientSource = await readFile(join(installedRoot, 'src', 'client.js'), 'utf8');
  const clientId = /__ModuleLoader__\.load\(\s*\{[\s\S]{0,200}?\bid:\s*['"]([^'"]+)['"]/.exec(clientSource)?.[1];
  assert.ok(clientId, 'client.js must register through window.__ModuleLoader__.load with an id');
  assert.ok(
    clientId === installedManifest.name || clientId === `${installedManifest.name}/client`,
    `client id "${clientId}" must be "${installedManifest.name}" or "${installedManifest.name}/client"`,
  );
  const mode = await import(pathToFileURL(join(installedRoot, 'src', 'mode.mjs')).href);
  assert.equal(mode.name, 'awa-ddd-penetration-mode');
  assert.equal(typeof mode.apply, 'function');
  assert.equal(mode.penetrationProjection.key, 'penetration');
  const stopPolicy = await import(pathToFileURL(join(installedRoot, 'src', 'stop-policy.mjs')).href);
  assert.deepEqual(stopPolicy.inject, ['systemPrompt']);
  assert.match(stopPolicy.STOP_POLICY_TEXT, /Finalization is exhaustion_only/);
  assert.match(stopPolicy.STOP_POLICY_TEXT, /plan\.finalize accepts only reason:completed/);
  assert.match(stopPolicy.STOP_POLICY_TEXT, /A normal host turn end is not assessment completion/);
  const hostContinuation = await import(pathToFileURL(join(installedRoot, 'src', 'host-continuation.mjs')).href);
  assert.equal(hostContinuation.TURN_STOPPING_EVENT, 'agent/turn-stopping');
  assert.equal(typeof hostContinuation.createController, 'function');
  assert.equal(typeof hooks.get('agent/pre-step'), 'function');
  assert.equal(typeof hooks.get(hostContinuation.TURN_STOPPING_EVENT), 'function');
  const signal = new AbortController().signal;
  const dispatch = async (name, action, input = {}, project_id = 'package-smoke', execution = { signal }) => {
    const tool = registered.find(tool => tool.name === name);
    return (await tool.execute({ action, ...(project_id ? { project_id } : {}), input }, execution)).data;
  };
  try {
    const catalog = await dispatch('awa_project', 'action.help', {}, null);
    assert.equal(catalog.action_count, ACTIONS.length);
    assert.deepEqual(Object.values(catalog.groups).flat().sort(), [...ACTIONS].sort());
    const help = await dispatch('awa_project', 'action.help', { name: 'http.preflight' }, null);
    assert.equal(help.fields.body_file.includes('local file'), true);
    const stopHelp = await dispatch('awa_project', 'action.help', { name: 'plan.finalize' }, null);
    assert.match(stopHelp.fields.reason, /^completed/);
    assert.doesNotMatch(stopHelp.fields.reason, /\|/);
    const runtime = await dispatch('awa_external', 'runtime.probe', { backend: 'native' }, null);
    assert.ok(Array.isArray(runtime.sqlmap_candidates));
    for (const candidate of runtime.sqlmap_candidates) {
      assert.equal(candidate.automatic_execution_allowed, false);
      assert.equal(candidate.verified_absolute, true);
      assert.equal(candidate.verified_file, true);
      assert.equal(candidate.action, 'tool.probe');
      assert.equal(candidate.input_template.sqlmap_path, candidate.path);
    }
    assert.equal(runtime.target_traffic_sent, false);
    await dispatch('awa_project', 'project.create', { target: 'https://example.invalid/', scope: ['https://example.invalid/'] });
    const projects = await dispatch('awa_project', 'project.list', {}, null);
    assert.ok(projects.projects.includes('package-smoke'));
    const specPath = join(stage, 'openapi.json');
    await writeFile(specPath, JSON.stringify({ openapi: '3.0.3', info: { title: 'Offline package smoke', version: '1' },
      servers: [{ url: 'https://example.invalid' }], paths: { '/health': { get: { security: [], responses: { 200: { description: 'ok' } } } } } }));
    const imported = await dispatch('awa_surface', 'surface.import', { path: specPath, format: 'openapi' });
    assert.equal(imported.operation_ids.length, 1);
    const javascriptPath = join(stage, 'client.js');
    await writeFile(javascriptPath, "fetch('https://example.invalid/profile', { method: 'GET' });\n");
    const javascript = await dispatch('awa_surface', 'surface.import', { path: javascriptPath, format: 'javascript' });
    assert.equal(javascript.operation_ids.length, 1, 'Packaged AST helper and acorn must be usable.');
    const inventory = await dispatch('awa_surface', 'surface.list', { limit: 1 });
    assert.equal(inventory.operation_total, 2);
    assert.equal(inventory.operations.length, 1);
    assert.equal(inventory.registration_is_testing, false);
    const reconHelp = await dispatch('awa_project', 'action.help', { name: 'surface.recon' }, null);
    assert.equal(reconHelp.group, 'awa_surface');
    assert.deepEqual(Object.keys(reconHelp.fields).sort(),
      ['limit', 'mode', 'offset', 'refresh', 'required_assessment_mode', 'section']);
    assert.equal(typeof reconHelp.fields.required_assessment_mode, 'string');
    const reconPrepare = await dispatch('awa_surface', 'surface.recon', { mode: 'prepare', section: 'collection', limit: 1 });
    assert.equal(reconPrepare.requests_sent, 0);
    assert.equal(reconPrepare.baseline_id, null);
    assert.equal(reconPrepare.profile_is_security_evidence, false);
    const recon = await dispatch('awa_surface', 'surface.recon', { mode: 'aggregate' });
    const reusedRecon = await dispatch('awa_surface', 'surface.recon', { mode: 'aggregate' });
    assert.match(recon.baseline_id, /^RC-[a-f0-9]{24,32}$/);
    assert.equal(reusedRecon.baseline_id, recon.baseline_id);
    assert.equal(reusedRecon.baseline_reused, true);
    assert.equal(recon.summary.current_observation_total, 0);
    assert.equal(recon.requests_sent, 0);
    assert.equal(recon.completion_claim_allowed, false);
    assert.equal((await dispatch('awa_project', 'project.status')).run_total, 0);
    const parserSmoke = await run(pythonExecutable, ['-E', '-s', '-X', 'utf8', '-B', '-c',
      'import json; from awa_ddd.recon_parsing import parse_response; print(json.dumps(parse_response("https://example.invalid/", '
      + '[("server","nginx/1.26.2"),("content-type","text/html")], b"<html><script src=\'/_next/app.js\'></script></html>")))'],
    { ...options, cwd: installedRoot });
    const passiveHints = JSON.parse(parserSmoke.stdout);
    assert.ok(passiveHints.technologies.some(item => item.name === 'Next.js' && item.confidence === 'hint'));
    assert.ok(passiveHints.technologies.some(item => item.name === 'nginx' && item.version === '1.26.2'));
    const planned = await dispatch('awa_plan', 'plan.build', { limit: 1 });
    assert.equal(typeof planned.obligations, 'number');
    assert.equal(planned.obligation_items.length, 1);
    const ready = await dispatch('awa_plan', 'plan.next');
    assert.equal(ready.requests_sent, 0);
    assert.equal(typeof ready.browser_testing_summary.task_total, 'number');
    assert.ok(ready.work_items.every(item => item.browser_testing && typeof item.browser_testing.call_needed === 'boolean'));
    const localOperation = await dispatch('awa_surface', 'surface.register', {
      url: 'https://example.invalid/offline-fixture', method: 'GET', auth: 'public',
      inputs: [{ name: 'q', location: 'query', consumer: 'business_input', test_families: ['generic'] }],
    });
    const agent = { id: 'packaged-agent-fixture', status: 'running', session: {},
      inbox: { nextStep: [], nextTurn: [] }, steer(message) { this.inbox.nextStep.push(message); } };
    const boundary = { agent, signal, turn: 1 };
    await hooks.get('agent/pre-step')(boundary, async () => ({ kind: 'enter', messages: [{
      id: 'packaged-user-fixture', role: 'user', source: { kind: 'user' },
      content: [{ type: 'text', text: 'Continue offline planning and source review for this fixture; no target requests.' }],
    }] }));
    const boundReady = await dispatch('awa_plan', 'plan.next', {}, 'package-smoke', { agent, signal });
    const actualReady = boundReady.work_items.find(item => item.operation_id === localOperation.id && item.queue_status === 'ready');
    assert.ok(actualReady, 'The packaged fixture must have actual ready work before a caller block.');
    await dispatch('awa_plan', 'plan.disposition', { obligation_id: actualReady.obligation_id, status: 'blocked',
      reason: 'Caller-only package fixture declaration; no prerequisite changed.' });
    const reconciled = await dispatch('awa_plan', 'plan.next');
    const blocker = reconciled.work_items.find(item => item.obligation_id === actualReady.obligation_id);
    assert.equal(blocker.queue_status, 'review');
    assert.equal(blocker.blocker_reconciliation_required, true);
    assert.equal(blocker.execution_blocked, true);
    assert.equal(blocker.suggested_action, 'plan.disposition');
    assert.equal(reconciled.requests_sent, 0);
    await hooks.get(hostContinuation.TURN_STOPPING_EVENT)(boundary);
    assert.equal(agent.inbox.nextStep.length, 1);
    assert.equal(agent.inbox.nextStep[0].source.kind, 'awa-ddd-host-continuation');
    assert.match(agent.inbox.nextStep[0].content[0].text, /OFFLINE/);
    await dispatch('awa_plan', 'plan.disposition', blocker.input_template);
    const afterReopen = await dispatch('awa_project', 'project.status');
    assert.equal(afterReopen.continuation.semantic_progress_id, boundReady.continuation.semantic_progress_id,
      'A caller blocked/open cycle is administrative state, not new semantic closure progress.');
    // The second notice supplies concrete current work; an administrative reopen
    // must not insert another generic notice or reset the zero-tool bound.
    const consumeNotice = async () => hooks.get('agent/pre-step')(boundary,
      async () => ({ kind: 'enter', messages: agent.inbox.nextStep.splice(0) }));
    await consumeNotice();
    await hooks.get(hostContinuation.TURN_STOPPING_EVENT)(boundary);
    assert.equal(agent.inbox.nextStep.length, 1, 'Unchanged progress must first receive concrete current review/preparation work.');
    assert.match(agent.inbox.nextStep[0].content[0].text, /Current review\/ready tasks:/);
    assert.match(agent.inbox.nextStep[0].content[0].text, /input_template/);
    await consumeNotice();
    await hooks.get(hostContinuation.TURN_STOPPING_EVENT)(boundary);
    assert.equal(agent.inbox.nextStep.length, 0, 'A zero-tool tail cannot repeat the concrete corrective handoff.');
    await hooks.get(hostContinuation.TURN_STOPPING_EVENT)(boundary);
    assert.equal(agent.inbox.nextStep.length, 0);
    const unfinished = await dispatch('awa_project', 'project.status');
    assert.equal(unfinished.continuation.continue_required, true);
    assert.equal(unfinished.continuation.automatic_stop_allowed, false);
    assert.equal((await dispatch('awa_project', 'project.status')).run_total, 0);
    const closure = await dispatch('awa_plan', 'plan.audit', { limit: 1 });
    assert.equal(closure.requests_sent, 0);
    assert.equal(closure.completion.status, 'partial');
    assert.ok(closure.category_matrix.length > 0);
    const prepared = await dispatch('awa_execute', 'http.preflight', { operation_id: imported.operation_ids[0] });
    assert.equal(prepared.ready, true);
    assert.equal(prepared.requests_sent, 0);
    assert.equal((await dispatch('awa_project', 'project.status')).run_total, 0);

    const requestFile = join(stage, 'unicode-request.json');
    const resultFile = join(stage, 'unicode-result.json');
    const label = 'UTF-8: \u4e2d\u6587\u{1f680}';
    await writeFile(requestFile, '\uFEFF' + JSON.stringify({ action: 'identity.actor', args: {
      project_id: 'package-smoke', actor_id: 'unicode-actor', subject: 'unicode-subject', label,
    } }));
    const fileResult = await run(process.execPath, [join(installedRoot, 'scripts', 'invoke-request.mjs'),
      '--workspace', workspace, '--python', pythonExecutable, '--request-file', requestFile, '--output-file', resultFile], options);
    const resultBytes = await readFile(resultFile);
    assert.deepEqual(resultBytes, Buffer.from(fileResult.stdout, 'utf8'));
    assert.notDeepEqual(resultBytes.subarray(0, 3), Buffer.from([0xef, 0xbb, 0xbf]));
    assert.equal(JSON.parse(resultBytes.toString('utf8')).data.label, label);
    await dispatch('awa_identity', 'identity.actor', { actor_id: 'fixture-actor', subject: 'fixture', roles: ['user'] });
    const credential = 'synthetic-private-package-smoke';
    const headerFile = join(stage, 'headers.json');
    await writeFile(headerFile, JSON.stringify({ Authorization: `Bearer ${credential}` }));
    const session = await dispatch('awa_identity', 'identity.session', { actor_id: 'fixture-actor', headers_file: headerFile });
    assert.doesNotMatch(JSON.stringify(session), new RegExp(credential));
    const plan = await dispatch('awa_plan', 'plan.list');
    const coverage = await dispatch('awa_report', 'report.coverage');
    assert.deepEqual(plan, coverage);
    assert.ok(coverage.gap_total > 0);
    // Every gap must carry a stable identity and a structured reason from the packaged engine.
    const firstGap = coverage.gaps[0];
    assert.match(firstGap.gap_id, /^G-[0-9a-f]{24}$/);
    assert.equal(typeof firstGap.reason_code, 'string');
    assert.equal(typeof firstGap.next_action, 'string');
    // Unresolved import clues must be readable back through the candidate ledger.
    const unresolvedPath = join(stage, 'unresolved.js');
    await writeFile(unresolvedPath, "const url = '/api/items/' + id; fetch(url);\n");
    await dispatch('awa_surface', 'surface.import', { path: unresolvedPath, format: 'javascript' });
    const candidates = await dispatch('awa_candidate', 'candidate.list', { limit: 10 });
    assert.ok(candidates.candidate_total > 0, 'Unresolved discovery clues must persist as candidates.');
    const target = candidates.candidates[0];
    const inspected = await dispatch('awa_candidate', 'candidate.inspect', { candidate_id: target.id });
    assert.equal(inspected.candidate.id, target.id);
    const dismissed = await dispatch('awa_candidate', 'candidate.dismiss',
      { candidate_id: target.id, reason: 'package smoke: verified the ledger round-trip' });
    assert.equal(dismissed.status, 'dismissed');
    const candidateAudit = await dispatch('awa_plan', 'plan.audit', { limit: 100 });
    const candidateReview = candidateAudit.checklist.find(item => item.candidate_id === target.id);
    assert.ok(candidateReview, 'A reason-only dismissal must not erase the packaged discovery queue.');
    assert.equal(candidateReview.reason_code, 'candidate_dismissal_unverified');
    assert.equal(candidateReview.suggested_action, 'candidate.reopen');
    assert.equal(candidateReview.administrative_review_allowed, false);
    assert.ok(candidateAudit.completion.unresolved_candidates > 0);
    await assert.rejects(dispatch('awa_plan', 'plan.review', { checklist_id: candidateReview.id,
      status: 'blocked', reviewer: 'package fixture reviewer', reason: 'Caller text is not candidate evidence.' }),
    error => error.code === 'closure_review');
    const draft = await dispatch('awa_report', 'report.build', { stage: 'draft' });
    assert.equal(draft.stage, 'draft');
    assert.equal(draft.continuation.continue_required, true);
    assert.ok(draft.continuation.actionable_total > 0);
    const round = await dispatch('awa_plan', 'plan.checkpoint', { label: 'Offline package fixture pause' });
    assert.match(round.continuation.semantic_progress_id, /^PR-[a-f0-9]{64}$/);
    assert.equal(round.checkpoint.semantic_progress_id, round.continuation.semantic_progress_id);
    assert.equal(typeof round.checkpoint.semantic_progress_changed, 'boolean');
    assert.equal(round.checkpoint.semantic_progress, undefined, 'The private milestone projection must not enter the host context.');
    await assert.rejects(dispatch('awa_plan', 'plan.finalize', {
      checkpoint_id: round.checkpoint.id, reason: 'completed', reviewer: 'package fixture reviewer',
      explanation: 'This attempt must fail because ready/review fixture tasks remain.',
    }), error => error.code === 'continue_required');
    for (const reason of ['budget_exhausted', 'user_stop', 'authorization_boundary', 'blocked']) {
      await assert.rejects(dispatch('awa_plan', 'plan.finalize', {
        checkpoint_id: round.checkpoint.id, reason, reviewer: 'package fixture reviewer',
        explanation: 'Caller text cannot authorize automatic stopping with unfinished fixture work.',
      }), error => error.code === 'stop_policy' && error.details?.continuation?.continue_required === true);
    }
    await assert.rejects(dispatch('awa_report', 'report.build', { stage: 'final' }),
      error => error.code === 'finalization_required');
    const report = await dispatch('awa_report', 'report.build', { stage: 'draft' });
    assert.equal(report.delivery_status, 'draft');
    assert.equal(report.continuation.can_claim_complete, false);
    assert.equal(report.continuation.stop_policy, 'exhaustion_only');
    assert.equal(report.continuation.automatic_stop_allowed, false);
    assert.equal(report.continuation.continue_required, true);
    assert.equal(report.finalization, null);
    assert.doesNotMatch(JSON.stringify(report), new RegExp(credential));
    const reportBytes = await readFile(report.report);
    const summaryBytes = await readFile(report.summary);
    assert.equal(createHash('sha256').update(reportBytes).digest('hex'), report.report_sha256);
    assert.equal(createHash('sha256').update(summaryBytes).digest('hex'), report.summary_sha256);
    const summary = JSON.parse(summaryBytes.toString('utf8'));
    assert.equal(summary.format_version, 5);
    assert.equal(summary.language, 'zh-CN');
    assert.match(reportBytes.toString('utf8'), /中文渗透测试报告/);
    const manifestBytes = await readFile(report.manifest);
    assert.equal(createHash('sha256').update(manifestBytes).digest('hex'), report.manifest_sha256);
    for (const file of JSON.parse(manifestBytes.toString('utf8')).files) {
      const bytes = await readFile(join(dirname(report.manifest), file.path));
      assert.equal(bytes.length, file.size_bytes);
      assert.equal(createHash('sha256').update(bytes).digest('hex'), file.sha256);
    }
    assert.doesNotMatch(reportBytes.toString('utf8') + summaryBytes.toString('utf8'), new RegExp(credential));
    assert.equal((await readFile(join(workspace, 'projects', 'package-smoke', 'assessment.sqlite3'))).subarray(0, 15).toString(), 'SQLite format 3');
    const upgradeSmoke = await verifyUpgradeSmoke(dispatch, installedRoot, stage, workspace);
    const sourceSmoke = await verifySourceInventorySmoke(dispatch, stage);
    assert.deepEqual(await shippedSourceManifest(files, installedRoot), publishedSource,
      'Release sources changed during package validation; rerun the check.');
    finishPhase({
      native_tool_groups: registered.length,
      upgrade_smoke: upgradeSmoke,
      source_inventory_smoke: sourceSmoke,
      source_manifest_sha256: createHash('sha256').update(JSON.stringify(publishedSource)).digest('hex'),
    });
    beginPhase('final-packlist-and-archive');
    const runArchiveDirectory = join(archiveRoot, runId);
    assertLexicallyWithin(runArchiveDirectory, archiveRoot);
    await mkdir(runArchiveDirectory);
    await assertNoLinkComponents(runArchiveDirectory, root);
    await assertRealPathWithin(runArchiveDirectory, await realpath(archiveRoot), false, 'run archive directory');
    const retainedArchive = assertLexicallyWithin(join(runArchiveDirectory, basename(packed.filename)), runArchiveDirectory);
    const pendingArchive = join(runArchiveDirectory, `.${basename(packed.filename)}.${randomUUID()}.pending`);
    await copyFile(archive, pendingArchive);
    await assertNoLinkComponents(pendingArchive, root);
    await assertRealPathWithin(pendingArchive, await realpath(runArchiveDirectory), false, 'pending archive');
    const archiveDigest = createHash('sha256').update(await readFile(pendingArchive)).digest('hex');
    assert.equal(archiveDigest, createHash('sha256').update(await readFile(archive)).digest('hex'),
      'The run archive changed while it was being retained.');
    assert.equal(basename(retainedArchive), packed.filename, 'Retained archive filename changed.');
    await rename(pendingArchive, retainedArchive);
    await assertNoLinkComponents(retainedArchive, root);
    await assertRealPathWithin(retainedArchive, await realpath(runArchiveDirectory), false, 'retained archive');
    assert.equal(createHash('sha256').update(await readFile(retainedArchive)).digest('hex'), archiveDigest,
      'The retained archive changed before publication.');

    const currentPackResult = await run(process.execPath, [process.env.npm_execpath, 'pack', '--ignore-scripts',
      '--offline', '--dry-run', '--json', '--cache', join(stage, 'cache')], options);
    const currentPackResults = JSON.parse(currentPackResult.stdout);
    assert.equal(currentPackResults.length, 1, 'Final npm pack dry-run must contain exactly one package result.');
    const [currentPack] = currentPackResults;
    assert.equal(currentPack.name, packed.name, 'Final npm pack dry-run changed the package name.');
    assert.equal(currentPack.version, packed.version, 'Final npm pack dry-run changed the package version.');
    assert.ok(Array.isArray(currentPack.files) && currentPack.files.length > 0,
      'Final npm pack dry-run returned no file manifest.');
    const currentPaths = currentPack.files.map(file => file.path);
    assert.equal(currentPaths.length, new Set(currentPaths).size,
      'Final npm pack dry-run manifest contains duplicate paths.');
    for (const file of currentPack.files) {
      assert.ok(Number.isInteger(file.size), `Final npm pack manifest has no integer size for ${file.path}.`);
      assert.ok(Number.isInteger(file.mode), `Final npm pack manifest has no integer mode for ${file.path}.`);
    }
    const initialMetadata = new Map(packed.files.map(file => [file.path, {
      size: file.size, mode: file.mode,
    }]));
    const currentMetadata = new Map(currentPack.files.map(file => [file.path, {
      size: file.size, mode: file.mode,
    }]));
    assert.deepEqual(currentMetadata, initialMetadata,
      'The current npm pack metadata changed during package validation; rerun the check.');
    const currentFiles = new Set(currentPack.files.map(file => file.path));
    assert.deepEqual([...currentFiles].sort(), [...files].sort(),
      'The current npm packlist changed during package validation; rerun the check.');
    assert.deepEqual(await shippedSourceManifest(currentFiles, installedRoot), publishedSource,
      'The final npm packlist no longer matches the extracted archive and frozen source bytes.');
    const gitHead = (await run('git', ['rev-parse', 'HEAD'], options)).stdout.trim();
    assert.match(gitHead, /^[a-f0-9]{40}$/, 'The release must record its exact Git source revision.');
    const releaseSourceFingerprint = createHash('sha256').update(JSON.stringify(publishedSource)).digest('hex');
    successRecord = {
      schema_version: 1,
      run_id: runId,
      package: packed.name, version: packed.version, files: files.size,
      git_head: gitHead,
      source_frozen: true,
      release_source_fingerprint: releaseSourceFingerprint,
      archive_path: retainedArchive,
      archive_sha256: archiveDigest,
      archive_membership_exact: true,
      final_packlist_unique: true,
      final_packlist_sha256: createHash('sha256').update(JSON.stringify(currentPack.files)).digest('hex'),
      source_sha256: releaseSourceFingerprint,
      source_files: publishedSource,
      sdk_entry: 'extracted package/src/index.mjs', native_tool_groups: registered.length, upgrade_smoke: upgradeSmoke, source_inventory_smoke: sourceSmoke,
      checks: ['archive contents', 'current source byte equality before and after smoke', 'current packaged version and retained archive SHA-256', 'native SDK tool definitions', 'Python bridge', 'SQLite persistence',
        'OpenAPI import', 'JavaScript AST/acorn import', 'Actuator source preview/read/exact snapshot apply pages with zero target traffic', 'private session summary', 'shared plan/coverage evaluator',
        'stable gap projection', 'candidate ledger round-trip and unverified dismissal review', 'penetration mode module and client entry',
        'always-on exhaustion-only prompt and packaged public-hook registration',
        'active bound offline steering through the extracted entry with a fixture Agent',
        'caller-only blocked ready work retains an offline reconciliation template; zero target runs',
        'packaged action/help catalog equality', 'native runtime inventory', 'bounded inventory/readiness',
        'packaged information-first prepare/aggregate and non-proof semantic baseline reuse with zero traffic',
        'packaged passive framework/server parser emits only source hints without code or network execution',
        'packaged unchanged progress receives concrete current review/preparation before bounded zero-tool deduplication',
        'packaged eight-discriminator oracle help and typed extraction contract',
        'packaged native and normalized assessment hints stay unverified with no finding or guessed method',
        'packaged JavaScript HTML/navigation sinks retain uncertain input bindings without source execution',
        'packaged assessment.prepare help and exact imported JS/OpenAPI targets retain zero requests, zero decisions and no execution authority',
        'packaged finding.bind help and rejected source-only binding preserve the finding ledger',
        'packaged exact-parameter coverage has independent pagination and untested/consumer-review filters',
        'packaged multipart BOM preflight rejects with repair; valid control remains offline and caller bytes unchanged',
        'upgrade fixture read-only SQLite confirms zero runs, evidence, decisions and findings',
        'offline plan.build/http.preflight with no run claims', 'packaged UTF-8 BOM input and no-BOM result CLI',
        'read-only completion/category audit', 'draft is not a stop record', 'persisted round checkpoint',
        'ready/review work rejects completed finalization', 'caller-declared budget/user/authorization/blocked exits rejected',
        'final report without strict finalization rejected; interrupted work remains draft',
        'Chinese format-5 report export and complete manifest digests'],
      network_requests: 0,
    };
    finishPhase({
      archive: retainedArchive,
      archive_sha256: archiveDigest,
      final_packlist_unique: true,
      final_packlist_files: currentFiles.size,
    });
  } finally {
    if (dispose) {
      try {
        await dispose();
      } catch (error) {
        disposeFailure = error;
      }
    }
  }
} catch (error) {
  mainFailure = error;
} finally {
  if (stage) {
    try {
      assertLexicallyWithin(stage, validation);
      await assertNoLinkComponents(stage, root);
      await assertRealPathWithin(stage, await realpath(validation), false, 'cleanup stage');
      await rm(stage, { recursive: true, force: true });
    } catch (error) {
      addCleanupFailure('stage_cleanup', error);
    }
  }
}

if (!lockAcquired) {
  const conflict = {
    schema_version: 1,
    run_id: runId,
    result: 'failed',
    phase: currentPhase,
    error: errorRecord(mainFailure || new Error('Package-check lock was not acquired.')),
    observed_at: new Date().toISOString(),
    shared_result_untouched: true,
  };
  const conflictPath = join(validation, `package-check-conflict.${randomUUID()}.json`);
  try {
    await atomicWriteJson(conflictPath, conflict);
  } catch (error) {
    process.stderr.write(`Package check failed and its conflict record could not be written: ${error.message}\n`);
  }
  process.stderr.write(JSON.stringify(conflict) + '\n');
  process.exitCode = 1;
} else {
  let exitFailure = mainFailure || cleanupErrors[0]?.error || disposeFailure || null;

  if (!exitFailure) {
    beginPhase('finalize');
    try {
      finishPhase({
        record_finalized: true,
        commit_status: 'committed',
        requires_running_marker_absent: true,
        requires_lock_absent: true,
        cleanup_succeeded_before_marker_commit: true,
      });
      const committedRecord = {
        ...successRecord,
        result: 'passed',
        record_finalized: true,
        commit_status: 'committed',
        requires_running_marker_absent: true,
        requires_lock_absent: true,
        cleanup_succeeded_before_marker_commit: true,
        phases: [...phases],
        started_at: startedAt,
        finished_at: new Date().toISOString(),
      };
      await atomicWriteJson(recordPath, committedRecord);

      try {
        await rm(runningRecordPath, { force: true });
      } catch (error) {
        addCleanupFailure('running_marker_commit', error);
      }
      if (cleanupErrors.length === 0) {
        try {
          await rm(lockPath, { force: true });
          lockAcquired = false;
        } catch (error) {
          addCleanupFailure('lock_release', error);
        }
      }
      exitFailure = cleanupErrors[0]?.error || disposeFailure || null;
    } catch (error) {
      exitFailure = error;
    }
  }

  if (exitFailure) {
    const failed = failureRecord(exitFailure, stage, {
      cleanupErrors,
      disposeError: disposeFailure,
    });
    failed['running_marker_removed'] = !(await lstat(runningRecordPath).then(() => true).catch(() => false));
    failed['lock_released'] = !(await lstat(lockPath).then(() => true).catch(() => false));
    let failureRecordCommitted = false;
    try {
      await atomicWriteJson(recordPath, failed);
      failureRecordCommitted = true;
    } catch (error) {
      addCleanupFailure('failure_record_write', error);
      process.stderr.write(`Package-check failure record could not be written: ${error.message}\n`);
    }

    if (failureRecordCommitted) {
      let runningRemoved = false;
      try {
        await rm(runningRecordPath, { force: true });
        runningRemoved = true;
        failed['running_marker_removed'] = true;
      } catch (error) {
        addCleanupFailure('running_marker_cleanup', error);
        failed['running_marker_removed'] = false;
      }
      if (runningRemoved) {
        try {
          await rm(lockPath, { force: true });
          lockAcquired = false;
          failed['lock_released'] = true;
        } catch (error) {
          addCleanupFailure('lock_cleanup', error);
          failed['lock_released'] = false;
        }
      }
    }
    failed['cleanup_errors'] = cleanupErrors.map(item => ({
      surface: item.surface,
      error: errorRecord(item.error),
    }));
    if (failureRecordCommitted) {
      try {
        await atomicWriteJson(recordPath, failed);
      } catch (error) {
        process.stderr.write(`Final package-check failure record could not be rewritten: ${error.message}\n`);
      }
    }
    process.stderr.write(JSON.stringify({
      schema_version: 1,
      run_id: runId,
      result: 'failed',
      phase: currentPhase,
      primary_error: errorRecord(exitFailure),
      cleanup_errors: failed['cleanup_errors'],
      running_marker_removed: failed['running_marker_removed'],
      lock_released: failed['lock_released'],
    }) + '\n');
    process.exitCode = 1;
  } else {
    process.stdout.write('Package smoke passed: archive/source/final-pack membership and byte equality, extracted entry/public hook, oracle/hint/parameter/sink/multipart and offline proof-preparation/binding fixtures, caller-block and candidate reconciliation, Python/SQLite, UTF-8 file CLI and draft report.\n');
  }
}
