import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { invokeEngine, resolveConfig, safeErrorDetails } from '../src/bridge.mjs';

test('real offline help exposes every existing oracle discriminator and typed extraction fields', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'awa-oracle-help-'));
  try {
    const config = resolveConfig({ workspace });
    const result = await invokeEngine(config, 'action.help', { name: 'assessment.evaluate' });
    const help = result.data;
    assert.equal(help.action, 'assessment.evaluate');
    assert.deepEqual(Object.keys(help.oracle_contracts).sort(), [
      'authorization', 'baseline', 'error_channel', 'extraction', 'semantic_negative', 'sql_metadata', 'state_invariant', 'state_transition',
    ]);
    for (const [kind, shape] of Object.entries(help.oracle_contracts)) {
      assert.equal(shape.example.type, kind);
      assert.ok(shape.required.includes('type'));
      assert.ok(shape.evidence_order.length > 0);
      assert.ok(shape.constraints.length > 0);
    }
    assert.deepEqual(help.oracle_contracts.extraction.required_for_typed, ['test_family', 'expected_value', 'source_reference']);
    assert.equal(help.runtime_proof_entry.action, 'finding.record');
    assert.equal(help.oracle_contracts.analyst_runtime, undefined);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test('new proof recovery preserves fixed typed instructions, never supplied payloads', () => {
  const details = safeErrorDetails({
    test_family: 'xxe', oracle_type: 'extraction', framing_issue: 'utf8_bom', repair: 'rewrite_utf8_without_bom',
    required_fields: ['type', 'selector', 'expect', 'expected_value', 'source_reference'],
    help_input: { name: 'assessment.evaluate', body: 'PRIVATE_BODY' },
    raw_response: 'PRIVATE_RESPONSE', source_reference: 'PRIVATE_URI', instructions: 'execute PRIVATE_COMMAND',
  });
  assert.equal(details.test_family, 'xxe');
  assert.equal(details.oracle_type, 'extraction');
  assert.equal(details.repair, 'rewrite_utf8_without_bom');
  assert.deepEqual(details.required_fields, ['type', 'selector', 'expect', 'expected_value', 'source_reference']);
  assert.equal(details.help_input.name, 'assessment.evaluate');
  assert.doesNotMatch(JSON.stringify(details), /PRIVATE_/);
  assert.equal(safeErrorDetails({ test_family: 'attacker_text', oracle_type: ['extraction'], repair: 'execute',
    required_fields: ['PRIVATE_VALUE'] }), undefined);
});

test('real bridge returns a BOM correction before multipart dispatch without exposing bytes', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'awa-multipart-recovery-'));
  try {
    const config = resolveConfig({ workspace });
    await invokeEngine(config, 'project.create', { project_id: 'framing', target: 'http://fixture.invalid' });
    const registered = await invokeEngine(config, 'surface.register', { project_id: 'framing',
      operation: { url: 'http://fixture.invalid/upload', method: 'GET', auth: 'public' } });
    const wire = Buffer.from('\uFEFF--Boundary\r\nContent-Disposition: form-data; name="file"\r\n\r\nPRIVATE_BODY\r\n--Boundary--\r\n', 'utf8');
    await assert.rejects(() => invokeEngine(config, 'http.preflight', { project_id: 'framing',
      operation_id: registered.data.id, headers: { 'Content-Type': 'multipart/form-data; boundary=Boundary' },
      body_base64: wire.toString('base64'), effect: 'read_only' }), error => {
      assert.equal(error.code, 'multipart_framing');
      assert.equal(error.details.framing_issue, 'utf8_bom');
      assert.equal(error.details.repair, 'rewrite_utf8_without_bom');
      assert.equal(error.details.next_action, 'http.preflight');
      assert.doesNotMatch(JSON.stringify(error.details), /PRIVATE_BODY|Boundary/);
      return true;
    });
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});
