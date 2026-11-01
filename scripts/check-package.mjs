/** Offline release smoke: pack, inspect, extract and execute the shipped entry. */
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const validation = join(root, '.validation');
await mkdir(validation, { recursive: true });
const stage = await mkdtemp(join(validation, 'package-smoke-'));
const pythonExecutable = process.env.AWA_DDD_PYTHON || (process.platform === 'win32' ? 'python' : 'python3');
const options = { cwd: root, shell: false, windowsHide: true, timeout: 60000, maxBuffer: 8 * 1024 * 1024 };
const recordPath = join(validation, 'package-check.json');
const startedAt = new Date().toISOString();
await writeFile(recordPath, JSON.stringify({ result: 'running', started_at: startedAt }, null, 2) + '\n');

async function shippedSourceManifest(files, installedRoot) {
  const rows = [];
  for (const path of [...files].sort()) {
    const original = resolve(root, path);
    const delta = relative(root, original);
    assert.ok(delta && !isAbsolute(delta) && delta !== '..' && !delta.startsWith(`..${sep}`), 'Source must stay below the checkout.');
    const sourceDigest = createHash('sha256').update(await readFile(original)).digest('hex');
    assert.equal(sourceDigest, createHash('sha256').update(await readFile(join(installedRoot, path))).digest('hex'),
      `The extracted ${path} differs from the current release source.`);
    rows.push({ path, sha256: sourceDigest });
  }
  return rows;
}

try {
  assert.ok(process.env.npm_execpath, 'Run this check with npm run pack:check.');
  const { stdout } = await run(process.execPath, [process.env.npm_execpath, 'pack', '--ignore-scripts', '--offline',
    '--json', '--cache', join(stage, 'cache'), '--pack-destination', stage], options);
  const [packed] = JSON.parse(stdout);
  const files = new Set(packed.files.map(file => file.path));
  const required = ['package.json', 'cordis.patch.yml', 'README.md', 'LICENSE', 'pyproject.toml',
    'src/index.mjs', 'src/bridge.mjs', 'src/tools.mjs', 'src/actions.mjs', 'src/tool-guidance.mjs',
    'src/parse-js.mjs', 'src/mode.mjs', 'src/stop-policy.mjs', 'src/host-continuation.mjs', 'src/client.js',
    'scripts/invoke-request.mjs', 'scripts/Invoke-AwaDdd.ps1', 'skills/awa-ddd/SKILL.md',
    'docs/UPGRADE-20261029.md', 'docs/UPGRADE-20261030-ASSESSMENT.md', 'docs/UPGRADE-20261031.md', 'docs/REPRODUCTION.md',
    'docs/WINDOWS_WSL.md', 'docs/INTERNAL_CONTRACT.md', 'docs/HOST_CONTRACT.md', 'docs/PLAYWRIGHT_TESTING.md',
    ...['__init__', '__main__', 'store', 'engine', 'scope', 'transport', 'assessment', 'scenario',
      'discovery', 'importers', 'reporting', 'candidates', 'lineage', 'browser', 'browser_policy', 'external', 'contracts', 'continuation',
      'mcp_http', 'tscanplus',
      'workflow', 'runtime', 'wsl_runner', 'inputs', 'completeness', 'reproduction', 'publication'].map(module => `awa_ddd/${module}.py`)];
  for (const file of required) assert.ok(files.has(file), `Release is missing ${file}`);
  for (const file of files) {
    assert.doesNotMatch(file, /(?:^|\/)(?:\.validation|node_modules|__pycache__|\.cache|\.pytest_cache|\.mypy_cache|\.ruff_cache|htmlcov|coverage|projects|tests|backups?)(?:\/|$)/);
    assert.doesNotMatch(file, /(?:\.py[co]|\.sqlite[^/]*|\.db(?:-wal|-shm|-journal)?|\.tgz|\.log|\.tmp|\.temp|\.bak|\.backup|\.orig|\.rej|~)$/i);
    const environment = /(?:^|\/)(?:\.env|[^/]+\.env)(?:\.[^/]*)?$/i.test(file);
    assert.ok(!environment || /\.(?:example|sample|template)$/i.test(file), `Release contains private environment configuration: ${file}`);
  }

  // HARD RULE: the archive must never vendor @deepseek-ai/*.
  // @deepseek-ai/dsh-tools holds module-level Symbols (TOOL_RUNTIME_SCHEDULER); a
  // second instance shadows the host's and every `ctx.tools[SYMBOL]` lookup misses,
  // which crashes session creation in the host. The SDK must always resolve to the
  // host's own copy, so it stays a peerDependency and is never shipped here.
  const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
  for (const [name, range] of Object.entries(manifest.dependencies ?? {})) {
    assert.ok(!name.startsWith('@deepseek-ai/'),
      `dependencies must not include ${name}: shipping an SDK copy shadows the host's instance`);
  }
  for (const name of ['@deepseek-ai/dsh-tools', '@deepseek-ai/dsh-llm', '@deepseek-ai/schemastery', '@deepseek-ai/cordis']) {
    assert.ok(manifest.peerDependencies?.[name],
      `${name} must stay a peerDependency so the host supplies the single instance`);
  }
  const archive = join(stage, packed.filename);
  const destination = join(stage, 'unpacked');
  await mkdir(destination);
  // Manual extraction supports Python 3.10 and rejects links and every path escape.
  await run(pythonExecutable, ['-E', '-s', '-X', 'utf8', '-B', '-c', String.raw`
import pathlib, sys, tarfile
base = pathlib.Path(sys.argv[2]).resolve()
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
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as source:
                target.write_bytes(source.read())
        else:
            raise ValueError("Unsupported archive member")
`, archive, destination], options);

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
  assert.equal(installedManifest.dsh.client.platform, 'web');

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
  assert.match(stopPolicy.STOP_POLICY_TEXT, /Automatic finalization is exhaustion-only/);
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
    assert.deepEqual(await shippedSourceManifest(files, installedRoot), publishedSource,
      'Release sources changed during package validation; rerun the check.');
    const retainedArchive = join(validation, packed.filename);
    await copyFile(archive, retainedArchive);
    const archiveDigest = createHash('sha256').update(await readFile(retainedArchive)).digest('hex');
    assert.equal(archiveDigest, createHash('sha256').update(await readFile(archive)).digest('hex'));
    await writeFile(recordPath, JSON.stringify({
      package: packed.name, version: packed.version, files: files.size,
      archive_path: retainedArchive,
      archive_sha256: archiveDigest,
      source_sha256: createHash('sha256').update(JSON.stringify(publishedSource)).digest('hex'),
      source_files: publishedSource,
      sdk_entry: 'extracted package/src/index.mjs', native_tool_groups: registered.length,
      checks: ['archive contents', 'current source byte equality before and after smoke', 'current packaged version and retained archive SHA-256', 'native SDK tool definitions', 'Python bridge', 'SQLite persistence',
        'OpenAPI import', 'JavaScript AST/acorn import', 'private session summary', 'shared plan/coverage evaluator',
        'stable gap projection', 'candidate ledger round-trip and unverified dismissal review', 'penetration mode module and client entry',
        'always-on exhaustion-only prompt and packaged public-hook registration',
        'active bound offline steering through the extracted entry with a fixture Agent',
        'caller-only blocked ready work retains an offline reconciliation template; zero target runs',
        'packaged action/help catalog equality', 'native runtime inventory', 'bounded inventory/readiness',
        'offline plan.build/http.preflight with no run claims', 'packaged UTF-8 BOM input and no-BOM result CLI',
        'read-only completion/category audit', 'draft is not a stop record', 'persisted round checkpoint',
        'ready/review work rejects completed finalization', 'caller-declared budget/user/authorization/blocked exits rejected',
        'final report without strict finalization rejected; interrupted work remains draft',
        'Chinese format-5 report export and complete manifest digests'],
      network_requests: 0, result: 'passed', started_at: startedAt, finished_at: new Date().toISOString(),
    }, null, 2) + '\n');
  } finally {
    dispose();
  }
  process.stdout.write('Package smoke passed: extracted entry/public hook, caller-block and candidate reconciliation, Python/SQLite, UTF-8 file CLI and draft report.\n');
} catch (error) {
  await writeFile(recordPath, JSON.stringify({ result: 'failed', started_at: startedAt,
    finished_at: new Date().toISOString(), code: String(error.code || error.name || 'PACKAGE_CHECK_FAILED') }, null, 2) + '\n');
  throw error;
} finally {
  const delta = relative(validation, resolve(stage));
  assert.ok(delta && !isAbsolute(delta) && delta !== '..' && !delta.startsWith(`..${sep}`), 'Cleanup must stay below .validation.');
  await rm(stage, { recursive: true, force: true });
}
