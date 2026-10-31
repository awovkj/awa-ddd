import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { access, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const TEMP_PREFIX = 'awa-ddd-hygiene-';
const run = promisify(execFile);
const EXEC = { shell: false, windowsHide: true, encoding: 'utf8', timeout: 30000, maxBuffer: 4 * 1024 * 1024 };

const PRIVATE_FILES = [
  'examples/.env',
  'examples/.env.local',
  'examples/private.env',
  'examples/private.env.production',
  'skills/awa-ddd/private.env',
  'examples/request.log',
  'examples/request.tmp',
  'examples/request.temp',
  'examples/config.json.bak',
  'examples/config.backup',
  'examples/config.db',
  'examples/config.db-wal',
  'examples/config.db-shm',
  'examples/config.db-journal',
  'examples/state.sqlite3',
  'examples/state.sqlite3-wal',
  'examples/state.sqlite3-shm',
  'examples/state.sqlite3-journal',
  'examples/.cache/private.json',
  'skills/awa-ddd/.cache/private.json',
  'examples/.validation/backup.json',
  'examples/node_modules/private/index.js',
  'examples/.validation/public.env.example',
  'examples/node_modules/private/.env.example',
  'skills/.cache/public.env.sample',
];

const NPM_ONLY_PRIVATE_FILES = ['tests/public.env.template'];

const PUBLIC_FILES = [
  'examples/.env.example',
  'examples/.env.sample',
  'examples/.env.template',
  'examples/public.env.example',
  'examples/public.env.sample',
  'examples/public.env.template',
  'examples/public.env.local.example',
  'skills/awa-ddd/public.env.example',
  'skills/awa-ddd/public.env.sample',
  'skills/awa-ddd/public.env.template',
  'examples/javascript.js',
  'examples/openapi.json',
  'examples/tscanplus-mcp.json',
  'skills/awa-ddd/SKILL.md',
  'README.md',
];

function ignoredByGit(paths) {
  return new Promise((resolveResult, reject) => {
    const child = execFile('git', ['check-ignore', '--no-index', '--stdin', '-z'], { ...EXEC, cwd: ROOT },
      (error, stdout) => {
        if (error && error.code !== 1) return reject(error);
        resolveResult(new Set(stdout.split('\0').filter(Boolean)));
      });
    child.stdin.on('error', reject);
    child.stdin.end(paths.join('\0') + '\0');
  });
}

async function cleanupTemporaryStage(stage, tempRoot) {
  const target = resolve(stage);
  const within = relative(tempRoot, target);
  assert.ok(within && !isAbsolute(within) && within !== '..' && !within.startsWith('..' + sep));
  assert.equal(dirname(target), tempRoot);
  assert.ok(basename(target).startsWith(TEMP_PREFIX));
  assert.equal(await realpath(target), target, 'Refuse cleanup through a replaced path or link');
  await rm(target, { recursive: true, force: true });
}

test('Git ignores generated caches, secrets, backups, database sidecars and dependencies', async () => {
  const paths = [...PRIVATE_FILES, '.cache/tool.json', '.validation/baseline/engine.py', '.env', '.env.production',
    'node_modules/dependency/index.js', '.venv/Lib/site-packages/dependency.py',
    'awa_ddd/__pycache__/engine.cpython-313.pyc', 'tests/__pycache__/test_engine.cpython-313.pyc'];
  const ignored = await ignoredByGit(paths);
  assert.deepEqual([...ignored].sort(), [...paths].sort());
});

test('Git keeps public environment templates, source, tests, examples and the lockfile eligible for tracking', async () => {
  const paths = [...PUBLIC_FILES, '.env.example', '.env.sample', '.env.template',
    'src/index.mjs', 'src/tools.mjs', 'awa_ddd/engine.py', 'awa_ddd/browser_policy.py',
    'awa_ddd/tests_upgrade.py', 'tests/hygiene.test.mjs', 'tests/test_engine.py',
    'tests/test_browser_policy_20261031.py', 'package.json', 'package-lock.json', 'pyproject.toml',
    'scripts/check-package.mjs', 'docs/PLAYWRIGHT_TESTING.md', ...NPM_ONLY_PRIVATE_FILES];
  assert.deepEqual([...await ignoredByGit(paths)], []);
});

test('npm dry-run excludes private artifacts while retaining public templates and source examples', async (t) => {
  const tempRoot = await realpath(tmpdir());
  const stage = await mkdtemp(join(tempRoot, TEMP_PREFIX));
  t.after(() => cleanupTemporaryStage(stage, tempRoot));
  const fixture = join(stage, 'package');
  await mkdir(fixture);
  const sourceManifest = JSON.parse(await readFile(join(ROOT, 'package.json'), 'utf8'));
  // A root .npmignore cannot override allowlisted directories; copy the actual files policy.
  const filesPolicy = sourceManifest.files.filter(pattern => typeof pattern === 'string'
    && (pattern.startsWith('!') || (pattern.includes('.env') && /\.(?:example|sample|template)$/.test(pattern))));
  await writeFile(join(fixture, 'package.json'), JSON.stringify({
    name: 'awa-ddd-hygiene-fixture', version: '1.0.0', files: ['examples', 'skills', 'README.md', ...filesPolicy],
  }), { encoding: 'utf8', flag: 'wx' });
  await writeFile(join(fixture, '.npmignore'), await readFile(join(ROOT, '.npmignore')), { flag: 'wx' });
  for (const name of [...PRIVATE_FILES, ...NPM_ONLY_PRIVATE_FILES, ...PUBLIC_FILES]) {
    const target = resolve(fixture, name);
    const within = relative(fixture, target);
    assert.ok(within && !isAbsolute(within) && within !== '..' && !within.startsWith('..' + sep));
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, 'Synthetic hygiene fixture; no real credentials.\n', { encoding: 'utf8', flag: 'wx' });
  }
  const npmCli = process.env.npm_execpath || join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js');
  await access(npmCli);
  const { stdout } = await run(process.execPath, [npmCli, 'pack', '--dry-run', '--offline', '--ignore-scripts',
    '--json', '--cache', join(stage, 'npm-cache'), '--pack-destination', stage], { ...EXEC, cwd: fixture });
  const packed = JSON.parse(stdout);
  assert.equal(packed.length, 1);
  const files = new Set(packed[0].files.map(file => file.path.replaceAll('\\', '/')));
  const leaked = [...PRIVATE_FILES, ...NPM_ONLY_PRIVATE_FILES].filter(name => files.has(name));
  assert.deepEqual(leaked, [], 'Private artifacts entered npm package despite the files/ignore policy');
  for (const name of PUBLIC_FILES) assert.ok(files.has(name), `Public template or source example was excluded: ${name}`);
  assert.ok(files.has('package.json'));
});
