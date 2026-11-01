/** Bounded, cancellable argv-only bridge to the packaged Python engine. */
import { spawn } from 'node:child_process';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { types } from 'node:util';
import { ACTIONS } from './actions.mjs';
export { ACTIONS } from './actions.mjs';

export const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const DEFAULT_WORKSPACE = join(homedir(), '.dsh', 'awa-ddd-data');
export const MAX_REQUEST_BYTES = 1024 * 1024;
export const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
export const MAX_STDERR_BYTES = 64 * 1024;
export const MAX_JSON_DEPTH = 64;
export const MAX_JSON_NODES = 100000;
export const ENGINE_DISPATCH_UNCERTAIN = Symbol('awa-ddd:engine-dispatch-uncertain');
const LONE_SURROGATE = /\p{Surrogate}/u;
const QUOTED_VALUE = String.raw`(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')`;
const COOKIE_ASSIGNMENT = new RegExp(String.raw`\b(?:set[_-]?cookie|(?:anonymous[_-]?)?cookie)["']?\s*[:=]\s*(?:${QUOTED_VALUE}|[^\r\n]+)`, 'gi');
const CREDENTIAL_ASSIGNMENT = new RegExp(String.raw`\b(?:authorization|proxy[_-]?authorization|password|passwd|jwt|credentials?|(?:x[_-]?)?(?:auth|access|refresh|id|session|api)[_-]?token|token|(?:x[_-]?)?api[_-]?key|(?:client[_-]?)?secret)["']?\s*[:=]\s*(?:${QUOTED_VALUE}|[^\r\n,;]+)`, 'gi');
const CONTINUATION_BOOLEANS = ['continue_required', 'can_finalize', 'can_claim_complete', 'frontier_review_required',
  'automatic_stop_allowed', 'legacy_finalization_ignored'];
const CONTINUATION_COUNTS = ['actionable_total', 'ready_total', 'review_total', 'blocked_total', 'no_progress_rounds',
  'frontier_rounds', 'unresolved_total', 'applicability_review_total', 'scope_reduction_review_total'];
const CONTINUATION_VERSIONS = ['contract_version', 'stop_policy_version'];
const CONTINUATION_CODES = ['state', 'reason_code', 'next_action', 'snapshot_id', 'checkpoint_id', 'finalization_id', 'progress_id', 'coverage_status', 'stop_policy'];

/** Dynamic error prose is data, not a channel for credentials or raw URLs. */
export function safeErrorText(value, limit = 1600) {
  return String(value ?? '')
    .replace(/https?:\/\/[^\s<>"']+/gi, text => {
      try {
        const url = new URL(text);
        return `${url.protocol}//${url.host}${url.pathname || '/'}`;
      } catch { return '[invalid URL]'; }
    })
    .replace(COOKIE_ASSIGNMENT, '[cookie redacted]')
    .replace(CREDENTIAL_ASSIGNMENT, '[credential assignment redacted]')
    .replace(/\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi, 'Bearer [redacted]')
    .replace(/\bBasic\s+[A-Za-z0-9+/]+=*/gi, 'Basic [redacted]')
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[token redacted]')
    .replace(/\b(?:sk-|ghp_|github_pat_)[A-Za-z0-9_-]{16,}\b/g, '[token redacted]')
    .slice(0, limit);
}

/** Keep the same bounded machine controls in normal rendering and error recovery. */
export function compactContinuation(value, stringLimit = 160) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const result = Object.create(null);
  for (const key of CONTINUATION_BOOLEANS) if (typeof value[key] === 'boolean') result[key] = value[key];
  for (const key of CONTINUATION_COUNTS) {
    if (Number.isSafeInteger(value[key]) && value[key] >= 0) result[key] = value[key];
  }
  for (const key of CONTINUATION_VERSIONS) {
    if (Number.isSafeInteger(value[key]) && value[key] > 0) result[key] = value[key];
  }
  for (const key of CONTINUATION_CODES) {
    if (value[key] === null) result[key] = null;
    else if (typeof value[key] === 'string') result[key] = safeErrorText(value[key], stringLimit);
  }
  return result;
}

/** Positive-list recovery fields: opaque raw/error fields never cross the bridge. */
export function safeErrorDetails(details) {
  if (details === null || typeof details !== 'object' || Array.isArray(details)) return undefined;
  const safe = redactResult(details);
  const result = Object.create(null);
  const add = (key, value) => {
    result[key] = value;
    if (Buffer.byteLength(JSON.stringify(result), 'utf8') > 2048) { delete result[key]; return false; }
    return true;
  };
  // Counts and stop flags take priority over arbitrary flat error prose.
  for (const limit of [160, 80, 32]) {
    const continuation = compactContinuation(safe.continuation, limit);
    if (!continuation || add('continuation', continuation)) break;
  }
  for (const key of ['next_action', 'checkpoint_action', 'run_id', 'operation_id', 'action', 'field', 'help_action',
    'resource_id', 'evidence_id', 'obligation_id']) {
    if (typeof safe[key] === 'string') add(key, safeErrorText(safe[key], 200));
  }
  if (safe.stop_policy === 'exhaustion_only') add('stop_policy', safe.stop_policy);
  if (safe.requests_sent === 0) add('requests_sent', 0);
  if (safe.progress_export?.action === 'report.build' && safe.progress_export?.input?.stage === 'draft') {
    add('progress_export', { action: 'report.build', input: { stage: 'draft' } });
  }
  if (safe.help_input && typeof safe.help_input === 'object' && typeof safe.help_input.name === 'string') {
    add('help_input', { name: safeErrorText(safe.help_input.name, 200) });
  }
  return Object.keys(result).length ? result : undefined;
}

export class BridgeError extends Error {
  constructor(code, message, details) {
    super(safeErrorText(message));
    this.name = 'AwaDddError';
    this.code = code;
    const safe = safeErrorDetails(details);
    if (safe) this.details = safe;
  }
}

function contained(parent, candidate) {
  const delta = relative(parent, candidate);
  return delta === '' || (!isAbsolute(delta) && delta !== '..' && !delta.startsWith(`..${sep}`));
}

export function resolveConfig(config = {}) {
  if (config === null || typeof config !== 'object' || Array.isArray(config)) {
    throw new BridgeError('INVALID_CONFIG', 'awa-ddd configuration must be an object.');
  }
  const workspace = config.workspace ?? DEFAULT_WORKSPACE;
  const pythonExecutable = config.pythonExecutable ?? (process.platform === 'win32' ? 'python' : 'python3');
  const timeoutMs = config.timeoutMs ?? 120000;
  const executionBackend = config.executionBackend ?? 'native';
  const wslDistribution = config.wslDistribution ?? 'kali-linux';
  const wslPythonExecutable = config.wslPythonExecutable ?? 'python3';
  if (typeof workspace !== 'string' || !isAbsolute(workspace) || workspace.includes('\0')) {
    throw new BridgeError('INVALID_CONFIG', 'workspace must be an absolute local directory.');
  }
  if (contained(PACKAGE_ROOT, resolve(workspace))) {
    throw new BridgeError('INVALID_CONFIG', 'Assessment state must live outside the installed plugin directory.');
  }
  if (typeof pythonExecutable !== 'string' || !pythonExecutable.trim() || pythonExecutable.includes('\0') || pythonExecutable.startsWith('-')) {
    throw new BridgeError('INVALID_CONFIG', 'pythonExecutable must identify a Python executable, without shell arguments.');
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 600000) {
    throw new BridgeError('INVALID_CONFIG', 'timeoutMs must be an integer from 1000 to 600000.');
  }
  if (!['native', 'wsl'].includes(executionBackend)) {
    throw new BridgeError('INVALID_CONFIG', 'executionBackend must be native or wsl.');
  }
  if (executionBackend === 'wsl' && process.platform !== 'win32') {
    throw new BridgeError('INVALID_CONFIG', 'The WSL backend requires a Windows host; use native on Linux.');
  }
  if (typeof wslDistribution !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(wslDistribution)) {
    throw new BridgeError('INVALID_CONFIG', 'wslDistribution must be a distribution name, not command-line arguments.');
  }
  if (typeof wslPythonExecutable !== 'string' || !/^[A-Za-z0-9_./][A-Za-z0-9_./+-]*$/.test(wslPythonExecutable)) {
    throw new BridgeError('INVALID_CONFIG', 'wslPythonExecutable must be a Linux executable name or path, without shell arguments.');
  }
  return Object.freeze({ workspace: resolve(workspace), pythonExecutable, timeoutMs,
    executionBackend, wslDistribution, wslPythonExecutable });
}

/** Reject values JSON.stringify would silently change, omit or execute. */
export function validateJson(value) {
  const ancestors = new Set();
  let nodes = 0;
  const visit = (node, depth) => {
    if (++nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH) {
      throw new BridgeError('INVALID_ARGUMENTS', 'Arguments exceed the supported JSON nesting or item budget.');
    }
    if (typeof node === 'string') {
      if (LONE_SURROGATE.test(node)) {
        throw new BridgeError('INVALID_ARGUMENTS', 'JSON strings and keys must contain valid Unicode scalar values, not isolated UTF-16 surrogates.');
      }
      return;
    }
    if (node === null || typeof node === 'boolean') return;
    if (typeof node === 'number') {
      if (Number.isFinite(node)) return;
      throw new BridgeError('INVALID_ARGUMENTS', 'JSON numbers must be finite; NaN and Infinity are not supported.');
    }
    if (typeof node !== 'object') {
      throw new BridgeError('INVALID_ARGUMENTS', 'Arguments must contain only JSON values; undefined, functions, symbols and bigint are not supported.');
    }
    if (types.isProxy(node)) throw new BridgeError('INVALID_ARGUMENTS', 'Arguments cannot contain Proxy objects.');
    const array = Array.isArray(node);
    const prototype = Object.getPrototypeOf(node);
    if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) {
      throw new BridgeError('INVALID_ARGUMENTS', 'Arguments must contain plain JSON objects and arrays, not class instances.');
    }
    if (ancestors.has(node)) throw new BridgeError('INVALID_ARGUMENTS', 'Arguments cannot contain circular references.');
    // Enforce breadth before allocating descriptors for an oversized collection.
    const remaining = MAX_JSON_NODES - nodes;
    if (array && node.length > remaining) {
      throw new BridgeError('INVALID_ARGUMENTS', 'Arguments exceed the supported JSON nesting or item budget.');
    }
    const keys = Reflect.ownKeys(node);
    if (keys.length > remaining + (array ? 1 : 0)) {
      throw new BridgeError('INVALID_ARGUMENTS', 'Arguments exceed the supported JSON nesting or item budget.');
    }
    const descriptors = Object.getOwnPropertyDescriptors(node);
    if (Reflect.ownKeys(descriptors).some(key => typeof key !== 'string')) {
      throw new BridgeError('INVALID_ARGUMENTS', 'JSON objects cannot contain symbol keys.');
    }
    ancestors.add(node);
    if (array) {
      if (node.length > MAX_JSON_NODES || Object.keys(descriptors).length !== node.length + 1) {
        throw new BridgeError('INVALID_ARGUMENTS', 'JSON arrays cannot contain holes or extra properties.');
      }
      for (let index = 0; index < node.length; index++) {
        const item = descriptors[String(index)];
        if (!item || !item.enumerable || !Object.hasOwn(item, 'value')) {
          throw new BridgeError('INVALID_ARGUMENTS', 'JSON arrays cannot contain holes or accessor properties.');
        }
        visit(item.value, depth + 1);
      }
    } else {
      for (const [key, descriptor] of Object.entries(descriptors)) {
        if (LONE_SURROGATE.test(key)) {
          throw new BridgeError('INVALID_ARGUMENTS', 'JSON strings and keys must contain valid Unicode scalar values, not isolated UTF-16 surrogates.');
        }
        if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
          throw new BridgeError('INVALID_ARGUMENTS', 'JSON objects cannot contain hidden or accessor properties.');
        }
        visit(descriptor.value, depth + 1);
      }
    }
    ancestors.delete(node);
  };
  visit(value, 0);
  return value;
}

export function validateRequest(action, args) {
  if (!ACTIONS.includes(action)) throw new BridgeError('UNKNOWN_ACTION', 'Unsupported awa-ddd action.');
  if (args === null || typeof args !== 'object' || Array.isArray(args)) {
    throw new BridgeError('INVALID_ARGUMENTS', 'Action arguments must be a JSON object.');
  }
  validateJson(args);
  if (!['action.help', 'runtime.probe', 'project.create', 'project.list'].includes(action) && !args.project_id) {
    throw new BridgeError('PROJECT_REQUIRED', 'This action requires project_id.');
  }
  if (args.project_id !== undefined && (typeof args.project_id !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(args.project_id))) {
    throw new BridgeError('INVALID_PROJECT_ID', 'project_id must be 1–64 lowercase letters, digits, underscores or hyphens and start with a letter or digit.');
  }
  let request;
  try { request = JSON.stringify({ action, args }); }
  catch { throw new BridgeError('INVALID_ARGUMENTS', 'Arguments must be serializable JSON.'); }
  if (Buffer.byteLength(request, 'utf8') > MAX_REQUEST_BYTES) {
    throw new BridgeError('INPUT_TOO_LARGE', 'Action request exceeds the 1 MiB limit; use a local import file.');
  }
  return request;
}

const PRIVATE_KEYS = new Set([
  'authorization', 'proxyauthorization', 'cookie', 'cookies', 'setcookie',
  'headers', 'password', 'passwd', 'secret', 'secrets', 'token', 'accesstoken',
  'refreshtoken', 'idtoken', 'authtoken', 'xauthtoken', 'xsessiontoken', 'sessiontoken', 'anonymouscookie',
  'sessioncookie', 'credentials', 'credential', 'clientsecret', 'apitoken',
  'apikey', 'xapikey', 'jwt', 'privatekey', 'storagestate',
  'credentialsignature', 'credentialnonce', 'redactioncontextsha256', 'candidateclosurecontext',
]);
const RAW_KEYS = new Set(['request', 'response', 'body', 'bodypreview', 'bodybase64',
  'requestbody', 'responsebody', 'requestbodybase64', 'responsebodybase64', 'raw', 'rawhttp', 'rawbody']);

/** Redact the canonical value too: PTC callers can access more than rendered text. */
export function redactResult(value, depth = 0) {
  if (depth > 64) throw new BridgeError('INVALID_RESPONSE', 'Engine response nesting exceeds the supported limit.');
  if (Array.isArray(value)) return value.map(item => redactResult(item, depth + 1));
  if (value === null || typeof value !== 'object') return value;
  const result = Object.create(null);
  for (const [key, child] of Object.entries(value)) {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '');
    result[key] = PRIVATE_KEYS.has(normalized) ? '[redacted]' : RAW_KEYS.has(normalized)
      ? '[raw HTTP data omitted; inspect the protected local artifact]' : redactResult(child, depth + 1);
  }
  return result;
}

/** Static help field descriptions are schema text, never captured header/body values. */
export function redactActionResult(action, value) {
  const safe = redactResult(value);
  if (action !== 'action.help' || !value || typeof value !== 'object' || Array.isArray(value)
      || !value.fields || typeof value.fields !== 'object' || Array.isArray(value.fields)) return safe;
  const fields = Object.create(null);
  for (const [key, description] of Object.entries(value.fields)) {
    if (typeof description === 'string' && key.length <= 160) fields[key] = safeErrorText(description, 2000);
  }
  safe.fields = fields;
  return safe;
}

/**
 * Spawn only the configured interpreter and fixed module argv. stdin/stdout own
 * the JSON protocol. Cancellation rejects after the owned process has closed.
 */
export function invokeEngine(config, action, args, { signal, spawnProcess = spawn } = {}) {
  const resolved = resolveConfig(config);
  const input = validateRequest(action, args);
  if (signal?.aborted) return Promise.reject(new BridgeError('ABORTED_BEFORE_DISPATCH', 'Assessment action was cancelled before execution.'));
  return new Promise((fulfill, reject) => {
    let child;
    let timer;
    let killTimer;
    let failure;
    let stopping = false;
    let settled = false;
    let submitted = false;
    let outputLength = 0;
    let stderrLength = 0;
    const output = [];

    const cleanup = () => {
      clearTimeout(timer);
      clearTimeout(killTimer);
      signal?.removeEventListener('abort', onAbort);
    };
    const finish = (error, value, accounted = false) => {
      if (settled) return;
      if (error && submitted && child?.pid && !accounted) {
        Object.defineProperty(error, ENGINE_DISPATCH_UNCERTAIN, { value: true });
      }
      settled = true;
      cleanup();
      error ? reject(error) : fulfill(value);
    };
    const forceKill = () => {
      if (!child?.pid || settled) return;
      try {
        if (process.platform === 'win32') child.kill('SIGKILL');
        else process.kill(-child.pid, 'SIGKILL');
      } catch { /* Already exited; close owns settlement. */ }
    };
    const stop = (code, message) => {
      if (stopping || settled) return;
      stopping = true;
      failure ??= new BridgeError(code, message);
      if (child?.pid) {
        if (resolved.executionBackend === 'wsl') {
          // The Linux supervisor owns its process group. Killing wsl.exe alone
          // is not cancellation: send the private control frame and close stdin.
          try { child.stdin.end('CANCEL\n', 'utf8'); }
          catch { /* Its EOF/deadline supervisor still owns Linux cleanup. */ }
        } else if (process.platform === 'win32') {
          // taskkill receives only the pid of the child created by this call.
          const killer = spawn('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'],
            { shell: false, windowsHide: true, stdio: 'ignore' });
          killer.on('error', forceKill);
          killer.on('close', code => { if (code !== 0) forceKill(); });
        } else {
          try { process.kill(-child.pid, 'SIGTERM'); }
          catch { try { child.kill('SIGTERM'); } catch { /* Already exited. */ } }
        }
        killTimer = setTimeout(forceKill, 1000);
        killTimer.unref();
      }
    };
    const onAbort = () => stop('ABORTED', 'Assessment action was cancelled; inspect its persisted run before retrying a state-changing action.');
    try {
      const wsl = resolved.executionBackend === 'wsl';
      const executable = wsl ? 'wsl.exe' : resolved.pythonExecutable;
      const argv = wsl
        ? ['--distribution', resolved.wslDistribution, '--cd', PACKAGE_ROOT, '--exec', resolved.wslPythonExecutable,
          '-E', '-s', '-X', 'utf8', '-B', '-m', 'awa_ddd.wsl_runner', '--workspace', resolved.workspace,
          '--deadline-ms', String(resolved.timeoutMs)]
        : ['-E', '-s', '-X', 'utf8', '-B', '-m', 'awa_ddd', '--workspace', resolved.workspace];
      child = spawnProcess(executable, argv,
        { cwd: PACKAGE_ROOT, shell: false, windowsHide: true,
          detached: process.platform !== 'win32', stdio: ['pipe', 'pipe', 'pipe'] });
    } catch {
      finish(new BridgeError('PYTHON_START_FAILED', 'Could not start the configured Python executable.'));
      return;
    }
    signal?.addEventListener('abort', onAbort, { once: true });
    timer = setTimeout(() => stop('ENGINE_TIMEOUT', 'Assessment action exceeded its timeout; inspect its persisted run before retrying.'), resolved.timeoutMs);
    timer.unref();
    child.on('error', () => stop('PYTHON_START_FAILED', 'Could not start or communicate with the configured Python executable.'));
    child.stdin.on('error', () => stop('ENGINE_IO_ERROR', 'The engine closed its input before accepting the request.'));
    child.stdout.on('data', chunk => {
      outputLength += chunk.length;
      if (outputLength > MAX_OUTPUT_BYTES) stop('OUTPUT_TOO_LARGE', 'Engine response exceeds the 4 MiB limit; request a smaller summary.');
      else if (!failure) output.push(chunk);
    });
    child.stderr.on('data', chunk => {
      stderrLength += chunk.length;
      if (stderrLength > MAX_STDERR_BYTES) stop('DIAGNOSTICS_TOO_LARGE', 'Engine diagnostics exceeded their limit. Diagnostic contents were not published.');
    });
    child.on('close', (code, killedBySignal) => {
      if (failure) { finish(failure); return; }
      let envelope;
      try { envelope = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(output))); }
      catch { finish(new BridgeError('INVALID_RESPONSE', 'Engine did not return one valid JSON response. Diagnostic contents were not published.')); return; }
      try { validateJson(envelope); }
      catch { finish(new BridgeError('INVALID_RESPONSE', 'Engine response contains unsupported JSON values, Unicode or nesting.')); return; }
      if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope) || typeof envelope.ok !== 'boolean') {
        finish(new BridgeError('INVALID_RESPONSE', 'Engine response has no valid result envelope.')); return;
      }
      if (!envelope.ok) {
        const error = envelope.error;
        if (!error || typeof error.code !== 'string' || typeof error.message !== 'string') {
          finish(new BridgeError('INVALID_RESPONSE', 'Engine returned a malformed error.')); return;
        }
        if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,95}$/.test(error.code)) {
          finish(new BridgeError('INVALID_RESPONSE', 'Engine returned an invalid error code.')); return;
        }
        try { finish(new BridgeError(error.code, error.message, error.details), undefined, error.code !== 'engine_error'); }
        catch (invalid) { finish(new BridgeError('INVALID_RESPONSE', 'Engine returned invalid recovery metadata.')); }
        return;
      }
      if (code !== 0 || killedBySignal) {
        finish(new BridgeError('ENGINE_FAILED', 'Engine exited unsuccessfully; its output is not a successful assessment result.')); return;
      }
      if (!Object.hasOwn(envelope, 'data')) {
        finish(new BridgeError('INVALID_RESPONSE', 'Successful engine response is missing data.')); return;
      }
      try { finish(null, { ok: true, data: redactActionResult(action, envelope.data) }); }
      catch (error) { finish(error); }
    });
    if (signal?.aborted) onAbort();
    if (!failure) {
      submitted = true;
      try {
        if (resolved.executionBackend === 'wsl') child.stdin.write(input + '\n', 'utf8');
        else child.stdin.end(input + '\n', 'utf8');
      } catch { stop('ENGINE_IO_ERROR', 'The engine did not establish a complete request outcome; inspect its persisted state before any retry.'); }
    } else if (resolved.executionBackend !== 'wsl') child.stdin.destroy();
  });
}
