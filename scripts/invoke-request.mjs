#!/usr/bin/env node
/** File-based UTF-8 entry: no PowerShell JSON interpolation or shell execution. */
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { BridgeError, invokeEngine, MAX_REQUEST_BYTES } from '../src/bridge.mjs';

const allowed = new Set(['--workspace', '--request-file', '--output-file', '--backend', '--distribution', '--python', '--wsl-python', '--timeout-ms']);
const options = Object.create(null);
const controller = new AbortController();
let outputFile;
let envelope;
process.once('SIGINT', () => controller.abort());
process.once('SIGTERM', () => controller.abort());

async function readRequestFile(path) {
  const file = await open(path, constants.O_RDONLY | (process.platform === 'win32' ? 0 : constants.O_NONBLOCK));
  try {
    const info = await file.stat();
    if (!info.isFile() || info.size > MAX_REQUEST_BYTES) throw new Error('Request must be a regular file of at most 1 MiB.');
    const buffer = Buffer.alloc(MAX_REQUEST_BYTES + 1);
    let length = 0;
    while (length < buffer.length) {
      if (controller.signal.aborted) throw new BridgeError('ABORTED_BEFORE_DISPATCH', 'Request file loading was cancelled before action dispatch.');
      const { bytesRead } = await file.read(buffer, length, buffer.length - length, null);
      if (!bytesRead) break;
      length += bytesRead;
    }
    if (length > MAX_REQUEST_BYTES) throw new Error('Request file exceeds 1 MiB.');
    return buffer.subarray(0, length);
  } finally {
    await file.close();
  }
}

try {
  const argv = process.argv.slice(2);
  if (argv.length % 2) throw new Error('Options require a value. Use --request-file <UTF-8 JSON file>.');
  for (let index = 0; index < argv.length; index += 2) {
    if (!allowed.has(argv[index]) || Object.hasOwn(options, argv[index])) throw new Error('Unknown or repeated option.');
    options[argv[index]] = argv[index + 1];
  }
  if (!options['--request-file']) throw new Error('A UTF-8 --request-file is required; JSON is never evaluated as a command.');
  if (Object.hasOwn(options, '--output-file')) {
    if (!options['--output-file']) throw new BridgeError('RESULT_FILE', 'Output file must identify a new local file.');
    try {
      // Reserve before dispatch: never overwrite an input, existing file or symlink.
      outputFile = await open(options['--output-file'], 'wx', 0o600);
    } catch {
      throw new BridgeError('RESULT_FILE', 'Output file must be a new writable local file; existing files are never overwritten. No action was dispatched.');
    }
  }
  const raw = await readRequestFile(options['--request-file']);
  const request = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
  if (!request || typeof request !== 'object' || Array.isArray(request) || typeof request.action !== 'string') {
    throw new Error('Request must contain action and args.');
  }
  const config = {
    ...(options['--workspace'] ? { workspace: options['--workspace'] } : {}),
    ...(options['--backend'] ? { executionBackend: options['--backend'] } : {}),
    ...(options['--distribution'] ? { wslDistribution: options['--distribution'] } : {}),
    ...(options['--python'] ? { pythonExecutable: options['--python'] } : {}),
    ...(options['--wsl-python'] ? { wslPythonExecutable: options['--wsl-python'] } : {}),
    ...(options['--timeout-ms'] ? { timeoutMs: Number(options['--timeout-ms']) } : {}),
  };
  envelope = await invokeEngine(config, request.action, request.args ?? {}, { signal: controller.signal });
} catch (error) {
  const known = error instanceof BridgeError;
  envelope = { ok: false, error: { code: known ? error.code : 'REQUEST_FILE',
    message: known ? error.message : 'Could not parse the bounded UTF-8 request file or command options.',
    ...(known && error.details ? { details: error.details } : {}) } };
  process.exitCode = 2;
}

let serialized = JSON.stringify(envelope) + '\n';
try {
  if (outputFile) {
    await outputFile.writeFile(serialized, 'utf8');
    await outputFile.sync();
  }
} catch {
  serialized = JSON.stringify({ ok: false, error: { code: 'RESULT_FILE',
    message: 'Could not finish writing the UTF-8 result file; it may be incomplete. Inspect project state before retrying an action.' } }) + '\n';
  process.exitCode = 2;
} finally {
  if (outputFile) {
    try { await outputFile.close(); }
    catch {
      serialized = JSON.stringify({ ok: false, error: { code: 'RESULT_FILE',
        message: 'Could not close the UTF-8 result file. Inspect project state before retrying an action.' } }) + '\n';
      process.exitCode = 2;
    }
  }
}
process.stdout.write(serialized);
