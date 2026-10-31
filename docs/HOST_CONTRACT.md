# DeepSeek Harness integration

awa-ddd is a native Cordis tool plugin and a local Python package. The JavaScript entry exports `name`, `inject`, `Config`, and `apply`; it has no default export. It requests the existing `tools` service and registers ten tool groups with the real `defineTool` API. It does not start another LLM provider, copy an existing assessment system, or require an ARTEX server.

This contract was checked against DeepSeek Harness **0.2.1-rc.3**, `@deepseek-ai/dsh-tools@0.2.1-rc.3`, `@deepseek-ai/dsh-llm@0.2.1-rc.3`, `@deepseek-ai/cordis@4.0.5`, and `@deepseek-ai/schemastery@3.18.5`. All remain host peer dependencies, never a second bundled SDK. Tests validate the actual generated tool schemas; development does not activate or rewrite the user's desktop profile.

## Verified host interfaces

| Interface | Exact source checked | Consequence for awa-ddd |
|---|---|---|
| `ctx.tools.register(defineTool(...))` | `@deepseek-ai/dsh-tools/README.zh.md`, registration example; `lib/index.js:838` and `:2974` in the installed 0.2.1-rc.3 host | Use the native schema DSL and mandatory output `{schema, render}`. |
| Parameter and output schemas | `@deepseek-ai/dsh-tools/lib/types/schema.d.ts` | `required: true` belongs to a property; nested objects explicitly set `additionalProperties`; the supported `json` author node allows engine-owned result objects. |
| Cancellation | `@deepseek-ai/dsh-tools/README.zh.md:124` and `lib/types/index.d.ts`, `ToolDefinition.execute` | Forward `exec.signal`; stop the owned process and wait for it to close. Unloading the plugin also aborts its calls through a Cordis effect. |
| Deadline | `@deepseek-ai/dsh-tools/README.zh.md:235` | Tool `timeoutMs` is only a declaration unless host policy enforces it. The Python bridge independently enforces its deadline. |
| Concurrency | `@deepseek-ai/dsh-tools/lib/index.js:846` and `:882` | Use `isConcurrencySafe(args)`. Only read actions receive this classification; mutations are serial by default. |
| Plugin exports | `@deepseek-ai/dsh-tool-todo/README.zh.md`, “导出形状”; `@deepseek-ai/dsh-tool-working-directory/lib/index.js:8` | Export a namespace with `name`, `inject`, `apply`; default-exporting can discard injection metadata in the loader. |
| Bundle discovery | Installed `ALL-in-dsh/package.json`, `dsh.bundle.patch`; its `cordis.patch.yml` | Publish `cordis.patch.yml` with a single `insert` row naming `awa-ddd`. |
| Profile package management | `dsh plugin --help` from the installed desktop launcher | `dsh plugin --profile <profile> add <package>` forwards package-manager arguments to that profile. |

The examined desktop files were under `E:/app/deepseek/resources/app.asar`, with SDK package paths below `dsh/node_modules/@deepseek-ai/`. The CLI was `E:/app/deepseek/resources/runtime/cli/bin/dsh.cmd`. These paths are audit provenance, not hard-coded runtime dependencies. `~/.dsh/dsh-runtimes/dsh-primary-runtime/runtime.json` recorded an older rc.2 desktop payload with Python 3.12.14; SDK compatibility was established from the actual rc.3 package, not that stale metadata.

## Penetration mode (server + client halves)

The plugin ships a session-scoped "penetration mode" switch. It is an optional capability and must never be able to take the assessment tools down with it.

**Server half — `src/mode.mjs`.** Registers the `penetration` session projection, a prompt section, and `/penetration [off|status]` (empty input enables it). Only valid mutating command events change state; status and rejected input do not enable it. The section is empty while disabled.

**Client half — `src/client.js`.** A browser module in `window.__ModuleLoader__.load` format. It mounts the existing input button through the supported DOM fallback, not a fabricated slot/useProjection subscription. It reads authoritative `/penetration status`, sets explicit on/off, and rechecks. Single-flight, session guards and effect disposal prevent stale/double updates. Missing/old commands produce a visible unavailable/reload error, not guessed local state.

**Optional, not required.** `src/index.mjs` declares only `inject = ['tools']`. The three mode services are probed at runtime by `applyMode`, and a missing service degrades to "mode unavailable" with a logged reason while all registered tool groups still register. Putting them into the top-level `inject` would make them hard requirements and silently disable the whole plugin on a host that lacks `commands`.

The original slot discussion is historical provenance only. Current tests exercise the real fallback, nested kind:error command results, projection replay, session isolation and disposal. Mode never changes project scope or write permission.

## Configuration and process protocol

`workspace` defaults to `~/.dsh/awa-ddd-data`, outside the plugin installation. `pythonExecutable` defaults to `python` on Windows or `python3` elsewhere and must refer to Python 3.10+. `timeoutMs` defaults to 120000 and accepts integers from 1000 to 600000. No directories are created simply by importing or registering the plugin.

`executionBackend` defaults to native; Windows may select wsl with wslDistribution:kali-linux and wslPythonExecutable:python3. The model cannot select these through action input. WSL uses an owned Linux guardian/worker group, unbuffered cancellation/request pipes and a local deadline. Path conversion remains in the group; URL/scope are never rewritten. See `WINDOWS_WSL.md` for network/storage boundaries and real known-PID tests.

The model cannot replace the configured workspace or interpreter through tool parameters. The bridge starts a fixed argument vector equivalent to `python -E -s -X utf8 -B -m awa_ddd --workspace <configured-directory>` with `shell: false`. The packaged directory is the child working directory. One JSON request is sent through stdin; exactly one JSON result is expected on stdout. Input, output and diagnostics are bounded to 1 MiB, 4 MiB and 64 KiB respectively.

Both requests and responses reject lone surrogates and nonfinite numbers instead of silently changing bytes. The file CLI optionally reserves a new `--output-file` before dispatch and writes the UTF-8/no-BOM JSON result directly; the PowerShell wrapper exposes `-OutputFile`. PowerShell 5.1 `>` may re-encode output as UTF-16 despite console settings, so it is not the supported protocol file writer. No profile/global encoding settings change.

Windows process windows remain hidden. Abort, deadline and output-budget failures terminate the owned child tree and reject after the Python process closes. A success-shaped JSON response with a nonzero exit is rejected. An interrupted write may already have affected a test resource. `run.inspect` reads a specific run's persisted status, checkpoints, evidence IDs and error using `project_id` and `run_id`. `run.recover` marks stale running records as interrupted (`stale_seconds` defaults to 300 and must be at least 60); it does not replay requests.

The Python engine returns metadata instead of raw HTTP. The bridge additionally removes credential keys and raw request/response/body fields from the canonical JSON value, so native rendering and PTC cannot expose those fields by choosing different projections. This does not promise to recognize every secret embedded in arbitrary prose. Prefer `headers_file` for session registration so credentials do not appear in model tool arguments or conversation logs.

Public inventories are paged; renderer output is valid JSON capped at 24 KiB with explicit partial markers, while canonical data is not truncated. The action.help exception preserves only static string field descriptions, never actual body/header objects.

Continuation controls and safe cursors are retained independently of list/detail truncation. `render_recovery` re-fetches the current page at a smaller limit before following the canonical next cursor; `required_original_filters` names filters that must be reapplied without echoing sensitive values. `plan.checkpoint/review/finalize` are persisted mutations, not read-only tool calls. Draft reports never authorize stopping; final reports require a current snapshot-bound finalization. The plugin does not provide a verified host final-text/turn-continuation hook, and external stop reasons remain caller declarations rather than authenticated host events or measured budgets.

Native errors use the host's own HarnessError. The installed SDK persists name/code, not arbitrary details: safe recovery IDs/help metadata are bounded to 2 KiB and retained on direct errors and in a valid `Recovery` JSON message. Do not claim structured durable details support. Raw stderr and credential values are not recovery channels.

## Build, test and installation

No JavaScript transpilation is required. Node.js 22.19+ and Python 3.10+ are required. The JavaScript AST helper uses the pinned `acorn@8.19.0` dependency; it runs offline after package installation.

```powershell
npm ci --ignore-scripts
npm test
python -X utf8 -B -m unittest discover -s tests -p "test_*.py"
npm run pack:check
npm pack --ignore-scripts
```

Install the generated package only in the profile chosen by the user:

```powershell
dsh plugin --profile desktop add "D:/path/to/awa-ddd-0.8.0.tgz"
```

Then activate/configure its bundle through the host's profile/plugin management. The packaged bundle patch makes the native plugin row available; adding a dependency and activating a composition are distinct host operations. For an explicit composed row, use:

```yaml
- id: awa-ddd
  name: awa-ddd
  config:
    workspace: D:/Assessments/awa-ddd
    pythonExecutable: C:/Python312/python.exe
    timeoutMs: 120000
```

Development tests exercise actual SDK definition/schema compilation, grouped action routing, stdin/stdout protocol boundaries, real child-process cancellation and timeouts, input-pipe failures, and credential removal. An input-pipe failure terminates the owned process even if it remains alive after closing stdin.

`npm run pack:check` creates an archive with an isolated local npm cache, checks its contents, safely extracts it, and loads the extracted native entry. It invokes the packaged Python engine to create a temporary SQLite assessment, import local OpenAPI and JavaScript documents (including the packaged AST/acorn helper), register an actor/session, compare plan and coverage output, and export a report with verified digests. It additionally verifies help/catalog equality, local runtime metadata, paged inventory/readiness, offline preflight with no run claims, and the extracted UTF-8 input/result CLI. No target requests are sent. SDK dependencies resolve from the installed development dependencies; this check does not install dependencies from the registry or launch the desktop host. Set `AWA_DDD_PYTHON` to select a different Python executable for this check. Temporary state is removed after the check; the verified archive is retained at `.validation/awa-ddd-0.8.0.tgz`, and `.validation/package-check.json` records its path, digest and validated behavior. A failed check overwrites the result status so an earlier success cannot be mistaken for the current result.

The current retained archive is `.validation/awa-ddd-0.8.0.tgz`; earlier filenames in the original smoke-test discussion are historical. Package smoke also requires the shipped help/workflow/WSL modules and UTF-8 file CLI, and exercises plan.build/preflight without network requests. WSL live validation is separate and only runs trusted local version fixtures, not historical targets.

These checks do not claim that the user's live desktop profile has been changed or that external targets have been tested.
