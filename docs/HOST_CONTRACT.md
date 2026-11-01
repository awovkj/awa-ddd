# DeepSeek Harness integration

awa-ddd is a native Cordis tool plugin and a local Python package. The JavaScript entry exports `name`, `inject`, `Config`, and `apply`; it has no default export. It requests the existing `tools` service and registers ten tool groups with the real `defineTool` API. It does not start another LLM provider, copy an existing assessment system, or require an ARTEX server.

This contract was checked against DeepSeek Harness **0.2.1-rc.3**, `@deepseek-ai/dsh-tools@0.2.1-rc.3`, `@deepseek-ai/dsh-llm@0.2.1-rc.3`, `@deepseek-ai/cordis@4.0.5`, and `@deepseek-ai/schemastery@3.18.5`. All remain host peer dependencies, never a second bundled SDK. Tests validate the actual generated tool schemas; development does not activate or rewrite the user's desktop profile.

The development SDK pins vulnerable Zod 4.4.3 upstream. This checkout's root override and lock use Zod 4.6.6 for the same rc.3 SDK, addressing `GHSA-mrhx-c7xc-m3w5`; regression checks include early constrained-collection rejection and the actual tool schemas. npm only honors dependency overrides from the installing root: this override does not update a desktop host when awa-ddd is installed as its dependency. The host's owner must separately update its Zod/SDK dependency resolution. No SDK copy, desktop profile change or global dependency patch is bundled or performed here.

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

**Server half — `src/mode.mjs`.** Registers the `penetration` session projection, a prompt section, and `/penetration [off|status]` (empty input enables it). Only valid mutating command events change state; status and rejected input do not enable it. This mode-specific section is empty while disabled.

**Independent stop prompt — `src/stop-policy.mjs`.** Optionally requests only `systemPrompt` and registers `awa-ddd:exhaustion-stop-guard`. Its conditional assessment instructions remain available with penetration mode off and when the host lacks commands/projections. It never starts a project or target request. A missing prompt service does not remove the Python finalization/report gate.

**Public host continuation — `src/host-continuation.mjs`.** The rc.3 public `agent/turn-stopping` event is awaited serially before an otherwise closing turn settles (`dsh-agent/README.zh.md:67`, `runtime-types.d.ts:387`). The driver rereads steering afterward. The controller observes this tool execution's real `exec.agent`, admitted user intent, turn and cancellation boundary; it never trusts an agent/project from a result or `source_meta`. It audits only bound active work through fixed-config, zero-target-request `plan.audit`, then calls public `Agent.steer(createUserMessage(...))` with its own source. `followup` opens another turn and `inject` does not wake, so neither is used as a veto. It does not turn report-only/history inspection into target testing. Blocked-only work retains an unfinished checkpoint without replay. `continuationGuard` defaults to true; explicit static disable does not disable the Python gate. Unsupported/missing host context is diagnosed without taking the tools down.

Blocked-only means actual unavailable prerequisites, never caller prose: otherwise-feasible obligations/setup and administrative material produce `blocker_reconciliation_required` offline reopen work and therefore same-turn steering. The guard follows current engine templates before any new target action; unknown writes, forbidden scope, missing fixture/identity/browser or incomplete materials are not bypassed. Unverified candidate dismissals likewise remain current review work.

Local integration tests use the real installed SDK/Cordis serial dispatcher, real Python bridge and engine, and a bounded Agent fixture against fresh loopback counters. The installed `dsh-agent` exports registry/events but no concrete `Agent` constructor, and `dsh-agent-loop` is not installed. These tests do not prove the desktop/live driver closing-to-next-step path, install a driver or invoke an LLM. The public contract is verified separately from that untested host deployment boundary.

The callback respects the actual turn/plugin abort before and after asynchronous work and must not steer after cancellation: public `Agent.send` documents that a late wake can open a later turn (`runtime-types.d.ts:177`). It cannot retract committed assistant text or bypass actual host termination and does not provide an unbounded platform guarantee. Public `maxTokens` limits one model request; the public session event documents that a plugin can continue after a step output cap. This is not a measured overall assessment budget.

**Client half — `src/client.js`.** A browser module in `window.__ModuleLoader__.load` format. It mounts the existing input button through the supported DOM fallback, not a fabricated slot/useProjection subscription. It reads authoritative `/penetration status`, sets explicit on/off, and rechecks. Single-flight, session guards and effect disposal prevent stale/double updates. Missing/old commands produce a visible unavailable/reload error, not guessed local state.

**Optional, not required.** `src/index.mjs` declares only `inject = ['tools']`. The three mode services are probed at runtime by `applyMode`, and a missing service degrades to "mode unavailable" with a logged reason while all registered tool groups still register. Putting them into the top-level `inject` would make them hard requirements and silently disable the whole plugin on a host that lacks `commands`.

The original slot discussion is historical provenance only. Current tests exercise the real fallback, nested kind:error command results, projection replay, session isolation and disposal. Mode never changes project scope or write permission.

## Configuration and process protocol

`workspace` defaults to `~/.dsh/awa-ddd-data`, outside the plugin installation. `pythonExecutable` defaults to `python` on Windows or `python3` elsewhere and must refer to Python 3.10+. `timeoutMs` defaults to 120000 and accepts integers from 1000 to 600000. This is an individual process-call safety deadline, NOT an assessment/turn/token budget or permission to finalize. No directories are created simply by importing or registering the plugin.

`executionBackend` defaults to native; Windows may select wsl with wslDistribution:kali-linux and wslPythonExecutable:python3. The model cannot select these through action input. WSL uses an owned Linux guardian/worker group, unbuffered cancellation/request pipes and a local deadline. Path conversion remains in the group; URL/scope are never rewritten. See `WINDOWS_WSL.md` for network/storage boundaries and real known-PID tests.

The model cannot replace the configured workspace or interpreter through tool parameters. The bridge starts a fixed argument vector equivalent to `python -E -s -X utf8 -B -m awa_ddd --workspace <configured-directory>` with `shell: false`. The packaged directory is the child working directory. One JSON request is sent through stdin; exactly one JSON result is expected on stdout. Input, output and diagnostics are bounded to 1 MiB, 4 MiB and 64 KiB respectively.

Both requests and responses reject lone surrogates and nonfinite numbers instead of silently changing bytes. The file CLI optionally reserves a new `--output-file` before dispatch and writes the UTF-8/no-BOM JSON result directly; the PowerShell wrapper exposes `-OutputFile`. PowerShell 5.1 `>` may re-encode output as UTF-16 despite console settings, so it is not the supported protocol file writer. No profile/global encoding settings change.

Windows process windows remain hidden. Abort, deadline and output-budget failures terminate the owned child tree and reject after the Python process closes. A success-shaped JSON response with a nonzero exit is rejected. An interrupted write may already have affected a test resource. `run.inspect` reads a specific run's persisted status, checkpoints, evidence IDs and error using `project_id` and `run_id`. `run.recover` marks stale running records as interrupted (`stale_seconds` defaults to 300 and must be at least 60); it does not replay requests.

The Python engine returns metadata instead of raw HTTP. Project dispatch uses the shared private-context publisher for all results and errors, including ordinary surface/status/preflight and scenario labels. Known project secrets, encoded/short numeric aliases and secret-bearing locators are removed; only action-schema machine controls and genuinely bound generated handles are restored. This is not a promise to recognize every previously unknown secret embedded in arbitrary prose. The bridge additionally removes credential keys and raw request/response/body fields from canonical JSON, so native rendering and PTC cannot expose them through different projections. Prefer `headers_file` for session registration so credentials do not appear in model tool arguments or conversation logs.

Publication is checked before target execution. A publication failure after an actual dispatch does not roll back its run/evidence or authorize a retry: safe error recovery binds only the invocation's real persisted SC/RUN handle, when available, and requires offline inspection with no automatic replay. Pure offline mutations may be rolled back together with an unsafe projection. Missing legacy context produces explicit unavailable metadata while current required context fails closed.

Public inventories are paged; renderer output is valid JSON capped at 24 KiB with explicit partial markers, while canonical data is not truncated. The action.help exception preserves only static string field descriptions, never actual body/header objects.

Continuation controls and safe cursors are retained independently of list/detail truncation. `render_recovery` re-fetches the current page at a smaller limit before following the canonical next cursor; `required_original_filters` names filters that must be reapplied without echoing sensitive values. `plan.checkpoint/review/finalize` are persisted mutations, not read-only tool calls. Continuation v2 pins `stop_policy:exhaustion_only`, strict boolean stop authority, remaining counts and policy versions in rendering and bounded recovery.

`plan.finalize` accepts only `reason:completed`, after actual complete registered coverage, zero ready/review/blocked/unresolved work, a latest current checkpoint and two complete current evidence-bound frontier reviews. Caller-declared budget/user/authorization/blocked exits are rejected; old partial receipts remain private history without stop authority. Actual explicit user stops and host interruptions preserve checkpoint/draft, not formal completion. A final report independently checks strict completed permission before preparation and again after source preparation; partial/inconsistent stops cannot create final-partial. The supported awaited host hook guards the otherwise-closing active assessment branch but cannot override actual cancellation, undo already published text or guarantee endless turns.

Native errors use the host's own HarnessError. The installed SDK persists name/code, not arbitrary details: safe recovery IDs/help metadata are bounded to 2 KiB and retained on direct errors and in a valid `Recovery` JSON message. Stop rejection also retains the fixed checkpoint/draft recovery instructions when they fit; arbitrary event assertions, credentials or target prose are never recovery authority. Do not claim structured durable details support. Raw stderr and credential values are not recovery channels.

## Build, test and installation

No JavaScript transpilation is required. Node.js 22.19+ and Python 3.10+ are required. The JavaScript AST helper uses the pinned `acorn@8.19.0` dependency; it runs offline after package installation.

```sh
npm ci
npm run check
npm run test:python
npm run pack:check
```

On Windows PowerShell, use `npm.cmd` if the `npm` PowerShell shim is unavailable. Install the archive produced by the successful current check, only in the profile chosen by the user:

```powershell
$package = Get-Content -LiteralPath '.validation/package-check.json' -Raw | ConvertFrom-Json
$manifest = Get-Content -LiteralPath 'package.json' -Raw | ConvertFrom-Json
if ($package.result -ne 'passed') { throw 'The current package check did not pass.' }
if ($package.package -ne $manifest.name -or $package.version -ne $manifest.version) { throw 'The package check belongs to a different release.' }
if (-not $package.source_files -or $package.source_files.Count -ne $package.files) { throw 'Missing current release source bindings.' }
$root = (Resolve-Path -LiteralPath '.').Path
foreach ($source in $package.source_files) {
    $path = [IO.Path]::GetFullPath((Join-Path $root $source.path))
    if (-not $path.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid source binding path.' }
    if ($source.sha256 -notmatch '^[0-9a-f]{64}$') { throw 'Invalid source binding digest.' }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $source.sha256) { throw 'Release sources changed; rerun pack:check.' }
}
if ($package.archive_sha256 -notmatch '^[0-9a-f]{64}$') { throw 'Missing validated archive digest.' }
$archive = (Resolve-Path -LiteralPath $package.archive_path).Path
$digest = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($digest -ne $package.archive_sha256) { throw 'The archive changed after validation.' }
dsh plugin --profile desktop add "$archive"
```

Use the actual `archive_path` and verify `archive_sha256` and the source bindings; an older archive with the same version is not a validation of later source edits. The filename comes from the current package version, not a private timestamp directory. A fresh clone does not contain old `.validation` artifacts or local release archives. Their absence is expected, not a missing runtime dependency; rerun the commands to obtain current results. Replace `desktop` with the profile explicitly chosen by the user when appropriate.

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

`npm run pack:check` automatically creates ignored `.validation` scratch space and an archive with an isolated local npm cache, checks its contents, safely extracts it, and loads the extracted native entry. It invokes the packaged Python engine to create a temporary SQLite assessment, import local OpenAPI and JavaScript documents (including the packaged AST/acorn helper), register an actor/session, compare plan and coverage output, and export a draft report with verified digests. It verifies rejection of unfinished completed finalization, all caller-declared external/blocked reasons and final reporting without a valid receipt, as well as the independent stop guard, help/catalog equality, local runtime metadata, paged inventory/readiness, offline preflight with no run claims, and the extracted UTF-8 input/result CLI. No target requests are sent. SDK dependencies resolve from the development dependencies installed by `npm ci`; this check does not install dependencies from the registry or launch the desktop host. Set `AWA_DDD_PYTHON` to select a different Python executable for this check. Temporary state is removed after the check; a successful run retains its newly generated archive and writes `.validation/package-check.json` with `archive_path`, `archive_sha256` and validated behavior. A failed check overwrites the result status so an earlier success cannot be mistaken for the current result.

The extracted entry also registers its public host hooks, steers an admitted fixture Agent through an actual offline audit, retains caller-blocked ready work as local reconciliation, and refuses to remove a reason-only dismissed discovery clue through administrative review. It does not substitute a fixture Agent for a claim that the desktop driver was run.

Generated scratch data, logs and archives are not GitHub source files or prerequisites for another checkout. Cleanup can remove them; the next check rebuilds them from source. For a manual `npm pack`, use a fresh ignored `dist` or temporary output directory after validation, rather than treating an old local tarball as the current release. Package smoke also requires the shipped help/workflow/WSL modules and UTF-8 file CLI, and exercises plan.build/preflight without network requests. WSL live validation is separate and only runs trusted local version fixtures, not historical targets.

These checks do not claim that the user's live desktop profile has been changed or that external targets have been tested.
