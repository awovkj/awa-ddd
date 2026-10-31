# awa-ddd internal contract

This is the implementation contract for v0.8.0. Native or optional WSL execution uses fixed argv, never a shell. Historical sections remain context; newer constraints take precedence.

## Bridge

Run `python -m awa_ddd --workspace <absolute workspace>` with the project root as cwd (or insert the packaged root in Python sys.path). Stdin is one bounded JSON object `{ "action": "project.create", "args": {} }`. Stdout is exactly one JSON result: `{ "ok": true, "data": ... }` or `{ "ok": false, "error": { "code": "...", "message": "..." } }`. Diagnostics go to stderr. A nonzero exit indicates failure. Actions are explicit; there is no arbitrary shell-command tool.

`src/actions.mjs` is shared by native schemas/bridge. Python `contracts.py` implements the corresponding 58-action help catalog; real cross-language tests require equality. action.help supplies required fields/enums/examples with no project or target traffic. Action-specific top-level fields are rejected rather than silently ignored; use `input`.

Protocol strings/keys must contain valid Unicode scalars; finite JSON numbers and bounded depth/items are checked before dispatch. The Python CLI owns UTF-8 stdout/stderr even without `-X utf8`. File helpers accept UTF-8 BOM input, use bounded regular-file reads, and optionally create a new UTF-8/no-BOM result file before dispatch. Existing result files are never overwritten; PowerShell redirection is not an encoding-safe result channel.

All actions except project.create/list, action.help and runtime.probe require args.project_id. Workspace/backend/interpreter are host configuration, never target-derived. IDs match `[a-z0-9][a-z0-9_-]{0,63}`. New projects default scope to their target URL path prefix, not an implicitly wider origin; empty scope is invalid. Existing configured scopes are not rewritten.

## Storage API (root owns awa_ddd/store.py)

`Project(workspace, project_id, create=False)` exposes:

- `.base: pathlib.Path`, `.config: dict`
- `.get(kind, id, required=True) -> dict | None`
- `.list(kind) -> list[dict]`
- `.put(kind, record, create_only=False) -> dict` (record must contain id)
- `.event(event_type, payload) -> None`
- `.connection` (SQLite, row factory Row; use only if an operation must be transactional)
- `.id(prefix) -> str`

Kinds: `operation`, `actor`, `session`, `resource`, `obligation`, `run`, `evidence`, `decision`, `finding`, `candidate`. All objects have id. Runtime mutation and relationship checks are enforced by engine actions, not by accepting arbitrary dictionaries from callers. Raw evidence is immutable and hash-verified. Imported records never become verified decisions automatically.

## Candidate lifecycle (root owns awa_ddd/candidates.py)

`candidate` records are discovery clues, never evidence. They carry a stable ID derived from the source digest + locator, so re-importing identical material cannot proliferate rows, and a human disposition survives a repeated import. States are `unverified`, `linked`, `dismissed`.

`candidate.list(project, {status, kind, offset, limit})` is read-only and paged (`limit` 1..500) and reports per-state counts. `candidate.inspect` returns the full record plus its linked operation. `candidate.link` records lineage from a clue to an already-registered `operation_id`, optionally to a concrete `input_location`/`input_selector` that must already exist on that operation; the clue URL must equal the operation URL. `candidate.dismiss` requires a reason and is explicitly not a test. `candidate.reopen` requires a reason and drops the previous link.

Linking never registers an input, closes an obligation, or creates evidence or a decision. `store_candidate` is the single write path shared by `surface.import` and the legacy importer; it merges new sources into an existing row without overwriting status.

Important entity fields:

- operation: id,url,method,protocol (`http`/`graphql`),operation_name,content_type,inputs,sources,auth (`public`/`authenticated`/`restricted`/`unknown`),allowed_roles,ownership (bool),consumer_state
- input: name,location,selector,source (`declared`/`observed`/`inferred`),consumer (`unknown` or named category), optional explicit `test_families` and `schema_branch`
- source: path,sha256,locator,trust (`declared`/`observed`/`mock`/`unknown`)
- actor: id,label,tenant_id,roles (list)
- session: id,actor_id,generation,headers (private),verified_at,expires_at,verification_evidence_id; never return headers in tool summaries
- resource: id,owner_actor_id,tenant_id,operation_id,state
- obligation: id,operation_id,kind,actor_id,baseline_actor_id,resource_id,input_selector,status (`open`/`blocked`/`not_applicable`/`evaluated`),reason,decision_id
- evidence: id,kind,operation_id,session_id,actor_id,session_generation,resource_id,artifact_path,sha256,complete,created_at,trust; raw HTTP request/response are in the artifact
- decision: id,obligation_id,oracle,outcome (`confirmed`/`refuted`/`inconclusive`),evidence_ids,reason,mode (`machine`/`analyst`),created_at
- finding: id,title,category,severity,decision_id,evidence_ids,origin,status,limitations,created_at

## Discovery API (discovery agent owns)

`discover(path, format, base_url=None) -> {operations: [...], candidates: [...], limitations: [...]}`.

Read-only and bounded. No network. Formats: openapi, javascript, har, artex, sarif (source/binary optional). Operation hints omit id, engine assigns stable identity. Inferred and mock artifacts are candidates, not confirmation evidence. Preserve input JSON Pointer, media type and schema-branch information where applicable. Unresolved methods stay candidates. Schema/spec declares applicability, not runtime success. Never copy credential values into normalized output. JS AST may use a packaged Node/acorn helper with bounded output; absent parser must return an explicit limitation rather than pretending regex matches are full AST analysis.

## Reporting/import API (quality agent owns)

`coverage(project) -> dict`: use `awa_ddd.engine.evaluate_coverage(project)` as the single evaluator. No second implementation of completion logic.

`build_report(project, output_dir=None) -> dict`: default `<project.base>/reports/<timestamp-id>/report.md, summary.json`. Include scope, operation/input counts, genuine unresolved gaps, confirmed findings and source trust. Do not export raw credentials/evidence bodies. Unknown/blocked must remain visible. Return paths and report digest; exported report is a snapshot.

`import_pentest(project, source_path) -> dict`: bounded read-only legacy import into the new project, never change source. Import inventory as operations via `awa_ddd.engine.register_operation(project, hint)`; import finding metadata into `candidate` records with legacy status/origin and explicit unverified state. Copy no sessions/credentials/target evidence by default. Legacy tested/confirmed does not satisfy new obligations. Keep source SHA256 and IDs. Read inventory/config/findings only, reject symlink/path escapes. Report limitations and counts.

Root also implements `evaluate_coverage(project)` returning `{operations,inputs,obligations,total,evaluated,open,blocked,not_applicable,coverage_ratio,gaps:[...],gap_dependencies,findings:[...],limitations:[...]}`. Evidence/session invalidity can reopen a previously evaluated obligation; this function is read-only. `plan.list` and `report.coverage` consume the same gaps.

## Gap projection (M2-02)

Every gap carries `gap_id` (stable per obligation), `status`, `reason_code`, `reason`, `next_action`, `obligation_kind`, and `operator_reason` when a human wrote one. `reason_code` is a closed set: `evidence_invalid`, `decision_missing`, `obligation_superseded`, `exclusion_evidence_invalid`, `not_started`, `blocked_precondition`. `next_action` derives from the reason code; the obligation kind may refine it only while the reason is `not_started`, so a broken evaluation always points at `repair_evidence` instead of hiding the repair behind a setup label. `gap_dependencies` aggregates pending gaps per next action. Gaps sort deterministically by `(operation_id, obligation_kind, gap_id)`.


## SQL and runtime proof (0.5.0)

SQL input confirmations accept three channels, all with operation/input/identity binding:

1. `sql_metadata` direct recovery: database/current_user, exact recovered value, normal business baseline and input/identity controls. The equality predicate remains valid.
2. `sql_metadata` with `tool_run_id`: an intact successful metadata-only sqlmap run that actually returned database()/current_user() is direct confirmation, including ORDER BY / LIKE injection points where a constant predicate degenerates. `negative_value` + numeric equality predicates are an optional strengthening control.
3. `error_channel`: baseline/recovery/negative captures, metadata_type, exact expected_value and a response_pattern with a named `(?P<value>...)` group matching DBMS error text; the value must not be in baseline, negative or the submitted input.

Write-side SQL uses `sql_evidence{control_evidence_id,injection_evidence_id,observed_change,input_location,input_selector,response_selector}`. Require registered SQL input, same actor/session/generation, ordered independent writes, only that input changed, and discriminating finite business values, not message/status/nonce/timing or generic GET response differences. Proof version 2 rechecks actual selected values; old missing fields become historical with sql_behaviour_proof_required, never fabricated migration.

Analyst XSS requires a digested browser page_visit, an application-triggered matching dialog on the consumer page and a marker bound to same-origin captured attack input. A consumer page reached through a successful browser action is valid; the dialog must occur at or after that arrival action. Imported Playwright MCP output keeps imported_mcp provenance and explicit analyst review.

## Session and evidence lifecycle (0.5.0)

`identity.session renew:true` keeps session_id, generation, headers and verification, extends `expires_at` only, and rejects credential changes with `renew_shape`. Default TTL is 7200 seconds. `session_valid` gates issuing new requests; `verify_current_evidence` tolerates TTL expiry but still enforces generation/actor binding and an intact verification artifact. `evidence.inspect` reports `integrity`, `lineage`, `session_status` and `usable_for_new_requests` separately.

## External MCP and tool runs (0.5.0)

tool.probe discovers Yakit through actual stdio MCP initialize/tools-list exchanges or executes sqlmap version argv. Successful local paths are saved as tool_config in the project. tool.yakit_replay supports one public GET packet via the advertised http_fuzzer with `fuzzTagMode: standard` and redirect controls, and records `transport_warning` when a template prefix is left unrendered. tool.sqlmap supports one registered GET query input or a permitted POST JSON/form SQL input with a matching disposable fixture; only database/current-user metadata is queried. POST repeats can mutate business state, so preflight permission/effect/resource gates apply. DBMS names are case-insensitive and common aliases are accepted.

External executions use kind external_tool run records, start/finish events, isolated logs and digested execution artifacts. Parsed metadata is a candidate; discovery/execution does not close HTTP obligations. tool.inspect checks original execution metadata and log digests and exposes partial files after interruption. The outer bridge owns process-tree cancellation; run.recover never automatically replays uncertain work.

page_visit, tool_config and immutable finding_revision are additional kinds. Report format 4 includes current impact/remediation/proof/evidence references, lifecycle corrections, method distinctions and tool diagnostics. SQLite schema version 1 stays compatible through additive fields/kinds; existing history is preserved.

## 0.6.0 Integrity And Workflow

- Actor subject/tenant/roles changes increase security revision; verified sessions/captures bind its signature. Label-only updates do not. Boolean subjects cannot impersonate integer identities.
- Fixture identity/binding changes invalidate associated lineage; ordinary state or unrelated fixtures must not switch established ownership representatives and supersede valid proof.
- Credential header names are explicit and snapshot-bound to actual bytes. Conventional names default; custom X-Actor/X-User must be declared. Other session headers remain business controls and must match in authorization comparisons, including legacy decisions.
- Restricted authorization requires server roles_selector for every nonanonymous actor, including a verified empty set. roles=[] without it is unknown, not denied permission. Authenticated ownership can use distinct verified subjects without invented roles.
- TTL gates new requests, not historical evidence. Minimal renewal is session_id/renew:true; credentials/classification remain unchanged.
- http.preflight reuses capture's gates with zero request/run/artifact creation. body_file is explicit, bounded, link-checked raw bytes.
- Scenarios: 1..25 steps, concurrent 2..40, <=200 attempts. Static failures/Pointer syntax are checked before execution; future data stays deferred and is fully rechecked. Target variables cannot select local files, internal IDs, sessions or execution policy. Failures retain run_id/step/phase/attempt context; uncertain work is never replayed.
- plan.next is bounded readiness, not approval/evidence/coverage. plan.build keeps integer obligations and exposes obligation_items pages. plan.list/report.coverage share evaluator pages; full library/report snapshots remain on disk.
- finding.update appends immutable finding_revision with reviewer/reason. Lifecycle active/withdrawn/superseded is separate from original confirmed status. Replacement must be distinct/current/in this project; cycles and proof edits fail. current requires evidence_current and active lifecycle.
- tool.artifact only reads named digest-checked files belonging to a run. Full text is redacted before character pagination; traffic bodies/private headers are omitted and output remains untrusted. Successful sqlmap candidate IDs are strings, not dicts.
- WSL supervises one owned Linux group including path conversion/descendants. Unbuffered control/request pipes avoid shutdown locks and backpressure blocking deadlines. No generic shell/scanner command adapter is added.

## 0.6.0 Continuation Hardening

- An established session is bound to its verified endpoint origin, including scheme/port. Native HTTP and scenario preflight now enforce this as browser/external already did; re-verification cannot move a generation to another origin. Initial explicit verification may bind a new session to a scoped endpoint. Historical cross-origin captures remain readable but not current.
- Test resources require one concrete query value, unique multipart fields/disposition parameters and unambiguous JSON key selection. Quoted/unquoted/folded MIME parameters all participate in duplicate checks. Broad multipart aliases matching multiple parts fail; pointers select precise JSON members. Current evidence rechecks actual bindings even when the capture-time resource signature still matches.
- Fixture-free `state_scope:actor` writes require a concrete HTTP path and no actual query/body. Empty inventory does not waive this check. Business inputs use an explicit test resource. Historical fixture-free business writes become historical; no resource or proof is fabricated during upgrade.
- Tool target execution records digested capture-time actor, generation, credentials/classification, selected input policy, endpoint origin and actual request context. Log digests are part of the immutable execution artifact. `tool.inspect` distinguishes byte integrity, lineage and confirmation eligibility. Legacy runs without snapshots cannot be upgraded by changing mutable run fields.
- SQL transcript confirmation rechecks every control against the tool's actual path, non-tested inputs, body, business headers and baseline tested value. TTL expiry does not invalidate historical identity proof, but actor/credential/input/context changes do.
- Plain HTTP MCP text and traffic views omit bodies/private headers. Unescaped sqlmap traces can contain fake markers inside bodies; only initial identifiable framing is displayed, with explicit suffix omission and untrusted marker counts. This is not a complete packet view.
- `surface.inspect` overlays the same evaluator used by plan/report. `plan.next` chooses same-origin sessions, preserves multiple sessions per actor and recommends adapters only for supported profiles. Public input tests do not inherit arbitrary credentials. Invalid `evidence.inspect` branches explicitly return unusable lineage/liveness fields.
- Delegated work shares backend/workspace/project and concrete entity references, never plaintext credentials. Workers return persisted IDs and unresolved prerequisites. Shell-only observations stay unverified until bound; uncertain executions are inspected, not replayed.

## 0.8.0 Formal Stop Contract

- `continuation` is shared by the evaluator, readiness, audit and reports. An empty rendered page, raw traffic count, finding count or draft report is not exhaustion. Rendering pins small control fields and supplies current-page recovery before following a cursor that omitted displayed rows.
- `plan.checkpoint` appends an immutable round. Progress uses current semantic decisions, applicability/frontier and resolved administrative work, not duplicate captures or new IDs for identical decisions. A new checkpoint resumes the project and invalidates the previous stop record.
- Completed/blocked finalization requires zero actionable tasks and two current, evidence-bound discovery/category/page scope reviews. Reviews are analyst boundary attestations, not independent experiments. Declared blockers and external user/budget/authorization exits are not authenticated host facts; external exits always remain partial.
- `plan.review` only handles source-bound administrative records. It never closes security obligations or candidates, never archives running runs or valid unadopted browser visits, and reopens reviewed observations when their bytes/lineage become invalid. Failed native/scenario runs remain in the uncertainty ledger.
- Uncertain writes require captured fixture context and explicit readback bindings to later same-identity, read-only business-state observations. A repeated POST, a 200 status, unsupported browser/legacy context or over-budget material cannot prove reconciliation. No request is replayed by a closure action.
- Optional analyst XSS obligation binding rechecks exact input controls, actual consumer runtime and identity without claiming machine provenance. Static/no-dialog negatives cannot close XSS. `report.build` defaults to draft; final stage validates a current finalization before preparing any files. All stop prose is redacted in public returns; private source records remain unchanged.
- TscanPlus uses an explicit loopback Streamable HTTP endpoint, private catalog/exchange artifacts and a nondefault namespace. Only typed single-request and local result-query profiles are adapted, never generic MCP forwarding or implicit POC/crack/crawl. Result rows are safe unverified candidates; missing pages and unverified remote execution cannot be text-archived as complete. A closed MCP connection is not proof of remote cancellation. See `TSCANPLUS.md`.
