# awa-ddd internal contract

This is the implementation contract for v0.9.0. Native or optional WSL execution uses fixed argv, never a shell. Historical sections remain context; newer constraints take precedence.

## Bridge

Run `python -m awa_ddd --workspace <absolute workspace>` with the project root as cwd (or insert the packaged root in Python sys.path). Stdin is one bounded JSON object `{ "action": "project.create", "args": {} }`. Stdout is exactly one JSON result: `{ "ok": true, "data": ... }` or `{ "ok": false, "error": { "code": "...", "message": "..." } }`. Diagnostics go to stderr. A nonzero exit indicates failure. Actions are explicit; there is no arbitrary shell-command tool.

`src/actions.mjs` is shared by native schemas/bridge. Python `contracts.py` implements the corresponding 60-action help catalog; real cross-language tests require equality. action.help supplies required fields/enums/examples with no project or target traffic. Action-specific top-level fields are rejected rather than silently ignored; use `input`.

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

`candidate.list(project, {status, kind, offset, limit})` is read-only and paged (`limit` 1..500) and reports per-state counts. `candidate.inspect` returns the source record plus its linked operation, not private closure context. `candidate.link` records lineage from a clue to an already-registered `operation_id`, optionally to a concrete `input_location`/`input_selector` that must already exist on that operation; the clue URL must equal the operation URL. `candidate.dismiss` requires a reason and is explicitly not a test. Reason-only and legacy dismissals remain unresolved discovery review. Optional `basis:outside_scope` requires an actual concrete URL outside declared scope, not a mutable caller exclusion; `basis:duplicate_operation` also requires an exact ordinary source-matching `operation_id`, including method/protocol/input/schema/declarations and all current typed obligations evaluated with a security plan. Dynamic/private locators, scanner findings and a baseline alone do not qualify. Source context and real scope/coverage are revalidated on every audit; imported receipts are stripped and private source context is not public. `candidate.reopen` requires a reason, drops the previous link/closure and records the prior lifecycle state.

Linking never registers an input, closes an obligation, or creates evidence or a decision. `store_candidate` is the single write path shared by `surface.import` and the legacy importer; it merges new sources into an existing row without overwriting status.

Rejected import wrappers use their nested hint source digest, locator, URL and method in candidate identity. An old collapsed wrapper ID is reused only for the exact original source-bound hint; distinct previously omitted siblings obtain distinct IDs. No old candidate is deleted or rewritten, and an old dismissed label never imports strict closure authority.

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

## 0.9.0 Exhaustion-Only Stop Contract

- `continuation` is shared by the evaluator, readiness, audit and reports. An empty rendered page, raw traffic count, finding count or draft report is not exhaustion. Rendering pins small control fields and supplies current-page recovery before following a cursor that omitted displayed rows.
- `plan.checkpoint` appends an immutable round. Progress uses current semantic decisions, applicability/frontier and resolved administrative work, not duplicate captures or new IDs for identical decisions. A new checkpoint resumes the project and invalidates the previous stop record.
- Automatic `plan.finalize` accepts only `reason:completed`. Its shared predicate requires nonempty operations, complete evaluated coverage, zero ready/review/blocked/unresolved work, the latest current checkpoint and two complete current evidence-bound discovery/category/page frontier reviews. Blocked declarations do not count as complete frontier rounds. Reviews remain analyst boundary attestations, not independent experiments or proof of unknown-surface absence.
- Continuation contract v2 publishes `stop_policy:exhaustion_only`, policy version 1, `automatic_stop_allowed` and `legacy_finalization_ignored` as strict booleans. Caller-declared blocked/budget/user/authorization exits and extra force/override/event fields cannot establish stop authority. An actual explicit user stop or host interruption can preserve checkpoint/draft only. The rc.3 public awaited `agent/turn-stopping` seam audits real-agent-bound active work and submits plugin-sourced steering before an otherwise completed turn closes; it does not retract streams, override actual cancellation or create new authorization.
- Legacy partial stop records are retained unchanged but ignored for current authority. Legacy completed records must pass the same actual current predicate, receipt flags, engine-gate basis and integer-zero remaining counts. A new checkpoint without current frontier cannot borrow old frontier completion, and a new stop cannot silently revive an earlier valid receipt after a later incompatible receipt.
- Caller `not_applicable` receipts authenticate their supporting observation, not the claim that an entire obligation is inapplicable. They remain immutable declarations but create `unverified_applicability` review work. Deleted/omitted concrete input families/branches or reduced access/ownership boundaries create `scope_reduction` work. Both counters participate in completion, continuation and strict exhaustion; neither kind can be text-archived through `plan.review`. Current consumer labels cannot rewrite a historical family. Restore and actually assess the authorized boundary instead of using all-N/A or queue pruning as completion.
- Caller-only blocked obligations and administrative rows remain actionable offline reconciliation when actual scope/session/fixture/browser/material/write prerequisites allow it. Raw declarations remain recorded; `blocker_reconciliation_required`, `underlying_queue_status` and generated local reopen templates never approve a request or widen authorization. Readiness and current administrative review/adoption gates are shared, including revalidation of weaker legacy reviewed receipts. Genuine missing or uncertain prerequisites remain blocked.
- A query-free inventory locator rejected only by an exact-query scope retains offline source/binding preparation rather than a blocked-only queue. `scope_binding_review_required` hands off to `surface.inspect`, then an independently supplied current complete URL and `http.preflight`. No original query is copied into the template, no scope is widened and no request is sent; true identity/fixture/write/path/page blockers stay blocked. Required browser policy stays at prepare with `invoke_now:false`; qualified existing evidence can still be reviewed offline.
- `plan.review` only handles source-bound administrative records. It never closes security obligations or candidates, never archives running runs or valid unadopted browser visits, and reopens reviewed observations when their bytes/lineage become invalid. Failed native/scenario runs remain in the uncertainty ledger.
- Uncertain writes require captured fixture context and explicit readback bindings to later same-identity, read-only business-state observations. A repeated POST, a 200 status, unsupported browser/legacy context or over-budget material cannot prove reconciliation. No request is replayed by a closure action.
- JSON business predicates use shared recursive type-aware equality: booleans never equal numbers, valid numeric `1/1.0` and zero remain supported. The same rule revalidates historical decisions and readback receipts. Metadata-only nested containers and generic ACK/denial string arrays cannot assert fixture state. Actual string/numeric resource-ID compatibility remains, but JSON booleans cannot be stringified into IDs.
- Optional analyst XSS obligation binding rechecks exact input controls, actual consumer runtime and identity without claiming machine provenance. Static/no-dialog negatives cannot close XSS. `report.build` defaults to draft; final stage checks strict completed permission, all remaining counts, scope and snapshot/checkpoint/receipt bindings before preparing materials and rechecks after preparation. It rejects inconsistent/partial stops instead of generating final-partial. All stop prose is redacted in public returns; private source records remain unchanged.
- TscanPlus uses an explicit loopback Streamable HTTP endpoint, private catalog/exchange artifacts and a nondefault namespace. Only typed single-request and local result-query profiles are adapted, never generic MCP forwarding or implicit POC/crack/crawl. Result rows are safe unverified candidates; missing pages and unverified remote execution cannot be text-archived as complete. A closed MCP connection is not proof of remote cancellation. See `TSCANPLUS.md`.

## 0.9.0 Evidence and Publication Boundaries

- `publication.py` wraps all project dispatch results and errors with one project-aware private credential/browser context. Action-specific typed controls are restored after redaction, never arbitrary fields named status/count/id; caller-selected IDs, step labels, schema branches, domain booleans and numeric secret aliases remain content. Generated local handles require private mint provenance and the actual project entity/function. Required context is checked before execution. Offline mutations may roll back together with publication, but dispatched HTTP/scenario/browser/tool runs and evidence retain their real checkpoints; post-dispatch publication failure gives a verified invocation-bound SC/RUN recovery handle when one exists, fixed inspect/no-replay guidance and no inferred concurrent run.
- JSON response decoding shares the bounded unique-key/finite/Unicode input checks. A parsing error is never a missing negative-control field. Revalidation applies to legacy JSON-based decisions without imposing JSON parsing on legitimate text-regex evidence.
- Shared redaction checks bounded percent decoding in direct APIs and disk reports too. Known private content or still-unresolved nested encoding is omitted, not exported as a reversibly encoded secret; such locators cannot produce a manual request template. Privacy flags are applied after caller fields and cannot be overwritten by their order. Original artifacts remain unchanged, and stable benign encoded paths/ordinary nonce values are not indiscriminately removed.
- Strict content covers short embedded credentials, JSON keys, numeric aliases and all supported text/JSON/XML/form/multipart bodies. Only actual bound ledger/file facts qualify as report control exceptions, not caller UUID/hash-looking content or source counts. `publish_report_summary` binds reproduction members to real bytes and F/E order and rebuilds fixed curl/sqlmap profiles; original arbitrary commands are not restored. Unknown legacy browser context produces metadata-only reports with no request/body files or commands, not a stop receipt.
- Authorization needs successful protected business data, not an HTTP-200 denial flag, boolean, generic error text or metadata-only object. Finite numeric business zero remains meaningful. The evaluator and historical confirmation validator share the same rule.
- Explicit English/Chinese denial and generic ACK values use Unicode-preserving control normalization instead of dropping all non-ASCII letters. Authorization, semantic-negative sensitivity, state assertions and uncertain-write readback use the shared meaningful-state rule during fresh and historical revalidation. Actual non-ASCII business text, named booleans, finite zero, valid large integers and domain states remain supported.
- A finite generic signal selector cannot supply business sensitivity or state proof. An explicit denied HTTP status does not refute access/ownership while selected protected business data remains present; legacy weak denials reopen. Complete plain/metadata-only denials remain valid controls, and malformed structured bodies fail parsing instead of becoming absent negative-control fields.
- Streamable HTTP counts each blocking body read before rechecking the original client deadline, then classifies EOF. Watchdog-induced late EOF/partial data cannot claim a complete transcript or masquerade as ordinary protocol EOF; genuine early EOF and short Content-Length retain their distinct incomplete/result status. Per-call deadlines do not establish an assessment stopping budget.
- Fixture-free actor writes have no declared input of any location and no actual business query/body/header/cookie. Normal management headers and the exact verified credential classification are allowed; private executor framing must have its fixed values. Unsupported header/cookie resource bindings stay blocked. New preflight and historical evidence checks use the same actual-header rule.
- Native browser dispatch first persists an owned run. Timeout, invalid output and execution failure retain interrupted state and a safe run reference, not replay permission. Unknown writes without a captured fixture cannot be archived by text.
- Public browser/page/run/plan/report projections learn private credential and fill context while retaining original raw artifacts for proof. Context integrity is checked, sensitive numeric fields are handled by field, and opaque handles/digests/counts remain stable. Old unrecoverable fill context exposes only safe metadata with an unavailable marker; new missing/changed required context fails closed.
- New credential/fill integrity inputs contain a private CSPRNG nonce; it never enters target headers/arguments. Renewal preserves the generation's nonce and new generations replace it. Legacy no-nonce verification remains compatible. Public pure credential/context digest fields are omitted, preventing cheap PIN/OTP dictionary checking; ordinary material hashes are integrity metadata, not encryption or server authentication. Generated completion/continuation/receipt enums remain machine values even when a fill secret happens to equal an enum word.
