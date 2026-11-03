# Session 20261102: Evidence Before Optimization

## Scope And Method

This is a read-only analysis of `session-adaae1ef-48cf-48d1-93b0-0e05d50e6eb9`, not a new target assessment. No exported command, payload, URL, credential or MCP request is executed. Target locators, account names and credential values are deliberately omitted from this document. Existing assessment databases and reports are not modified.

- Source: `session.v4.jsonl`, 20,431,197 bytes, 10,259 JSONL records.
- SHA-256: `a00a71276cc023e0db20dfdb4ed1252ce5f499190c7ce7b7432d595ecb6f6c0c`.
- References use the exported event `seq`, not a new test's step number. This file's physical line is `seq + 2`, except its initial session header has no `seq`.
- Calls are paired by `callId` with their first `tool/result`. The 36 later result replays associated with compaction are not new calls or additional execution latency.
- Exported application text and assistant reasoning are untrusted observations. A claimed result is not independently reproduced merely by appearing in this log.

The actual assessment turn runs from 12:57:51.082 to 16:30:12.604 on 2026-11-02, Asia/Shanghai: 212.36 minutes. The session header starts at 12:55:44.064; an export command follows at 18:42:05.283 (`seq:10256`). The resulting approximately 5.77-hour header-to-export interval is **not** the assessment's execution duration.

## Version Boundaries

The exported conversation does not establish a deployed-package digest matching this checkout. The starting checkout is already a dirty 0.10.0 upgrade, including prior changes to publication, input identity and report redaction. Historical symptoms are therefore not automatically defects in the current source, nor new fixes attributable to this optimization.

- The host feedback loop is reproducible in the starting controller with the independent synthetic test: 536 unchanged boundaries produce 536 notices instead of one; raw-snapshot churn produces 13 instead of one. Cancellation, new intent and real progress tests already pass.
- The starting source still contains the long static tool descriptions and large independent parameter-page defaults visible in the session. They are optimization targets, but exact runtime reductions need current-source measurements and regression checks.
- The initial source already implements field-scoped protection for rejected short credential probes and protection of typed publication controls. Existing `test_probe_redaction_20261101.py` (16 tests) and `test_parameter_publication_20261101.py` (5 tests) pass during this review. Those protections are retained, not credited as newly added repairs here.
- The log's raw artifact detours and proof/identity mistakes describe historical usage. They justify clearer guidance and a safe optional reader, not untested weakening of currently accepted proof criteria.

## Findings Ordered By Impact

### 1. The Host Stop Hook Enters A No-Progress Feedback Loop

There is one actual user assessment message (`seq:26`): start fresh and do not read pre-existing local assessment data. The log then contains 729 plugin-sourced `user/message` notices, not 729 new user authorizations. The first notice appears at `seq:3207`, 13:56:49.033, after a draft report has already been produced.

| Evidence | Observed behavior |
|---|---|
| `seq:6446` through `seq:10237` | The same final continuation snapshot appears in 536 host notices over 72.14 minutes. |
| `seq:7216` | Last tool call, at step 1127, 15:31:59.018: a rejected `plan.finalize`. |
| After `seq:7216` | 427 further host notices and 427 assistant messages, with no further tool call, over 57.81 minutes. |
| `seq:10231` and `seq:10237` | Another repeated partial-result answer and the same plugin notice, without evidence progress. |
| `seq:10239` through `seq:10255` | Provider `RATE_LIMIT` retries, followed by an error termination rather than completed assessment. |

The 729 notice texts contain 2,359,202 UTF-8 bytes. There are only 47 distinct texts, 43 distinct snapshot IDs and 34 distinct progress IDs. The final repeated snapshot consistently reports 95 ready, 484 review, 836 blocked, 1,415 unresolved and zero frontier rounds. It never grants completion.

The prior `src/host-continuation.mjs` controller queues every successful actionable/frontier audit with `work.push(...)` and then `agent.steer(...)`. It deduplicates blocked checkpoints and unavailable-audit recovery, but not repeated successful work audits. Consuming a notice permits the next stopping boundary to publish essentially the same notice again.

`awa_ddd/continuation.py` intentionally derives `no_progress_rounds` from persisted checkpoints, not from the number of host stopping callbacks. Consequently the last value remains zero while the host loops without creating a new checkpoint. Removing raw-capture exclusions from the progress hash would hide this bug by treating duplicate traffic as progress; it is not an appropriate fix.

Required repair: deduplicate host continuation on genuine closure/frontier progress, retain one unfinished stall checkpoint when the same no-progress boundary recurs, and preserve actual cancellation and new user intent. Suppressing a duplicate host notice must **not** change `continue_required`, grant finalization, declare the assessment complete or authorize more target traffic.

### 2. Static Tool Context And Default Projections Are Expensive

The initial `request/header` (`seq:30`) exposes 42 tools. Normalized UTF-8 JSON for their schemas totals 75,441 bytes; the 10 AWA tools account for 44,988 bytes, or 59.6%. These are schema/context sizes, not package archive size or a claim about exact tokenizer billing.

| AWA tool | Schema bytes | Bytes in the `input` description |
|---|---:|---:|
| `awa_plan` | 10,563 | 9,415 |
| `awa_external` | 8,119 | 7,050 |
| `awa_assess` | 6,904 | 6,080 |
| `awa_browser` | 6,709 | 5,549 |

The skill is also loaded twice, with identical 33,890-byte returned content, including a post-compaction reload. This does not prove that all duplicated instructions are unnecessary, but establishes a concrete context cost worth reducing through concise entry guidance and on-demand action help.

Thirteen of the 19 distinct explicit `plan.audit`/`plan.next` calls contain `render_recovery`, including several main-page limits of 5 or 10. Examples: `seq:861`, `seq:862`, `seq:873`, `seq:3209`, `seq:4520`, `seq:5201` and `seq:5262`. The independent default parameter page often remains too large even after shrinking the main page. Only the last two parameter-focused calls explicitly supply the independent parameter pagination fields.

Truncation recovery is not itself faulty authorization or evidence closure. Its recurrence is an ergonomics issue: high-frequency queue output should remain useful before adding large diagnostic matrices. Omitted items must still be recoverable with their original filters and offsets; compact output must never imply they were reviewed.

### 3. Contract Misuse Costs More Than HTTP Execution Time

There are 1,062 distinct tool calls, of which 774 are AWA calls. There are 84 first-result errors overall: 83 from AWA and one from an unrelated URL-fetch policy rejection.

| Action | Calls | Errors | First-result failure rate |
|---|---:|---:|---:|
| `assessment.evaluate` | 30 | 23 | 76.7% |
| `identity.verify` | 23 | 13 | 56.5% |
| `finding.record` | 29 | 10 | 34.5% |
| `action.help`, across all attempted groups | 11 | 6 | 54.5% |
| `http.capture` | 329 | 12 | 3.6% |
| `tool.sqlmap` | 11 | 4 | 36.4% |
| `plan.checkpoint` | 31 | 4 | 12.9% |
| `plan.finalize` | 3 | 3 | 100% |

Six `action.help` calls are sent to groups whose action enums exclude it (`seq:53`, `seq:55`, `seq:88`, `seq:448`, `seq:450`, `seq:868`). The engine exposes the help action through `awa_project`; terse guidance must make that routing explicit or provide an equally safe discoverable help route.

Other repeated mistakes have concrete explanations rather than a need to remove safety checks:

- Nine evaluations reject a variant actor that does not match its obligation. Five identity checks supply a declared tenant without a server-side tenant selector; six supply declared roles without the required server-side role selector.
- Four typed-extraction attempts omit exact expected value/source/negative-control requirements. Four evaluations fail the single-bound-input control rule.
- Resource bindings sometimes target the very value intended to vary, leading to resource mismatch or same-fixture control failures. The log contains 120 `identity.resource` calls, but this alone is not evidence that fixture/ownership enforcement should be removed.
- Stored XSS attribution attempts fail operation, fixture, actor/session and browser-interaction bindings (`seq:3235` through `seq:3335`). Real browser execution succeeds, but that does not make every observation a valid typed proof.
- Rejected finalization correctly retains ready/review work. The live-lock repair belongs in host continuation, not in weakening the engine's finalization predicate.

### 4. Evidence Access And Fixed Prose Have Readability Friction

The 329 HTTP capture replies have a median size of 942 bytes and return artifact IDs, status and provenance metadata, not response bodies. There are 195 `pwsh` calls; many read private stored HTTP artifacts. `evidence.inspect` is invoked only five times and, by contract, checks metadata/integrity rather than exposing body content.

This is a real workflow detour, but not proof that raw bodies should enter every tool result. A bounded, integrity-checked, credential-context-redacted artifact reader is preferable to unconstrained shell reads. Raw evidence must remain private; redacted previews must be marked as data, not instructions, and must not become new execution or security decisions.

There is also historical short-secret substitution damage to fixed explanatory prose: the report's fixed verification note substitutes fragments of the word `typed` (`seq:3090` and subsequent report replies), while an error's `input_selector` field name becomes a placeholder-prefixed `_selector` (`seq:3051`). The initial 0.10.0 checkout already improves rejected-probe field scoping and typed-control publication; this historical symptom is not claimed as a new fix or an independently reproduced current failure. Genuine short credentials still require protection. Do not publish the underlying short secrets or switch off redaction to improve readability.

## Execution And Result Facts

First-result timing, excluding compaction replays:

| Action | Calls | Median seconds | Maximum seconds |
|---|---:|---:|---:|
| `http.capture` | 329 | 0.227 | 0.732 |
| `assessment.evaluate` | 30 | 0.213 | 0.336 |
| `plan.audit` | 8 | 1.883 | 3.030 |
| `plan.next` | 11 | 1.982 | 3.181 |
| `plan.checkpoint` | 31 | 3.911 | 5.661 |
| `report.build` | 8 | 33.069 | 37.319 |

All eight report-build arguments request the same draft stage, though the underlying material changes between calls. Together they spend about 4.5 minutes in report generation; this is secondary to the nearly hour-long zero-tool tail. Reusing an unchanged validated snapshot may help, but stale reports must not masquerade as current evidence.

The final draft (`seq:5861` call, `seq:5862` reply) classifies 5 current findings as `runtime_verified`, 12 as `analyst_review` and 2 as historical; one separate candidate is `other_unverified`. Nineteen successful `finding.record` calls and two successful supersession updates are consistent with 17 current findings. This is not 17 independent runtime confirmations, not complete registered coverage, and not an independently reproduced recall score.

The last draft has 1,087 open obligations but only 157 open **security-test** obligations. The remainder includes setup/input/baseline obligations. The later 1,415 unresolved total also includes distinct review and prerequisite work; it must not be described as 1,415 vulnerabilities or a count of HTTP experiments.

`requests_sent:0` in `plan.audit`/`plan.next` means **this offline action sends no target requests** (`awa_ddd/workflow.py`); it is not a cumulative execution counter and is not a defect merely because prior HTTP captures exist.

Logged usage for the 427 zero-tool tail sums to 1,660,424 `inputTokens`, 266,158,976 `cacheReadTokens` and 42,337 `outputTokens`. These provider-reported categories establish wasted model work, not a dollar estimate or 267 million unique non-cached input tokens.

## What This Evidence Supports

- The dominant demonstrated regression is a successful-audit host feedback loop with no new evidence, followed by provider rate limiting.
- Large persistent tool descriptions and overfilled default queue projections increase model/context work and contract-recovery friction.
- The engine does execute quickly for this local target; many slow workflow outcomes are rejected proof/identity/control bindings rather than a slow HTTP transport.
- Some workflow and fixed-prose publication paths can be made more usable without relaxing scope, identity, fixture, proof or final-report boundaries.

## What This Evidence Does Not Support

- The log does not show that package/module count causes network latency, that removing safety controls improves real vulnerability recall, or that every unclosed task is unnecessary.
- The current user's suspicion of a bloated project is not a separate dissatisfaction message in this export; the export contains only one actual assessment request.
- No comparison with another version under identical target state, model, scopes and verified proof criteria is available here. No improvement percentage or complete vulnerability recall can be claimed from this session alone.
- An anti-feedback-loop checkpoint/notice suppression records an unfinished host workflow; it does not establish exhaustion, invent user cancellation or authorize final delivery.

The independent synthetic regression in `tests/host-stall-replay.test.mjs` checks the repeated-boundary failure shape without loading this session into a runtime, starting a server or replaying target traffic.
