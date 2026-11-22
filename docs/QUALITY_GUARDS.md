# Quality guards: anti-repeat and report redaction

Version 2.3.0 keeps bounded repeat hints and report redaction checks for two
failure modes observed in long assessments:

1. a read-only queue page being inspected repeatedly without any state or
   evidence change;
2. automatic redaction replacing ordinary letters with placeholders in report
   prose.

## 1. Queue loop guard

`plan.next` tracks the exact returned page signature in a private SQLite
advisory table. Updates are atomic across processes and do not mutate domain
entities or events. Existing `<project>/.loop_guard/next_work.json` files may
seed the advisory counter once; they remain historical files. A page is
counted only when the same offset/limit, row signatures and obligation facts
are returned again. A persisted obligation change resets the repeat count.

After three identical page views:

- the rows carry `repeat_advisory:true`;
- the hint asks the caller to inspect the actual blocker or perform the
  prepared action;
- readiness, suggested actions and missing prerequisites retain their
  current values.

Repeated reads cannot manufacture a blocker or an execution attempt. Actual
attempt results and changed prerequisites govern task readiness.

`assessment.prepare` has the same bounded counter. After three views of the
same preparation set, its rows carry `repeat_advisory:true` and an inspection
hint. The preparation state and action retain their actual values.

## 2. Preflight deduplication

`http.preflight` atomically records the exact `request_signature` in the same
SQLite advisory store, with a 24-hour TTL and a bounded entry count. A repeated
signature returns `repeat_advisory:true` after the normal current preflight
checks. It still sends no request and creates no run or evidence record.

These actions write advisory state and therefore are excluded from the Node
pure-read concurrency set. The historical `already_preflighted` code remains
recognized for compatibility; repeated preparation does not raise it in the
current path.

## 3. Report redaction regression fix

The previous redactor learned values from JavaScript/HTML response source. A
short variable name such as `auth_token:y` or `phone:s` became a global
placeholder alias and corrupted all report prose (`local` -> `locpl`,
`/api` -> `/ppi`, `innerHTML` -> letter placeholders).

The fix:

- `Redactor.learn_text(..., assignment_scan=False)` for non-structured
  JavaScript/HTML bodies, while structured JSON/form/multipart/XML bodies are
  parsed explicitly;
- short browser/private values are kept in field scope (`short_alias=False`)
  rather than becoming global prose aliases;
- short values that are already captured as submitted fields are promoted out
  of `field_values` when a trusted private context learns them;
- `report.build` runs a redaction self-test before publishing: the report must
  retain its non-secret route vocabulary (`http`, `api`, `login` when present
  in registered operations). A corrupted report fails closed with
  `report_redaction_failed` instead of writing a misleading artifact.

## 4. Verification

```powershell
python -X utf8 -B -m unittest tests.test_loop_guard_redaction_20261106 -v
npm test
npm run test:python
```

The regression suite covers:

- short browser fill values do not become prose aliases;
- a short submitted field is promoted without global string replacement;
- preflight duplicate detection is bounded and TTL-aware;
- repetitive page views produce bounded hints after three identical
  signatures while preserving task readiness and actions;
- a changed obligation state resets the loop counter;
- report generation rejects corrupted route vocabulary.
