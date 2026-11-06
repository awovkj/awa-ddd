# Quality guards: anti-repeat and report redaction

Version 2.1.0 adds bounded guards for two failure modes observed in long
assessments:

1. a read-only queue page being inspected repeatedly without any state or
   evidence change;
2. automatic redaction replacing ordinary letters with placeholders in report
   prose.

## 1. Queue loop guard

`plan.next` tracks the exact returned page signature in a private sidecar file
under `<project>/.loop_guard/next_work.json`. A page is counted only when the
same page (same offset/limit and same row signatures) is returned again. A
persisted obligation change also changes the signature, so legitimate review
work is not frozen.

After three identical page views:

- the rows are marked `execution_blocked=true`;
- the suggested action becomes `plan.review`;
- `no_progress_frozen` is added to `missing_prerequisites`;
- the user must reopen or change the prerequisite before the task can progress.

The guard never deletes obligations, evaluates evidence, or changes the
underlying ledger. It only prevents the same queue page from being consumed
forever.

`assessment.prepare` has the same signature counter. If the same preparation
set is returned three times without a state/evidence change, its
`preparation_state` becomes `frozen`, `assessment_action` becomes
`plan.review`, and the caller must change a prerequisite or evidence before
retrying.

## 2. Preflight deduplication

`http.preflight` records the exact `request_signature` in
`<project>/.loop_guard/preflight.json`. An identical request signature may be
preflighted once per 24 hours. A second preflight raises `already_preflighted`
and points to `http.capture`; it never sends a request and never creates a run
or evidence record.

The cache is a sidecar file, not SQLite metadata, because preflight must remain
a read-only preparation action with no entity/event/metadata mutation.

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
- repetitive page views freeze only after three identical signatures;
- a changed obligation state resets the loop counter;
- report generation rejects corrupted route vocabulary.
