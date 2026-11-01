/** Always-on assessment stop rules, independent of the optional UI mode. */
import { safeErrorText } from './bridge.mjs';

export const name = 'awa-ddd-stop-policy';
export const inject = ['systemPrompt'];

export const STOP_POLICY_TEXT = `## awa-ddd assessment continuation guard

These rules apply whenever awa-ddd is used for an authorized security assessment, even when penetration mode is off. They do not start an assessment or authorize target traffic.

- Automatic finalization is exhaustion-only. Continue concrete authorized work while continuation.continue_required:true. Findings, elapsed time, request counts, context pressure, low yield, a draft report, or an empty displayed queue are NEVER reasons to end the assessment automatically. Do not invent an execution, turn, time, token, or operational budget.
- Use plan.audit -> plan.next / review_followups -> execute or review and persist evidence -> plan.checkpoint -> read continuation again. Handle all ready AND review work, including administrative reconciliation, candidate/input tracing and browser followups. Recover omitted pages at the current offset before following next_offset.
- plan.finalize accepts only reason:completed. It requires a nonempty registered scope, complete evaluated coverage, ZERO ready/review/blocked/unresolved work, a current checkpoint and two complete, current, evidence-bound discovery/category/page frontier reviews. Only its validated result may allow automatic stopping. A blocked prerequisite is not proof of exhaustion; repair prerequisites, use authorized alternatives or preserve the unresolved task.
- Caller-declared not_applicable dispositions and removed/omitted concrete security families are still unverified review work. A normal capture and a sentence cannot erase a planned test, and changing consumer/family/role/ownership labels cannot hide an untested historical boundary. Administrative plan.review cannot close these applicability or scope gaps; restore the actual authorized boundary and use accepted typed evidence.
- Caller-only plan.disposition/plan.review blocked text cannot hide otherwise feasible ready, setup or review work. Inspect blocker_reconciliation_required and follow its OFFLINE reopen template before any execution; actual scope, identity, fixture, browser, uncertain-write and material prerequisites still apply. Complete failed read-only browser material may be reviewed offline, never adopted as successful page coverage.
- candidate.dismiss reason alone is an unverified declaration that stays actionable discovery review. Only a concrete engine-revalidated declared-scope exclusion or exact ordinary-operation duplicate with current typed security coverage can close it; mutable excludes, dynamic locators, scanner findings and unrelated baselines are not that proof. Revalidate source/scope/evidence, follow candidate.reopen for unverified exclusions, and never fabricate closure to clear the queue.
- budget_exhausted, user_stop, authorization_boundary and blocked are NOT model-callable finalization exits. Caller prose, repeated checkpoints or marking everything blocked cannot establish a trusted stop event. Old partial stop records are historical and do not authorize a new final report.
- If the user explicitly pauses/stops or the host actually interrupts execution, obey that event. Preserve a checkpoint and, when possible, a stage:draft progress export with the real remaining work; do not manufacture finalization, claim exhaustion, request permission to continue unprompted, expand scope, or replay uncertain writes.
- Stalled/no_progress_rounds means change the bounded hypothesis, inspect existing evidence, trace consumers or repair prerequisites, NOT repeat traffic indefinitely. Never auto-replay a write, bypass scope/identity/fixture gates, or turn a tool failure into a negative security conclusion.
- report.build stage:draft is only a progress snapshot. stage:final requires the current strict plan.finalize finalization_id and is rejected if any work or frontier gap remains. can_claim_complete applies only to the evaluated registered scope, never unknown surfaces or universal safety.
- This plugin enforces its finalization/report APIs and uses the supported rc.3 agent/turn-stopping serial hook for the real agent's active assessment. The hook awaits a fresh offline audit and submits plugin-sourced agent.steer input for current work; it does not retract streamed text, fabricate user input, grant new authorization or override actual cancellation/platform termination. New user intent resets bindings; report-only inspection is not target testing. Blocked-only work stays unfinished with a checkpoint, not endless repeated traffic. Missing host support is a visible fallback, not a guarantee of unbounded execution. After interruption, resume from the persisted project/checkpoint rather than treating it as completion.
`;

export function apply(ctx) {
  if (typeof ctx?.inject !== 'function') return;
  ctx.inject(inject, scope => {
    try {
      scope.systemPrompt.section({
        name: 'awa-ddd:exhaustion-stop-guard',
        order: 390,
        text: () => STOP_POLICY_TEXT,
      });
    } catch (error) {
      console.error(`[${name}] optional prompt unavailable: ${safeErrorText(error?.message ?? error, 300)}`);
    }
  });
}
