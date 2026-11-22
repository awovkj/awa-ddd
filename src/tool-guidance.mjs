/** Short tool-selection guidance; exact schemas and examples live in action.help. */
export const GUIDANCE = Object.freeze({
  awa_plan: [
    'Start: surface.recon -> surface.import/batch -> plan.next(limit:3,parameter_limit:3,compact:true); verify identity/fixtures first. plan.why is offline; list/audit paginate; empty pages are not exhaustion.',
    'parameter_coverage pages independently; observed/carried are not typed tested. Inspect controls offline. render_recovery.combined_input restores current pages; render_actionable:false is non-executable.',
    'browser_testing required/assisted: must_call_playwright:true. Check stage/call_needed/invoke_now; prepare/review_existing offline. Preserve scope/identity/fixture/provider.',
    'While continuation.continue_required,review each registered input/saved HTTP/browser control: plan.audit -> plan.next/review_followups -> inspect,prepare/evaluate,bind/archive -> checkpoint. Finish CURRENT pages before next_offset. no_progress_rounds: switch items/fix prerequisites,never repeat uncertain writes.',
    'plan.checkpoint: label,frontier_review. Finalization: two COMPLETE current same-snapshot all 12 categories/page frontier rounds,nonempty registered coverage,ZERO ready/review/blocked/unresolved work.',
    'plan.review: administrative checklist_id only, never security obligations/candidates/runs. plan.disposition: obligation_id,status:open|blocked|not_applicable,reason. Caller blocked/N/A/removed families do not erase work; follow offline blocker_reconciliation_required/typed proof.',
    'plan.accept_partial: current checkpoint; no completion/stop/final.',
    'plan.finalize: checkpoint_id,reason:completed,explanation,reviewer. Reject budget_exhausted/user_stop/authorization_boundary/blocked; findings,context pressure,time do not prove exhaustion. report.build stage:draft is progress; stage:final needs current finalization_id.',
    'A normal host turn end is not assessment completion. Use concrete current review/ready tasks before a partial handoff; stalled work stays unfinished. Zero-tool repeats stay bounded. Obey user stop/host abort. Mode off does not disable engine gates.',
  ].join(' '),
  awa_browser: [
    'Use real Playwright when required or assisted. Assisted also means mandatory when UI/browser behavior is materially useful. Cover XSS,DOM,CSRF,CORS,clickjacking,SameSite,HttpOnly,Secure,postMessage,OAuth,multi-role,file-upload and business workflows obligations; pure backend proof need not be browserized.',
    'Discover actual host Playwright MCP tools and save observations. Only the native fallback first calls browser.probe then browser.visit; local unavailability does not negate host MCP availability.',
    'browser.visit: authorized URL,verified session_id,timeout, and bounded action objects. Check stage/call_needed/invoke_now, prepare controls first, and review_existing offline. Recheck scope/exclude; consumer_locator is neither an executable URL nor permission to guess private values.',
    'Native scope/write guards block redirects,WebSockets,service workers,cross-origin writes and unsupported upload/evaluate/multi-context/download. Writes still need explicit authorization and test-resource limits. Host MCP tabs are not isolated browser contexts; Unsafe run_code is not a default safe entry.',
    'browser.import_mcp: path to actual saved JSON,required url/finalUrl/status/signals/network. Imports do NOT bind session_id/actor and cannot replace authenticated XSS typed closure; upload/evaluate/tab output must not be disguised as click.',
    'Proof needs application-triggered runtime,matching HTTP controls,identity and real consumer. Manual evaluate(alert),blank/login pages or absent dialogs are not an XSS negative; reach the input through successful business interaction with observer sensitivity.',
    'page.register: url (registration is not a visit). page.adopt: page_visit_id. page.function: page_id,name. page.mark: page_id,target,status,real page_visit_id for success or reason for BLOCKED; functions also need a successful interaction. page.coverage checks saved provenance.',
  ].join(' '),
  awa_assess: [
    'assessment.prepare: offline saved-control review; assessment.evaluate: actual typed proof; assessment.batch: up to 50 explicit {obligation_id,evidence_ids,oracle} items using the same exact gates. Use action.help for fields,oracle discriminator and control order.',
    'Controls must bind the exact input,family,schema branch,identity and fixture; change only the tested input. state_transition needs a completed real scenario read/write/read and matching current snapshots. Never relabel unrelated evidence or reuse one family result to close another.',
    'SQL confirmation needs real database/current-user metadata or a DBMS error channel with baseline/recovery/negative controls; scanner signals stay candidates. Analyst write-side sql_evidence is bounded business-count behaviour, never all-table access. Typed extraction needs exact expected_value,source_reference and negative controls.',
    'XSS binds the real source: direct GET needs same-identity exact consumer; stored API-to-SPA uses finding.record xss_consumption with writer controls,JSON content/fixture readbacks and native normal/attack viewers. A search locator is not the writing source; manual evaluate(alert),no-dialog or unbound MCP output is not typed proof.',
    'finding.record: actual impact/remediation with machine/analyst proof. finding.bind: finding_id,confirmed decision_id,reviewer,reason; recheck source proof. finding.list: offset/limit; finding.update appends lifecycle history. evidence.inspect: offline integrity/lineage.',
  ].join(' '),
  awa_external: [
    'runtime.probe: no project/target traffic; sqlmap_candidates provide tool.probe inputs. Fixed backend; WSL: separate workspace. tool.probe: adapter:yakit|sqlmap,absolute path; Tscan: loopback-only mcp_url and nondefault scanner_project; timeout:5..120.',
    'TscanPlus: loopback-only namespace <=20 chars. Never truncate/rebind/default buckets/launch servers. tool.tscanplus_request: authorized GET/HEAD or fixture only POST; allow_mutation,effect:test_resource_write,follow_redirect:false. Output cannot machine-confirm or refute obligations.',
    'tool.tscanplus_ingest source_kind:results,result_limit:1..100 reads saved results/routes; Preview still persists. Follow next_input/surface.sources; Match probe; Never accepts arbitrary tools,paths,scans,POC,cracks,brute. Rows: untrusted, non-requestable; no scanner/target request.',
    'tool.tscanplus_results: No offset pagination exists remotely; result_limit is a compatible alias. tool.tscanplus_summary never remote prompt/hint prose. tool.tscanplus_routes: This limit is local; scoped routes are unverified candidates, catalog-only and never executed.',
    'url_redacted locators are not executable. Remote timeout/cancel does not prove stop; inspect uncertain runs.',
    'tool.sqlmap: operation_id,concrete url,input_location:query|body,input_selector,effect,timeout:5..120. One GET query or controlled JSON/form POST needs verified identity and matching disposable resource_id; no crawl/dump/stacked/time/proxy inheritance. tool.yakit_replay: public GET,effect:read_only,one packet,redirects disabled.',
    'tool.inspect: run_id. tool.artifact: run_id,name,offset/limit; redacted pages. Provider output never proves a negative.',
  ].join(' '),
});
