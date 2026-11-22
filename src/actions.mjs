/** One native action catalog, shared by tool schemas and the process bridge. */
export const ACTION_GROUPS = Object.freeze(Object.fromEntries(Object.entries({
  awa_project: ['action.help', 'project.create', 'project.list', 'project.status', 'project.update',
    'project.migrate', 'project.rollback', 'project.projection', 'project.import_pentest',
    'integration.import', 'integration.export'],
  awa_surface: ['surface.import', 'surface.sources', 'surface.register', 'surface.list', 'surface.inspect', 'surface.batch', 'surface.declare_consumer', 'surface.recon'],
  awa_identity: ['identity.actor', 'identity.session', 'identity.verify', 'identity.resource'],
  awa_browser: ['browser.probe', 'browser.visit', 'browser.import_mcp', 'page.register', 'page.adopt', 'page.function', 'page.mark', 'page.coverage'],
  awa_candidate: ['candidate.list', 'candidate.inspect', 'candidate.link', 'candidate.dismiss', 'candidate.reopen'],
  awa_plan: ['plan.build', 'plan.list', 'plan.next', 'plan.why', 'plan.audit', 'plan.checkpoint', 'plan.review',
    'plan.accept_partial', 'plan.finalize', 'plan.disposition'],
  awa_execute: ['http.preflight', 'http.capture', 'scenario.preflight', 'scenario.run', 'run.inspect',
    'run.recover', 'execution.reconcile'],
  awa_assess: ['assessment.prepare', 'assessment.evaluate', 'assessment.batch', 'finding.record', 'finding.bind', 'finding.list', 'finding.update', 'evidence.inspect'],
  awa_external: ['runtime.probe', 'tool.probe', 'tool.sqlmap', 'tool.yakit_replay', 'tool.tscanplus_request', 'tool.tscanplus_ingest', 'tool.tscanplus_results', 'tool.tscanplus_summary', 'tool.tscanplus_routes', 'tool.inspect', 'tool.artifact'],
  awa_report: ['report.build', 'report.coverage', 'report.artifact'],
}).map(([name, actions]) => [name, Object.freeze(actions)])));

/** AWA-DDD 2.0 surface, registered instead of the legacy groups when assessmentModel=v2. */
export const V2_ACTION_GROUPS = Object.freeze(Object.fromEntries(Object.entries({
  awa_campaign: ['campaign.start', 'campaign.status', 'campaign.next', 'campaign.checkpoint', 'campaign.review_frontier', 'campaign.finish', 'campaign.migrate', 'campaign.rollback'],
  awa_recon: ['recon.snapshot', 'recon.import', 'recon.routes', 'recon.hypotheses', 'recon.capabilities'],
  awa_test: ['test.run', 'test.run_browser', 'test.run_scenario', 'test.run_external',
    'test.record_external', 'test.inspect', 'test.fixture_create', 'test.fixture_verify', 'test.fixture_lease',
    'test.fixture_inspect', 'test.fixture_readback', 'test.fixture_cleanup', 'execution.reconcile'],
  awa_review: ['review.evidence', 'review.finding', 'review.bind', 'review.disposition'],
  awa_report: ['report.matrix', 'report.build', 'report.compare', 'report.artifact'],
  awa_admin: ['project.create', 'project.list', 'project.status', 'project.update', 'project.migrate',
    'project.rollback', 'project.projection', 'identity.actor', 'identity.session', 'identity.verify',
    'identity.resource', 'action.help', 'integration.import', 'integration.export'],
}).map(([name, actions]) => [name, Object.freeze(actions)])));

export const ACTIONS = Object.freeze(Object.values(ACTION_GROUPS).flat());
export const V2_ACTIONS = Object.freeze(Object.values(V2_ACTION_GROUPS).flat());
export const ALL_ACTIONS = Object.freeze([...new Set([...ACTIONS, ...V2_ACTIONS])]);
export const READ_ACTIONS = new Set(['action.help', 'runtime.probe', 'project.list', 'project.status', 'surface.sources', 'surface.list', 'surface.inspect',
  'plan.list', 'plan.why', 'plan.audit', 'scenario.preflight', 'run.inspect',
  'finding.list', 'evidence.inspect', 'report.coverage', 'candidate.list', 'candidate.inspect',
  'page.coverage', 'tool.inspect', 'tool.artifact',
  'campaign.status', 'campaign.next', 'recon.snapshot', 'recon.routes', 'recon.hypotheses', 'recon.capabilities',
  'test.inspect', 'test.fixture_inspect', 'review.evidence', 'report.matrix', 'report.compare', 'report.artifact',
  'integration.export']);

/** The same action can carry a read or a local state change in an explicit mode. */
export function isReadOnlyAction(action, input = {}) {
  if (action === 'project.migrate') return (input?.mode ?? 'dry_run') === 'dry_run';
  if (action === 'project.projection') return ['inspect', 'compare'].includes(input?.mode ?? 'inspect');
  return READ_ACTIONS.has(action);
}
