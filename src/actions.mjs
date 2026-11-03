/** One native action catalog, shared by tool schemas and the process bridge. */
export const ACTION_GROUPS = Object.freeze(Object.fromEntries(Object.entries({
  awa_project: ['action.help', 'project.create', 'project.list', 'project.status', 'project.update', 'project.import_pentest'],
  awa_surface: ['surface.import', 'surface.register', 'surface.list', 'surface.inspect', 'surface.batch', 'surface.declare_consumer', 'surface.recon'],
  awa_identity: ['identity.actor', 'identity.session', 'identity.verify', 'identity.resource'],
  awa_browser: ['browser.probe', 'browser.visit', 'browser.import_mcp', 'page.register', 'page.adopt', 'page.function', 'page.mark', 'page.coverage'],
  awa_candidate: ['candidate.list', 'candidate.inspect', 'candidate.link', 'candidate.dismiss', 'candidate.reopen'],
  awa_plan: ['plan.build', 'plan.list', 'plan.next', 'plan.audit', 'plan.checkpoint', 'plan.review', 'plan.finalize', 'plan.disposition'],
  awa_execute: ['http.preflight', 'http.capture', 'scenario.preflight', 'scenario.run', 'run.inspect', 'run.recover'],
  awa_assess: ['assessment.prepare', 'assessment.evaluate', 'finding.record', 'finding.bind', 'finding.list', 'finding.update', 'evidence.inspect'],
  awa_external: ['runtime.probe', 'tool.probe', 'tool.sqlmap', 'tool.yakit_replay', 'tool.tscanplus_request', 'tool.tscanplus_results', 'tool.tscanplus_summary', 'tool.tscanplus_routes', 'tool.inspect', 'tool.artifact'],
  awa_report: ['report.build', 'report.coverage'],
}).map(([name, actions]) => [name, Object.freeze(actions)])));

/** AWA-DDD 2.0 surface, registered instead of the legacy groups when assessmentModel=v2. */
export const V2_ACTION_GROUPS = Object.freeze(Object.fromEntries(Object.entries({
  awa_campaign: ['campaign.start', 'campaign.status', 'campaign.next', 'campaign.checkpoint', 'campaign.finish', 'campaign.migrate', 'campaign.rollback'],
  awa_recon: ['recon.snapshot', 'recon.import', 'recon.routes', 'recon.hypotheses', 'recon.capabilities'],
  awa_test: ['test.run', 'test.run_browser', 'test.run_scenario', 'test.run_external', 'test.record_external', 'test.inspect'],
  awa_review: ['review.evidence', 'review.finding', 'review.bind', 'review.disposition'],
  awa_report: ['report.matrix', 'report.build', 'report.compare'],
  awa_admin: ['project.create', 'project.list', 'project.status', 'project.update', 'identity.actor', 'identity.session', 'identity.verify', 'identity.resource', 'action.help'],
}).map(([name, actions]) => [name, Object.freeze(actions)])));

export const ACTIONS = Object.freeze(Object.values(ACTION_GROUPS).flat());
export const V2_ACTIONS = Object.freeze(Object.values(V2_ACTION_GROUPS).flat());
export const ALL_ACTIONS = Object.freeze([...new Set([...ACTIONS, ...V2_ACTIONS])]);
export const READ_ACTIONS = new Set(['action.help', 'runtime.probe', 'project.list', 'project.status', 'surface.list', 'surface.inspect',
  'plan.list', 'plan.next', 'plan.audit', 'http.preflight', 'scenario.preflight', 'run.inspect',
  'assessment.prepare', 'finding.list', 'evidence.inspect', 'report.coverage', 'candidate.list', 'candidate.inspect',
  'page.coverage', 'tool.inspect', 'tool.artifact',
  'campaign.status', 'campaign.next', 'recon.snapshot', 'recon.routes', 'recon.hypotheses', 'recon.capabilities',
  'test.inspect', 'review.evidence', 'report.matrix', 'report.compare']);
