/** One native action catalog, shared by tool schemas and the process bridge. */
export const ACTION_GROUPS = Object.freeze(Object.fromEntries(Object.entries({
  awa_project: ['action.help', 'project.create', 'project.list', 'project.status', 'project.update', 'project.import_pentest'],
  awa_surface: ['surface.import', 'surface.register', 'surface.list', 'surface.inspect', 'surface.batch', 'surface.declare_consumer'],
  awa_identity: ['identity.actor', 'identity.session', 'identity.verify', 'identity.resource'],
  awa_browser: ['browser.probe', 'browser.visit', 'browser.import_mcp', 'page.register', 'page.adopt', 'page.function', 'page.mark', 'page.coverage'],
  awa_candidate: ['candidate.list', 'candidate.inspect', 'candidate.link', 'candidate.dismiss', 'candidate.reopen'],
  awa_plan: ['plan.build', 'plan.list', 'plan.next', 'plan.audit', 'plan.checkpoint', 'plan.review', 'plan.finalize', 'plan.disposition'],
  awa_execute: ['http.preflight', 'http.capture', 'scenario.preflight', 'scenario.run', 'run.inspect', 'run.recover'],
  awa_assess: ['assessment.evaluate', 'finding.record', 'finding.list', 'finding.update', 'evidence.inspect'],
  awa_external: ['runtime.probe', 'tool.probe', 'tool.sqlmap', 'tool.yakit_replay', 'tool.tscanplus_request', 'tool.tscanplus_results', 'tool.tscanplus_summary', 'tool.tscanplus_routes', 'tool.inspect', 'tool.artifact'],
  awa_report: ['report.build', 'report.coverage'],
}).map(([name, actions]) => [name, Object.freeze(actions)])));

export const ACTIONS = Object.freeze(Object.values(ACTION_GROUPS).flat());
export const READ_ACTIONS = new Set(['action.help', 'runtime.probe', 'project.list', 'project.status', 'surface.list', 'surface.inspect',
  'plan.list', 'plan.next', 'plan.audit', 'http.preflight', 'scenario.preflight', 'run.inspect',
  'finding.list', 'evidence.inspect', 'report.coverage', 'candidate.list', 'candidate.inspect',
  'page.coverage', 'tool.inspect', 'tool.artifact']);
