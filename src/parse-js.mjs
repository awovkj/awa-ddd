// Offline bounded AST discovery. This helper never executes the supplied source.
// The Python adapter removes URL query values and adds file provenance.
const LIMIT = 8 * 1024 * 1024;
const UNKNOWN = Symbol('unknown');
const AXIOS = Object.freeze({client: 'axios', baseURL: ''});
const FETCH = Object.freeze({client: 'fetch'});
const result = {operations: [], candidates: [], client_sinks: [], limitations: []};
const seenLimits = new Set();
let visited = 0;

function limitation(code, node) {
  const locator = node?.loc ? `line:${node.loc.start.line}:column:${node.loc.start.column + 1}` : '#';
  const key = code + locator;
  if (!seenLimits.has(key) && result.limitations.length < 2000) {
    seenLimits.add(key);
    result.limitations.push({code, locator});
  }
}
function tick(depth = 0) {
  if (++visited > 300000 || depth > 100) throw new Error('ast_budget_exceeded');
}
class Scope {
  constructor(parent = null, varRoot = false) {
    this.parent = parent; this.bindings = new Map();
    this.varScope = varRoot ? this : parent?.varScope || this;
  }
  lookup(name) { return this.bindings.has(name) ? this.bindings.get(name) : this.parent?.lookup(name); }
}
const validName = value => typeof value === 'string' && value.length > 0 && value.length <= 1024 && !/[\u0000-\u001f]/.test(value);
const pointer = value => value.replaceAll('~', '~0').replaceAll('/', '~1');
const scopes = new WeakMap();

function patternTargets(node, visit, depth = 0) {
  if (!node) return;
  tick(depth);
  if (node.type === 'Identifier' || node.type === 'MemberExpression') visit(node);
  else if (node.type === 'ObjectPattern') {
    for (const property of node.properties) patternTargets(property.type === 'RestElement' ? property.argument : property.value, visit, depth + 1);
  } else if (node.type === 'ArrayPattern') {
    for (const element of node.elements) patternTargets(element, visit, depth + 1);
  } else if (node.type === 'AssignmentPattern') patternTargets(node.left, visit, depth + 1);
  else if (node.type === 'RestElement') patternTargets(node.argument, visit, depth + 1);
}
function bindPattern(node, scope) {
  patternTargets(node, target => {
    if (target.type === 'Identifier') scope.bindings.set(target.name, {value: UNKNOWN});
  });
}
function hoistVars(root, scope) {
  const stack = [root];
  while (stack.length) {
    const node = stack.pop();
    if (!node || typeof node.type !== 'string') continue;
    tick();
    if (['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 'ClassDeclaration', 'ClassExpression'].includes(node.type)) continue;
    if (node.type === 'VariableDeclaration' && node.kind === 'var') {
      for (const declaration of node.declarations) bindPattern(declaration.id, scope);
    }
    for (const [key, value] of Object.entries(node)) {
      if (['loc', 'start', 'end'].includes(key)) continue;
      if (Array.isArray(value)) stack.push(...value.filter(child => child && typeof child === 'object'));
      else if (value && typeof value === 'object') stack.push(value);
    }
  }
}

function declarations(body, scope) {
  for (let statement of body || []) {
    if (statement.type === 'ExportNamedDeclaration' || statement.type === 'ExportDefaultDeclaration') statement = statement.declaration || statement;
    if (statement.type === 'ImportDeclaration') {
      for (const specifier of statement.specifiers) {
        const value = statement.source.value === 'axios' && ['ImportDefaultSpecifier', 'ImportNamespaceSpecifier'].includes(specifier.type) ? AXIOS : UNKNOWN;
        scope.bindings.set(specifier.local.name, {value});
      }
    } else if (statement.type === 'VariableDeclaration') {
      for (const declaration of statement.declarations) {
        const targetScope = statement.kind === 'var' ? scope.varScope : scope;
        if (declaration.id.type === 'Identifier') targetScope.bindings.set(declaration.id.name,
          {node: declaration.init, scope, mutable: statement.kind !== 'const', constant: statement.kind === 'const'});
        else bindPattern(declaration.id, targetScope);
      }
    } else if (['FunctionDeclaration', 'ClassDeclaration'].includes(statement.type) && statement.id) {
      scope.bindings.set(statement.id.name, {value: UNKNOWN});
    }
  }
}
function identifier(node, scope, depth) {
  const binding = scope.lookup(node.name);
  if (!binding || binding.mutable || depth > 30) return UNKNOWN;
  return Object.hasOwn(binding, 'value') ? binding.value : evaluate(binding.node, binding.scope, depth + 1);
}
function propertyName(node, scope, depth) {
  return node.computed ? evaluate(node.property || node.key, scope, depth + 1) : (node.property || node.key).name ?? (node.property || node.key).value;
}
function evaluate(node, scope, depth = 0) {
  tick(depth);
  if (!node || depth > 30) return UNKNOWN;
  if (node.type === 'Literal') return typeof node.value === 'string' || typeof node.value === 'number' || typeof node.value === 'boolean' || node.value === null ? node.value : UNKNOWN;
  if (node.type === 'Identifier') return identifier(node, scope, depth);
  if (node.type === 'TemplateLiteral') {
    let text = node.quasis[0].value.cooked;
    for (let i = 0; i < node.expressions.length; i++) {
      const value = evaluate(node.expressions[i], scope, depth + 1);
      if (!['string', 'number', 'boolean'].includes(typeof value)) return UNKNOWN;
      text += String(value) + node.quasis[i + 1].value.cooked;
      if (text.length > 8192) return UNKNOWN;
    }
    return text;
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = evaluate(node.left, scope, depth + 1), right = evaluate(node.right, scope, depth + 1);
    if (['string', 'number'].includes(typeof left) && ['string', 'number'].includes(typeof right)) {
      const value = left + right;
      return typeof value !== 'string' || value.length <= 8192 ? value : UNKNOWN;
    }
  }
  if (node.type === 'ObjectExpression') {
    const value = Object.create(null);
    for (const property of node.properties) {
      if (property.type === 'SpreadElement') return UNKNOWN;
      const name = propertyName(property, scope, depth);
      if (!validName(name)) return UNKNOWN;
      value[name] = evaluate(property.value, scope, depth + 1);
    }
    return value;
  }
  if (node.type === 'MemberExpression') {
    const object = evaluate(node.object, scope, depth + 1), name = propertyName(node, scope, depth);
    if (object !== UNKNOWN && object && typeof object === 'object' && typeof name === 'string' && Object.hasOwn(object, name)) return object[name];
  }
  if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') {
    const object = evaluate(node.callee.object, scope, depth + 1);
    if (object?.client === 'axios' && propertyName(node.callee, scope, depth) === 'create') {
      const config = evaluate(node.arguments[0], scope, depth + 1);
      return config !== UNKNOWN && config && (typeof config.baseURL === 'string' || config.baseURL === undefined)
        ? {client:'axios', baseURL:config.baseURL || ''} : UNKNOWN;
    }
  }
  if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'require' && node.arguments[0]?.value === 'axios' && !scope.lookup('require')) return AXIOS;
  return UNKNOWN;
}
function unwrap(node, scope, depth = 0) {
  if (!node || depth > 30) return {node, scope};
  if (node.type === 'Identifier') {
    const binding = scope.lookup(node.name);
    if (binding?.node && !binding.mutable) return unwrap(binding.node, binding.scope, depth + 1);
  }
  if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression' &&
      node.callee.object.type === 'Identifier' && node.callee.object.name === 'JSON' &&
      propertyName(node.callee, scope, 0) === 'stringify' && !scope.lookup('JSON')) return unwrap(node.arguments[0], scope, depth + 1);
  return {node, scope};
}
function objectProperties(node, scope) {
  ({node, scope} = unwrap(node, scope));
  if (!node || node.type !== 'ObjectExpression') return null;
  const properties = new Map();
  for (const property of node.properties) {
    if (property.type === 'SpreadElement') {
      limitation('object_spread_requires_review', property);
      // An unknown spread may override method/url/data; do not guess its effect.
      return null;
    }
    const name = propertyName(property, scope, 0);
    if (typeof name !== 'string') return null;
    properties.set(name, {node:property.value, scope});
  }
  return properties;
}
function staticProperty(properties, key) {
  const value = properties?.get(key);
  return value ? evaluate(value.node, value.scope) : undefined;
}
function fields(original, originalScope, location, output, prefix = '', name = '', depth = 0) {
  tick(depth);
  if (depth > 24 || output.length >= 2048) { limitation('input_shape_budget_exceeded', original); return; }
  let {node, scope} = unwrap(original, originalScope);
  if (!node) return;
  if (node.type === 'ObjectExpression') {
    for (const property of node.properties) {
      if (property.type === 'SpreadElement') { limitation('input_spread_requires_review', property); continue; }
      const key = propertyName(property, scope, 0);
      if (!validName(key)) { limitation('dynamic_input_name', property); continue; }
      const next = location === 'query' || location === 'header' ? key : prefix + '/' + pointer(key);
      const child = unwrap(property.value, scope).node;
      if (['body', 'graphql'].includes(location) && child && ['ObjectExpression', 'ArrayExpression'].includes(child.type) &&
          (child.properties?.length || child.elements?.length)) fields(property.value, scope, location, output, next, key, depth + 1);
      else output.push({name:key, location, selector:next});
    }
  } else if (node.type === 'ArrayExpression') {
    node.elements.forEach((child, index) => {
      if (!child) return;
      if (child.type === 'SpreadElement') { limitation('array_spread_requires_review', child); return; }
      const next = prefix + '/' + index;
      const unwrapped = unwrap(child, scope).node;
      if (['ObjectExpression', 'ArrayExpression'].includes(unwrapped?.type)) fields(child, scope, location, output, next, name, depth + 1);
      else output.push({name:name || '$item', location, selector:next});
    });
  } else if (node.type === 'NewExpression' && node.callee.name === 'URLSearchParams' && !scope.lookup('URLSearchParams')) {
    fields(node.arguments[0], scope, 'body', output, '', '', depth + 1);
  } else if (name) output.push({name, location, selector:prefix});
  else limitation('dynamic_or_unsupported_input_shape', node);
}
function graphqlDocument(query) {
  if (typeof query !== 'string' || query.length > LIMIT) return null;
  const stripped = query.replace(/"""(?:\\.|[^\\])*?"""|"(?:\\.|[^"\\])*"|#[^\r\n]*/g,
    value => value.startsWith('"') ? '""' : '');
  const tokens = [];
  for (const match of stripped.matchAll(/[A-Za-z_][A-Za-z0-9_]*|[^\s,\ufeff]/g)) {
    tokens.push(match[0]);
    if (tokens.length > 50000) return null;
  }
  const names = [];
  let cursor = 0;
  while (cursor < tokens.length) {
    const keyword = tokens[cursor];
    if (!['query', 'mutation', 'subscription', 'fragment', '{'].includes(keyword)) return null;
    let name = '';
    if (keyword !== '{') {
      cursor++;
      if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(tokens[cursor] || '')) name = tokens[cursor++];
    }
    const stack = [];
    while (cursor < tokens.length) {
      const token = tokens[cursor];
      if (token === '{' && stack.length === 0) break;
      if (['(', '[', '{'].includes(token)) stack.push(token);
      else if ([')', ']', '}'].includes(token) && stack.pop() !== {')':'(', ']':'[', '}':'{'}[token]) return null;
      cursor++;
    }
    if (cursor === tokens.length) return null;
    let depth = 1;
    cursor++;
    while (cursor < tokens.length && depth) {
      depth += Number(tokens[cursor] === '{') - Number(tokens[cursor] === '}');
      cursor++;
    }
    if (depth) return null;
    if (keyword !== 'fragment') names.push(name.length <= 128 ? name : '');
  }
  return names.length ? names : null;
}

function syntacticProperty(node) {
  if (!node) return null;
  const property = node.property || node.key;
  if (!node.computed) return property?.name ?? property?.value;
  return property?.type === 'Literal' && typeof property.value === 'string' ? property.value : null;
}
function navigationTarget(node, scope, depth = 0, seen = new Set()) {
  if (!node || depth > 24 || seen.has(node)) return null;
  seen.add(node);
  if (node.type === 'Identifier') {
    const binding = scope.lookup(node.name);
    if (binding?.browserGlobal) return {binding, root: binding.browserGlobal, path: [], uncertain: binding.reassigned === true};
    if (binding?.constant && binding.node) {
      const target = navigationTarget(binding.node, binding.scope, depth + 1, seen);
      return target ? {...target, uncertain: target.uncertain || binding.reassigned === true} : null;
    }
  } else if (node.type === 'MemberExpression') {
    const target = navigationTarget(node.object, scope, depth + 1, seen);
    return target ? {...target, path: [...target.path, syntacticProperty(node)]} : null;
  }
  return null;
}
function locationObject(original, originalScope, method) {
  const target = navigationTarget(original, originalScope);
  if (!target || !(target.root === 'location' && target.path.length === 0 ||
      ['window', 'globalThis', 'document', 'self'].includes(target.root) && target.path.length === 1 && target.path[0] === 'location')) return false;
  const changed = target.binding.navigationWrites.has('location') ||
    method && target.binding.navigationWrites.has('location.' + method);
  if (target.uncertain || changed) {
    limitation('client_navigation_target_requires_review', original);
    return false;
  }
  return true;
}
function recordNavigationWrite(writes, path) {
  if (path[0] !== 'location' && path[0] !== null) return;
  if (path.length === 1) writes.add('location');
  else if (path.length === 2) {
    for (const method of ['assign', 'replace']) if (path[1] === null || path[1] === method) writes.add('location.' + method);
  }
}
function markMutation(node, scope) {
  patternTargets(node, target => {
    if (target.type === 'Identifier') {
      const binding = scope.lookup(target.name);
      if (binding) { binding.mutable = true; binding.reassigned = true; }
      if (binding?.browserGlobal === 'location') binding.navigationWrites.add('location');
      if (binding?.globalClient) binding.clientNamespace[binding.globalClient] = UNKNOWN;
      return;
    }
    const navigation = navigationTarget(target, scope);
    if (navigation) {
      const path = navigation.root === 'location' ? ['location', ...navigation.path] : navigation.path;
      recordNavigationWrite(navigation.binding.navigationWrites, path);
      if (['window', 'globalThis', 'self'].includes(navigation.root) &&
          (navigation.path[0] === null || ['fetch', 'axios'].includes(navigation.path[0]))) {
        for (const name of ['fetch', 'axios']) {
          if (navigation.path[0] !== null && name !== navigation.path[0]) continue;
          navigation.binding.clientBindings[name].mutable = true;
          navigation.binding.clientNamespace[name] = UNKNOWN;
        }
      }
    }
    let root = target.object;
    while (root?.type === 'MemberExpression') root = root.object;
    let rootScope = scope;
    const seen = new Set();
    while (root?.type === 'Identifier') {
      const binding = rootScope.lookup(root.name);
      if (!binding || seen.has(binding)) break;
      seen.add(binding);
      binding.mutable = true;
      if (binding.globalClient) binding.clientNamespace[binding.globalClient] = UNKNOWN;
      if (!binding.constant || binding.node?.type !== 'Identifier') break;
      root = binding.node;
      rootScope = binding.scope;
    }
  });
}
function sinkReferences(original, originalScope) {
  const fields = new Set(), seen = new Set();
  let limited = false;
  function add(name) {
    // Only syntactic field/identifier names, never resolved computed-key values.
    if (typeof name !== 'string' || !/^[A-Za-z_$][A-Za-z0-9_$]{0,127}$/.test(name)) return;
    if (fields.size < 64) fields.add(name);
    else limited = true;
  }
  function visit(node, scope, depth = 0) {
    if (!node || typeof node.type !== 'string') return;
    tick(depth);
    if (depth > 24 || seen.has(node)) { limited = true; return; }
    seen.add(node);
    if (node.type === 'Literal' || node.type === 'TemplateElement') return;
    if (node.type === 'Identifier') {
      const binding = scope.lookup(node.name);
      if (binding?.node && !binding.mutable) visit(binding.node, binding.scope, depth + 1);
      else add(node.name);
      return;
    }
    if (node.type === 'MemberExpression') {
      const name = syntacticProperty(node);
      if (name === null) limited = true;
      else add(name);
      // The terminal field is the reference. Intermediate property names are
      // not independently treated as submitted inputs or proven data sources.
      if (!['Identifier', 'MemberExpression'].includes(node.object.type)) visit(node.object, scope, depth + 1);
      if (node.computed && name === null) visit(node.property, scope, depth + 1);
      return;
    }
    if (node.type === 'CallExpression' || node.type === 'NewExpression') {
      if (node.callee?.type === 'MemberExpression') visit(node.callee.object, scope, depth + 1);
      for (const argument of node.arguments || []) visit(argument, scope, depth + 1);
      return;
    }
    for (const [key, value] of Object.entries(node)) {
      if (['loc', 'start', 'end', 'key'].includes(key)) continue;
      if (Array.isArray(value)) for (const child of value) visit(child, scope, depth + 1);
      else if (value && typeof value === 'object') visit(value, scope, depth + 1);
    }
  }
  visit(original, originalScope);
  return {referenced_fields: [...fields].sort(), references_limited: limited};
}
function analyzeSink(node, scope, parent) {
  let sink, category, value;
  if (node.type === 'AssignmentExpression' && node.left.type === 'MemberExpression') {
    const property = syntacticProperty(node.left);
    if (property === 'innerHTML') { sink = 'innerHTML.assignment'; category = 'html_execution'; value = node.right; }
    else if (property === 'href' && locationObject(node.left.object, scope)) {
      sink = 'location.href'; category = 'client_navigation'; value = node.right;
    }
  } else if (node.type === 'Property' && parent?.type === 'ObjectExpression' && node.kind === 'init' && syntacticProperty(node) === 'innerHTML') {
    sink = 'innerHTML.object_property'; category = 'html_execution'; value = node.value;
  } else if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') {
    const method = syntacticProperty(node.callee);
    if (method === 'insertAdjacentHTML') { sink = 'insertAdjacentHTML'; category = 'html_execution'; value = node.arguments[1]; }
    else if (['assign', 'replace'].includes(method) && locationObject(node.callee.object, scope, method)) {
      sink = 'location.' + method; category = 'client_navigation'; value = node.arguments[0];
    }
  }
  if (!sink) return;
  if (result.client_sinks.length >= 2000) { limitation('client_sink_rows_truncated', node); return; }
  const references = sinkReferences(value, scope);
  const valueKind = !value ? 'dynamic' : value.type === 'Literal' ||
    value.type === 'TemplateLiteral' && !value.expressions.length ? 'static' : 'reference';
  result.client_sinks.push({sink, category, ...references, value_kind: valueKind,
    locator: `line:${node.loc.start.line}:column:${node.loc.start.column + 1}`,
    source_line: node.loc.start.line, source_column: node.loc.start.column + 1});
  if (references.references_limited) limitation('client_sink_reference_requires_review', node);
}
function analyzeCall(node, scope) {
  let client, action, configNode, bodyNode, urlNode;
  if (node.callee.type === 'Identifier') {
    client = evaluate(node.callee, scope);
    if (client?.client === 'fetch') { action = 'fetch'; urlNode = node.arguments[0]; configNode = node.arguments[1]; }
    else if (client?.client === 'axios') { action = 'request'; configNode = node.arguments[0]; }
    else return;
  } else if (node.callee.type === 'MemberExpression') {
    const callable = evaluate(node.callee, scope);
    if (callable?.client === 'fetch') {
      client = callable; action = 'fetch'; urlNode = node.arguments[0]; configNode = node.arguments[1];
    } else {
      client = evaluate(node.callee.object, scope);
      action = propertyName(node.callee, scope, 0);
      if (client?.client !== 'axios' || !['get','post','put','patch','delete','head','options','request'].includes(action)) return;
      if (action === 'request') configNode = node.arguments[0];
      else {
        urlNode = node.arguments[0];
        if (['post','put','patch'].includes(action)) { bodyNode = node.arguments[1]; configNode = node.arguments[2]; }
        else configNode = node.arguments[1];
      }
    }
  } else return;
  const options = configNode ? objectProperties(configNode, scope) : new Map();
  let url = urlNode ? evaluate(urlNode, scope) : staticProperty(options, 'url');
  let method = ['fetch','request'].includes(action) ? staticProperty(options, 'method') : action;
  if (method === undefined) method = options ? 'GET' : UNKNOWN;
  method = typeof method === 'string' && /^[A-Za-z][A-Za-z0-9_-]{0,31}$/.test(method) ? method.toUpperCase() : null;
  const ownBase = staticProperty(options, 'baseURL');
  const base = ownBase === undefined ? client.baseURL : ownBase;
  if (typeof url === 'string' && client.client === 'axios' && !/^[a-z][a-z0-9+.-]*:/i.test(url) && base) {
    url = typeof base === 'string' ? base.replace(/\/+$/, '') + '/' + url.replace(/^\/+/, '') : UNKNOWN;
  }
  const inputs = [];
  const requestBody = options?.get(client.client === 'fetch' ? 'body' : 'data');
  const bodyScope = bodyNode ? scope : requestBody?.scope || scope;
  const bodyObject = objectProperties(bodyNode || requestBody?.node, bodyScope);
  let protocol = 'http', operation_name = '';
  const query = staticProperty(bodyObject, 'query');
  const explicitName = staticProperty(bodyObject, 'operationName');
  const documentNames = graphqlDocument(query);
  const validExplicitName = typeof explicitName === 'string' && /^[A-Za-z_]\w{0,127}$/.test(explicitName);
  if (bodyObject && (validExplicitName || documentNames)) {
    protocol = 'graphql';
    if (validExplicitName) {
      if (documentNames && !documentNames.includes(explicitName)) limitation('graphql_operation_selection_mismatch', node);
      else operation_name = explicitName;
    } else if (documentNames.length === 1) operation_name = documentNames[0];
    const variables = bodyObject.get('variables');
    if (variables) fields(variables.node, variables.scope, 'graphql', inputs, '/variables');
    limitation('graphql_selection_requires_review', node);
  } else if (bodyNode) fields(bodyNode, scope, 'body', inputs);
  else if (requestBody) fields(requestBody.node, requestBody.scope, 'body', inputs);
  for (const [key, location] of [['params','query'], ['headers','header']]) {
    const field = options?.get(key);
    if (field) fields(field.node, field.scope, location, inputs);
  }
  let content_type = '';
  const headerNode = options?.get('headers');
  if (headerNode) {
    const headers = evaluate(headerNode.node, headerNode.scope);
    if (headers !== UNKNOWN && headers) for (const [name, value] of Object.entries(headers)) {
      if (name.toLowerCase() === 'content-type' && typeof value === 'string' && /^[\w.+-]+\/[\w.+-]+(?:\s*;.*)?$/.test(value)) content_type = value.split(';',1)[0].toLowerCase();
    }
  }
  const body = bodyNode || requestBody?.node;
  if (!content_type && client.client === 'axios' && unwrap(body, bodyScope).node?.type === 'ObjectExpression') content_type = 'application/json';
  const row = {url:typeof url === 'string' && url.length <= 8192 ? url : null, method, content_type, inputs, protocol, operation_name,
    locator:`line:${node.loc.start.line}:column:${node.loc.start.column + 1}`};
  if (row.url && row.method) result.operations.push(row);
  else {
    result.candidates.push(row);
    limitation(!row.url ? 'dynamic_request_url' : 'dynamic_request_method', node);
  }
  if (!options) limitation('dynamic_request_options', node);
  if (result.operations.length + result.candidates.length > 10000) throw new Error('ast_row_budget_exceeded');
}
function walk(node, scope, depth = 0, prepare = false, parent = null) {
  if (!node || typeof node.type !== 'string') return;
  tick(depth);
  const outer = scope;
  const block = ['Program', 'BlockStatement', 'StaticBlock'].includes(node.type);
  const fn = ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'].includes(node.type);
  if (prepare) {
    if (block) {
      scope = new Scope(scope, node.type !== 'BlockStatement');
      if (node.type !== 'BlockStatement') hoistVars(node, scope);
      declarations(node.body, scope);
    } else if (fn) {
      scope = new Scope(scope, true);
      for (const param of node.params) {
        bindPattern(param, scope);
        if (param.type !== 'Identifier') limitation('destructured_parameter_requires_review', param);
      }
      if (node.id) scope.bindings.set(node.id.name, {value: UNKNOWN});
      hoistVars(node.body, scope);
    } else if (node.type === 'CatchClause') {
      scope = new Scope(scope);
      bindPattern(node.param, scope);
    } else if (['ForStatement', 'ForInStatement', 'ForOfStatement'].includes(node.type)) {
      scope = new Scope(scope);
      const declaration = node.init || node.left;
      if (declaration?.type === 'VariableDeclaration') declarations([declaration], scope);
    } else if (node.type === 'SwitchStatement') {
      scope = new Scope(scope);
      declarations(node.cases.flatMap(branch => branch.consequent), scope);
    } else if (['ClassDeclaration', 'ClassExpression'].includes(node.type)) {
      scope = new Scope(scope);
      if (node.id) scope.bindings.set(node.id.name, {value: UNKNOWN});
    }
    if (scope !== outer) scopes.set(node, scope);
    if (node.type === 'AssignmentExpression') markMutation(node.left, scope);
    else if (node.type === 'UpdateExpression' || node.type === 'UnaryExpression' && node.operator === 'delete') markMutation(node.argument, scope);
    else if (['ForInStatement', 'ForOfStatement'].includes(node.type) && node.left.type !== 'VariableDeclaration') markMutation(node.left, scope);
  } else scope = scopes.get(node) || scope;
  if (block) {
    for (const child of node.body) walk(child, scope, depth + 1, prepare, node);
    return;
  }
  if (fn) {
    for (const param of node.params) walk(param, scope, depth + 1, prepare, node);
    walk(node.body, scope, depth + 1, prepare, node);
    return;
  }
  if (node.type === 'SwitchStatement') {
    walk(node.discriminant, outer, depth + 1, prepare, node);
    for (const branch of node.cases) walk(branch, scope, depth + 1, prepare, node);
    return;
  }
  if (!prepare) {
    analyzeSink(node, scope, parent);
    if (node.type === 'CallExpression') analyzeCall(node, scope);
    if (node.type === 'ImportExpression') limitation('dynamic_import_not_loaded', node);
  }
  for (const [key, value] of Object.entries(node)) {
    if (['loc','start','end'].includes(key)) continue;
    if (Array.isArray(value)) for (const child of value) { if (child && typeof child === 'object') walk(child, scope, depth + 1, prepare, node); }
    else if (value && typeof value === 'object') walk(value, scope, depth + 1, prepare, node);
  }
}

try {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > LIMIT * 6 + 1024) throw new Error('input_budget_exceeded');
    chunks.push(chunk);
  }
  const payload = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (typeof payload.source !== 'string' || Buffer.byteLength(payload.source) > LIMIT) throw new Error('invalid_source');
  let acorn;
  try { acorn = await import('acorn'); }
  catch { limitation('javascript_ast_parser_unavailable'); }
  if (acorn) {
    let ast;
    try { ast = acorn.parse(payload.source, {ecmaVersion:'latest', sourceType:'module', locations:true}); }
    catch {
      try { ast = acorn.parse(payload.source, {ecmaVersion:'latest', sourceType:'script', locations:true}); }
      catch { limitation('javascript_syntax_not_supported'); }
    }
    if (ast) {
      const scope = new Scope(null, true);
      const clientNamespace = {fetch: FETCH, axios: AXIOS};
      const clientBindings = {fetch: {value: FETCH, globalClient: 'fetch', clientNamespace},
        axios: {value: AXIOS, globalClient: 'axios', clientNamespace}};
      const navigationWrites = new Set();
      scope.bindings.set('fetch', clientBindings.fetch);
      scope.bindings.set('axios', clientBindings.axios);
      for (const name of ['window', 'globalThis']) scope.bindings.set(name,
        {value: clientNamespace, browserGlobal: name, navigationWrites, clientBindings, clientNamespace});
      for (const name of ['location', 'document', 'self']) scope.bindings.set(name,
        {value: UNKNOWN, browserGlobal: name, navigationWrites, clientBindings, clientNamespace});
      // Bind scopes and writes before inference; later assignments cannot lend
      // stale aliases or shadowed browser globals to an earlier request/sink.
      walk(ast, scope, 0, true);
      visited = 0;
      walk(ast, scope);
    }
  }
} catch {
  result.operations = []; result.candidates = []; result.client_sinks = [];
  limitation('javascript_analysis_budget_or_input_error');
}
process.stdout.write(JSON.stringify(result) + '\n');
