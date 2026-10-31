// Offline bounded AST discovery. This helper never executes the supplied source.
// The Python adapter removes URL query values and adds file provenance.
const LIMIT = 8 * 1024 * 1024;
const UNKNOWN = Symbol('unknown');
const AXIOS = Object.freeze({client: 'axios', baseURL: ''});
const FETCH = Object.freeze({client: 'fetch'});
const result = {operations: [], candidates: [], limitations: []};
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
  constructor(parent = null) { this.parent = parent; this.bindings = new Map(); }
  lookup(name) { return this.bindings.has(name) ? this.bindings.get(name) : this.parent?.lookup(name); }
}
const validName = value => typeof value === 'string' && value.length > 0 && value.length <= 1024 && !/[\u0000-\u001f]/.test(value);
const pointer = value => value.replaceAll('~', '~0').replaceAll('/', '~1');
let mutated;

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
        if (declaration.id.type === 'Identifier') scope.bindings.set(declaration.id.name,
          {node: declaration.init, scope, mutable: statement.kind !== 'const' || mutated.has(declaration.id.name)});
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
function walk(node, scope, depth = 0) {
  if (!node || typeof node.type !== 'string') return;
  tick(depth);
  if (node.type === 'Program' || node.type === 'BlockStatement') {
    const inner = new Scope(scope);
    declarations(node.body, inner);
    for (const child of node.body) walk(child, inner, depth + 1);
    return;
  }
  if (['FunctionDeclaration','FunctionExpression','ArrowFunctionExpression'].includes(node.type)) {
    const inner = new Scope(scope);
    for (const param of node.params) {
      if (param.type === 'Identifier') inner.bindings.set(param.name, {value:UNKNOWN});
      else {
        const stack = [param];
        while (stack.length) {
          const item = stack.pop();
          if (item.type === 'Identifier') inner.bindings.set(item.name, {value:UNKNOWN});
          else if (item.type === 'ObjectPattern') stack.push(...item.properties.map(p => p.value || p.argument));
          else if (item.type === 'ArrayPattern') stack.push(...item.elements.filter(Boolean));
          else if (item.type === 'RestElement') stack.push(item.argument);
          else if (item.type === 'AssignmentPattern') stack.push(item.left);
        }
        limitation('destructured_parameter_requires_review', param);
      }
    }
    if (node.id) inner.bindings.set(node.id.name, {value:UNKNOWN});
    walk(node.body, inner, depth + 1);
    return;
  }
  if (node.type === 'CallExpression') analyzeCall(node, scope);
  if (node.type === 'ImportExpression') limitation('dynamic_import_not_loaded', node);
  for (const [key, value] of Object.entries(node)) {
    if (['loc','start','end'].includes(key)) continue;
    if (Array.isArray(value)) for (const child of value) { if (child && typeof child === 'object') walk(child, scope, depth + 1); }
    else if (value && typeof value === 'object') walk(value, scope, depth + 1);
  }
}
function collectMutations(ast) {
  const names = new Set(), stack = [ast];
  let total = 0;
  while (stack.length) {
    const node = stack.pop();
    if (++total > 300000) throw new Error('ast_budget_exceeded');
    if (!node || typeof node.type !== 'string') continue;
    let target = node.type === 'AssignmentExpression' ? node.left : node.type === 'UpdateExpression' ? node.argument : null;
    while (target?.type === 'MemberExpression') target = target.object;
    if (target?.type === 'Identifier') names.add(target.name);
    for (const [key, value] of Object.entries(node)) {
      if (['loc','start','end'].includes(key)) continue;
      if (Array.isArray(value)) stack.push(...value.filter(x => x && typeof x === 'object'));
      else if (value && typeof value === 'object') stack.push(value);
    }
  }
  return names;
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
      mutated = collectMutations(ast);
      const scope = new Scope();
      scope.bindings.set('fetch', {value:mutated.has('fetch') ? UNKNOWN : FETCH});
      scope.bindings.set('axios', {value:mutated.has('axios') ? UNKNOWN : AXIOS});
      for (const name of ['window', 'globalThis']) scope.bindings.set(name,
        {value:mutated.has(name) ? UNKNOWN : {fetch:FETCH, axios:AXIOS}});
      walk(ast, scope);
    }
  }
} catch {
  result.operations = []; result.candidates = [];
  limitation('javascript_analysis_budget_or_input_error');
}
process.stdout.write(JSON.stringify(result) + '\n');
