"""Page and function coverage ledger, plus a browser execution path.

Two rounds of the heasec-mall assessment treated the API as the whole attack surface.
Every conclusion came from HTTP captures, so page-level facts were never recorded:
SPA route guards (`/merchant`, `/admin` reachable without a session), DOM-only
sinks (the admin console renders `description`/`shop_name` through innerHTML), and
whether an XSS payload actually executes were all left as prose limitations.

This module gives the ledger a place to say "this page was visited and this function
was triggered", and gives the executor a way to drive a real browser when the question
is about rendering rather than about bytes on the wire.

Design constraints:
- The browser is optional. `available()` reports why it is not usable instead of raising,
  so a missing browser degrades to BLOCKED rather than failing the assessment.
- Page observations are not HTTP evidence. A digest binds each visit to what it saw
  (title, DOM signals, console errors) and never claims request-level proof.
- Driving the browser runs out-of-process through Node + playwright-core. The plugin
  keeps no runtime dependency; it discovers an installed browser the same way a user
  would, and says so when it cannot.
"""
from __future__ import annotations

import json
import hashlib
import re
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import quote, quote_plus, unquote, urlsplit

from .store import EngineError, canonical, contained, now
from .scope import normalize_url, origin, require_scope
from .transport import headers_map

VISIT_STATUSES = {"visited", "BLOCKED"}
TRIGGER_STATUSES = {"triggered", "BLOCKED"}
_SAFE_EXTRA_HEADERS = {"accept", "accept-language", "cache-control", "pragma", "dnt", "sec-gpc"}
_INTERACTIONS = {"click", "fill", "press"}
_ACTION_TYPES = _INTERACTIONS | {"wait", "waitForSelector", "waitForDialog", "waitForURL"}
_STRUCTURAL_SIGNALS = {"hasApp", "forms", "inputs", "buttons", "links", "textLength", "selectorCount"}
_OBSERVATION_BUDGET = 4 * 1024 * 1024

# Candidate locations for a Node + playwright-core installation. Checked in order;
# the first one whose chromium can actually launch wins.
_BROWSER_ROOTS = (
    Path.home() / ".dsh" / "mcp" / "playwright",
    Path.home() / ".cache" / "ms-playwright",
)


def _node():
    return shutil.which("node") or shutil.which("node.exe")


def _playwright_module():
    """Return the directory containing node_modules/playwright-core, if any."""
    for root in _BROWSER_ROOTS:
        candidate = root / "node_modules" / "playwright-core"
        if candidate.is_dir():
            return root
        if root.name == "ms-playwright" and root.is_dir():
            # Browsers installed without a local playwright package; the caller may
            # still have one elsewhere, so report the browser cache and let the probe decide.
            return root
    return None


def available():
    """Describe browser availability without raising."""
    node = _node()
    if not node:
        return {"available": False, "reason": "node_not_found",
                "detail": "Install Node.js to drive a browser; HTTP captures still work."}
    module_root = _playwright_module()
    if module_root is None:
        return {"available": False, "reason": "playwright_not_found",
                "detail": "No playwright-core installation was found under ~/.dsh/mcp/playwright.",
                "node": node}
    return {"available": True, "node": node, "module_root": str(module_root)}


_PROBE = r"""
const path = process.argv[2];
let chromium;
try { ({ chromium } = require(path + '/node_modules/playwright-core')); }
catch (e) { console.log(JSON.stringify({ok:false, reason:'require_failed', detail:String(e.message).slice(0,200)})); process.exit(0); }
const fs = require('fs');
const os = require('os');
// playwright-core pins an exact browser build; a machine may hold a different revision.
// Try the pinned default first, then any chromium build present in the cache.
function candidates() {
  const list = [];
  try { list.push(chromium.executablePath()); } catch (e) {}
  const cache = process.env.PLAYWRIGHT_BROWSERS_PATH || (os.homedir() + '/AppData/Local/ms-playwright');
  try {
    for (const entry of fs.readdirSync(cache)) {
      if (!entry.startsWith('chromium-')) continue;
      for (const rel of ['chrome-win64/chrome.exe', 'chrome-win/chrome.exe', 'chrome-linux/chrome']) {
        const p = cache + '/' + entry + '/' + rel;
        if (fs.existsSync(p)) list.push(p);
      }
    }
  } catch (e) {}
  return [...new Set(list)];
}
(async () => {
  const tried = [];
  for (const exe of candidates()) {
    if (!fs.existsSync(exe)) { tried.push({exe, err: 'missing'}); continue; }
    try {
      const browser = await chromium.launch({ headless: true, executablePath: exe });
      const version = browser.version();
      await browser.close();
      console.log(JSON.stringify({ok:true, version, executablePath: exe, tried}));
      return;
    } catch (e) {
      tried.push({exe, err: String(e.message).split('\n')[0].slice(0,120)});
    }
  }
  console.log(JSON.stringify({ok:false, reason:'no_launchable_chromium', tried}));
})();
"""


def probe():
    """Launch and immediately close a headless browser to prove the path works."""
    state = available()
    if not state["available"]:
        return state
    with tempfile.TemporaryDirectory() as tmp:
        script = Path(tmp) / "probe.cjs"
        script.write_text(_PROBE, encoding="utf-8")
        try:
            process = subprocess.run([state["node"], str(script), state["module_root"]],
                                     capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"available": False, "reason": "probe_failed", "detail": type(exc).__name__}
    try:
        result = json.loads(process.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"available": False, "reason": "probe_unparseable",
                "detail": (process.stderr or process.stdout)[:200]}
    if not result.get("ok"):
        return {"available": False, **result}
    return {**state, "available": True, "version": result.get("version"),
            "executable_path": result.get("executablePath")}


_VISIT = r"""
const [moduleRoot, specPath] = process.argv.slice(2);
const fs = require('fs');
const { createHash } = require('node:crypto');
const spec = JSON.parse(fs.readFileSync(specPath, 'utf8'));
const BODY_DIGEST_BUDGET = 8 * 1024 * 1024;
function digest(data) { return createHash('sha256').update(data).digest('hex'); }

// The descriptors are produced by Python's scope normalizer. Reject ambiguous
// encodings before WHATWG URL parsing can collapse dot segments or backslashes.
function parsedURL(raw) {
  if (typeof raw !== 'string' || !raw || /[\u0000-\u0020\\]/.test(raw)) throw new Error('invalid_url');
  const match = /^(https?):\/\/([^/?#]+)([^?#]*)(?:\?([^#]*))?$/i.exec(raw);
  if (!match) throw new Error('invalid_url');
  const u = new URL(raw);
  if (u.username || u.password || u.hash) throw new Error('invalid_url');
  const path = match[3] || '/';
  let decoded = path;
  for (let i = 0; i < 3; ++i) {
    const next = decodeURIComponent(decoded);
    if (next === decoded) break;
    decoded = next;
  }
  if (/[\\\u0000-\u001f]/.test(decoded) || decoded.includes('//') ||
      decoded.split('/').some(p => p === '.' || p === '..')) throw new Error('ambiguous_url');
  return { scheme: u.protocol.slice(0, -1), authority: u.host.toLowerCase(),
           path: decodeURIComponent(path), query: match[4] || '', origin: u.origin };
}
function matches(rule, u) {
  return rule.scheme === u.scheme && rule.authority === u.authority &&
    (!rule.root || u.path === rule.root || u.path.startsWith(rule.root + '/')) &&
    (!rule.query || rule.query === u.query);
}
function allowed(raw) {
  try {
    const u = parsedURL(raw);
    return (spec.scope || []).some(r => matches(r, u)) &&
      !(spec.exclude || []).some(r => matches(r, u));
  } catch (_) { return false; }
}
// A write is only ever replayed against the origin the visit was aimed at, so an
// injected form action cannot turn one authorized visit into a cross-site POST.
function sameOrigin(raw, base) {
  try { return parsedURL(raw).origin === parsedURL(base).origin; } catch (_) { return false; }
}

(async () => {
  const out = { url: spec.url, finalUrl: null, status: null, started_at: new Date().toISOString(),
                headless: spec.headless !== false, console: [], dialogs: [],
                network: [], blocked_requests: [], actions: [] };
  let browser, context, page, actionIndex = null;
  function block(url, method, reason, extra) {
    if (out.blocked_requests.length < 1000) {
      out.blocked_requests.push({ url, method, reason, action_index: actionIndex, ...extra });
    } else out.network_truncated = true;
  }
  function collectSignals() {
    return page.evaluate((s) => {
      const pick = {};
      pick.hasApp = !!document.querySelector('#app, #root, main');
      pick.forms = document.querySelectorAll('form').length;
      pick.inputs = document.querySelectorAll('input,textarea,select').length;
      pick.buttons = document.querySelectorAll('button,[role=button]').length;
      pick.links = document.querySelectorAll('a[href]').length;
      pick.textLength = (document.body && document.body.innerText || '').length;
      if (s && s.selector) pick.selectorCount = document.querySelectorAll(s.selector).length;
      return pick;
    }, spec.signals || null);
  }
  function guardPage() {
    const url = page.url();
    if (!allowed(url)) {
      out.scope_error = 'final_url_out_of_scope';
      throw new Error('final_url_out_of_scope');
    }
  }
  function attach(p) {
    p.on('console', m => {
      if (out.console.length < 50) out.console.push({ type: m.type(), text: String(m.text()).slice(0, 300) });
    });
    p.on('dialog', async d => {
      if (out.dialogs.length < 50) out.dialogs.push({ type: d.type(), message: String(d.message()).slice(0, 300),
                                                   action_index: actionIndex, document_url: p.url() });
      await d.dismiss().catch(() => {});
    });
    p.on('response', r => {
      const request = r.request();
      if (p === page && request.isNavigationRequest() && request.frame() === p.mainFrame()) {
        out.status = r.status();
      }
    });
  }
  try {
    if (!allowed(spec.url)) throw new Error('initial_url_out_of_scope');
    const { chromium } = require(moduleRoot + '/node_modules/playwright-core');
    browser = await chromium.launch({
      headless: out.headless, executablePath: spec.executablePath || undefined,
      args: ['--disable-background-networking'],
    });
    context = await browser.newContext({
      ignoreHTTPSErrors: true, userAgent: spec.userAgent || undefined,
      extraHTTPHeaders: spec.headers || {}, serviceWorkers: 'block',
      acceptDownloads: false, permissions: [],
    });
    // A separate context is made for every visit. On older runtimes without a
    // worker-aware WebSocket guard, fail before opening any target page.
    if (typeof context.routeWebSocket !== 'function') throw new Error('websocket_guard_unavailable');
    await context.routeWebSocket('**/*', socket => {
      block(socket.url(), 'WEBSOCKET', 'websocket_disabled');
      socket.close({ code: 1008, reason: 'browser_scope_guard' });
    });
    await context.route('**/*', async route => {
      const request = route.request();
      const url = request.url(), method = request.method().toUpperCase();
      const entry = { url, method, type: request.resourceType(), action_index: actionIndex };
      if (out.network.length < 1000) out.network.push(entry);
      else out.network_truncated = true;
      if (!allowed(url)) {
        entry.blocked = true; entry.reason = 'out_of_scope';
        block(url, method, entry.reason, { type: entry.type });
        await route.abort('blockedbyclient'); return;
      }
      if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
        // Read-only is the default. Writes are allowed only when Python has already
        // confirmed project mutation permission; the page itself supplies the
        // request shape, but never to a different origin than the visit target.
        if (!spec.allowWrite) {
          entry.blocked = true; entry.reason = 'write_operation_not_authorized';
          block(url, method, entry.reason, { type: entry.type });
          await route.abort('blockedbyclient'); return;
        }
        if (!sameOrigin(url, spec.url)) {
          entry.blocked = true; entry.reason = 'write_out_of_origin';
          block(url, method, entry.reason, { type: entry.type });
          await route.abort('blockedbyclient'); return;
        }
        entry.write = true;
      }
      try {
        const headers = await request.allHeaders();
        const credentialNames = new Set(spec.credentialHeaders || []);
        for (const key of Object.keys(headers)) {
          if (credentialNames.has(key.toLowerCase()) && parsedURL(url).origin !== spec.sessionOrigin) delete headers[key];
        }
        if (spec.sessionOrigin && parsedURL(url).origin === spec.sessionOrigin) {
          Object.assign(headers, spec.sessionHeaders || {});
        }
        entry.request_headers = headers;
        if (typeof request.postDataBuffer === 'function') {
          const body = request.postDataBuffer() || Buffer.alloc(0);
          entry.request_body_sha256 = digest(body);
          entry.request_body_bytes = body.length;
        }
        // Playwright's route callback does not run on subsequent automatic
        // redirects. Fetch one response only; do not continue any redirect chain.
        const response = await route.fetch({ headers, maxRedirects: 0, maxRetries: 0, timeout: spec.timeout || 20000 });
        entry.status = response.status();
        entry.response_headers = response.headers();
        if (['document', 'xhr', 'fetch'].includes(entry.type)) {
          entry.response_body_complete = false;
          const declared = entry.response_headers['content-length'];
          const declaredBytes = typeof declared === 'string' && /^\d+$/.test(declared) ? Number(declared) : null;
          // A known oversized body is never read for proof. Unknown lengths are
          // checked after the actual response body arrives, before hashing it.
          if (declaredBytes === null || declaredBytes <= BODY_DIGEST_BUDGET) {
            try {
              const body = await response.body();
              entry.response_body_bytes = body.length;
              if (body.length <= BODY_DIGEST_BUDGET) {
                entry.response_body_sha256 = digest(body);
                entry.response_body_complete = true;
              }
            } catch (_) { /* Fetch can still render; an unread body is not proof. */ }
          }
        }
        const location = entry.response_headers.location;
        if ([301, 302, 303, 307, 308].includes(entry.status) && location) {
          let target = null;
          try { target = new URL(location, url).href; } catch (_) {}
          entry.blocked = true;
          entry.reason = target && allowed(target) ? 'redirect_not_followed' : 'redirect_out_of_scope';
          block(url, method, entry.reason, { location: target || String(location), type: entry.type });
          await route.abort('blockedbyclient'); return;
        }
        entry.allowed = true;
        await route.fulfill({ response });
      } catch (e) {
        entry.error = String(e.message).split('\n')[0].slice(0, 200);
        entry.blocked = true; entry.reason = 'request_failed';
        block(url, method, entry.reason, { type: entry.type });
        await route.abort('failed').catch(() => {});
      }
    });
    context.on('page', attach);
    page = await context.newPage();
    const response = await page.goto(spec.url, { waitUntil: spec.waitUntil || 'domcontentloaded', timeout: spec.timeout || 20000 });
    out.status = response ? response.status() : null;
    if (spec.settleMs) await page.waitForTimeout(spec.settleMs);
    guardPage();
    out.title = await page.title();
    out.signals = await collectSignals();
    for (let index = 0; index < (spec.actions || []).length; ++index) {
      const action = spec.actions[index];
      const step = { index, action: action.type, selector: action.selector };
      const blockedBefore = out.blocked_requests.length;
      actionIndex = index;
      try {
        guardPage();
        if (action.type === 'click') {
          await page.click(action.selector, { timeout: action.timeout || 5000 });
        } else if (action.type === 'fill') {
          const value = String(action.value == null ? '' : action.value);
          // The raw observation stays private. Public views learn and scrub
          // fill values; neither this value nor its low-entropy digest is proof
          // that a browser input belongs to a separate source experiment.
          step.value = value;
          step.value_sha256 = digest(Buffer.from(value, 'utf8'));
          await page.fill(action.selector, value, { timeout: action.timeout || 5000 });
        } else if (action.type === 'press') {
          step.key = action.key || 'Enter';
          await page.press(action.selector || 'body', step.key, { timeout: action.timeout || 5000 });
        } else if (action.type === 'wait') {
          await page.waitForTimeout(action.ms || 500);
        } else if (action.type === 'waitForSelector') {
          await page.waitForSelector(action.selector, { timeout: action.timeout || 5000 });
        } else if (action.type === 'waitForDialog') {
          const dialog = await page.waitForEvent('dialog', { timeout: action.timeout || 5000 });
          step.dialog_type = dialog.type();
          step.dialog_message = String(dialog.message()).slice(0, 300);
        } else if (action.type === 'waitForURL') {
          await page.waitForURL(action.value || action.text, { timeout: action.timeout || 5000 });
          step.url = page.url();
        } else throw new Error('unknown_action');
        const settle = action.settleMs == null ? spec.actionSettleMs : action.settleMs;
        if (settle) await page.waitForTimeout(settle);
        guardPage();
        if (out.blocked_requests.length > blockedBefore) throw new Error('action_request_blocked');
        step.ok = true;
      } catch (e) {
        step.ok = false;
        step.error = String(e.message).split('\n')[0].slice(0, 200);
      }
      step.blocked_request_count = out.blocked_requests.length - blockedBefore;
      step.finalUrl = page.url();
      out.actions.push(step);
      actionIndex = null;
    }
    out.finalUrl = page.url();
    guardPage();
    out.afterActions = await collectSignals();
    // Keep the write trail explicit: Python decides whether the observation may
    // count as a successful visit instead of a blocked one.
    out.write_requests = out.network.filter(e => e.write).map(e => ({
      method: e.method, url: e.url, status: e.status == null ? null : e.status,
      action_index: e.action_index,
    }));
    out.write_authorized = !!spec.allowWrite;
    if (out.write_requests.length && !spec.allowWrite) out.write_requests = [];
    if (spec.screenshot) {
      const buf = await page.screenshot({ fullPage: false });
      out.screenshotBytes = buf.length;
      fs.writeFileSync(spec.screenshot, buf, { flag: 'wx' });
    }
    if (spec.html) fs.writeFileSync(spec.html, await page.content(), { flag: 'wx' });
    if (spec.afterActionsHtml) fs.writeFileSync(spec.afterActionsHtml, await page.content(), { flag: 'wx' });
  } catch (e) {
    out.error = String(e.message).split('\n')[0].slice(0, 300);
  } finally {
    if (page) {
      out.finalUrl = page.url();
      if (!allowed(out.finalUrl)) out.scope_error = 'final_url_out_of_scope';
    }
    // Everything worth recording is already captured; the remaining time only
    // serves a human watching the window.
    if (spec.holdMs > 0 && !out.headless) {
      try { await page.waitForTimeout(spec.holdMs); } catch (_) {}
    }
    if (context) await context.close().catch(() => {});
    if (browser) await browser.close().catch(() => {});
    out.completed_at = new Date().toISOString();
  }
  console.log(JSON.stringify(out));
})();
"""


def _scope_descriptors(config, key):
    result = []
    for rule in config.get(key) or []:
        parsed = urlsplit(normalize_url(rule))
        result.append({"scheme": parsed.scheme, "authority": parsed.netloc,
                       "root": unquote(parsed.path).rstrip("/"), "query": parsed.query})
    return result


def _number(args, key, default, maximum, *, minimum=0):
    value = args.get(key, default)
    if type(value) not in (int, float) or not minimum <= value <= maximum:
        raise EngineError("browser_budget", key + " is outside its supported budget")
    return value


def _actions(args):
    actions = args.get("actions") or []
    if not isinstance(actions, list) or len(actions) > 50:
        raise EngineError("browser_actions", "actions must be an array of at most 50 steps")
    normalized = []
    for action in actions:
        if not isinstance(action, dict):
            raise EngineError("browser_actions", "Unknown browser action type")
        # `action` is a compatibility alias; the executor reads `type`.
        action_type = action.get("type", action.get("action", "click"))
        if action_type not in _ACTION_TYPES:
            raise EngineError("browser_actions", "Unknown browser action type")
        step = {**action, "type": action_type}
        if step["type"] in {"click", "fill", "waitForSelector"} and (
                not isinstance(step.get("selector"), str) or not step["selector"].strip()):
            raise EngineError("browser_actions", "This action needs a selector")
        if step["type"] == "waitForURL" and not isinstance(step.get("value", step.get("text")), str):
            raise EngineError("browser_actions", "waitForURL needs a string URL or pattern")
        if step["type"] == "fill":
            value = step.get("value", step.get("text"))
            if value is not None and not isinstance(value, str):
                raise EngineError("browser_actions", "Fill values must be text or null")
            step["value"] = value or ""
        for field, default, limit in (("timeout", 5000, 20000), ("ms", 500, 10000),
                                      ("settleMs", 0, 10000)):
            if field in step:
                _number(step, field, default, limit, minimum=1 if field == "timeout" else 0)
        normalized.append(step)
    return normalized


def _browser_identity(project, args, url):
    from .engine import session_valid
    extra = headers_map(args.get("headers") or {})
    if any(key not in _SAFE_EXTRA_HEADERS for key in extra):
        raise EngineError("credential_override",
                          "Browser identity headers must come from a verified session_id; "
                          "extra headers are limited to display and cache preferences")
    session = project.get("session", args["session_id"]) if args.get("session_id") else None
    actor = session_valid(project, session) if session else None
    session_headers = headers_map(session.get("headers") or {}) if session else {}
    if any(key in session_headers for key in extra):
        raise EngineError("credential_override", "Extra headers cannot replace verified session headers")
    session_origin = None
    if session:
        evidence = project.get("evidence", session["verification_evidence_id"])
        raw = project.read_artifact(evidence)
        session_origin = origin(raw["request"]["url"])
        if origin(url) != session_origin:
            raise EngineError("identity_origin", "Browser URL must share the verified session's origin")
    credential_names = {"cookie", "authorization", "proxy-authorization", "x-api-key",
                        "x-auth-token", "x-session-token"}
    credential_names.update(session_headers)
    for stored in project.list("session"):
        credential_names.update(key.lower() for key in (stored.get("headers") or {}))
    return extra, session_headers, session_origin, sorted(credential_names), session, actor


def _valid_signals(signals):
    if not isinstance(signals, dict) or not signals:
        return False
    for key in _STRUCTURAL_SIGNALS & signals.keys():
        value = signals[key]
        if key == "hasApp" and type(value) is bool:
            return True
        if key != "hasApp" and type(value) is int and value >= 0:
            return True
    return False


def _network(raw):
    network = raw.get("network", raw.get("requests"))
    if not isinstance(network, list):
        raise EngineError("browser_observation", "Observation requires the original network array")
    for item in network:
        if not isinstance(item, dict):
            raise EngineError("browser_observation", "Network entries must be objects")
        request = item.get("request", item)
        if not isinstance(request, dict) or not isinstance(request.get("url"), str) or not request["url"]:
            raise EngineError("browser_observation", "Each network entry needs its original request URL")
    return network


def _navigation_trail(raw):
    """Every in-scope document URL the visit actually reached.

    A single visit can start on /admin/login and, through a successful login
    action, end on /admin/merchants. Treating only the initial URL as page
    identity made SPA pages impossible to mark even though the page was rendered
    and observed. The trail keeps who reached where and at which action.
    """
    trail, seen = [], set()

    def add(value, index):
        if not isinstance(value, str) or not value:
            return
        try:
            url = normalize_url(value)
        except EngineError:
            return
        if url in seen:
            return
        seen.add(url)
        trail.append({"url": url, "action_index": index})

    add(raw.get("url"), None)
    for index, action in enumerate(raw.get("actions") or []):
        if isinstance(action, dict) and action.get("ok") is True:
            add(action.get("finalUrl"), index)
    add(raw.get("finalUrl"), None)
    return trail


def _visit_target(raw, page_url):
    """Return (found, action_index) for a page URL reached during this visit."""
    try:
        target = normalize_url(page_url)
    except EngineError:
        return False, None
    for entry in _navigation_trail(raw):
        if entry["url"] == target:
            return True, entry["action_index"]
    return False, None


def _successful(project, raw):
    if raw.get("error") or raw.get("scope_error") or raw.get("blocked_requests") or raw.get("network_truncated"):
        return False
    if type(raw.get("status")) is not int or not 200 <= raw["status"] < 300 or not _valid_signals(raw.get("signals")):
        return False
    mutations = raw.get("write_requests") or []
    if mutations and not raw.get("write_authorized"):
        return False
    if any(not isinstance(item, dict) or type(item.get("status")) is not int or not 200 <= item["status"] < 600
           for item in mutations):
        return False
    try:
        require_scope(project.config, raw.get("url"))
        require_scope(project.config, raw.get("finalUrl"))
        network = _network(raw)
        if not network:
            return False
        page_response_seen = False
        for item in network:
            request = item.get("request", item)
            request_url = require_scope(project.config, request["url"])
            if request.get("method", "GET").upper() not in {"GET", "HEAD", "OPTIONS"}:
                status = item.get("status", (item.get("response") or {}).get("status"))
                if not item.get("write") or type(status) is not int or not 200 <= status < 600:
                    return False
            if item.get("blocked") or item.get("error"):
                return False
            if request_url in {normalize_url(raw["url"]), normalize_url(raw["finalUrl"])}:
                status = item.get("status", (item.get("response") or {}).get("status"))
                if status is not None and status != raw["status"]:
                    return False
                page_response_seen = True
        if not page_response_seen:
            return False
    except (EngineError, AttributeError, KeyError, TypeError):
        return False
    return True


def _redaction_inputs(actions):
    values = []
    available = True
    for action in actions or []:
        if not isinstance(action, dict) or action.get("action", action.get("type")) != "fill":
            continue
        if "value" not in action:
            available = False
            continue
        value = action["value"]
        if value is None:
            continue
        if not isinstance(value, (str, int, float, bool)):
            available = False
            continue
        text = value if isinstance(value, str) else str(value)
        if text and not re.fullmatch(r"AWA-XSS-[a-fA-F0-9]{16,64}", text) and text not in values:
            values.append(text)
    return values, available


def _learn_private_value(redactor, value):
    placeholder = redactor.slot(value, "BROWSER_INPUT")
    if value:
        for alias in {value, quote(value, safe=""), quote_plus(value),
                      json.dumps(value, ensure_ascii=True)[1:-1], json.dumps(value, ensure_ascii=False)[1:-1]}:
            redactor.aliases[alias] = placeholder
        redactor._pattern = None


def _private_redaction_context(values):
    return {"browser_fill_values": list(values), "redaction_nonce": secrets.token_hex(32)}


def learn_redaction_context(project, redactor):
    """Learn protected fill values; return legacy unavailable IDs, never secrets."""
    unavailable = {"page_visit_ids": [], "run_ids": []}
    for kind in ("run", "page_visit"):
        for record in project.list(kind):
            if kind == "run" and record.get("kind") != "browser":
                continue
            context = record.get("credentials")
            values = context.get("browser_fill_values") if isinstance(context, dict) else None
            valid = isinstance(values, list) and len(values) <= 50 \
                and all(isinstance(value, str) for value in values) \
                and isinstance(context.get("redaction_nonce"), str) \
                and re.fullmatch(r"[a-f0-9]{64}", context["redaction_nonce"]) is not None \
                and record.get("redaction_context_sha256") == hashlib.sha256(canonical(context).encode("utf-8")).hexdigest()
            if (record.get("redaction_context_required") or record.get("redaction_context_checked")) and not valid:
                raise EngineError("browser_redaction_context", "Required private browser redaction context is missing or changed; no browser content was published")
            if valid:
                for value in values:
                    _learn_private_value(redactor, value)
            legacy_fill = kind == "page_visit" and record.get("source") == "local_playwright" and any(
                isinstance(action, dict) and action.get("action", action.get("type")) == "fill"
                for action in record.get("actions", []))
            if record.get("redaction_context_available") is False or legacy_fill and not record.get("redaction_context_checked"):
                unavailable["page_visit_ids" if kind == "page_visit" else "run_ids"].append(record["id"])
    return unavailable


def public_metadata(project, record, *, raw=None):
    from .engine import credential_header_names
    from .reproduction import Redactor, _learn_header, _secret_key

    raw = record if raw is None else raw
    redactor = Redactor()
    contexts = learn_redaction_context(project, redactor)
    redactor.learn(raw)
    redactor.learn(record)

    def learn_keys(value):
        if isinstance(value, dict):
            for key, item in value.items():
                redactor.learn_text(key)
                learn_keys(item)
        elif isinstance(value, list):
            for item in value:
                learn_keys(item)

    learn_keys(raw)
    credential_names = {"cookie", "set-cookie", "authorization", "proxy-authorization",
                        "x-api-key", "x-auth-token", "x-session-token"}
    for session in project.list("session"):
        names = credential_header_names(session)
        credential_names.update(names)
        for name in names:
            _learn_header(redactor, name, session["headers"][name])

    # Learn cookie/auth subtokens and URL secrets before rendering any prose.
    network = raw.get("network", raw.get("requests", []))
    for item in network if isinstance(network, list) else []:
        if not isinstance(item, dict):
            continue
        header_sets = [item.get("request_headers"), item.get("response_headers")]
        for side in ("request", "response"):
            nested = item.get(side)
            if isinstance(nested, dict):
                header_sets.append(nested.get("headers"))
        for headers in header_sets:
            pairs = headers.items() if isinstance(headers, dict) else headers if isinstance(headers, list) else ()
            for pair in pairs:
                if not isinstance(pair, (tuple, list)) or len(pair) != 2:
                    continue
                name, value = pair
                if isinstance(name, str) and isinstance(value, str) and (
                        name.lower() in credential_names or _secret_key(name)):
                    _learn_header(redactor, name, value)

    def locator(value):
        try:
            return redactor.url(value)[:4000]
        except (TypeError, ValueError):
            return redactor.prose(value)

    urls = []

    def collect_locators(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"url", "finalUrl", "location", "document_url"} and isinstance(item, str):
                    urls.append((value, key))
                collect_locators(item)
        elif isinstance(value, list):
            for item in value:
                collect_locators(item)

    collect_locators(record)
    for item, key in urls:
        if isinstance(item.get(key), str):
            locator(item[key])

    schema_keys = {"id", "kind", "url", "finalUrl", "status", "signals", "hasApp", "forms", "inputs", "buttons", "links",
                   "textLength", "selectorCount", "title", "console", "dialogs", "actions", "source_meta", "type", "message",
                   "text", "action", "selector", "index", "action_index", "ok", "error", "blocked", "reason", "location", "document_url",
                   "method", "blocked_requests", "write_requests", "write_authorized", "navigation_trail", "network_count",
                   "observation_status", "complete", "source", "trust", "machine_authenticated", "scope_enforced", "note",
                   "artifact_path", "sha256", "created_at", "started_at", "finished_at", "completed_at", "session_id", "session_generation",
                   "actor_id", "operation_id", "obligation_id", "resource_id", "page_id", "function_id", "page_visit_id", "visit_id",
                   "run_id", "planned_page_visit_id", "page_ids", "page_adoptions", "functions", "pages", "pages_visited", "functions_triggered",
                   "unvisited", "untriggered", "name", "trigger", "apis", "triggered", "trigger_status", "visited", "visit_status",
                   "blocked_reason", "page_adoption", "page_adoption_error", "next_action", "run_status", "error_code", "effect",
                   "allow_write", "target_origin", "action_count", "dispatch_attempted", "request_signature", "credential_signature",
                   "actor_signature", "credential_header_names", "redaction_context_required", "redaction_context_available",
                   "redaction_context_checked", "redaction_context_sha256", "source_file_sha256", "headless", "network_truncated"}

    def safe_key(key):
        return key if key in schema_keys else redactor.prose(key, 160)

    numeric_secrets = {int(value): placeholder for value, placeholder in redactor.values.items()
                       if re.fullmatch(r"[0-9]{1,64}", value)}

    def sensitive_fields(value, sensitive=False, field="SECRET", untrusted=False):
        if isinstance(value, dict):
            declared = value.get("name")
            result = {}
            for key, item in value.items():
                if key in {"redaction_context_sha256", "value_sha256"}:
                    continue
                structural = field == "signals" and key in _STRUCTURAL_SIGNALS and (
                    key == "hasApp" and type(item) is bool or key != "hasApp" and type(item) is int and item >= 0)
                if structural:
                    result[key] = item
                else:
                    result[key] = sensitive_fields(item, sensitive or _secret_key(key) or
                        (key == "value" and _secret_key(declared)), str(key),
                        untrusted or field == "signals" or key in {"source_meta", "console", "dialogs"})
            return result
        if isinstance(value, list):
            return [sensitive_fields(item, sensitive, field, untrusted) for item in value]
        if sensitive and value is not None:
            return redactor.slot(value, field)
        if untrusted and isinstance(value, (int, float)) and not isinstance(value, bool):
            candidates = [str(value)]
            if isinstance(value, float) and value.is_integer():
                candidates.append(str(int(value)))
            for candidate in candidates:
                if candidate in redactor.values:
                    return redactor.values[candidate]
            if value in numeric_secrets:
                return numeric_secrets[value]
        return value

    def scrub_keys(value):
        if isinstance(value, dict):
            return {safe_key(key): scrub_keys(item) for key, item in value.items()}
        if isinstance(value, list):
            return [scrub_keys(item) for item in value]
        return value

    public = scrub_keys(redactor.metadata(sensitive_fields(record)))

    def restore_locators(original, sanitized):
        if isinstance(original, dict) and isinstance(sanitized, dict):
            for key, item in original.items():
                public_key = safe_key(key)
                if public_key not in sanitized:
                    continue
                if key in {"url", "finalUrl", "location", "document_url"} and isinstance(item, str):
                    sanitized[public_key] = locator(item)
                    if sanitized[public_key] != item:
                        sanitized[public_key + "_redacted"] = True
                        sanitized["locator_requires_binding"] = True
                        sanitized["native_input_requires_binding"] = True
                        sanitized["requestable"] = False
                else:
                    restore_locators(item, sanitized[public_key])
        elif isinstance(original, list) and isinstance(sanitized, list):
            for item, safe_item in zip(original, sanitized):
                restore_locators(item, safe_item)

    restore_locators(record, public)

    with project._lock:
        known_ids = {row[0] for row in project.connection.execute("SELECT id FROM entities").fetchall()}
    known_ids.add(project.project_id)
    pages = project.list("page")
    for page in pages:
        known_ids.update(item["id"] for item in page.get("functions", []) if isinstance(item, dict) and isinstance(item.get("id"), str))
    handle_keys = {"id", "project_id", "session_id", "actor_id", "operation_id", "obligation_id", "resource_id",
                   "evidence_id", "decision_id", "finding_id", "candidate_id", "page_id", "function_id", "run_id",
                   "visit_id", "page_visit_id", "checkpoint_id", "finalization_id", "planned_page_visit_id"}

    def restore_handles(original, sanitized):
        if isinstance(original, dict) and isinstance(sanitized, dict):
            for key, item in original.items():
                public_key = safe_key(key)
                if public_key not in sanitized:
                    continue
                if key in handle_keys and isinstance(item, str) and item in known_ids:
                    sanitized[public_key] = item
                elif key.endswith("_ids") and isinstance(item, list) and isinstance(sanitized[public_key], list):
                    for index, identity in enumerate(item):
                        if isinstance(identity, str) and identity in known_ids and index < len(sanitized[public_key]):
                            sanitized[public_key][index] = identity
                else:
                    restore_handles(item, sanitized[public_key])
        elif isinstance(original, list) and isinstance(sanitized, list):
            for item, safe_item in zip(original, sanitized):
                restore_handles(item, safe_item)

    restore_handles(record, public)

    # Ledger handles/digests are control data, even when a custom identity header
    # happens to equal an actor ID. Raw observation fields remain private.
    for key in ("id", "run_id", "artifact_path", "sha256", "session_id", "actor_id", "created_at", "started_at", "finished_at", "completed_at", "source_file_sha256",
                "request_signature", "credential_signature", "actor_signature",
                "screenshot", "screenshot_sha256", "html", "html_sha256", "after_actions_html", "after_actions_html_sha256"):
        if key in record:
            public[key] = record[key]

    missing = set(contexts["page_visit_ids"])
    missing_runs = set(contexts["run_ids"])
    missing_visits = [item for item in project.list("page_visit") if item["id"] in missing]
    missing_urls = {item[key] for item in missing_visits for key in ("url", "finalUrl") if isinstance(item.get(key), str)}
    missing_pages = {page["id"] for page in pages if page.get("page_visit_id", page.get("visit_id")) in missing or page.get("url") in missing_urls}
    missing_functions = {item["id"] for page in pages if page["id"] in missing_pages for item in page.get("functions", [])
                         if isinstance(item, dict) and isinstance(item.get("id"), str)}
    trusted_metadata = {item["id"]: item for item in missing_visits + pages + project.list("run")}
    trusted_metadata.update({item["id"]: item for page in pages for item in page.get("functions", [])
                             if isinstance(item, dict) and isinstance(item.get("id"), str)})
    safe_codes = {"kind": {"page_visit", "browser"}, "source": {"local_playwright", "imported_mcp"},
                  "trust": {"observed_render", "imported_mcp"}, "observation_status": {"visited", "BLOCKED"},
                  "status": {"running", "interrupted", "succeeded", "failed"}, "method": {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"},
                  "action": _ACTION_TYPES, "type": _ACTION_TYPES | {"alert", "confirm", "prompt", "log", "error"},
                  "effect": {"read_only", "test_resource_write"}, "visit_status": {"visited", "BLOCKED"},
                  "trigger_status": {"triggered", "BLOCKED"}, "next_action": {"run.inspect", "page.adopt"}}

    def restore_codes(original, sanitized):
        if isinstance(original, dict) and isinstance(sanitized, dict):
            for key, item in original.items():
                public_key = safe_key(key)
                if public_key not in sanitized:
                    continue
                if isinstance(item, str) and item in safe_codes.get(key, set()):
                    sanitized[public_key] = item
                else:
                    restore_codes(item, sanitized[public_key])
        elif isinstance(original, list) and isinstance(sanitized, list):
            for item, safe_item in zip(original, sanitized):
                restore_codes(item, safe_item)

    restore_codes(record, public)

    def omit_unavailable(original, sanitized, inherited=False):
        if isinstance(original, dict) and isinstance(sanitized, dict):
            def member(value, collection):
                return isinstance(value, str) and value in collection
            unavailable = inherited or member(original.get("id"), missing | missing_runs | missing_pages | missing_functions) \
                or member(original.get("page_visit_id", original.get("visit_id")), missing) \
                or member(original.get("page_id"), missing_pages) or member(original.get("function_id"), missing_functions) \
                or member(original.get("url"), missing_urls)
            if unavailable:
                sanitized["redaction_context_status"] = "unavailable"
            for key, item in original.items():
                public_key = safe_key(key)
                if public_key not in sanitized:
                    continue
                if unavailable and key not in schema_keys:
                    sanitized.pop(public_key, None)
                elif unavailable and isinstance(item, str):
                    identity = next((original.get(field) for field in ("id", "function_id", "page_id")
                                     if isinstance(original.get(field), str)), None)
                    trusted = trusted_metadata.get(identity, {})
                    if key in handle_keys and item in known_ids or item in safe_codes.get(key, set()) \
                            or key in {"artifact_path", "sha256", "created_at", "started_at", "finished_at", "completed_at", "request_signature", "redaction_context_sha256"} \
                            and trusted.get(key) == item:
                        sanitized[public_key] = item
                    elif key == "message" and re.fullmatch(r"AWA-XSS-[a-fA-F0-9]{16,64}", item) \
                            and redactor.replace(item) == item:
                        sanitized[public_key] = item
                    else:
                        sanitized[public_key] = "[browser content omitted: redaction context unavailable]"
                        if key in {"url", "finalUrl", "location", "document_url"}:
                            sanitized[public_key + "_redacted"] = True
                            sanitized["locator_requires_binding"] = True
                            sanitized["native_input_requires_binding"] = True
                            sanitized["requestable"] = False
                else:
                    omit_unavailable(item, sanitized[public_key], unavailable)
        elif isinstance(original, list) and isinstance(sanitized, list):
            for index, (item, safe_item) in enumerate(zip(original, sanitized)):
                if inherited and isinstance(item, str) and item not in known_ids:
                    sanitized[index] = "[browser content omitted: redaction context unavailable]"
                else:
                    omit_unavailable(item, safe_item, inherited)

    omit_unavailable(record, public)
    return public


def _public_observation(project, record, raw):
    return public_metadata(project, record, raw=raw)


def _record_observation(project, raw, visit_id, source, *, session=None, actor=None, attachments=None,
                        source_file_sha256=None, run_id=None, input_secrets=None, redaction_context=None):
    # Keep the original observation (including external declarations) exclusively
    # in the artifact. Only the explicit rendering fields become ledger metadata.
    path, digest = project.artifact(visit_id, raw)
    succeeded = _successful(project, raw)
    network = _network(raw)
    record = {
        "id": visit_id, "kind": "page_visit", "url": raw["url"], "finalUrl": raw.get("finalUrl"),
        "status": raw.get("status"), "title": raw.get("title", ""), "signals": raw.get("signals", {}),
        "actions": raw.get("actions") or [], "console": raw.get("console") or [],
        "dialogs": raw.get("dialogs") or [], "blocked_requests": raw.get("blocked_requests") or [],
        "write_requests": raw.get("write_requests") or [],
        "write_authorized": bool(raw.get("write_authorized")),
        "navigation_trail": _navigation_trail(raw),
        "network_count": len(network), "observation_status": "visited" if succeeded else "BLOCKED",
        "complete": succeeded, "source": source,
        "trust": "observed_render" if source == "local_playwright" else "imported_mcp",
        "machine_authenticated": source == "local_playwright",
        "scope_enforced": source == "local_playwright", "artifact_path": path, "sha256": digest,
        "created_at": now(), "session_id": session["id"] if session else None,
        "session_generation": session["generation"] if session else None,
        "actor_id": actor["id"] if actor else None,
        "note": ("Rendering observations cannot satisfy HTTP evidence or confirm a vulnerability. "
                 + ("Imported MCP output is an external observation, not machine-authenticated execution."
                    if source == "imported_mcp" else "All requests were subject to browser scope and method guards.")),
    }
    for key in ("error", "scope_error", "headless", "afterActions", "network_truncated", "source_meta", "started_at", "completed_at"):
        if key in raw:
            record[key] = raw[key]
    if not succeeded:
        record["blocked_reason"] = str(raw.get("error") or raw.get("scope_error")
                                       or (raw.get("blocked_requests") or [{}])[0].get("reason")
                                       or "page_observation_incomplete")
    if attachments:
        record.update(attachments)
    if source_file_sha256:
        record["source_file_sha256"] = source_file_sha256
    if run_id is not None:
        record["run_id"] = run_id
    derived, available = _redaction_inputs(raw.get("actions"))
    values = derived if input_secrets is None else input_secrets
    available = available if input_secrets is None else True
    context = _private_redaction_context(values) if redaction_context is None else redaction_context
    record.update(credentials=context, redaction_context_required=bool(values), redaction_context_checked=available,
                  redaction_context_available=available,
                  redaction_context_sha256=hashlib.sha256(canonical(context).encode("utf-8")).hexdigest())
    with project.transaction():
        project.put("page_visit", record, create_only=True)
        project.event("browser.imported_mcp" if source == "imported_mcp" else "browser.visited",
                      {"visit_id": visit_id, "url": record["url"], "status": record["status"],
                       "observation_status": record["observation_status"], "source": source,
                       "artifact_path": path, "sha256": digest,
                       "actor_id": record["actor_id"], "session_id": record["session_id"],
                       "session_generation": record["session_generation"],
                       **{key: record[key] for key in ("started_at", "completed_at") if key in record}})
    if source == "local_playwright" and succeeded:
        try:
            adopted = adopt_visit(project, {"page_visit_id": visit_id})
            return {**_public_observation(project, record, raw),
                    "page_ids": adopted["page_ids"], "page_adoption": "adopted"}
        except (EngineError, OSError, ValueError) as exc:
            # Do not hide an already persisted browser observation if the local
            # page ledger could not be updated. Adoption itself is transactional.
            return {**_public_observation(project, record, raw), "page_adoption": "incomplete",
                    "page_adoption_error": getattr(exc, "code", "page_adoption_failed"),
                    "next_action": "page.adopt"}
    return _public_observation(project, record, raw)


def visit(project, args):
    """Drive an isolated browser; guard every request before it reaches the network."""
    url = require_scope(project.config, args["url"])
    actions = _actions(args)
    timeout = _number(args, "timeout", 20, 60, minimum=1)
    settle_ms = _number(args, "settle_ms", 0, 10000)
    action_settle_ms = _number(args, "action_settle_ms", 400, 10000)
    headless = args.get("headless", True)
    if not isinstance(headless, bool):
        raise EngineError("browser_arguments", "headless must be a boolean")
    hold_ms = _number(args, "hold_ms", 0 if headless else 1500, 300000, minimum=0)
    wait_until = args.get("wait_until", "domcontentloaded")
    if wait_until not in {"domcontentloaded", "load", "networkidle"}:
        raise EngineError("browser_arguments", "Unsupported wait_until")
    if "allow_write" in args and not isinstance(args["allow_write"], bool):
        raise EngineError("browser_arguments", "allow_write must be a boolean")
    extra, session_headers, session_origin, credentials, session, actor = _browser_identity(project, args, url)
    # Writes stay opt-in at project level, exactly like http.capture's
    # allow_mutation. A single visit can opt out but cannot silently escalate.
    allow_write = bool(project.config.get("allow_mutation")) and args.get("allow_write") is not False
    if args.get("allow_write") is True and not project.config.get("allow_mutation"):
        raise EngineError("browser_write_not_authorized",
                          "Project permission is required before the browser may submit writes; "
                          "enable allow_mutation with project.update")
    state = probe()
    if not state.get("available"):
        raise EngineError("browser_unavailable", "No usable browser: " + str(state.get("reason"))
                          + ". " + str(state.get("detail", ""))
                          + " Record the page as BLOCKED instead of inferring from HTML.")
    artifact_dir = contained(project.base / "browser", project.base)
    artifact_dir.mkdir(exist_ok=True, mode=0o700)
    visit_id = project.id("PV")
    screenshot = contained(artifact_dir / (visit_id + ".png"), project.base) if args.get("screenshot") else None
    html = contained(artifact_dir / (visit_id + ".html"), project.base) if args.get("html") else None
    after = contained(artifact_dir / (visit_id + ".after.html"), project.base) if actions else None
    spec = {
        "url": url, "scope": _scope_descriptors(project.config, "scope"),
        "exclude": _scope_descriptors(project.config, "exclude"),
        "headless": headless, "headers": extra, "sessionHeaders": session_headers,
        "sessionOrigin": session_origin, "credentialHeaders": credentials,
        "waitUntil": wait_until, "timeout": int(timeout * 1000), "settleMs": settle_ms,
        "signals": {"selector": args["selector"]} if args.get("selector") else None,
        "screenshot": str(screenshot) if screenshot else None, "html": str(html) if html else None,
        "executablePath": state.get("executable_path"), "actions": actions,
        "actionSettleMs": action_settle_ms, "afterActionsHtml": str(after) if after else None,
        "allowWrite": allow_write, "holdMs": int(hold_ms),
    }
    from .contracts import _validate_json
    from .engine import actor_signature, credential_header_names, credential_signature, stable
    from .inputs import json_document

    input_secrets, _ = _redaction_inputs(actions)
    redaction_context = _private_redaction_context(input_secrets)
    run, claimed = None, False
    try:
        with tempfile.TemporaryDirectory() as tmp:
            spec_path, script_path = Path(tmp) / "spec.json", Path(tmp) / "visit.cjs"
            spec_path.write_text(json.dumps(spec, ensure_ascii=False, allow_nan=False), encoding="utf-8")
            script_path.write_text(_VISIT, encoding="utf-8")
            deadline = timeout + settle_ms / 1000 + hold_ms / 1000 + 15 + sum(
                action.get("timeout", 5000) / 1000 + action.get("ms", 0) / 1000
                + action.get("settleMs", action_settle_ms) / 1000 for action in actions)
            run = {"id": project.id("RUN"), "kind": "browser", "status": "running", "started_at": now(),
                   "method": "GET", "target_origin": origin(url), "planned_page_visit_id": visit_id,
                   "allow_write": allow_write, "effect": "test_resource_write" if allow_write else "read_only",
                   "session_id": session["id"] if session else None,
                   "session_generation": session["generation"] if session else None,
                   "actor_id": actor["id"] if actor else None,
                   "actor_signature": actor_signature(actor) if actor else None,
                   "credential_header_names": credential_header_names(session) if session else [],
                   "credential_signature": credential_signature(session) if session else None,
                   "credentials": redaction_context, "redaction_context_required": bool(input_secrets),
                   "redaction_context_checked": True, "redaction_context_available": True,
                   "redaction_context_sha256": hashlib.sha256(canonical(redaction_context).encode("utf-8")).hexdigest(),
                   "request_signature": stable("BR", {"redaction_nonce": redaction_context["redaction_nonce"],
                       **{key: spec[key] for key in ("url", "scope", "exclude", "headers", "sessionHeaders", "sessionOrigin", "credentialHeaders",
                           "actions", "allowWrite", "headless", "waitUntil", "timeout", "settleMs", "actionSettleMs")}}),
                   "action_count": len(actions), "dispatch_attempted": True}
            project.claim(run)
            claimed = True
            project.event("browser.started", {"run_id": run["id"], "page_visit_id": visit_id, "allow_write": allow_write})
            process = subprocess.run([state["node"], str(script_path), state["module_root"], str(spec_path)],
                                     capture_output=True, text=True, encoding="utf-8", errors="strict",
                                     timeout=deadline)
        if process.returncode != 0:
            raise EngineError("browser_failed", "The owned browser runtime exited unsuccessfully")
        if not isinstance(process.stdout, str) or len(process.stdout.encode("utf-8")) > _OBSERVATION_BUDGET:
            raise EngineError("browser_observation", "Browser output exceeds its budget or is not UTF-8 text")
        try:
            raw = json_document(process.stdout.strip().splitlines()[-1])
            _validate_json(raw)
        except (EngineError, ValueError, IndexError, UnicodeError, TypeError, RecursionError):
            raise EngineError("browser_observation", "Browser produced no bounded, unambiguous UTF-8 observation") from None
        if not isinstance(raw, dict) or raw.get("url") != url:
            raise EngineError("browser_observation", "Browser output does not match the requested URL")
        _network(raw)
        attachments = {}
        for key, path in (("screenshot", screenshot), ("html", html), ("after_actions_html", after)):
            if path and path.exists():
                attachments[key] = path.relative_to(project.base).as_posix()
                attachments[key + "_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        public = _record_observation(project, raw, visit_id, "local_playwright", run_id=run["id"],
                                     session=session, actor=actor, attachments=attachments, input_secrets=input_secrets,
                                     redaction_context=redaction_context)
        saved = project.get("page_visit", visit_id)
        run.update(status="succeeded" if saved["complete"] else "interrupted", finished_at=now(),
                   page_visit_id=visit_id, artifact_path=saved["artifact_path"], sha256=saved["sha256"],
                   observation_status=saved["observation_status"])
        if not saved["complete"]:
            run.update(error_code="browser_observation_incomplete", next_action="run.inspect")
        project.put("run", run)
        project.event("browser.finished", {"run_id": run["id"], "page_visit_id": visit_id, "status": run["status"]})
        return {**public, "run_id": run["id"], "run_status": run["status"],
                **({"next_action": "run.inspect"} if run["status"] != "succeeded" else {})}
    except Exception as exc:
        if not claimed:
            raise
        code = "browser_timeout" if isinstance(exc, subprocess.TimeoutExpired) else getattr(exc, "code", "browser_failed")
        message = ("Browser visit exceeded its deadline; execution effects remain unverified" if code == "browser_timeout"
                   else str(exc) if isinstance(exc, EngineError) else "Browser execution did not produce a verified terminal observation")
        run.update(status="interrupted", finished_at=now(), error_code=code, next_action="run.inspect")
        try:
            saved = project.get("page_visit", visit_id, required=False)
            if saved:
                run.update(page_visit_id=visit_id, artifact_path=saved["artifact_path"], sha256=saved["sha256"])
            project.put("run", run)
        except Exception:
            message += "; the final checkpoint could not be saved, so inspect the claimed run"
        raise EngineError(code, message, {"run_id": run["id"], "next_action": "run.inspect"}) from exc


def import_observation(project, args):
    """Import a local JSON observation produced by Playwright MCP, with explicit provenance."""
    path = Path(args["path"]).expanduser()
    if not path.is_file() or path.is_symlink() or path.stat().st_size > _OBSERVATION_BUDGET:
        raise EngineError("browser_import", "Expected a bounded local observation JSON file")
    try:
        from .contracts import _validate_json
        from .inputs import json_document

        data = path.read_bytes()
        raw = json_document(data)
        _validate_json(raw)
    except (EngineError, OSError, ValueError, UnicodeError, TypeError, RecursionError):
        raise EngineError("browser_import", "Could not read the observation JSON") from None
    if not isinstance(raw, dict):
        raise EngineError("browser_observation", "Observation must be an object")
    url = require_scope(project.config, raw.get("url"))
    require_scope(project.config, raw.get("finalUrl"))
    if args.get("url") and require_scope(project.config, args["url"]) != url:
        raise EngineError("page_visit_binding", "Imported observation does not match the requested URL")
    if type(raw.get("status")) is not int or not 100 <= raw["status"] <= 599:
        raise EngineError("browser_observation", "Observation requires an integer HTTP status")
    if not _valid_signals(raw.get("signals")):
        raise EngineError("browser_observation", "Observation requires actual page structure signals")
    network = _network(raw)
    if not network:
        raise EngineError("browser_observation", "Observation requires nonempty original network data")
    observed_url = False
    for item in network:
        request = item.get("request", item)
        try:
            if normalize_url(request["url"]) in {url, normalize_url(raw["finalUrl"])}:
                observed_url = True
        except EngineError:
            # Preserve WebSocket or excluded URL attempts as raw observation; do
            # not pretend that scope was enforced by this external execution.
            pass
    if not observed_url:
        raise EngineError("browser_observation", "Original network does not include the observed page URL")
    actions = raw.get("actions") or []
    if not isinstance(actions, list) or len(actions) > 50 or any(
            not isinstance(action, dict) or type(action.get("ok")) is not bool
            or action.get("action", action.get("type")) not in _ACTION_TYPES for action in actions):
        raise EngineError("browser_observation", "Imported actions require a supported type and explicit boolean ok")
    return _record_observation(project, raw, project.id("PV"), "imported_mcp",
                               source_file_sha256=hashlib.sha256(data).hexdigest())


# ---------------------------------------------------------------- page ledger

def register_page(project, args):
    url = require_scope(project.config, args["url"])
    if args.get("visited") is not None and args.get("visited") is not False:
        raise EngineError("page_evidence_required", "Registering a page cannot declare it visited; use page.mark with a page_visit_id")
    matches = [page for page in project.list("page") if normalize_url(page["url"]) == url]
    page_id = args.get("page_id") or (matches[0]["id"] if matches else project.id("PG"))
    existing = project.get("page", page_id, required=False)
    if existing and normalize_url(existing["url"]) != url:
        raise EngineError("page_binding", "A page ID cannot be reassigned to a different URL")
    record = {
        **(existing or {}), "id": page_id, "url": url, "name": str(args.get("name") or (existing or {}).get("name") or url),
        "source": str(args.get("source") or (existing or {}).get("source") or "declared"), "visited": bool(existing.get("visited")) if existing else False,
        "visit_status": existing.get("visit_status") if existing else None,
        "visit_id": existing.get("visit_id") if existing else None,
        "functions": existing.get("functions", []) if existing else [],
        "created_at": existing.get("created_at") if existing else now(),
    }
    with project.transaction():
        project.put("page", record)
        project.event("page.registered", {"page_id": page_id, "url": url})
    return record


def adopt_visit(project, args):
    """Bind a saved, verified visit to pages without sending any target traffic."""
    identity = _visit_reference(args)
    with project.transaction():
        visit_record = project.get("page_visit", identity)
        _, raw = _verified_visit(project, identity, visit_record["url"])
        origins, _ = _adoption_history(project)
        if not _adoption_origin_matches(visit_record, origins.get(identity)):
            raise EngineError("page_evidence_invalid", "Browser provenance differs from the original recorded observation")
        trail = _navigation_trail(raw)
        if args.get("url") is not None:
            selected = require_scope(project.config, args["url"])
            trail = [entry for entry in trail if entry["url"] == selected]
            if not trail:
                raise EngineError("page_visit_binding", "The selected page was not reached by this browser observation")
        adopted_pages = {entry["page_id"] for entry in validated_adoptions(project, visits=[visit_record])}
        existing_pages = {normalize_url(page["url"]): page for page in project.list("page")}
        page_ids, changed = [], False
        for entry in trail:
            page = existing_pages.get(entry["url"])
            if page is None:
                page = register_page(project, {"url": entry["url"], "source": visit_record["source"]})
            if page["id"] not in adopted_pages:
                mark(project, {"page_id": page["id"], "target": "page", "status": "visited", "page_visit_id": identity})
                changed = True
            page_ids.append(page["id"])
        if changed:
            project.event("page.visit_adopted", {"page_visit_id": identity, "page_ids": page_ids,
                                                 "source": visit_record["source"], "sha256": visit_record["sha256"]})
    return {"page_visit_id": identity, "page_ids": page_ids, "pages_adopted": len(page_ids), "functions_marked": 0,
            "requests_sent": 0, "source": visit_record["source"],
            "limitation": "Only observed pages are marked; functions still require real interactions. Imported MCP provenance is unchanged, and no HTTP security obligation is completed."}


def register_function(project, args):
    page = project.get("page", args["page_id"])
    require_scope(project.config, page["url"])
    if args.get("function_id") is not None and (not isinstance(args["function_id"], str)
            or not args["function_id"].strip() or len(args["function_id"]) > 200):
        raise EngineError("function_id", "function_id must be a nonempty local handle of at most 200 characters")
    func_id = args.get("function_id") or project.id("FN")
    functions = list(page.get("functions") or [])
    entry = next((f for f in functions if f["id"] == func_id), None)
    if entry is None:
        entry = {"id": func_id, "name": str(args.get("name") or func_id),
                 "trigger": str(args.get("trigger") or "unknown"),
                 "apis": list(args.get("apis") or []), "triggered": False,
                 "trigger_status": None, "created_at": now()}
        functions.append(entry)
    else:
        entry.update({"name": args.get("name", entry["name"]),
                      "trigger": args.get("trigger", entry["trigger"]),
                      "apis": list(args.get("apis") or entry["apis"])})
    page["functions"] = functions
    project.put("page", page)
    return entry


def _visit_reference(args):
    primary, legacy = args.get("page_visit_id"), args.get("visit_id")
    if primary and legacy and primary != legacy:
        raise EngineError("page_visit_binding", "page_visit_id and visit_id refer to different observations")
    identity = primary or legacy
    if not isinstance(identity, str) or not identity:
        raise EngineError("page_evidence_required", "A real page_visit_id is required for a successful mark")
    return identity


def _verified_visit(project, identity, page_url, *, origin_events=None):
    visit_record = project.get("page_visit", identity)
    if visit_record.get("kind") != "page_visit" or visit_record.get("source") not in {"local_playwright", "imported_mcp"}:
        raise EngineError("page_evidence_invalid", "A recorded browser observation is required")
    raw = project.read_artifact(visit_record)
    url = require_scope(project.config, page_url)
    found, arrival_index = _visit_target(raw, url)
    if not found:
        # Preserve the original exact-URL check message for genuinely unrelated
        # pages, but name the URLs that were actually reached so SPA redirects are
        # diagnosable instead of an opaque mismatch.
        reached = ", ".join(entry["url"] for entry in _navigation_trail(raw)[:6])
        raise EngineError("page_visit_binding",
                          "Page visit URL does not match the registered page; this visit reached: " + reached)
    if normalize_url(visit_record.get("url")) not in {entry["url"] for entry in _navigation_trail(raw)}:
        raise EngineError("page_visit_binding", "Page visit record URL is not part of the original navigation trail")
    # All coverage-bearing fields must still agree with the digested original.
    for key in ("finalUrl", "status", "signals", "actions", "blocked_requests", "write_requests"):
        default = [] if key in {"actions", "blocked_requests", "write_requests"} else None
        if visit_record.get(key, default) != raw.get(key, default):
            raise EngineError("page_evidence_invalid", "Page visit metadata differs from the original observation")
    for key in ("started_at", "completed_at"):
        if key in visit_record or key in raw:
            if visit_record.get(key) != raw.get(key):
                raise EngineError("page_evidence_invalid", "Page visit timing differs from the original observation")
    if "navigation_trail" in visit_record and visit_record.get("navigation_trail") != _navigation_trail(raw):
        raise EngineError("page_evidence_invalid", "Page visit navigation trail differs from the original observation")
    if not visit_record.get("complete") or visit_record.get("observation_status") != "visited" or not _successful(project, raw):
        raise EngineError("page_visit_incomplete", "A successful, unblocked page observation is required")
    if origin_events is None:
        origin_events, _ = _adoption_history(project)
    if not _adoption_origin_matches(visit_record, origin_events.get(identity)):
        raise EngineError("page_evidence_invalid", "Browser provenance differs from the original recorded observation")
    _network(raw)
    return visit_record, raw


def _verified_action(raw, index=None):
    actions = raw.get("actions") or []
    if index is None:
        candidates = [i for i, a in enumerate(actions)
                      if a.get("action", a.get("type")) in _INTERACTIONS]
        if len(candidates) != 1:
            raise EngineError("action_reference", "Choose action_index for the function's observed interaction")
        index = candidates[0]
    if type(index) is not int or not 0 <= index < len(actions):
        raise EngineError("action_reference", "action_index must reference an observed action")
    step = actions[index]
    if step.get("action", step.get("type")) not in _INTERACTIONS or step.get("ok") is not True:
        raise EngineError("action_failed", "The referenced function interaction did not succeed")
    if step.get("blocked_request_count"):
        raise EngineError("action_failed", "The referenced interaction had blocked requests")
    return index


def _adoption_reference(visit, page):
    """A rendering archive binds one original visit to one exact registered page."""
    return {"page_id": page["id"], "url": normalize_url(page["url"]), "page_visit_id": visit["id"],
            **{key: visit.get(key) for key in ("sha256", "artifact_path", "source", "actor_id",
                                               "session_id", "session_generation")}}


def _adoption_history(project):
    """Read old adoption receipts without migrating or trusting mutable visited flags.

    Old receipts lack a digest, but their original browser event records it. A
    later explicit page blocker invalidates prior associations until that exact
    visit is adopted again; visiting the page with another run is insufficient.
    """
    with project._lock:
        events = project.connection.execute(
            "SELECT type,document FROM events WHERE type IN "
            "('browser.visited','browser.imported_mcp','page.marked','page.visit_adopted') ORDER BY seq").fetchall()
    origins, associations = {}, {}
    for row in events:
        try:
            event = json.loads(row[1])
        except (ValueError, TypeError):
            continue
        if not isinstance(event, dict):
            continue
        if row[0] in {"browser.visited", "browser.imported_mcp"}:
            identity = event.get("visit_id")
            source = "local_playwright" if row[0] == "browser.visited" else "imported_mcp"
            if isinstance(identity, str) and event.get("source") == source:
                origins.setdefault(identity, event)
        elif row[0] == "page.marked" and event.get("target") == "page":
            page_id, identity = event.get("page_id"), event.get("visit_id")
            if not isinstance(page_id, str):
                continue
            if event.get("status") == "BLOCKED":
                associations[page_id] = {}
            elif event.get("status") == "visited" and isinstance(identity, str):
                associations.setdefault(page_id, {})[identity] = event
        elif row[0] == "page.visit_adopted":
            identity, page_ids = event.get("page_visit_id"), event.get("page_ids")
            if not isinstance(identity, str) or not isinstance(page_ids, list) \
                    or event.get("source") != (origins.get(identity) or {}).get("source"):
                continue
            for page_id in page_ids:
                if isinstance(page_id, str):
                    associations.setdefault(page_id, {})[identity] = event
    return origins, associations


def _adoption_origin_matches(visit, event):
    if not isinstance(event, dict) or any(event.get(key) != visit.get(key)
            for key in ("source", "url", "sha256", "artifact_path")):
        return False
    # New receipts freeze identity too. Legacy receipts remain rendering-only
    # provenance and never manufacture authenticated HTTP or XSS proof.
    return all(key not in event or event[key] == visit.get(key)
               for key in ("actor_id", "session_id", "session_generation", "started_at", "completed_at"))


def validated_adoptions(project, *, pages=None, visits=None):
    """Return independently revalidated archives for all adopted observations.

    Latest page/function pointers remain display and interaction references.
    Every prior adopted visit is retained separately and must still match its
    original source, artifact, identity context and current page/scope policy.
    """
    pages = project.list("page") if pages is None else pages
    visits = project.list("page_visit") if visits is None else visits
    page_map = {page["id"]: page for page in pages}
    origins, associations = _adoption_history(project)
    result = []
    for visit in visits:
        identity = visit["id"]
        if not _adoption_origin_matches(visit, origins.get(identity)):
            continue
        if "page_adoptions" in visit:
            references = visit["page_adoptions"]
        else:
            # Compatibility for an untouched old project is a read-only
            # projection from actual adoption events and the original digest.
            references = [_adoption_reference(visit, page) for page in pages
                          if identity in associations.get(page["id"], {})]
        if not isinstance(references, list) or not references:
            continue
        accepted = []
        for reference in references:
            try:
                if not isinstance(reference, dict):
                    raise EngineError("page_evidence_invalid", "Invalid browser adoption reference")
                page = page_map[reference["page_id"]]
                receipt = associations.get(page["id"], {}).get(identity)
                if page.get("visited") is not True or page.get("visit_status") != "visited" \
                        or receipt is None or reference != _adoption_reference(visit, page) \
                        or receipt.get("sha256", visit["sha256"]) != visit["sha256"]:
                    raise EngineError("page_evidence_invalid", "Browser adoption is no longer current")
                _verified_visit(project, identity, page["url"], origin_events=origins)
                if reference not in accepted:
                    accepted.append(reference)
            except (EngineError, OSError, ValueError, TypeError, KeyError):
                # A partial archive cannot hide an observation that still has
                # a blocked, changed or missing adopted page to reconcile.
                accepted = []
                break
        result.extend(accepted)
    return result


def mark(project, args):
    """Bind coverage to digested rendering evidence; preserve explicit BLOCKED gaps."""
    with project.transaction():
        return _mark(project, args)


def _mark(project, args):
    page = project.get("page", args["page_id"])
    original_page = canonical(page)
    target, status = args.get("target"), args.get("status")
    if target not in {"page", "function"}:
        raise EngineError("target", "target must be 'page' or 'function'")
    if status not in (VISIT_STATUSES if target == "page" else TRIGGER_STATUSES):
        raise EngineError("page_status", "Unsupported coverage status for this target")
    reason = args.get("reason")
    if status == "BLOCKED" and (not isinstance(reason, str) or not reason.strip()):
        raise EngineError("blocked_reason", "BLOCKED requires a nonempty reason")
    entry = page
    if target == "function":
        entry = next((f for f in page.get("functions") or [] if f["id"] == args.get("function_id")), None)
        if entry is None:
            raise EngineError("function_missing", "Unknown function on this page")
    if status != "BLOCKED":
        identity = _visit_reference(args)
        visit_record, raw = _verified_visit(project, identity, page["url"])
        archive_changed = False
        if target == "function":
            entry["action_index"] = _verified_action(raw, args.get("action_index"))
            entry["triggered"], entry["trigger_status"] = True, "triggered"
        else:
            origins, _ = _adoption_history(project)
            if not _adoption_origin_matches(visit_record, origins.get(identity)):
                raise EngineError("page_evidence_invalid", "Browser provenance differs from the original recorded observation")
            valid = validated_adoptions(project, visits=[visit_record])
            reference = _adoption_reference(visit_record, page)
            archive_changed = reference not in valid
            references = visit_record.get("page_adoptions", valid)
            if not isinstance(references, list):
                references = []
            references = list(references)
            index = next((index for index, item in enumerate(references)
                          if isinstance(item, dict) and item.get("page_id") == page["id"]), None)
            if index is None:
                references.append(reference)
            else:
                references[index] = reference
            if visit_record.get("page_adoptions") != references:
                visit_record["page_adoptions"] = references
                project.put("page_visit", visit_record)
            entry["visited"], entry["visit_status"] = True, "visited"
        entry["visit_id"] = identity
        entry["page_visit_id"] = identity
        entry["visit_sha256"] = visit_record["sha256"]
        found, arrival_index = _visit_target(raw, page["url"])
        entry["arrival"] = "direct" if arrival_index is None else "navigation"
        if arrival_index is not None:
            entry["arrival_action_index"] = arrival_index
        else:
            entry.pop("arrival_action_index", None)
        entry.pop("blocked_reason", None)
    else:
        archive_changed = False
        entry["blocked_reason"] = reason.strip()
        if target == "page":
            entry["visited"], entry["visit_status"] = False, "BLOCKED"
        else:
            entry["triggered"], entry["trigger_status"] = False, "BLOCKED"
        for key in ("visit_id", "page_visit_id", "visit_sha256", "action_index",
                    "arrival", "arrival_action_index"):
            entry.pop(key, None)
    if canonical(page) != original_page or archive_changed:
        project.put("page", page)
        project.event("page.marked", {"page_id": page["id"], "target": target, "status": status,
                                     "function_id": args.get("function_id"), "visit_id": entry.get("visit_id"),
                                     **({"sha256": visit_record["sha256"]} if status != "BLOCKED" else {})})
    return entry


def _coverage_reference(project, page, entry, function=False):
    try:
        identity = _visit_reference(entry)
        record, raw = _verified_visit(project, identity, page["url"])
        if entry.get("visit_sha256") != record["sha256"]:
            raise EngineError("page_evidence_invalid", "Coverage digest does not match the referenced visit")
        if function:
            _verified_action(raw, entry.get("action_index"))
        return None
    except (EngineError, OSError, ValueError, TypeError, KeyError) as exc:
        return getattr(exc, "code", "page_evidence_invalid")


def coverage(project):
    """Revalidate referenced artifacts rather than trusting mutable ledger flags."""
    pages = project.list("page")
    unvisited, untriggered = [], []
    for page in pages:
        page_error = None
        if page.get("visited") and page.get("visit_status") == "visited":
            page_error = _coverage_reference(project, page, page)
        else:
            page_error = page.get("blocked_reason") or "page_not_visited"
        if page_error:
            unvisited.append({"page_id": page["id"], "url": page["url"], "status": page.get("visit_status"),
                              "reason": page_error})
        for function in page.get("functions") or []:
            function_error = None
            if function.get("triggered") and function.get("trigger_status") == "triggered":
                function_error = _coverage_reference(project, page, function, function=True)
            else:
                function_error = function.get("blocked_reason") or "function_not_triggered"
            if function_error:
                untriggered.append({"page_id": page["id"], "url": page["url"],
                                    "function_id": function["id"], "name": function.get("name"),
                                    "status": function.get("trigger_status"), "reason": function_error})
    total_functions = sum(len(page.get("functions") or []) for page in pages)
    return {
        "pages": len(pages), "pages_visited": len(pages) - len(unvisited),
        "functions": total_functions, "functions_triggered": total_functions - len(untriggered),
        "unvisited": unvisited, "untriggered": untriggered,
        "complete": bool(pages) and not unvisited and not untriggered,
        "note": ("An empty ledger is not evidence that no page exists. Successful marks require a valid "
                 "page_visit artifact and functions require a successful interaction. BLOCKED entries "
                 "remain coverage gaps. Imported MCP observations retain external provenance and cannot "
                 "close HTTP obligations or confirm vulnerabilities."),
    }
