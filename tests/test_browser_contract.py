"""Browser scope and evidence contracts exercised through Node and loopback HTTP."""
from datetime import datetime, timedelta, timezone
import hashlib
import http.server
import json
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from awa_ddd import browser, engine
from awa_ddd.__main__ import dispatch
from awa_ddd.store import EngineError, Project
from awa_ddd.scope import require_scope


# This runtime uses actual HTTP for route.fetch, and deliberately models
# Playwright's redirect-routing limitation. Rendering is simulated; the request
# guard, JS execution, identity headers, observations and artifact writes are real.
_FAKE_PLAYWRIGHT = r"""
const { EventEmitter } = require('events');
const http = require('http');
const https = require('https');
function fetchOne(url, method, headers, body) {
  return new Promise((resolve, reject) => {
    const client = new URL(url).protocol === 'https:' ? https : http;
    const request = client.request(url, { method, headers }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve({
        status: () => response.statusCode, headers: () => response.headers,
        url: () => url, body: () => Promise.resolve(Buffer.concat(chunks)),
      }));
    });
    request.on('error', reject);
    if (body) request.write(body);
    request.end();
  });
}
class FakePage extends EventEmitter {
  constructor(context) { super(); this.context = context; this.current = 'about:blank'; this.document = {}; }
  url() { return this.current; }
  mainFrame() { return this; }
  async request(url, method = 'GET', type = 'fetch', navigation = false, body = null) {
    let result, aborted = false;
    const request = {
      url: () => url, method: () => method, resourceType: () => type,
      allHeaders: async () => ({...this.context.options.extraHTTPHeaders}),
      isNavigationRequest: () => navigation, frame: () => this,
      postDataBuffer: () => body == null ? null : Buffer.from(body, 'utf8'),
    };
    const route = {
      request: () => request,
      abort: async () => { aborted = true; },
      fetch: async options => {
        if (options.maxRedirects !== 0) throw new Error('unguarded_redirect_fetch');
        return fetchOne(url, method, options.headers, body);
      },
      fulfill: async options => { result = options.response; },
    };
    await this.context.routeHandler(route);
    if (aborted || !result) {
      if (navigation) throw new Error('navigation_blocked');
      return null;
    }
    // A fulfilled 302 would bypass the next route callback, as an automatic
    // redirect can in Playwright. The hardened code must never reach this branch.
    if ([301, 302, 303, 307, 308].includes(result.status()) && result.headers().location) {
      result = await fetchOne(new URL(result.headers().location, url).href, method, {});
    }
    if (navigation) {
      this.current = result.url();
      this.emit('response', { request: () => request, status: result.status });
      try { this.document = JSON.parse((await result.body()).toString()); } catch (_) { this.document = {}; }
      for (const asset of this.document.resources || []) {
        await this.request(asset.url, asset.method || 'GET', asset.type || 'fetch');
      }
      for (const url of this.document.websockets || []) {
        let closed = false;
        await this.context.websocketHandler({ url: () => url, close: () => { closed = true; } });
        if (!closed) throw new Error('websocket_was_not_blocked');
      }
    }
    return result;
  }
  goto(url) { return this.request(url, 'GET', 'document', true); }
  async click(selector) {
    if (selector === '#missing') throw new Error('selector_missing');
    for (const request of (this.document.click_requests || {})[selector] || []) {
      await this.request(request.url, request.method || 'GET', request.type || 'fetch', !!request.navigation, request.body);
    }
    for (const message of (this.document.click_dialogs || {})[selector] || []) {
      this.emit('dialog', {type: () => 'alert', message: () => message, dismiss: async () => {}});
    }
    if (this.document.click_urls && this.document.click_urls[selector]) {
      this.current = this.document.click_urls[selector];
    }
  }
  async fill(selector) { if (selector === '#missing') throw new Error('selector_missing'); }
  async press(selector) { return this.click(selector); }
  async waitForSelector(selector) { if (selector === '#missing') throw new Error('selector_missing'); }
  async waitForTimeout() {}
  async title() { return this.document.title || 'Contract page'; }
  async evaluate() { return this.document.signals || {hasApp:true, forms:1, inputs:1, buttons:1, links:1, textLength:32}; }
  async content() { return '<main>Contract page</main>'; }
  async screenshot() { return Buffer.from('fake-screenshot'); }
}
class FakeContext extends EventEmitter {
  constructor(options) { super(); this.options = options; }
  async route(pattern, handler) { this.routeHandler = handler; }
  async routeWebSocket(pattern, handler) { this.websocketHandler = handler; }
  async newPage() {
    if (this.options.serviceWorkers !== 'block' || this.options.storageState) throw new Error('context_not_isolated');
    if (!this.routeHandler || !this.websocketHandler) throw new Error('guard_was_installed_too_late');
    const page = new FakePage(this); this.emit('page', page); return page;
  }
  async close() {}
}
exports.chromium = {
  launch: async () => ({newContext: async options => new FakeContext(options), close: async () => {}}),
};
"""


class ContractHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.calls.append((self.command, self.path, dict(self.headers)))
        if self.path == "/whoami":
            actor = self.headers.get("X-Actor") or (
                "alice" if "actor=alice" in self.headers.get("Cookie", "") else None)
            self.reply(200 if actor else 401, {"id": actor, "roles": ["user"]})
            return
        result = self.server.documents.get(self.path, {"title": "Contract page"})
        if isinstance(result, tuple):
            status, location = result
            self.send_response(status)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if isinstance(result, str):
            self.reply(200, result, "text/html")
            return
        self.reply(200, result)

    def do_POST(self):
        self.server.calls.append((self.command, self.path, dict(self.headers)))
        self.reply(200, {"changed": True})

    def reply(self, status, body, media_type="application/json"):
        raw = body.encode("utf-8") if isinstance(body, str) else json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", media_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        try:
            self.wfile.write(raw)
        except (ConnectionResetError, BrokenPipeError):
            pass


class BrowserContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-browser-contract-")
        self.addCleanup(self.tmp.cleanup)
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ContractHandler)
        self.server.calls, self.server.documents = [], {}
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        engine.create_project(self.tmp.name, {"project_id": "browser", "target": self.base + "/ui",
                                              "scope": [self.base + "/ui", self.base + "/whoami"],
                                              "exclude": [self.base + "/ui/private"]})
        self.project = Project(self.tmp.name, "browser")
        self.addCleanup(self.project.close)
        self.node = shutil.which("node") or shutil.which("node.exe")
        module = Path(self.tmp.name) / "runtime" / "node_modules" / "playwright-core"
        module.mkdir(parents=True)
        (module / "index.js").write_text(_FAKE_PLAYWRIGHT, encoding="utf-8")
        self.state = {"available": True, "node": self.node, "module_root": str(module.parents[1])}

    def drive(self, path="/ui", **args):
        if not self.node:
            self.skipTest("Node is required for browser runtime contract tests")
        with patch.object(browser, "probe", return_value=self.state):
            return browser.visit(self.project, {"url": self.base + path, "action_settle_ms": 0, **args})

    def page(self, path="/ui"):
        return browser.register_page(self.project, {"url": self.base + path})

    def observation_file(self, **overrides):
        raw = {"url": self.base + "/ui", "finalUrl": self.base + "/ui", "status": 200,
               "signals": {"buttons": 2, "forms": 1}, "actions": [{"type": "click", "selector": "#details", "ok": True}],
               "network": [{"url": self.base + "/ui", "method": "GET", "status": 200}],
               "source_meta": {"tool": "mcp__playwright__browser_evaluate"},
               "raw_network_output": "Actual MCP network output", **overrides}
        path = Path(self.tmp.name) / "mcp-observation.json"
        path.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")
        return path, raw

    def test_request_guard_blocks_assets_exclusions_writes_websockets_and_prefix_confusion(self):
        self.server.documents["/ui"] = {
            "resources": [
                {"url": self.base + "/ui/allowed"},
                {"url": self.base + "/ui/private/secret"},
                {"url": self.base + "/ui-escape"},
                {"url": self.base + "/outside"},
                {"url": self.base + "/ui/%252e%252e/outside"},
            ],
            "websockets": [self.base.replace("http:", "ws:") + "/ui/socket"],
            "click_requests": {"#save": [{"url": self.base + "/ui/save", "method": "POST"}]},
        }
        observed = self.drive(actions=[{"type": "click", "selector": "#save"}])
        self.assertEqual([call[1] for call in self.server.calls], ["/ui", "/ui/allowed"])
        reasons = {r["reason"] for r in observed["blocked_requests"]}
        self.assertTrue({"out_of_scope", "websocket_disabled", "write_operation_not_authorized"} <= reasons)
        self.assertEqual(observed["observation_status"], "BLOCKED")
        self.assertFalse(observed["actions"][0]["ok"])
        raw = self.project.read_artifact(observed)
        self.assertEqual(len(raw["network"]), 7)
        self.assertEqual(raw["network"][0]["status"], 200)
        self.assertFalse(self.project.list("evidence"))
        with self.assertRaises(EngineError) as error:
            browser.mark(self.project, {"page_id": self.page()["id"], "target": "page",
                                       "status": "visited", "page_visit_id": observed["id"]})
        self.assertEqual(error.exception.code, "page_visit_incomplete")

    def test_redirects_never_reach_their_second_hop(self):
        for location, expected in ((self.base + "/ui/redirect-destination", "redirect_not_followed"),
                                   (self.base + "/outside", "redirect_out_of_scope")):
            with self.subTest(location=location):
                self.server.calls.clear()
                self.server.documents["/ui/redirect"] = (302, location)
                observed = self.drive("/ui/redirect")
                self.assertEqual([call[1] for call in self.server.calls], ["/ui/redirect"])
                self.assertEqual(observed["blocked_requests"][0]["reason"], expected)
                self.assertFalse(observed["complete"])
                self.assertEqual(self.project.read_artifact(observed)["network"][0]["status"], 302)

    def test_js_rule_matching_respects_query_and_decoded_path_boundaries(self):
        config = self.project.config
        config["scope"] = [self.base + "/ui", self.base + "/assets?tenant=one"]
        config["exclude"] = [self.base + "/ui/private?hidden=yes"]
        self.project.set_config(config)
        self.server.documents["/ui"] = {"resources": [
            {"url": self.base + "/ui/%70ublic"},
            {"url": self.base + "/assets?tenant=one"},
            {"url": self.base + "/assets?tenant=two"},
            {"url": self.base + "/ui/private?hidden=no"},
            {"url": self.base + "/ui/private?hidden=yes"},
        ]}
        observed = self.drive()
        self.assertEqual([c[1] for c in self.server.calls],
                         ["/ui", "/ui/%70ublic", "/assets?tenant=one", "/ui/private?hidden=no"])
        self.assertEqual(len(observed["blocked_requests"]), 2)

    def test_final_url_is_checked_after_an_action(self):
        self.server.documents["/ui"] = {"click_urls": {"#leave": self.base + "/outside"}}
        observed = self.drive(actions=[{"type": "click", "selector": "#leave"}])
        self.assertEqual(observed["finalUrl"], self.base + "/outside")
        self.assertEqual(observed["scope_error"], "final_url_out_of_scope")
        self.assertFalse(observed["actions"][0]["ok"])
        self.assertFalse(observed["complete"])

    def test_arguments_and_identity_are_validated_before_probe(self):
        for args in ({"url": self.base + "/outside"}, {"url": self.base + "/ui", "headers": {"X-Actor": "alice"}},
                     {"url": self.base + "/ui", "headers": {"Cookie": "actor=alice"}},
                     {"url": self.base + "/ui", "actions": [{"type": "evaluate", "value": "fetch('outside')"}]}):
            with self.subTest(args=args), patch.object(browser, "probe") as probe:
                with self.assertRaises(EngineError):
                    browser.visit(self.project, args)
                probe.assert_not_called()
        self.assertFalse(self.server.calls)

    def test_verified_session_is_bound_and_anonymous_visits_start_clean(self):
        engine.add_actor(self.project, {"actor_id": "alice", "subject": "alice", "roles": ["user"]})
        session = engine.add_session(self.project, {"actor_id": "alice", "headers": {"X-Actor": "alice"},
                                                   "credential_header_names": ["X-Actor"]})
        identity = engine.register_operation(self.project, {"url": self.base + "/whoami", "method": "GET", "auth": "authenticated"})
        with self.assertRaises(EngineError) as unverified:
            self.drive(session_id=session["id"])
        self.assertEqual(unverified.exception.code, "identity_unverified")
        engine.verify_identity(self.project, {"session_id": session["id"], "operation_id": identity["id"],
                                              "subject_selector": "/id", "roles_selector": "/roles"})
        self.server.calls.clear()
        observed = self.drive(session_id=session["id"], headers={"Accept-Language": "zh-CN"})
        self.assertEqual(observed["actor_id"], "alice")
        self.assertEqual(observed["session_generation"], 1)
        self.assertEqual(self.server.calls[0][2].get("x-actor"), "alice")
        self.assertEqual(self.server.calls[0][2].get("accept-language"), "zh-CN")
        self.drive()
        self.assertNotIn("x-actor", {k.lower(): v for k, v in self.server.calls[-1][2].items()})
        with self.assertRaises(EngineError) as override:
            self.drive(session_id=session["id"], headers={"X-Actor": "bob"})
        self.assertEqual(override.exception.code, "credential_override")
        stored = self.project.get("session", session["id"])
        stored["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        self.project.put("session", stored)
        with self.assertRaises(EngineError) as expired:
            self.drive(session_id=session["id"])
        self.assertEqual(expired.exception.code, "session_expired")

    def test_successful_marks_require_the_same_page_a_successful_action_and_valid_digest(self):
        self.assertFalse(browser.coverage(self.project)["complete"])
        page = self.page()
        function = browser.register_function(self.project, {"page_id": page["id"], "name": "Details", "trigger": "button"})
        for args in ({"status": "visited"}, {"status": "visited", "page_visit_id": "PV-does-not-exist"},
                     {"status": "BLOCKED"}, {"status": "typo", "reason": "test"}):
            with self.assertRaises(EngineError):
                browser.mark(self.project, {"page_id": page["id"], "target": "page", **args})
        observed = self.drive(actions=[{"type": "click", "selector": "#details"}])
        browser.mark(self.project, {"page_id": page["id"], "target": "page", "status": "visited", "visit_id": observed["id"]})
        browser.mark(self.project, {"page_id": page["id"], "function_id": function["id"], "target": "function",
                                   "status": "triggered", "page_visit_id": observed["id"], "action_index": 0})
        self.assertTrue(browser.coverage(self.project)["complete"])
        other = self.page("/ui/other")
        with self.assertRaises(EngineError) as mismatch:
            browser.mark(self.project, {"page_id": other["id"], "target": "page", "status": "visited", "visit_id": observed["id"]})
        self.assertEqual(mismatch.exception.code, "page_visit_binding")
        (self.project.base / observed["artifact_path"]).write_text("{}", encoding="utf-8")
        report = browser.coverage(self.project)
        self.assertFalse(report["complete"])
        self.assertEqual(report["pages_visited"], 0)
        self.assertEqual(report["functions_triggered"], 0)
        self.assertEqual(report["untriggered"][0]["reason"], "evidence_changed")

    def test_failed_wait_and_ambiguous_actions_cannot_trigger_a_function(self):
        page = self.page()
        function = browser.register_function(self.project, {"page_id": page["id"], "name": "Details"})
        for actions, index in (([{"type": "click", "selector": "#missing"}], 0),
                               ([{"type": "wait", "ms": 1}], 0),
                               ([{"type": "click", "selector": "#one"}, {"type": "click", "selector": "#two"}], None)):
            with self.subTest(actions=actions):
                observed = self.drive(actions=actions)
                with self.assertRaises(EngineError):
                    browser.mark(self.project, {"page_id": page["id"], "target": "function", "status": "triggered",
                                               "function_id": function["id"], "visit_id": observed["id"], "action_index": index})

    def test_registration_and_legacy_flags_do_not_manufacture_coverage(self):
        for args in ({"url": self.base + "/outside"}, {"url": self.base + "/ui", "visited": True}):
            with self.assertRaises(EngineError):
                browser.register_page(self.project, args)
        page = self.page()
        page.update(visited=True, visit_status="visited")
        self.project.put("page", page)
        self.assertFalse(browser.coverage(self.project)["complete"])
        with self.assertRaises(EngineError):
            browser.register_page(self.project, {"page_id": page["id"], "url": self.base + "/ui/different"})
        blocked = browser.mark(self.project, {"page_id": page["id"], "target": "page", "status": "BLOCKED", "reason": "Browser unavailable"})
        self.assertEqual(blocked["blocked_reason"], "Browser unavailable")
        self.assertFalse(browser.coverage(self.project)["complete"])

    def test_mcp_import_preserves_original_data_without_accepting_external_confirmation(self):
        path, raw = self.observation_file(finding={"status": "confirmed", "kind": "xss"}, trust="observed", machine_authenticated=True)
        observed = browser.import_observation(self.project, {"path": str(path)})
        self.assertEqual(observed["source"], "imported_mcp")
        self.assertEqual(observed["trust"], "imported_mcp")
        self.assertFalse(observed["machine_authenticated"])
        self.assertFalse(observed["scope_enforced"])
        self.assertEqual(self.project.read_artifact(observed), raw)
        self.assertNotIn("finding", observed)
        self.assertFalse(self.project.list("finding"))
        self.assertFalse(self.project.list("evidence"))
        page = self.page()
        function = browser.register_function(self.project, {"page_id": page["id"], "name": "Details"})
        browser.mark(self.project, {"page_id": page["id"], "target": "page", "status": "visited", "page_visit_id": observed["id"]})
        browser.mark(self.project, {"page_id": page["id"], "target": "function", "status": "triggered",
                                   "function_id": function["id"], "page_visit_id": observed["id"]})
        self.assertTrue(browser.coverage(self.project)["complete"])
        changed = self.project.get("page_visit", observed["id"])
        changed["actions"][0]["ok"] = False
        self.project.put("page_visit", changed)
        self.assertFalse(browser.coverage(self.project)["complete"])

    def test_native_body_digests_match_actual_document_and_api_response_bytes(self):
        self.server.documents["/ui"] = {"title": "Digest fixture", "resources": [
            {"url": self.base + "/ui/data", "type": "xhr"},
            {"url": self.base + "/ui/asset", "type": "image"}]}
        self.server.documents["/ui/data"] = {"private_payload": "synthetic-api-body-012345"}
        self.server.documents["/ui/asset"] = "synthetic-untracked-image"
        public = self.drive()
        visit = self.project.get("page_visit", public["id"])
        raw = self.project.read_artifact(visit)
        for path in ("/ui", "/ui/data"):
            entry = next(item for item in raw["network"] if item["url"] == self.base + path)
            response = json.dumps(self.server.documents[path]).encode("utf-8")
            self.assertTrue(entry["response_body_complete"])
            self.assertEqual(len(response), entry["response_body_bytes"])
            self.assertEqual(hashlib.sha256(response).hexdigest(), entry["response_body_sha256"])
            self.assertEqual(0, entry["request_body_bytes"])
            self.assertEqual(hashlib.sha256(b"").hexdigest(), entry["request_body_sha256"])
        asset = next(item for item in raw["network"] if item["url"].endswith("/asset"))
        self.assertNotIn("response_body_sha256", asset)
        self.assertNotIn("synthetic-api-body-012345", json.dumps(raw))

    def test_native_body_digest_does_not_grant_permission_to_submit_a_write(self):
        body = "message=synthetic-wire-body-012345"
        self.server.documents["/ui"] = {"click_requests": {"#save": [
            {"url": self.base + "/ui/save", "method": "POST", "body": body}]}}
        blocked = self.drive(actions=[{"type": "click", "selector": "#save"}])
        self.assertEqual(["/ui"], [call[1] for call in self.server.calls])
        self.assertEqual("BLOCKED", blocked["observation_status"])
        engine.update_project(self.project, {"allow_mutation": True})
        observed = self.drive(actions=[{"type": "click", "selector": "#save"}])
        raw = self.project.read_artifact(self.project.get("page_visit", observed["id"]))
        entry = next(item for item in raw["network"] if item["method"] == "POST")
        self.assertEqual(len(body.encode("utf-8")), entry["request_body_bytes"])
        self.assertEqual(hashlib.sha256(body.encode("utf-8")).hexdigest(), entry["request_body_sha256"])
        self.assertTrue(raw["write_authorized"])
        self.assertTrue(raw["write_requests"])
        self.assertNotIn(body, json.dumps(raw))

    def test_oversized_api_body_renders_without_manufacturing_a_complete_digest(self):
        self.server.documents["/ui"] = {"resources": [{"url": self.base + "/ui/large", "type": "fetch"}]}
        self.server.documents["/ui/large"] = "x" * (8 * 1024 * 1024 + 1)
        observed = self.drive()
        raw = self.project.read_artifact(self.project.get("page_visit", observed["id"]))
        entry = next(item for item in raw["network"] if item["url"].endswith("/large"))
        self.assertEqual("visited", observed["observation_status"])
        self.assertFalse(entry["response_body_complete"])
        self.assertNotIn("response_body_sha256", entry)
        self.assertNotIn("response_body_bytes", entry)

    def test_native_fill_stays_private_while_actions_dialog_document_and_timing_are_bound(self):
        value = "synthetic-search-value-012345-商城"
        marker = "AWA-XSS-0011223344556677"
        self.server.documents["/ui"] = {"click_dialogs": {"#search": [marker]}}
        public = self.drive(actions=[{"type": "fill", "selector": "#search", "value": value},
                                     {"type": "press", "selector": "#search", "key": "Enter"}])
        visit = self.project.get("page_visit", public["id"])
        raw = self.project.read_artifact(visit)
        self.assertEqual(value, raw["actions"][0]["value"])
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        self.assertEqual(digest, raw["actions"][0]["value_sha256"])
        self.assertEqual("Enter", raw["actions"][1]["key"])
        self.assertEqual(self.base + "/ui", raw["dialogs"][0]["document_url"])
        self.assertEqual(1, raw["dialogs"][0]["action_index"])
        self.assertLessEqual(datetime.fromisoformat(raw["started_at"].replace("Z", "+00:00")),
                             datetime.fromisoformat(raw["completed_at"].replace("Z", "+00:00")))
        event = json.loads(self.project.connection.execute(
            "SELECT document FROM events WHERE type='browser.visited'").fetchone()[0])
        for key in ("started_at", "completed_at"):
            self.assertEqual(raw[key], visit[key])
            self.assertEqual(raw[key], event[key])
        page_id = public["page_ids"][0]
        marked = dispatch(self.tmp.name, "page.mark", {"project_id": "browser", "page_id": page_id,
                          "target": "page", "status": "BLOCKED", "reason": value})
        inspected = dispatch(self.tmp.name, "run.inspect", {"project_id": "browser", "run_id": public["run_id"]})
        for output in (public, marked, inspected):
            serialized = json.dumps(output, ensure_ascii=False)
            self.assertNotIn(value, serialized)
            self.assertNotIn(digest, serialized)
        with self.assertRaises(EngineError) as caught:
            dispatch(self.tmp.name, "page.mark", {"project_id": "browser", "page_id": page_id,
                     "target": "page", "status": "visited", "page_visit_id": value})
        self.assertNotIn(value, str(caught.exception))

    def test_visit_timing_cannot_be_relabelled_in_mutable_metadata(self):
        observed = self.drive()
        visit = self.project.get("page_visit", observed["id"])
        self.project.put("page_visit", {**visit, "completed_at": "2099-01-01T00:00:00.000Z"})
        with self.assertRaises(EngineError) as caught:
            browser._verified_visit(self.project, observed["id"], self.base + "/ui")
        self.assertEqual("page_evidence_invalid", caught.exception.code)

    def test_mcp_import_requires_page_structure_real_network_and_scope(self):
        for overrides in ({"signals": {}}, {"signals": {"claim": "visited"}},
                          {"status": "200"}, {"network": []}, {"network": [{"url": self.base + "/ui/unrelated"}]},
                          {"finalUrl": self.base + "/outside"}, {"actions": [{"type": "click", "ok": "yes"}]}):
            with self.subTest(overrides=overrides):
                path, _ = self.observation_file(**overrides)
                with self.assertRaises(EngineError):
                    browser.import_observation(self.project, {"path": str(path)})
        self.assertFalse(self.project.list("page_visit"))

    def test_mcp_network_contradictions_remain_a_blocked_observation(self):
        for network in ([{"url": self.base + "/ui", "status": 403}],
                        [{"url": self.base + "/ui", "status": 200}, {"url": self.base + "/outside", "status": 200}],
                        [{"url": self.base + "/ui", "status": 200}, {"url": self.base + "/ui/write", "method": "POST", "status": 200}]):
            with self.subTest(network=network):
                path, _ = self.observation_file(network=network)
                observed = browser.import_observation(self.project, {"path": str(path)})
                self.assertFalse(observed["complete"])


class RealBrowserLoopbackTests(unittest.TestCase):
    def test_chromium_blocks_external_subrequests_and_mutating_click(self):
        state = browser.probe()
        if not state.get("available"):
            self.skipTest("A launchable Chromium is optional: " + str(state.get("reason")))
        with tempfile.TemporaryDirectory(prefix="awa-real-browser-") as tmp:
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ContractHandler)
            server.calls, server.documents = [], {}
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                base = f"http://127.0.0.1:{server.server_port}"
                server.documents["/ui"] = (
                    '<main><button id="save">Save</button>'
                    '<img src="/outside/image.png"><script>'
                    'fetch("/ui/private");'
                    'window.ws = new WebSocket("ws://127.0.0.1:' + str(server.server_port) + '/ui/socket");'
                    'document.querySelector("#save").onclick = () => fetch("/ui/write", {method:"POST"});'
                    '</script></main>'
                )
                engine.create_project(tmp, {"project_id": "real", "target": base + "/ui",
                                            "scope": [base + "/ui"], "exclude": [base + "/ui/private"]})
                with Project(tmp, "real") as project, patch.object(browser, "probe", return_value=state):
                    observed = browser.visit(project, {"url": base + "/ui", "settle_ms": 100,
                                                       "actions": [{"type": "click", "selector": "#save"}],
                                                       "action_settle_ms": 100})
                    self.assertEqual([call[1] for call in server.calls], ["/ui"])
                    self.assertFalse(observed["complete"])
                    self.assertFalse(observed["actions"][0]["ok"])
                    self.assertEqual(observed["signals"]["buttons"], 1)
                    self.assertTrue({"out_of_scope", "websocket_disabled", "write_operation_not_authorized"} <=
                                    {r["reason"] for r in observed["blocked_requests"]})
                    self.assertTrue(project.read_artifact(observed)["network"])
            finally:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
