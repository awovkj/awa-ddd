"""Synthetic loopback MCP exchanges; no scanner or external target is contacted."""
from __future__ import annotations

import base64
import http.server
import json
import os
import socket
import threading
import time
import unittest
from unittest.mock import patch

from awa_ddd import mcp_http
from awa_ddd.mcp_http import MCPHTTPError, StreamableHTTPClient, validate_endpoint


def envelope(request, result=None, error=None):
    return {"jsonrpc": "2.0", "id": request["id"], **({"error": error} if error is not None else {"result": result})}


def reply(request):
    method = request["method"]
    if method == "initialize":
        result = {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "fixture-mcp", "version": "1.0"}}
    elif method == "notifications/initialized":
        return {"status": 202, "body": b"", "headers": []}
    elif method == "tools/list":
        result = {"tools": [{"name": "fixture_tool", "inputSchema": {"type": "object"}}]}
    else:
        result = {"content": [{"type": "text", "text": "synthetic tool result"}], "isError": False}
    return {"body": json.dumps(envelope(request, result)).encode("utf-8"),
            "headers": [("MCP-Session-Id", "fixture-session")] if method == "initialize" else []}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):
        try:
            body = self.rfile.read(int(self.headers["Content-Length"]))
            request = json.loads(body.decode("utf-8"))
            self.server.calls.append({"request": request, "headers": dict(self.headers), "path": self.path})
            spec = self.server.callback(request)
            if spec.get("before_headers"):
                time.sleep(spec["before_headers"])
            self.send_response(spec.get("status", 200))
            self.send_header("Content-Type", spec.get("media", "application/json"))
            for name, value in spec.get("headers", []):
                self.send_header(name, value)
            if "chunks" not in spec:
                self.send_header("Content-Length", str(spec.get("content_length", len(spec.get("body", b"")))))
            self.end_headers()
            self.wfile.flush()
            if "chunks" in spec:
                for delay, chunk in spec["chunks"]:
                    time.sleep(delay)
                    self.wfile.write(chunk)
                    self.wfile.flush()
                if spec.get("hold"):
                    time.sleep(spec["hold"])
            else:
                self.wfile.write(spec.get("body", b""))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


class MCPHTTPTests(unittest.TestCase):
    def setUp(self):
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads, self.server.calls, self.server.callback = True, [], reply
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.endpoint = "http://127.0.0.1:" + str(self.server.server_port) + "/mcp"

    def client(self, **args):
        client = StreamableHTTPClient(self.endpoint, **args)
        self.addCleanup(client.close)
        return client

    def override(self, method, handler):
        def callback(request):
            return handler(request) if request["method"] == method else reply(request)
        self.server.callback = callback

    def assert_code(self, code, operation):
        with self.assertRaises(MCPHTTPError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_initialization_session_notification_and_tools_call_are_real_rpc_exchanges(self):
        client = self.client()
        initialized = client.initialize()
        self.assertEqual(initialized["protocolVersion"], "2025-03-26")
        self.assertEqual(client.session_id, "fixture-session")
        self.assertEqual(client.list_tools()[0]["name"], "fixture_tool")
        result = client.call_tool("fixture_tool", {"synthetic": True})
        self.assertFalse(result["isError"])
        calls = self.server.calls
        self.assertEqual([item["request"]["method"] for item in calls],
                         ["initialize", "notifications/initialized", "tools/list", "tools/call"])
        self.assertNotIn("MCP-Session-Id", calls[0]["headers"])
        for call in calls[1:]:
            self.assertEqual(call["headers"]["MCP-Session-Id"], "fixture-session")
            self.assertEqual(call["headers"]["MCP-Protocol-Version"], "2025-03-26")
        self.assertNotIn("id", calls[1]["request"])
        self.assertEqual(calls[3]["request"]["params"], {"name": "fixture_tool", "arguments": {"synthetic": True}})
        self.assertEqual(len(client.exchanges), 8)
        self.assertTrue(all(item["wire_bytes"] > 0 for item in client.exchanges if item["direction"] == "response"))
        responses = [item for item in client.exchanges if item["direction"] == "response"]
        for record in responses:
            self.assertTrue(record["raw_http_complete"])
            self.assertTrue(record["response_body_complete"])
            self.assertEqual(record["raw_http_bytes_received"], record["wire_bytes"])
            self.assertEqual(record["wire_bytes"], len(base64.b64decode(record["raw_http_base64"])))
        self.assertEqual(sum(record["raw_http_bytes_received"] for record in responses), client.bytes_received)
        self.assertEqual(responses[1]["response_body_bytes_read"], 0)
        self.assertTrue(all(record["response_body_bytes_read"] > 0 for record in (responses[0], responses[2], responses[3])))
        client.initialize()
        self.assertEqual(len(self.server.calls), 4)

    def test_json_close_delimited_eof_and_chunked_eof_are_complete(self):
        def body(request):
            return json.dumps(envelope(request, {"tools": []})).encode()

        for chunked in (False, True):
            with self.subTest(chunked=chunked):
                def callback(request, chunked=chunked):
                    data = body(request)
                    chunks = ("%x\r\n" % len(data)).encode() + data + b"\r\n0\r\n\r\n" if chunked else data
                    return {"chunks": [(0, chunks)], "headers": [("Transfer-Encoding", "chunked")] if chunked else []}
                self.override("tools/list", callback)
                client = self.client()
                client.initialize()
                self.assertEqual(client.list_tools(), [])
                record = client.exchanges[-1]
                self.assertTrue(record["matching_response_received"])
                self.assertTrue(record["raw_http_complete"])
                self.assertTrue(record["response_body_complete"])
                self.assertEqual(record["response_body_bytes_read"], len(body(self.server.calls[-1]["request"])))
                self.assertEqual(record["raw_http_bytes_received"], record["wire_bytes"])

    def test_valid_json_with_short_content_length_is_not_a_complete_transcript(self):
        def short_body(request):
            data = json.dumps(envelope(request, {"tools": []})).encode()
            return {"body": data, "content_length": len(data) + 7}
        self.override("tools/list", short_body)
        client = self.client()
        client.initialize()
        self.assertEqual(client.list_tools(), [])
        record = client.exchanges[-1]
        self.assertTrue(record["matching_response_received"])
        self.assertFalse(record["raw_http_complete"])
        self.assertFalse(record["response_body_complete"])
        self.assertGreater(record["response_body_bytes_read"], 0)

    def test_endpoint_whitelist_rejects_ambiguous_or_nonlocal_authorities(self):
        for endpoint in ("http://example.com/mcp", "http://127.1/mcp", "http://127.0.0.2/mcp",
                         "http://2130706433/mcp", "http://localhost./mcp", "http://localhost.example/mcp",
                         "http://[::ffff:127.0.0.1]/mcp", "http://user:pass@127.0.0.1:8088/mcp",
                         "http://127.0.0.1:8088/mcp?x=1", "http://127.0.0.1:8088/mcp?",
                         "http://127.0.0.1:8088/mcp#", "http://127.0.0.1:8088/mcp\n",
                         "http://127.0.0.1:8088/mcp%0d%0aX", "http://127.0.0.1:0/mcp",
                         "http://127.0.0.1:99999/mcp", "ftp://127.0.0.1/mcp", "http://127.0.0.1//mcp",
                         "http://127.0.0.1/mcp\\x", "http://127.0.0.1/mcp%xx", "http://127.0.0.1",
                         "http://127.0.0.1:/mcp"):
            with self.subTest(endpoint=endpoint):
                self.assert_code("mcp_endpoint", lambda: validate_endpoint(endpoint))
        self.assertEqual(validate_endpoint(), "http://127.0.0.1:8088/mcp")
        self.assertEqual(validate_endpoint("https://[::1]:8088/mcp"), "https://[::1]:8088/mcp")

    def test_localhost_is_pinned_without_dns_or_proxy_environment(self):
        endpoint = self.endpoint.replace("127.0.0.1", "localhost")
        with patch.dict(os.environ, {"HTTP_PROXY": "http://example.invalid:9999", "HTTPS_PROXY": "http://example.invalid:9999",
                                     "ALL_PROXY": "socks5://example.invalid:9999", "NO_PROXY": ""}), \
                patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS must not be consulted")):
            client = StreamableHTTPClient(endpoint)
            self.addCleanup(client.close)
            client.initialize()
        self.assertEqual(self.server.calls[0]["headers"]["Host"], "localhost:" + str(self.server.server_port))

    def test_redirect_is_not_followed_and_private_location_is_not_in_error(self):
        self.server.callback = lambda request: {"status": 307, "headers": [("Location", "http://example.invalid/private-token")], "body": b"private-body-secret"}
        client = self.client()
        error = self.assert_code("mcp_redirect", client.initialize)
        self.assertNotIn("private-token", str(error))
        self.assertNotIn("private-body-secret", str(error))
        self.assertEqual(error.details, {"http_status": 307})
        record = client.exchanges[-1]
        self.assertFalse(record["raw_http_complete"])
        self.assertFalse(record["response_body_complete"])
        self.assertEqual(record["response_body_bytes_read"], 0)
        self.assertEqual(record["raw_http_bytes_received"], record["wire_bytes"])
        self.assertEqual(len(self.server.calls), 1)
        self.assert_code("mcp_closed", lambda: client.call_tool("fixture_tool", {}))

    def test_server_version_negotiation_and_notification_protocol_header(self):
        def initialize(request):
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "fixture-mcp", "version": "2.0"}}
            return {"body": json.dumps(envelope(request, result)).encode(), "headers": [("MCP-Session-Id", "negotiated")]}
        self.override("initialize", initialize)
        client = self.client()
        client.initialize()
        client.list_tools()
        self.assertEqual(self.server.calls[0]["request"]["params"]["protocolVersion"], "2025-03-26")
        self.assertEqual(self.server.calls[-1]["headers"]["MCP-Protocol-Version"], "2025-06-18")

    def test_unsupported_or_malformed_initialize_does_not_send_initialized(self):
        for version in ("2099-01-01", "2024-11-05", ["2025-03-26"]):
            with self.subTest(version=version):
                self.server.calls.clear()
                self.override("initialize", lambda request, version=version: {"body": json.dumps(envelope(request,
                    {"protocolVersion": version, "capabilities": {"tools": {}}, "serverInfo": {"name": "fixture", "version": "1"}})).encode()})
                self.assert_code("mcp_protocol", self.client().initialize)
                self.assertEqual(len(self.server.calls), 1)

    def test_request_ids_are_exact_and_no_resend_follows_uncertainty(self):
        for wrong_id in (True, "3", 3.0, 99, None):
            with self.subTest(wrong_id=wrong_id):
                self.override("tools/list", lambda request, value=wrong_id: {"body": json.dumps(
                    {"jsonrpc": "2.0", "id": value, "result": {"tools": []}}).encode()})
                client = self.client()
                client.initialize()
                self.assert_code("mcp_response_id", client.list_tools)
                before = len(self.server.calls)
                self.assert_code("mcp_closed", lambda: client.call_tool("fixture_tool", {}))
                self.assertEqual(before, len(self.server.calls))

    def test_utf8_duplicate_nonfinite_and_surrogate_json_are_rejected(self):
        for raw in (b'\xff', b'{"jsonrpc":"2.0","id":3,"id":3,"result":{"tools":[]}}',
                    b'{"jsonrpc":"2.0","id":3,"result":{"bad":NaN}}',
                    b'{"jsonrpc":"2.0","id":3,"result":{"bad":1e999}}',
                    b'{"jsonrpc":"2.0","id":3,"result":{"bad":"\\ud800"}}'):
            with self.subTest(raw=raw):
                self.override("tools/list", lambda request, raw=raw: {"body": raw})
                client = self.client()
                client.initialize()
                self.assert_code("mcp_protocol", client.list_tools)
                self.assertIn(raw, base64.b64decode(client.exchanges[-1]["raw_http_base64"]))
                self.assertTrue(client.exchanges[-1]["raw_http_complete"])
                self.assertTrue(client.exchanges[-1]["response_body_complete"])
                self.assertEqual(client.exchanges[-1]["response_body_bytes_read"], len(raw))

    def test_rpc_and_tool_errors_do_not_export_server_secrets(self):
        secret = "Bearer synthetic-private-token"
        self.override("tools/list", lambda request: {"body": json.dumps(envelope(request,
            error={"code": -32602, "message": secret})).encode()})
        client = self.client()
        client.initialize()
        error = self.assert_code("mcp_error", client.list_tools)
        self.assertNotIn(secret, str(error))
        self.assertEqual(error.details, {"rpc_error_code": -32602})
        self.assertIn(secret.encode(), base64.b64decode(client.exchanges[-1]["raw_http_base64"]))
        self.override("tools/call", lambda request: {"body": json.dumps(envelope(request,
            {"content": [{"type": "text", "text": secret}], "isError": True})).encode()})
        second = self.client()
        second.initialize()
        error = self.assert_code("mcp_tool_error", lambda: second.call_tool("fixture_tool", {}))
        self.assertNotIn(secret, str(error))
        self.assertEqual(second.last_tool_result["content"][0]["text"], secret)

    def test_session_headers_must_be_single_visible_ascii_and_stable(self):
        for headers in ([("MCP-Session-Id", "a"), ("MCP-Session-Id", "b")],
                        [("MCP-Session-Id", "invalid session")], [("MCP-Session-Id", "bad\tvalue")],
                        [("MCP-Session-Id", "x" * 257)]):
            with self.subTest(headers=headers):
                self.override("initialize", lambda request, headers=headers: {**reply(request), "headers": headers})
                self.assert_code("mcp_session", self.client().initialize)
        self.override("tools/list", lambda request: {**reply(request), "headers": [("MCP-Session-Id", "different-session")]})
        client = self.client()
        client.initialize()
        self.assert_code("mcp_session", client.list_tools)
        self.assertEqual(client.session_id, "fixture-session")

    def test_stateless_initialization_cannot_receive_a_late_session_on_notification(self):
        def callback(request):
            if request["method"] == "initialize":
                return {**reply(request), "headers": []}
            if request["method"] == "notifications/initialized":
                return {**reply(request), "headers": [("MCP-Session-Id", "late-session")]}
            return reply(request)
        self.server.callback = callback
        self.assert_code("mcp_session", self.client().initialize)

    def test_sse_matching_result_returns_without_waiting_for_eof(self):
        def streamed(request):
            data = json.dumps(envelope(request, {"tools": []})).encode()
            progress = b'data: {"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}\r\n\r\n'
            return {"media": "text/event-stream; charset=utf-8", "chunks": [(0, b': heartbeat\r\n'),
                    (0, progress), (0, b'event: message\r\ndata: ' + data[:20]),
                    (0, data[20:] + b'\r\n\r'), (0, b'\n')], "hold": 0.6}
        self.override("tools/list", streamed)
        client = self.client(timeout=1)
        client.initialize()
        started = time.monotonic()
        self.assertEqual(client.list_tools(), [])
        self.assertLess(time.monotonic() - started, 0.3)
        self.assertEqual(len(client.exchanges[-1]["messages"]), 2)
        record = client.exchanges[-1]
        self.assertTrue(record["matching_response_received"])
        self.assertFalse(record["raw_http_complete"])
        self.assertFalse(record["response_body_complete"])
        self.assertGreater(record["response_body_bytes_read"], 0)
        self.assertEqual(record["raw_http_bytes_received"], record["wire_bytes"])

    def test_sse_waiting_keeps_the_original_handshake_deadline(self):
        def callback(request):
            if request["method"] in {"initialize", "notifications/initialized"}:
                return {**reply(request), "before_headers": 0.055}
            data = json.dumps(envelope(request, {"tools": []})).encode()
            return {"media": "text/event-stream", "chunks": [(0.035, b': beat\n\n') for _ in range(8)]
                    + [(0, b'data: ' + data + b'\n\n')]}
        self.server.callback = callback
        client = self.client(timeout=0.22)
        started = time.monotonic()
        client.initialize()
        self.assert_code("mcp_timeout", client.list_tools)
        self.assertLess(time.monotonic() - started, 0.38)
        self.assertFalse(client.exchanges[-1]["raw_http_complete"])
        self.assertFalse(client.exchanges[-1]["response_body_complete"])

    def test_sse_invalid_id_and_incomplete_event_are_not_results(self):
        for payload in (b'data: {"jsonrpc":"2.0","id":999,"result":{"tools":[]}}\n\n',
                        b'data: {"jsonrpc":"2.0","id":3,"result":{"tools":[]}}\n'):
            with self.subTest(payload=payload):
                self.override("tools/list", lambda request, payload=payload: {"media": "text/event-stream", "chunks": [(0, payload)]})
                client = self.client()
                client.initialize()
                self.assert_code("mcp_response_id" if b'999' in payload else "mcp_protocol", client.list_tools)

    def test_sse_invalid_utf8_is_a_protocol_error_not_a_network_error(self):
        self.override("tools/list", lambda request: {"media": "text/event-stream", "chunks": [(0, b'data: \xff\n\n')]})
        client = self.client()
        client.initialize()
        self.assert_code("mcp_protocol", client.list_tools)

    def test_constructor_deadline_does_not_restart_on_the_first_request(self):
        client = self.client(timeout=0.02)
        time.sleep(0.04)
        self.assert_code("mcp_timeout", client.initialize)
        self.assertEqual(self.server.calls, [])

    def test_header_timeout_has_an_explicit_incomplete_empty_transcript(self):
        self.override("initialize", lambda request: {**reply(request), "before_headers": 0.12})
        client = self.client(timeout=0.04)
        self.assert_code("mcp_timeout", client.initialize)
        record = client.exchanges[-1]
        self.assertFalse(record["raw_http_complete"])
        self.assertFalse(record["response_body_complete"])
        self.assertEqual(record["raw_http_bytes_received"], 0)
        self.assertEqual(record["response_body_bytes_read"], 0)
        self.assertEqual(record["wire_bytes"], 0)

    def test_response_budget_is_aggregate_and_includes_headers(self):
        header_limited = self.client(max_bytes=80)
        self.assert_code("tool_output_budget", header_limited.initialize)
        header_record = header_limited.exchanges[-1]
        self.assertFalse(header_record["raw_http_complete"])
        self.assertFalse(header_record["response_body_complete"])
        self.assertEqual(header_record["wire_bytes"], 80)
        self.assertEqual(header_record["raw_http_bytes_received"], 81)
        client = self.client(max_bytes=1200)
        client.initialize()
        client.list_tools()
        self.override("tools/call", lambda request: {"body": json.dumps(envelope(request,
            {"content": [{"type": "text", "text": "x" * 1000}]})).encode()})
        self.assert_code("tool_output_budget", lambda: client.call_tool("fixture_tool", {}))
        self.assertLessEqual(sum(item.get("wire_bytes", 0) for item in client.exchanges), 1200)
        record = client.exchanges[-1]
        self.assertFalse(record["raw_http_complete"])
        self.assertFalse(record["response_body_complete"])
        self.assertEqual(record["raw_http_bytes_received"], record["wire_bytes"] + 1)
        self.assertEqual(sum(item.get("raw_http_bytes_received", 0) for item in client.exchanges), client.bytes_received)

    def test_tools_list_paginates_and_rejects_cursor_loops_and_limits(self):
        def page(request):
            index = int(request["params"].get("cursor", "0"))
            result = {"tools": [{"name": "fixture_" + str(index), "inputSchema": {}}]}
            if index < 2:
                result["nextCursor"] = str(index + 1)
            return {"body": json.dumps(envelope(request, result)).encode()}
        self.override("tools/list", page)
        client = self.client()
        client.initialize()
        self.assertEqual([tool["name"] for tool in client.list_tools()], ["fixture_0", "fixture_1", "fixture_2"])
        self.override("tools/list", lambda request: {"body": json.dumps(envelope(request, {"tools": [], "nextCursor": "repeat"})).encode()})
        loop = self.client()
        loop.initialize()
        self.assert_code("mcp_budget", loop.list_tools)
        self.override("tools/list", page)
        limited = self.client()
        limited.initialize()
        with patch.object(mcp_http, "MAX_CATALOG_PAGES", 2):
            self.assert_code("mcp_budget", limited.list_tools)

    def test_tools_catalog_duplicate_names_and_tool_count_limit_are_rejected(self):
        for tools in ([{"name": "same", "inputSchema": {}}, {"name": "same", "inputSchema": {}}],
                      [{"name": "fixture_" + str(index), "inputSchema": {}} for index in range(4)]):
            with self.subTest(tools=tools):
                self.override("tools/list", lambda request, tools=tools: {"body": json.dumps(envelope(request, {"tools": tools})).encode()})
                client = self.client()
                client.initialize()
                with patch.object(mcp_http, "MAX_CATALOG_TOOLS", 3):
                    self.assert_code("mcp_protocol" if tools[0]["name"] == "same" else "mcp_budget", client.list_tools)

    def test_invalid_arguments_and_budgets_send_no_http_requests(self):
        for args in ({"timeout": False}, {"timeout": 0}, {"timeout": float("inf")}, {"timeout": 301},
                     {"timeout": 10 ** 400}, {"timeout": -(10 ** 400)},
                     {"max_bytes": False}, {"max_bytes": 0}, {"max_bytes": 12 * 1024 * 1024 + 1}):
            with self.subTest(args=args):
                self.assert_code("mcp_arguments", lambda: self.client(**args))
        client = self.client()
        client.initialize()
        before = len(self.server.calls)
        self.assert_code("mcp_arguments", lambda: client.call_tool("fixture_tool", {"bad": float("nan")}))
        self.assertEqual(len(self.server.calls), before)
        client.close()
        self.assert_code("mcp_closed", lambda: client.call_tool("fixture_tool", {}))

    def test_request_exchange_is_not_relabelled_by_later_argument_mutation(self):
        client = self.client()
        client.initialize()
        arguments = {"synthetic": "original"}
        client.call_tool("fixture_tool", arguments)
        arguments["synthetic"] = "changed"
        record = client.exchanges[-2]
        self.assertEqual(record["message"]["params"]["arguments"]["synthetic"], "original")
        self.assertEqual(json.loads(base64.b64decode(record["request_body_base64"]))["params"]["arguments"]["synthetic"], "original")

    def test_http_errors_unsupported_media_and_compression_fail_without_secret_text(self):
        for spec, code in (({"status": 500, "body": b'private-error-secret'}, "mcp_http_status"),
                           ({"media": "text/html", "body": b'private-error-secret'}, "mcp_protocol"),
                           ({"media": "application/json; charset=utf-16", "body": b'private-error-secret'}, "mcp_protocol"),
                           ({"headers": [("Content-Encoding", "gzip")], "body": b'private-error-secret'}, "mcp_protocol")):
            with self.subTest(code=code, spec=spec):
                self.override("tools/list", lambda request, spec=spec: spec)
                client = self.client()
                client.initialize()
                error = self.assert_code(code, client.list_tools)
                self.assertNotIn("private-error-secret", str(error))
                record = client.exchanges[-1]
                self.assertFalse(record["raw_http_complete"])
                self.assertFalse(record["response_body_complete"])
                self.assertEqual(record["response_body_bytes_read"], 0)
                self.assertEqual(record["raw_http_bytes_received"], record["wire_bytes"])


if __name__ == "__main__":
    unittest.main()
