"""Bounded loopback Streamable HTTP MCP transport; returned tool data is untrusted."""
from __future__ import annotations

import base64
import codecs
import http.client
import json
import math
import re
import socket
import ssl
import threading
import time
from urllib.parse import unquote, urlsplit

from .contracts import _validate_json
from .store import EngineError, canonical


DEFAULT_ENDPOINT = "http://127.0.0.1:8088/mcp"
PROTOCOL_VERSION = "2025-03-26"
SUPPORTED_PROTOCOL_VERSIONS = frozenset({"2025-03-26", "2025-06-18", "2025-11-25"})
MAX_CATALOG_PAGES = 20
MAX_CATALOG_TOOLS = 2000
MAX_REQUEST_BYTES = 1024 * 1024


class MCPHTTPError(EngineError):
    """Only fixed diagnostic text and non-sensitive structured details leave the client."""


def validate_endpoint(endpoint=DEFAULT_ENDPOINT):
    if not isinstance(endpoint, str) or not endpoint or len(endpoint) > 2048 \
            or any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in endpoint) \
            or any(character in endpoint for character in ("\\", "?", "#")):
        raise MCPHTTPError("mcp_endpoint", "Use an explicit, query-free loopback HTTP(S) MCP control endpoint")
    try:
        endpoint.encode("ascii", errors="strict")
        parsed = urlsplit(endpoint)
        host, port = parsed.hostname, parsed.port
        decoded_path = unquote(parsed.path, encoding="utf-8", errors="strict")
        if parsed.scheme not in {"http", "https"} or host not in {"127.0.0.1", "::1", "localhost"} \
                or parsed.username is not None or parsed.password is not None or "@" in parsed.netloc \
                or parsed.netloc.endswith(":") \
                or (port is not None and not 1 <= port <= 65535) \
                or not parsed.path.startswith("/") or parsed.path.startswith("//") \
                or re.search(r"%(?![0-9a-fA-F]{2})", parsed.path) \
                or any(character.isspace() or ord(character) < 32 or ord(character) == 127
                       or character == "\\" for character in decoded_path):
            raise ValueError()
    except (UnicodeError, ValueError, TypeError):
        raise MCPHTTPError("mcp_endpoint", "The MCP control endpoint must be exactly localhost, 127.0.0.1 or [::1]") from None
    authority = "[::1]" if host == "::1" else host
    if port is not None:
        authority += ":" + str(port)
    return parsed.scheme + "://" + authority + parsed.path


def _decode_json(raw):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError()
            result[key] = value
        return result

    def finite(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError()
        return result

    try:
        result = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=unique_pairs,
                            parse_float=finite, parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
        _validate_json(result)
        return result
    except (EngineError, UnicodeError, ValueError, TypeError, RecursionError):
        raise MCPHTTPError("mcp_protocol", "MCP responses require bounded, finite, unambiguous UTF-8 JSON") from None


class _BudgetReader:
    def __init__(self, reader, client, connection):
        self.reader, self.client, self.connection = reader, client, connection

    def _read(self, method, size=-1):
        remaining = self.client.max_bytes - self.client.bytes_received
        if remaining < 0:
            raise MCPHTTPError("tool_output_budget", "MCP HTTP responses exceeded the aggregate byte budget")
        self.connection.active_socket.settimeout(self.client._remaining())
        size = remaining + 1 if size < 0 else min(size, remaining + 1)
        raw = getattr(self.reader, method)(size)
        self.connection.wire.extend(raw[:remaining])
        self.client.bytes_received += len(raw)
        if self.client.bytes_received > self.client.max_bytes:
            raise MCPHTTPError("tool_output_budget", "MCP HTTP responses exceeded the aggregate byte budget")
        return raw

    def read(self, size=-1):
        return self._read("read", size)

    def read1(self, size=-1):
        return self._read("read1", size)

    def readline(self, size=-1):
        return self._read("readline", size)

    def __getattr__(self, name):
        return getattr(self.reader, name)


class _LoopbackConnection(http.client.HTTPConnection):
    def __init__(self, client):
        parsed = urlsplit(client.endpoint)
        super().__init__(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80),
                         timeout=client._remaining())
        self.client, self.scheme, self.wire, self.active_socket = client, parsed.scheme, bytearray(), None
        connection = self

        class Response(http.client.HTTPResponse):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.fp = _BudgetReader(self.fp, client, connection)

        self.response_class = Response

    def connect(self):
        address = "::1" if self.host == "::1" else "127.0.0.1"
        family = socket.AF_INET6 if address == "::1" else socket.AF_INET
        self.sock = self.active_socket = socket.socket(family, socket.SOCK_STREAM)
        self.sock.settimeout(self.client._remaining())
        # Numeric socket addresses bypass DNS and every ambient HTTP proxy setting.
        self.sock.connect((address, self.port))
        if self.scheme == "https":
            self.sock = self.active_socket = ssl.create_default_context().wrap_socket(
                self.sock, server_hostname=self.host, do_handshake_on_connect=False)
            self.sock.settimeout(self.client._remaining())
            self.sock.do_handshake()

    def abort(self):
        if self.active_socket is not None:
            try:
                self.active_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.close()


class StreamableHTTPClient:
    def __init__(self, endpoint=DEFAULT_ENDPOINT, timeout=30, max_bytes=4 * 1024 * 1024):
        self.endpoint = validate_endpoint(endpoint)
        if type(timeout) not in {int, float} or not math.isfinite(timeout) or not 0 < timeout <= 300 \
                or type(max_bytes) is not int or not 1 <= max_bytes <= 12 * 1024 * 1024:
            raise MCPHTTPError("mcp_arguments", "MCP timeout must be greater than zero and at most 300 seconds; max_bytes must be 1..12582912")
        self.timeout, self.max_bytes = timeout, max_bytes
        self.deadline = time.monotonic() + timeout
        self.sequence, self.bytes_received = 0, 0
        self.exchanges, self.last_tool_result = [], None
        self.protocol_version, self.session_id, self.server_info, self.capabilities = None, None, None, None
        self._initialized, self._closed, self._failed, self._initial_result = False, False, False, None
        self._active_connection, self._lock = None, threading.RLock()

    def _remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise MCPHTTPError("mcp_timeout", "The MCP operation exceeded its overall deadline")
        return remaining

    def _alive(self, initialized=False):
        if self._closed or self._failed:
            raise MCPHTTPError("mcp_closed", "This MCP connection is closed or uncertain; inspect its private exchange record before a new connection")
        self._remaining()
        if initialized and not self._initialized:
            raise MCPHTTPError("mcp_protocol", "Initialize this MCP connection before requesting tools")

    def _session_header(self, headers, *, establish=False):
        values = [value for name, value in headers if name.lower() == "mcp-session-id"]
        if not values:
            return
        if len(values) != 1 or not 1 <= len(values[0]) <= 256 \
                or any(not 33 <= ord(character) <= 126 for character in values[0]):
            raise MCPHTTPError("mcp_session", "The MCP session header is ambiguous or invalid")
        if self.session_id is not None and self.session_id != values[0]:
            raise MCPHTTPError("mcp_session", "The MCP server changed the session unexpectedly; do not automatically resend requests")
        if not establish and self.session_id is None:
            raise MCPHTTPError("mcp_session", "An MCP session may only be established by initialization")
        self.session_id = values[0]

    def _rpc_result(self, message, expected_id, *, stream=False):
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            raise MCPHTTPError("mcp_protocol", "The MCP server returned an invalid JSON-RPC envelope")
        if "id" not in message and stream and isinstance(message.get("method"), str) \
                and message["method"].startswith("notifications/") and not {"result", "error"}.intersection(message):
            return False, None
        if "method" in message:
            raise MCPHTTPError("mcp_protocol", "Server-initiated MCP requests are not supported by this bounded client")
        if type(message.get("id")) is not int or message["id"] != expected_id:
            raise MCPHTTPError("mcp_response_id", "The MCP response does not match the outstanding request ID")
        if ("result" in message) == ("error" in message):
            raise MCPHTTPError("mcp_protocol", "An MCP response must contain exactly one result or error")
        if "error" in message:
            error = message["error"]
            if not isinstance(error, dict) or type(error.get("code")) is not int or not isinstance(error.get("message"), str):
                raise MCPHTTPError("mcp_protocol", "The MCP error envelope is invalid")
            raise MCPHTTPError("mcp_error", "The MCP server rejected the request", {"rpc_error_code": error["code"]})
        return True, message["result"]

    def _read_body(self, response, exchange, size):
        raw = response.read1(size)
        exchange["response_body_bytes_read"] += len(raw)
        if not raw:
            # A matching SSE event is not EOF, and short Content-Length bodies
            # must not acquire a complete-transcript label merely on socket EOF.
            complete = response.length in (None, 0)
            exchange["response_body_complete"] = exchange["raw_http_complete"] = complete
        return raw

    def _sse(self, response, exchange, expected_id):
        decoder, buffered, data = codecs.getincrementaldecoder("utf-8")(errors="strict"), "", []
        messages = exchange["messages"] = []
        first = True
        while True:
            self._remaining()
            raw = self._read_body(response, exchange, 4096)
            text = decoder.decode(raw, final=not raw)
            if first and text:
                text = text.removeprefix("\ufeff")
                first = False
            buffered += text
            while "\n" in buffered or "\r" in buffered:
                self._remaining()
                index = min(index for index in (buffered.find("\n"), buffered.find("\r")) if index >= 0)
                if buffered[index] == "\r" and index == len(buffered) - 1 and raw:
                    break
                line, ending = buffered[:index], 2 if buffered[index:index + 2] == "\r\n" else 1
                buffered = buffered[index + ending:]
                if not line:
                    if data:
                        message = _decode_json("\n".join(data).encode("utf-8"))
                        messages.append(message)
                        data = []
                        matched, result = self._rpc_result(message, expected_id, stream=True)
                        if matched:
                            exchange["matching_response_received"] = True
                            return result
                elif line.startswith("data:"):
                    value = line[5:]
                    data.append(value[1:] if value.startswith(" ") else value)
            if not raw:
                raise MCPHTTPError("mcp_protocol", "The MCP event stream ended before a complete matching response")

    def _request(self, method, params=None, *, notification=False):
        self._alive()
        self.sequence += 1
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        if not notification:
            message["id"] = self.sequence
        try:
            _validate_json(message)
            body = canonical(message).encode("utf-8")
        except (EngineError, UnicodeError, ValueError, TypeError, RecursionError):
            raise MCPHTTPError("mcp_arguments", "MCP arguments require bounded finite JSON values") from None
        if len(body) > MAX_REQUEST_BYTES:
            raise MCPHTTPError("mcp_arguments", "MCP request arguments exceed the byte budget")
        parsed = urlsplit(self.endpoint)
        headers = {"Host": parsed.netloc, "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "Connection": "close", "MCP-Protocol-Version": self.protocol_version or PROTOCOL_VERSION}
        if self.session_id is not None:
            headers["MCP-Session-Id"] = self.session_id
        self.exchanges.append({"direction": "request", "message": json.loads(body), "headers": dict(headers),
                               "endpoint": self.endpoint, "request_body_base64": base64.b64encode(body).decode("ascii")})
        received_before = self.bytes_received
        exchange = {"direction": "response", "matching_response_received": False,
                    "raw_http_complete": False, "response_body_complete": False,
                    "raw_http_bytes_received": 0, "response_body_bytes_read": 0}
        self.exchanges.append(exchange)
        connection = self._active_connection = _LoopbackConnection(self)
        # A peer must not extend TLS/header/SSE reads by trickling bytes forever.
        watchdog = threading.Timer(self._remaining(), connection.abort)
        watchdog.daemon = True
        watchdog.start()
        response = None
        try:
            connection.request("POST", parsed.path, body=body, headers=headers)
            response = connection.getresponse()
            response_headers = response.getheaders()
            exchange.update(status=response.status, headers=response_headers)
            if 300 <= response.status < 400:
                raise MCPHTTPError("mcp_redirect", "MCP control endpoint redirects are not followed", {"http_status": response.status})
            if not 200 <= response.status < 300:
                raise MCPHTTPError("mcp_http_status", "The MCP control endpoint rejected the HTTP request", {"http_status": response.status})
            self._session_header(response_headers, establish=method == "initialize")
            types = [value for name, value in response_headers if name.lower() == "content-type"]
            encodings = [value for name, value in response_headers if name.lower() == "content-encoding"]
            if len(types) > 1 or encodings and (len(encodings) != 1 or encodings[0].lower() != "identity"):
                raise MCPHTTPError("mcp_protocol", "The MCP HTTP content headers are unsupported or ambiguous")
            media = types[0].split(";", 1)[0].strip().lower() if types else ""
            if types and re.search(r"charset\s*=\s*[^;]+", types[0], re.I):
                charset = re.search(r"charset\s*=\s*([^;]+)", types[0], re.I).group(1).strip().strip('"').lower()
                if charset not in {"utf-8", "utf8"}:
                    raise MCPHTTPError("mcp_protocol", "MCP HTTP responses must use UTF-8")
            if notification:
                if self._read_body(response, exchange, 1):
                    raise MCPHTTPError("mcp_protocol", "An MCP notification must not return a JSON-RPC result")
                exchange["notification_accepted"] = True
                self._remaining()
                return None
            if response.status == 202:
                raise MCPHTTPError("mcp_protocol", "An MCP request was accepted without a matching response; no automatic resume is attempted")
            if media == "text/event-stream":
                result = self._sse(response, exchange, message["id"])
                self._remaining()
                return result
            if media != "application/json":
                raise MCPHTTPError("mcp_protocol", "MCP responses must be application/json or text/event-stream")
            chunks = []
            while True:
                self._remaining()
                raw = self._read_body(response, exchange, 4096)
                if not raw:
                    break
                chunks.append(raw)
            result_message = _decode_json(b"".join(chunks))
            exchange["message"] = result_message
            matched, result = self._rpc_result(result_message, message["id"])
            exchange["matching_response_received"] = matched
            self._remaining()
            return result
        except MCPHTTPError as exc:
            self._failed, exchange["error_code"] = True, exc.code
            raise
        except UnicodeError:
            self._failed, exchange["error_code"] = True, "mcp_protocol"
            raise MCPHTTPError("mcp_protocol", "MCP event streams require strict UTF-8") from None
        except (OSError, http.client.HTTPException, ValueError) as exc:
            self._failed = True
            code = "mcp_timeout" if time.monotonic() >= self.deadline or isinstance(exc, (socket.timeout, TimeoutError)) else "mcp_io"
            exchange["error_code"] = code
            raise MCPHTTPError(code, "The MCP HTTP exchange timed out or failed; execution may be uncertain") from None
        finally:
            watchdog.cancel()
            exchange["raw_http_base64"] = base64.b64encode(connection.wire).decode("ascii")
            exchange["wire_bytes"] = len(connection.wire)
            exchange["raw_http_bytes_received"] = self.bytes_received - received_before
            if response is not None:
                response.close()
            connection.abort()
            self._active_connection = None

    def initialize(self):
        with self._lock:
            self._alive()
            if self._initialized:
                return self._initial_result
            try:
                from . import __version__
                result = self._request("initialize", {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                    "clientInfo": {"name": "awa-ddd", "version": __version__}})
                info = result.get("serverInfo") if isinstance(result, dict) else None
                if not isinstance(result, dict) or not isinstance(result.get("protocolVersion"), str) \
                        or result["protocolVersion"] not in SUPPORTED_PROTOCOL_VERSIONS \
                        or not isinstance(result.get("capabilities"), dict) or not isinstance(info, dict) \
                        or any(not isinstance(info.get(key), str) or not info[key].strip() or len(info[key]) > 256
                               for key in ("name", "version")):
                    raise MCPHTTPError("mcp_protocol", "MCP initialization did not negotiate a supported protocol and valid server information")
                self.protocol_version, self.server_info, self.capabilities = result["protocolVersion"], info, result["capabilities"]
                self._request("notifications/initialized", notification=True)
                self._remaining()
                self._initialized, self._initial_result = True, result
                return result
            except MCPHTTPError:
                self._failed = True
                raise

    def list_tools(self):
        with self._lock:
            self._alive(initialized=True)
            if not isinstance(self.capabilities.get("tools"), dict):
                raise MCPHTTPError("mcp_protocol", "The MCP server did not advertise tools capability")
            entries, cursor, seen_cursors, names = [], None, set(), set()
            try:
                for _ in range(MAX_CATALOG_PAGES):
                    result = self._request("tools/list", {"cursor": cursor} if cursor is not None else {})
                    if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
                        raise MCPHTTPError("mcp_protocol", "The MCP tools catalog must contain a tools array")
                    for tool in result["tools"]:
                        name = tool.get("name") if isinstance(tool, dict) else None
                        if not isinstance(name, str) or not name or len(name) > 200 or name in names \
                                or any(ord(character) < 32 or ord(character) == 127 for character in name) \
                                or not isinstance(tool.get("inputSchema"), dict):
                            raise MCPHTTPError("mcp_protocol", "MCP tool descriptors must have unique bounded names and object input schemas")
                        entries.append(tool)
                        names.add(name)
                    if len(entries) > MAX_CATALOG_TOOLS:
                        raise MCPHTTPError("mcp_budget", "The MCP tools catalog exceeded its tool budget")
                    cursor = result.get("nextCursor")
                    if cursor is None or cursor == "":
                        self._remaining()
                        return entries
                    if not isinstance(cursor, str) or len(cursor) > 1024 or cursor in seen_cursors:
                        raise MCPHTTPError("mcp_budget", "The MCP tools catalog cursor is invalid or repeated")
                    seen_cursors.add(cursor)
                raise MCPHTTPError("mcp_budget", "The MCP tools catalog exceeded its pagination budget")
            except MCPHTTPError:
                self._failed = True
                raise

    def call_tool(self, name, arguments):
        with self._lock:
            self._alive(initialized=True)
            if not isinstance(name, str) or not name or len(name) > 200 \
                    or any(ord(character) < 32 or ord(character) == 127 for character in name) or not isinstance(arguments, dict):
                raise MCPHTTPError("mcp_arguments", "Use a bounded tool name and an explicit JSON arguments object")
            result = self._request("tools/call", {"name": name, "arguments": arguments})
            self.last_tool_result = result
            if not isinstance(result, dict) or type(result.get("isError", False)) is not bool:
                self._failed = True
                raise MCPHTTPError("mcp_protocol", "The MCP tool result envelope is invalid")
            if result.get("isError"):
                self._failed = True
                raise MCPHTTPError("mcp_tool_error", "The MCP tool reported an error; inspect private artifacts before retrying")
            try:
                self._remaining()
            except MCPHTTPError:
                self._failed = True
                raise
            return result

    def close(self):
        # Only close local sockets; server sessions rely on its TTL. Session
        # cleanup would not prove that an outstanding remote task was cancelled.
        self._closed = True
        if self._active_connection is not None:
            self._active_connection.abort()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
