"""Controlled-clock reads distinguish deadline aborts from genuine peer EOF."""
from __future__ import annotations

from contextlib import contextmanager
import unittest
from unittest.mock import patch

from awa_ddd import mcp_http


class _Response:
    def __init__(self, clock, after_read, payload=b"", length=None):
        self.clock, self.after_read, self.payload, self.length = clock, after_read, payload, length

    def read1(self, size):
        self.clock[0] = self.after_read
        return self.payload


class MCPDeadlineReadTests(unittest.TestCase):
    @contextmanager
    def prepared(self):
        clock = [100.0]
        with patch.object(mcp_http.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(mcp_http.socket, "socket", side_effect=AssertionError("No network in a controlled-clock test")):
            client = mcp_http.StreamableHTTPClient(timeout=1)
            exchange = {"response_body_bytes_read": 0, "response_body_complete": False, "raw_http_complete": False,
                        "matching_response_received": False}
            try:
                yield client, clock, exchange
            finally:
                client.close()

    def test_watchdog_eof_after_the_deadline_is_timeout_not_protocol_or_complete(self):
        with self.prepared() as (client, clock, exchange):
            response = _Response(clock, 102.0)
            with self.assertRaises(mcp_http.MCPHTTPError) as caught:
                client._sse(response, exchange, 1)
            self.assertEqual("mcp_timeout", caught.exception.code)
            self.assertEqual(0, exchange["response_body_bytes_read"])
            self.assertFalse(exchange["raw_http_complete"])
            self.assertFalse(exchange["response_body_complete"])
            self.assertFalse(exchange["matching_response_received"])
            self.assertEqual([], exchange["messages"])

    def test_late_utf8_and_json_partial_bytes_are_counted_before_timeout(self):
        for payload in (b"\xff", b'{"jsonrpc":'):
            with self.subTest(payload=payload), self.prepared() as (client, clock, exchange):
                response = _Response(clock, 101.0, payload=payload)
                with self.assertRaises(mcp_http.MCPHTTPError) as caught:
                    client._read_body(response, exchange, 4096)
                self.assertEqual("mcp_timeout", caught.exception.code)
                self.assertEqual(len(payload), exchange["response_body_bytes_read"])
                self.assertFalse(exchange["raw_http_complete"])
                self.assertFalse(exchange["response_body_complete"])

    def test_real_early_close_delimited_eof_remains_an_sse_protocol_error(self):
        with self.prepared() as (client, clock, exchange):
            response = _Response(clock, 100.5)
            with self.assertRaises(mcp_http.MCPHTTPError) as caught:
                client._sse(response, exchange, 1)
            self.assertEqual("mcp_protocol", caught.exception.code)
            self.assertTrue(exchange["raw_http_complete"])
            self.assertTrue(exchange["response_body_complete"])
            self.assertFalse(exchange["matching_response_received"])

    def test_early_short_content_length_eof_is_protocol_and_incomplete(self):
        with self.prepared() as (client, clock, exchange):
            response = _Response(clock, 100.5, length=8)
            with self.assertRaises(mcp_http.MCPHTTPError) as caught:
                client._sse(response, exchange, 1)
            self.assertEqual("mcp_protocol", caught.exception.code)
            self.assertFalse(exchange["raw_http_complete"])
            self.assertFalse(exchange["response_body_complete"])
            self.assertFalse(exchange["matching_response_received"])


if __name__ == "__main__":
    unittest.main()
