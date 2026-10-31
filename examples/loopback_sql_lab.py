"""A read-only SQLite injection fixture for actual MCP/sqlmap integration checks.

Only binds 127.0.0.1. Contains synthetic data; SQL connections themselves are read-only.
Run: python -X utf8 -B examples/loopback_sql_lab.py --directory <isolated directory>
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sqlite3
import threading
from urllib.parse import parse_qs, urlsplit


PAGE = '''<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<title>awa-ddd SQL 证据验证</title><main><h1>本地 SQL 证据验证</h1>
<p>此页面查询隔离 SQLite 中的合成商品。</p>
<form id="search"><label>商品 ID <input name="id" value="1"></label><button>查询</button></form>
<pre id="result" aria-live="polite">等待查询</pre>
<script>document.querySelector('#search').addEventListener('submit', async event => {
event.preventDefault(); const id = document.querySelector('[name=id]').value;
const response = await fetch('/api/item?id=' + encodeURIComponent(id));
document.querySelector('#result').textContent = JSON.stringify(await response.json());
});</script></main></html>'''


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _reply(self, status, payload, content_type="application/json; charset=utf-8"):
        raw = payload.encode("utf-8") if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        parsed = urlsplit(self.path)
        with self.server.log_lock:
            self.server.calls += 1
            with self.server.traffic.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({"number": self.server.calls, "method": "GET", "path": self.path}) + "\n")
        if parsed.path == "/":
            return self._reply(200, PAGE, "text/html; charset=utf-8")
        if parsed.path == "/health":
            return self._reply(200, {"ok": True, "fixture": "read-only-sqlite", "requests": self.server.calls})
        if parsed.path == "/favicon.ico":
            return self._reply(204, "", "image/x-icon")
        if parsed.path not in {"/api/item", "/api/fixed"}:
            return self._reply(404, {"error": "not_found"})
        value = parse_qs(parsed.query, keep_blank_values=True).get("id", [""])[0]
        if len(value) > 8000:
            return self._reply(400, {"error": "input_budget"})
        database = sqlite3.connect(self.server.database.as_uri() + "?mode=ro", uri=True)
        try:
            if parsed.path == "/api/fixed":
                result = database.execute("SELECT name FROM products WHERE id = ?", (value,))
            else:
                result = database.execute("SELECT name FROM products WHERE id = " + value)
            rows = [{"name": row[0]} for row in result.fetchmany(10)]
            return self._reply(200, {"rows": rows})
        except sqlite3.Error as exc:
            return self._reply(400, {"error": str(exc), "rows": []})
        finally:
            database.close()

    def do_POST(self):
        self._reply(405, {"error": "read_only_fixture"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True)
    options = parser.parse_args()
    folder = Path(options.directory).resolve()
    folder.mkdir(parents=True, exist_ok=True)
    database = folder / "synthetic.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY,name TEXT NOT NULL)")
    connection.execute("INSERT OR IGNORE INTO products VALUES(1,'demo-product'),(2,'second-product')")
    connection.commit()
    connection.close()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.database, server.traffic, server.log_lock, server.calls = database, folder / "server-traffic.jsonl", threading.Lock(), 0
    state = {"pid": os.getpid(), "url": f"http://127.0.0.1:{server.server_port}", "database": str(database),
             "traffic": str(server.traffic), "scope": [f"http://127.0.0.1:{server.server_port}/"]}
    (folder / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    print(json.dumps(state), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
