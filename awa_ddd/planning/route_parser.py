"""Static route-table parsing: nested, dynamic, hash/base, lazy, alias and catch-all.

Parsing a source file is information collection only.  It never registers an
operation, sends a request or proves that a route is reachable at runtime.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..store import EngineError


MAX_ROUTES = 20000
MAX_DEPTH = 32
_PATH_EXPRESSION = re.compile(r"\$\{|\+|\?\.|=>|function\s*\(")


def _public_path(value):
    value = value.strip()
    if not value.startswith("/"):
        value = "/" + value
    return value


def _join(base, path):
    if path == "/":
        return (base.rstrip("/") or "/")
    if path.startswith("/"):
        return (base.rstrip("/") + path) if base else path
    return (base.rstrip("/") + "/" + path.lstrip("/")) if base else "/" + path


def _dynamic_params(path):
    params = []
    for match in re.finditer(r"(?::([A-Za-z_][A-Za-z0-9_]*)\??|\{([A-Za-z_][A-Za-z0-9_]*)\}|(?<!\*)\*([A-Za-z_][A-Za-z0-9_]*)?)", path):
        name = match.group(1) or match.group(2) or match.group(3) or "splat"
        if name not in params:
            params.append(name)
    return params


def _walk(routes, *, base, parent, depth, output):
    if depth > MAX_DEPTH:
        output.append({"path_template": base or "/", "name": None, "component": None,
                       "parent": parent, "aliases": [], "redirect": None,
                       "catch_all": False, "lazy": False, "unresolved": True,
                       "limitations": ["max_route_depth_exceeded"]})
        return
    for route in routes:
        if not isinstance(route, dict):
            continue
        raw_path = route.get("path", "")
        unresolved = not isinstance(raw_path, str) or bool(_PATH_EXPRESSION.search(str(raw_path)))
        if not isinstance(raw_path, str):
            raw_path = ""
        path = _join(base, raw_path)
        catch_all = raw_path in {"*", "/*"} or raw_path.endswith("/*") or raw_path.startswith("*")
        aliases = route.get("alias")
        aliases = [aliases] if isinstance(aliases, str) else aliases if isinstance(aliases, list) else []
        aliases = [str(alias) for alias in aliases if isinstance(alias, (str, int))]
        row = {
            "path_template": _public_path(path) if path else "/",
            "name": route.get("name") if isinstance(route.get("name"), str) else None,
            "component": route.get("component") if isinstance(route.get("component"), str) else None,
            "parent": parent,
            "aliases": aliases,
            "redirect": route.get("redirect") if isinstance(route.get("redirect"), str) else None,
            "catch_all": catch_all,
            "lazy": bool(route.get("lazy") or route.get("component") and str(route.get("component")).startswith("() =>")),
            "dynamic_params": _dynamic_params(path),
            "unresolved": unresolved,
            "limitations": ["unresolved_path_expression"] if unresolved else [],
        }
        if row["catch_all"]:
            row["limitations"].append("catch_all_cannot_enumerate_concrete_pages")
        output.append(row)
        children = route.get("children")
        if isinstance(children, list):
            _walk(children, base=path if not catch_all else base, parent=row["path_template"],
                  depth=depth + 1, output=output)


def parse_json_routes(document):
    """Return route records from a JSON route manifest."""
    if not isinstance(document, dict):
        raise EngineError("route_manifest", "Route manifest must be a JSON object")
    routes = document.get("routes")
    if not isinstance(routes, list):
        raise EngineError("route_manifest", "Route manifest requires a routes array")
    mode = str(document.get("mode") or "history").lower()
    if mode not in {"history", "hash", "abstract"}:
        raise EngineError("route_manifest", "mode must be history, hash or abstract")
    base = document.get("base") if isinstance(document.get("base"), str) else ""
    output = []
    _walk(routes[:MAX_ROUTES], base=base, parent=None, depth=0, output=output)
    return {"mode": mode, "routes": output, "limitations": [] if len(routes) <= MAX_ROUTES else ["route_budget_truncated"]}


_JS_PATH = re.compile(r"""path\s*:\s*(['"`])(.*?)\1""", re.S)
_JS_CHILDREN_HINT = re.compile(r"children\s*:\s*\[")


def parse_js_routes(source):
    """Best-effort static extraction from a JS router bundle.

    The parser intentionally reports every non-literal expression as unresolved
    instead of evaluating JavaScript.
    """
    if not isinstance(source, str):
        raise EngineError("route_manifest", "JavaScript route source must be text")
    routes = []
    for match in _JS_PATH.finditer(source[:2 * 1024 * 1024]):
        path = match.group(2)
        routes.append({"path": path})
    output = []
    _walk(routes[:MAX_ROUTES], base="", parent=None, depth=0, output=output)
    if not routes:
        output.append({"path_template": "/", "name": None, "component": None, "parent": None,
                       "aliases": [], "redirect": None, "catch_all": False, "lazy": False,
                       "dynamic_params": [], "unresolved": True,
                       "limitations": ["no_static_route_literals_found"]})
    return {"mode": "history", "routes": output,
            "limitations": ["static_js_extraction_only", "dynamic_imports_and_runtime_guards_not_evaluated"]}


def parse_route_manifest(path):
    path = Path(path).expanduser().resolve()
    if not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
        raise EngineError("route_manifest", "Route manifest must be a local UTF-8 file under 8 MiB")
    raw = path.read_text(encoding="utf-8-sig", errors="strict")
    try:
        document = json.loads(raw)
    except json.JSONDecodeError:
        result = parse_js_routes(raw)
    else:
        result = parse_json_routes(document)
    result["source_path"] = str(path)
    result["route_total"] = len(result["routes"])
    result["unresolved_total"] = sum(bool(row.get("unresolved")) for row in result["routes"])
    result["catch_all_total"] = sum(bool(row.get("catch_all")) for row in result["routes"])
    return result
