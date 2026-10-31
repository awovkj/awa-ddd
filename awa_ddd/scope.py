"""Explicit URL scope and request identity; redirects are never followed."""
from urllib.parse import urlsplit, urlunsplit, unquote
import re
from .store import EngineError


def normalize_url(value):
    if not isinstance(value, str) or not value or any(ord(c) < 33 for c in value) or "\\" in value:
        raise EngineError("url", "URL must be an absolute HTTP(S) URL without controls")
    try:
        u = urlsplit(value)
        if u.scheme.lower() not in {"http", "https"} or not u.hostname or u.username is not None or u.password is not None or u.fragment:
            raise ValueError()
        host = u.hostname.encode("idna").decode("ascii").lower()
        port = u.port or (443 if u.scheme.lower() == "https" else 80)
        authority = ("[" + host + "]" if ":" in host else host) + (":" + str(port) if port != (443 if u.scheme.lower() == "https" else 80) else "")
        path = u.path or "/"
        # Refuse alternate path encodings that make scope comparison ambiguous.
        decoded = path
        for _ in range(3):
            new = unquote(decoded)
            if new == decoded:
                break
            decoded = new
        if "\\" in decoded or any(p in {".", ".."} for p in decoded.split("/")) or "//" in decoded:
            raise ValueError()
        if any(ord(c) < 32 for c in decoded):
            raise ValueError()
        return urlunsplit((u.scheme.lower(), authority, path, u.query, ""))
    except (ValueError, UnicodeError) as exc:
        raise EngineError("url", "Invalid or ambiguous HTTP(S) URL") from exc


def origin(url):
    p = urlsplit(normalize_url(url))
    return p.scheme + "://" + p.netloc


def _matches(rule, url):
    r, u = urlsplit(normalize_url(rule)), urlsplit(normalize_url(url))
    if (r.scheme, r.netloc) != (u.scheme, u.netloc):
        return False
    root = unquote(r.path).rstrip("/")
    path = unquote(u.path)
    if root and path != root and not path.startswith(root + "/"):
        return False
    return not r.query or r.query == u.query


def validate_config(config):
    target = normalize_url(config["target"])
    scope = [target] if config.get("scope") is None else config["scope"]
    exclude = config.get("exclude") or []
    if not isinstance(scope, list) or not scope or not isinstance(exclude, list):
        raise EngineError("scope", "scope must be a nonempty URL array and exclude must be a URL array; an omitted scope defaults to the target URL prefix")
    for rule in scope + exclude:
        normalize_url(rule)
    if not any(_matches(rule, target) for rule in scope) or any(_matches(rule, target) for rule in exclude):
        raise EngineError("scope", "Target is outside configured scope")
    return {**config, "target": target, "scope": scope, "exclude": exclude}


def require_scope(config, url):
    url = normalize_url(url)
    if not any(_matches(rule, url) for rule in config.get("scope", [])) or any(_matches(rule, url) for rule in config.get("exclude", [])):
        raise EngineError("out_of_scope", "Request URL is outside the configured project scope")
    return url


def bind_operation(operation, url, method):
    normalized = normalize_url(url)
    a, b = urlsplit(operation["url"]), urlsplit(normalized)
    if (a.scheme, a.netloc, operation["method"]) != (b.scheme, b.netloc, method.upper()):
        raise EngineError("operation_binding", "Request does not match operation origin/method")
    names = re.findall(r"\{([A-Za-z_][\w-]*)\}", a.path)
    if len(set(names)) != len(names):
        raise EngineError("operation_binding", "Path resource placeholders must have unique names")
    expression = re.escape(a.path)
    for name in names:
        expression = expression.replace(re.escape("{" + name + "}"), r"([^/]+)", 1)
    match = re.fullmatch(expression, b.path)
    if not match:
        raise EngineError("operation_binding", "Request path does not match the operation")
    return dict(zip(names, [unquote(x) for x in match.groups()]))
