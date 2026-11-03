"""Bounded, passive response hints; never execute code or authorize a locator."""
from __future__ import annotations

from collections.abc import Mapping
from html.parser import HTMLParser
import re
from urllib.parse import unquote, unquote_plus, urljoin, urlsplit, urlunsplit


MAX_BODY_BYTES = 1024 * 1024
MAX_HEADERS = 64
MAX_HEADER_CHARS = 2048
MAX_URL_CHARS = 4096
MAX_HTML_NODES = 4096
MAX_HTML_DEPTH = 64
MAX_ATTRIBUTES = 64
MAX_CLUES = 128
MAX_FORMS = 32
MAX_FORM_INPUTS = 64
MAX_INPUT_NAME = 128
MAX_TECHNOLOGIES = 32
_VERSION = r"[0-9]{1,4}(?:\.[0-9]{1,4}){0,3}"
_VERSION_SUFFIX = re.compile(r"^[ /v!:-]*(" + _VERSION + r")(?=$|[\s/;,)\-])")
_CONTROL = re.compile(r"[\x00-\x20\x7f\\]")
_NAME_CONTROL = re.compile(r"[\x00-\x1f\x7f\ufffd]")
_VOID = frozenset("area base br col embed hr img input link meta param source track wbr".split())
_HTML_ATTRIBUTES = frozenset(("id name type src href action method form formaction formmethod disabled content "
                             "data-reactroot data-reactid data-v-app ng-app data-ng-app ng-version").split())
_CHARSETS = {
    "utf-8": "utf-8", "utf8": "utf-8", "ascii": "ascii", "us-ascii": "ascii",
    "iso-8859-1": "latin-1", "latin-1": "latin-1", "windows-1252": "cp1252",
    "gbk": "gbk", "gb2312": "gb2312", "gb18030": "gb18030", "big5": "big5",
    "utf-16": "utf-16", "utf-16le": "utf-16-le", "utf-16be": "utf-16-be",
}
_HEADER_MARKERS = (
    ("nginx", "web_server", r"\bnginx\b"),
    ("Apache HTTP Server", "web_server", r"\bApache(?=/|$|\s+(?!Tomcat))"),
    ("IIS", "web_server", r"\bMicrosoft-IIS\b"),
    ("OpenResty", "web_server", r"\bopenresty\b"),
    ("Caddy", "web_server", r"\bCaddy\b"),
    ("Apache Tomcat", "web_server", r"\bTomcat\b"),
    ("Gunicorn", "web_server", r"\bgunicorn\b"),
    ("Uvicorn", "web_server", r"\buvicorn\b"),
    ("PHP", "runtime", r"\bPHP\b"),
    ("ASP.NET", "framework", r"\bASP\.NET\b"),
    ("Express", "framework", r"\bExpress\b"),
    ("Next.js", "frontend_framework", r"\bNext\.js\b"),
)
_HEADER_MARKERS = tuple((name, category, re.compile(pattern, re.I)) for name, category, pattern in _HEADER_MARKERS)
_COOKIE_MARKERS = {
    "phpsessid": ("PHP", "runtime", "PHPSESSID"),
    "jsessionid": ("Java Servlet", "framework", "JSESSIONID"),
    "asp.net_sessionid": ("ASP.NET", "framework", "ASP.NET_SessionId"),
    "laravel_session": ("Laravel", "framework", "laravel_session"),
    "csrftoken": ("Django", "framework", "csrftoken"),
    "connect.sid": ("Express", "framework", "connect.sid"),
    "next-auth.session-token": ("NextAuth", "framework", "next-auth.session-token"),
    "__secure-next-auth.session-token": ("NextAuth", "framework", "__Secure-next-auth.session-token"),
}
_ASSET_MARKERS = (
    ("jQuery", "frontend_library", r"^jquery(?:[-.]({v}))?(?:\.slim)?(?:\.min)?\.js$"),
    ("Bootstrap", "frontend_library", r"^bootstrap(?:[-.]({v}))?(?:\.bundle)?(?:\.min)?\.(?:js|css)$"),
    ("React", "frontend_framework", r"^react(?:-dom)?(?:[-.]({v}|production|development))?(?:\.min)?\.(?:js|mjs)$"),
    ("Vue", "frontend_framework", r"^vue(?:[-.]({v}))?(?:\.(?:global|runtime|esm-browser|esm-bundler|common)){0,2}(?:\.prod)?(?:\.min)?\.js$"),
    ("Angular", "frontend_framework", r"^angular(?:[-.]({v}))?(?:\.min)?\.js$"),
    ("Joomla", "cms", r"^joomla(?:[-.]({v}))?(?:\.min)?\.js$"),
)
_ASSET_MARKERS = tuple((name, category, re.compile(pattern.replace("{v}", _VERSION), re.I))
                       for name, category, pattern in _ASSET_MARKERS)
_JS_MARKERS = (
    ("Next.js", "frontend_framework", "__NEXT_DATA__"),
    ("Next.js", "frontend_framework", "__next_f"),
    ("Nuxt", "frontend_framework", "__NUXT__"),
    ("Nuxt", "frontend_framework", "__NUXT_DATA__"),
    ("React", "frontend_framework", "__REACT_DEVTOOLS_GLOBAL_HOOK__"),
    ("React", "frontend_framework", "React.createElement"),
    ("Vue", "frontend_framework", "Vue.version"),
    ("Vue", "frontend_framework", "__VUE__"),
    ("Angular", "frontend_framework", "angular.module"),
    ("jQuery", "frontend_library", "jQuery.fn.jquery"),
)


class _LimitReached(Exception):
    pass


class _Hints:
    def __init__(self):
        self.technologies, self.clues, self.parse_errors = [], [], []
        self.truncated = False
        self._technologies, self._clues = set(), set()

    def error(self, code, *, truncated=False):
        self.truncated |= truncated
        if code not in self.parse_errors and len(self.parse_errors) < 8:
            self.parse_errors.append(code)

    def technology(self, name, category, signal, version=None):
        if version is not None and re.fullmatch(_VERSION, version) is None:
            version = None
        key = (name, category, signal, version)
        if key in self._technologies:
            return
        if len(self.technologies) >= MAX_TECHNOLOGIES:
            self.error("technology_limit", truncated=True)
            return
        row = {"name": name, "category": category, "signal": signal, "confidence": "hint"}
        if version:
            row["version"] = version
        self._technologies.add(key)
        self.technologies.append(row)

    def clue(self, row):
        key = (row["kind"], row["url"], row.get("method"), row["ambiguous"],
               tuple((field["name"], field["location"]) for field in row["inputs"]))
        if key in self._clues:
            return
        if len(self.clues) >= MAX_CLUES:
            self.error("clue_limit", truncated=True)
            return
        self._clues.add(key)
        self.clues.append(row)

    def result(self):
        return {"technologies": self.technologies, "clues": self.clues,
                "truncated": self.truncated, "parse_errors": self.parse_errors}


def _url(value, base):
    if not isinstance(value, str) or len(value) > MAX_URL_CHARS or "\ufffd" in value:
        return None
    if _NAME_CONTROL.search(value) or "\\" in value:
        return None
    value = value.strip()
    if _CONTROL.search(value):
        return None
    try:
        parsed = urlsplit(urljoin(base, value))
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname \
                or parsed.username is not None or parsed.password is not None or "%" in parsed.hostname:
            return None
        parsed.port
        result = urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.query, ""))
        return result if len(result) <= MAX_URL_CHARS else None
    except (TypeError, ValueError):
        return None


def _origin(url):
    parsed = urlsplit(url)
    port = parsed.port if parsed.port is not None else 443 if parsed.scheme == "https" else 80
    return parsed.scheme.lower(), parsed.hostname.lower(), port


def _input(name, location):
    if not isinstance(name, str) or not name or len(name) > MAX_INPUT_NAME or _NAME_CONTROL.search(name):
        return None
    return {"name": name, "location": location, "selector": name}


def _query_inputs(url, hints):
    query = urlsplit(url).query
    fields = query.split("&") if query else []
    if len(fields) > MAX_FORM_INPUTS:
        hints.error("query_input_limit", truncated=True)
        fields = fields[:MAX_FORM_INPUTS]
    rows = []
    for field in fields:
        name = unquote_plus(field.partition("=")[0])
        item = _input(name, "query")
        if item:
            rows.append(item)
        elif name:
            hints.error("invalid_input_name")
    return rows


def _ambiguous(inputs):
    identities = [(item["location"], item["name"]) for item in inputs]
    return len(set(identities)) != len(identities)


def _asset_hints(url, hints):
    path = unquote(urlsplit(url).path)
    lower = path.lower()
    for marker, name, category in (("/_next/", "Next.js", "frontend_framework"),
                                   ("/_nuxt/", "Nuxt", "frontend_framework"),
                                   ("/wp-content/", "WordPress", "cms"),
                                   ("/wp-includes/", "WordPress", "cms"),
                                   ("/core/misc/drupal", "Drupal", "cms")):
        if marker in lower:
            hints.technology(name, category, "asset-path:" + marker)
    filename = path.rsplit("/", 1)[-1]
    for name, category, pattern in _ASSET_MARKERS:
        match = pattern.fullmatch(filename)
        if match:
            hints.technology(name, category, "asset-filename:" + name, match.group(1))


def _script_hints(text, hints):
    for name, category, marker in _JS_MARKERS:
        if re.search(r"(?<![\w$])" + re.escape(marker) + r"(?![\w$])", text):
            hints.technology(name, category, "script-marker:" + marker)
    for name, category in (("jQuery", "frontend_library"), ("Bootstrap", "frontend_library"), ("Vue.js", "frontend_framework")):
        match = re.search(r"/\*!?\s*" + re.escape(name) + r"\s+v(" + _VERSION + r")(?=\s|\*|$)", text, re.I)
        if match:
            hints.technology("Vue" if name == "Vue.js" else name, category, "script-banner:" + name, match.group(1))


def _headers(headers, hints):
    if isinstance(headers, Mapping):
        pairs = iter(headers.items())
    elif isinstance(headers, (list, tuple)):
        pairs = iter(headers)
    else:
        hints.error("invalid_headers")
        return []
    result = []
    for index, pair in enumerate(pairs):
        if index >= MAX_HEADERS:
            hints.error("header_limit", truncated=True)
            break
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            hints.error("invalid_headers")
            continue
        key, value = pair
        if not isinstance(key, str) or not isinstance(value, str):
            hints.error("invalid_headers")
            continue
        if len(key) > 128:
            hints.error("header_size_limit", truncated=True)
            continue
        if len(value) > MAX_HEADER_CHARS:
            hints.error("header_size_limit", truncated=True)
            value = value[:MAX_HEADER_CHARS]
        key = key.lower()
        if key not in {"server", "x-powered-by", "set-cookie", "content-type"}:
            continue
        result.append((key, value))
        if key in {"server", "x-powered-by"}:
            for name, category, pattern in _HEADER_MARKERS:
                match = pattern.search(value)
                if match:
                    version = _VERSION_SUFFIX.match(value[match.end():])
                    hints.technology(name, category, "header:" + key + ":" + name,
                                     version.group(1) if version else None)
        elif key == "set-cookie":
            cookie = value.partition("=")[0].strip().lower()
            if cookie in _COOKIE_MARKERS:
                name, category, marker = _COOKIE_MARKERS[cookie]
                hints.technology(name, category, "cookie-name:" + marker)
            elif cookie.startswith(".aspnetcore."):
                hints.technology("ASP.NET Core", "framework", "cookie-name:.AspNetCore.*")
            elif cookie.startswith(("wordpress_logged_in_", "wordpress_sec_")):
                hints.technology("WordPress", "cms", "cookie-name:wordpress_*")
    return result


class _HTMLHints(HTMLParser):
    def __init__(self, url, hints):
        super().__init__(convert_charrefs=True)
        self.url, self.base, self.hints = url, url, hints
        self.nodes, self.stack, self.forms, self.open_forms = 0, [], [], []
        self.locators, self.fields, self.overrides = [], [], []
        self.locator_ids = set()
        self.has_base = False
        self.script_enabled = False

    def _node(self):
        self.nodes += 1
        if self.nodes > MAX_HTML_NODES:
            self.hints.error("html_node_limit", truncated=True)
            raise _LimitReached

    def handle_starttag(self, tag, attrs):
        self._node()
        if len(attrs) > MAX_ATTRIBUTES:
            self.hints.error("html_attribute_limit", truncated=True)
            raise _LimitReached
        values, duplicates = {}, set()
        for key, value in attrs:
            if key not in _HTML_ATTRIBUTES and re.fullmatch(r"data-v-[0-9a-f]{4,16}", key) is None:
                continue
            if key in values:
                duplicates.add(key)
            else:
                values[key] = value
        if tag not in _VOID:
            if len(self.stack) >= MAX_HTML_DEPTH:
                self.hints.error("html_depth_limit", truncated=True)
                raise _LimitReached
            self.stack.append(tag)
        if tag == "base" and not self.has_base:
            candidate = _url(values.get("href"), self.url)
            if candidate:
                self.base, self.has_base = candidate, True
        if tag in {"a", "area", "link", "script"}:
            locator = values.get("src" if tag == "script" else "href")
            if isinstance(locator, str) and locator and not locator.startswith("#"):
                identity = ("script" if tag == "script" else "link", locator, bool(duplicates & {"src", "href"}))
                if identity not in self.locator_ids:
                    if len(self.locators) >= MAX_CLUES:
                        self.hints.error("clue_limit", truncated=True)
                    else:
                        self.locator_ids.add(identity)
                        self.locators.append(identity)
        if tag == "script":
            self.script_enabled = "src" not in values and (values.get("type") or "").lower() in {
                "", "module", "text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript"}
        if tag == "form":
            if len(self.forms) >= MAX_FORMS:
                self.hints.error("form_limit", truncated=True)
                raise _LimitReached
            method = (values.get("method") or "GET").upper()
            form = {"action": values.get("action"), "method": method, "inputs": [],
                    "ambiguous": bool(duplicates & {"action", "method", "id"}), "id": values.get("id")}
            if method not in {"GET", "POST"}:
                form["ambiguous"] = True
                self.hints.error("unsupported_form_method")
            if self.open_forms:
                form["ambiguous"] = self.open_forms[-1]["ambiguous"] = True
                self.hints.error("nested_form")
            self.forms.append(form)
            self.open_forms.append(form)
        if tag in {"input", "select", "textarea", "button"} and "disabled" not in values:
            owner = self.open_forms[-1] if self.open_forms else None
            if tag in {"input", "button"} and ("formaction" in values or "formmethod" in values):
                if owner:
                    owner["ambiguous"] = True
                self.hints.error("submission_override")
                if len(self.overrides) < MAX_FORMS:
                    self.overrides.append((values.get("form"), owner, values.get("formaction"), values.get("formmethod")))
                else:
                    self.hints.error("form_variant_limit", truncated=True)
            item = _input(values.get("name"), "body")
            if item:
                if len(self.fields) >= MAX_FORMS * MAX_FORM_INPUTS:
                    self.hints.error("form_input_limit", truncated=True)
                    raise _LimitReached
                self.fields.append((values.get("form"), owner, item, bool(duplicates & {"name", "form"})))
        self._technology(tag, values)

    def _technology(self, tag, values):
        for attr, name in (("data-reactroot", "React"), ("data-reactid", "React"),
                           ("data-v-app", "Vue"), ("ng-app", "Angular"), ("data-ng-app", "Angular"),
                           ("ng-version", "Angular")):
            if attr in values:
                version = values.get(attr) if attr == "ng-version" else None
                self.hints.technology(name, "frontend_framework", "html-attribute:" + attr, version)
        if any(re.fullmatch(r"data-v-[0-9a-f]{4,16}", key) for key in values):
            self.hints.technology("Vue", "frontend_framework", "html-attribute:data-v-*")
        identities = {"__NEXT_DATA__": "Next.js", "__NUXT_DATA__": "Nuxt", "__nuxt": "Nuxt"}
        if values.get("id") in identities:
            self.hints.technology(identities[values["id"]], "frontend_framework", "html-id:" + values["id"])
        if tag == "meta" and (values.get("name") or "").lower() == "generator":
            content = values.get("content") or ""
            for name in ("WordPress", "Drupal", "Joomla"):
                match = re.match(re.escape(name) + r"\b", content, re.I)
                if match:
                    version = _VERSION_SUFFIX.match(content[match.end():])
                    self.hints.technology(name, "cms", "html-meta:generator:" + name,
                                          version.group(1) if version else None)

    def handle_endtag(self, tag):
        self._node()
        if tag == "script":
            self.script_enabled = False
        if tag == "form" and self.open_forms:
            self.open_forms.pop()
        if tag in self.stack:
            del self.stack[len(self.stack) - 1 - self.stack[::-1].index(tag):]

    def handle_data(self, data):
        self._node()
        if self.script_enabled and self.stack and self.stack[-1] == "script":
            _script_hints(data, self.hints)

    def handle_comment(self, data):
        self._node()

    def handle_decl(self, decl):
        self._node()

    def unknown_decl(self, data):
        self._node()

    def handle_pi(self, data):
        self._node()

    def finish(self):
        for reference, owner, item, ambiguous in self.fields:
            if reference is not None:
                matches = [form for form in self.forms if form["id"] == reference]
                if len(matches) != 1:
                    for form in matches:
                        form["ambiguous"] = True
                    self.hints.error("ambiguous_form_owner")
                    continue
                owner = matches[0]
            if owner is None:
                continue
            if len(owner["inputs"]) >= MAX_FORM_INPUTS:
                owner["ambiguous"] = True
                self.hints.error("form_input_limit", truncated=True)
                continue
            owner["ambiguous"] |= ambiguous
            owner["inputs"].append(item)
        # Forms survive link-heavy pages; all omitted data still marks truncation.
        for form in self.forms:
            url = _url(form["action"] or self.url, self.base)
            if not url:
                self.hints.error("unsafe_locator")
                continue
            method = form["method"]
            inputs = [{**item, "location": "query" if method == "GET" else "body"} for item in form["inputs"]]
            row = {"kind": "form", "url": url, "inputs": inputs, "external": _origin(url) != _origin(self.url),
                   "ambiguous": form["ambiguous"] or _ambiguous(inputs)
                   or self.hints.truncated and form in self.open_forms}
            if method in {"GET", "POST"}:
                row["method"] = method
            self.hints.clue(row)
        for reference, owner, action, method in self.overrides:
            if reference is not None:
                matches = [form for form in self.forms if form["id"] == reference]
                owner = matches[0] if len(matches) == 1 else None
            if owner is None:
                continue
            url = _url(action if action is not None else owner["action"] or self.url, self.base)
            if not url:
                self.hints.error("unsafe_locator")
                continue
            method = (method or owner["method"]).upper()
            inputs = [{**item, "location": "query" if method == "GET" else "body"} for item in owner["inputs"]]
            row = {"kind": "form", "url": url, "inputs": inputs, "ambiguous": True,
                   "external": _origin(url) != _origin(self.url)}
            if method in {"GET", "POST"}:
                row["method"] = method
            self.hints.clue(row)
        for kind, locator, ambiguous in self.locators:
            url = _url(locator, self.base)
            if not url:
                self.hints.error("unsafe_locator")
                continue
            _asset_hints(url, self.hints)
            inputs = _query_inputs(url, self.hints)
            self.hints.clue({"kind": kind, "url": url, "inputs": inputs,
                             "external": _origin(url) != _origin(self.url), "ambiguous": ambiguous or _ambiguous(inputs)})


def parse_response(url, headers, body: bytes, *, max_bytes=262144):
    """Return forgeable static hints and private locators, without scope approval."""
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_BODY_BYTES:
        raise ValueError("max_bytes must be an integer between 1 and 1048576")
    hints = _Hints()
    base = _url(url, "")
    if not base:
        hints.error("invalid_response_url")
        return hints.result()
    if not isinstance(body, (bytes, bytearray)):
        hints.error("invalid_response_body")
        return hints.result()
    selected = _headers(headers, hints)
    _asset_hints(base, hints)
    if len(body) > max_bytes:
        hints.error("body_limit", truncated=True)
    sample = body[:max_bytes]
    content_type = next((value for key, value in selected if key == "content-type"), "")
    charset = re.search(r"charset\s*=\s*[\"']?([a-z0-9_-]{1,32})", content_type, re.I)
    encoding = _CHARSETS.get(charset.group(1).lower()) if charset else "utf-8"
    if encoding is None:
        hints.error("unsupported_charset")
        encoding = "utf-8"
    if encoding == "utf-8" and sample.startswith(b"\xef\xbb\xbf"):
        sample = sample[3:]
    try:
        text = sample.decode(encoding)
    except (UnicodeError, LookupError):
        hints.error("response_decode_error")
        text = sample.decode("utf-8", errors="replace")
    media = content_type.partition(";")[0].strip().lower()
    if media in {"text/html", "application/xhtml+xml"} or not media and re.match(
            r"\s*(?:<!doctype\s+html\b|<(?:html|head|body|form)\b)", text, re.I):
        parser = _HTMLHints(base, hints)
        try:
            parser.feed(text)
            parser.close()
        except _LimitReached:
            pass
        except Exception:
            hints.error("html_parse_error", truncated=True)
        parser.finish()
    elif "javascript" in media or "ecmascript" in media or urlsplit(base).path.lower().endswith((".js", ".mjs")):
        _script_hints(text, hints)
    return hints.result()
