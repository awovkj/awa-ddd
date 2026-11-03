"""Synthetic passive recon parsing: hints are not execution or scope approval."""
from __future__ import annotations

from copy import deepcopy
import json
import socket
import unittest
from unittest.mock import patch
import urllib.request

from awa_ddd import recon_parsing as recon


BASE = "https://site.example/app/index.html"


class ReconParsingTests(unittest.TestCase):
    def parse(self, body, headers=None, url=BASE, **kwargs):
        if isinstance(body, str):
            body = body.encode("utf-8")
        return recon.parse_response(url, headers if headers is not None else {"Content-Type": "text/html"}, body, **kwargs)

    def names(self, result):
        return {row["name"] for row in result["technologies"]}

    def test_header_hints_never_return_full_banners_cookie_values_or_authentication(self):
        secrets = ["SYNTHETIC-PRIVATE-BANNER", "SYNTHETIC-COOKIE-VALUE", "SYNTHETIC-AUTH-TOKEN"]
        result = self.parse(b"", {"Server": "nginx/1.24.0 " + secrets[0], "X-Powered-By": "PHP/8.2.13",
                                 "Set-Cookie": "PHPSESSID=" + secrets[1] + "; HttpOnly; Secure",
                                 "Authorization": "Bearer " + secrets[2]})
        self.assertEqual({"nginx", "PHP"}, self.names(result))
        self.assertEqual("1.24.0", next(row for row in result["technologies"] if row["name"] == "nginx")["version"])
        for secret in secrets:
            self.assertNotIn(secret, json.dumps(result))
        for row in result["technologies"]:
            self.assertEqual("hint", row["confidence"])
            self.assertTrue(row["signal"].startswith(("header:", "cookie-name:")))
        self.assertFalse(result["truncated"])

    def test_repeated_set_cookie_headers_extract_only_explicit_names(self):
        headers = [("set-cookie", name + "=PRIVATE; Path=/") for name in
                   ("JSESSIONID", "ASP.NET_SessionId", ".AspNetCore.Cookies", "laravel_session", "csrftoken",
                    "connect.sid", "wordpress_logged_in_deadbeef", "unknown_session")]
        result = self.parse(b"", headers)
        self.assertEqual({"Java Servlet", "ASP.NET", "ASP.NET Core", "Laravel", "Django", "Express", "WordPress"}, self.names(result))
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertNotIn("deadbeef", json.dumps(result))

    def test_explicit_html_and_asset_markers_are_only_forgeable_hints(self):
        result = self.parse('''<!doctype html><html><head>
          <meta name="generator" content="WordPress 6.6.2 PRIVATE-GENERATOR-TEXT">
          <meta name="generator" content="Drupal 10.3.0">
          <meta name="generator" content="Joomla! 4.2.0">
          <script id="__NEXT_DATA__" type="application/json">{}</script>
          <script id="__NUXT_DATA__" type="application/json">[]</script>
          <script src="/vendor/jquery-3.7.1.min.js"></script>
          <link href="/vendor/bootstrap-5.3.3.min.css" rel="stylesheet">
          </head><body><div data-reactroot data-v-app ng-version="18.2.1"></div></body></html>''')
        self.assertEqual({"WordPress", "Drupal", "Joomla", "Next.js", "Nuxt", "jQuery", "Bootstrap", "React", "Vue", "Angular"}, self.names(result))
        self.assertNotIn("PRIVATE-GENERATOR-TEXT", json.dumps(result))
        self.assertTrue(all(row["confidence"] == "hint" for row in result["technologies"]))
        versions = {(row["name"], row.get("version")) for row in result["technologies"]}
        self.assertIn(("jQuery", "3.7.1"), versions)
        self.assertIn(("Angular", "18.2.1"), versions)

    def test_body_and_anchor_prose_are_not_fingerprints_or_returned_content(self):
        result = self.parse('<html><body><p>React.createElement Vue.version jQuery Angular PRIVATE-BODY</p>'
                            '<a href="/products">PRIVATE-ANCHOR</a></body></html>')
        self.assertEqual([], result["technologies"])
        self.assertNotIn("PRIVATE-BODY", json.dumps(result))
        self.assertNotIn("PRIVATE-ANCHOR", json.dumps(result))

    def test_script_markers_are_scanned_without_executing_code_or_reading_files(self):
        source = b'__NUXT__={}; React.createElement("div"); eval("open(\'PRIVATE-PATH\')");'
        with patch.object(socket, "create_connection") as connect, patch.object(urllib.request, "urlopen") as fetch, \
                patch("builtins.open") as files, patch("builtins.eval") as evaluate, patch("builtins.exec") as execute:
            result = self.parse(source, {"Content-Type": "application/javascript"}, BASE + "/bundle.js")
            for action in (connect, fetch, files, evaluate, execute):
                action.assert_not_called()
        self.assertEqual({"Nuxt", "React"}, self.names(result))
        self.assertNotIn("PRIVATE-PATH", json.dumps(result))

    def test_json_script_payloads_and_external_script_fallback_text_are_not_executed_js_hints(self):
        result = self.parse('<script type="application/json">{"text":"React.createElement PRIVATE"}</script>'
                            '<script src="/ordinary.js">Vue.version</script>')
        self.assertEqual([], result["technologies"])
        inline = self.parse('<script type="module">React.createElement("div");</script>')
        self.assertIn("React", self.names(inline))

    def test_base_relative_links_external_urls_and_fragments(self):
        result = self.parse('<html><head><base href="/shop/"></head><body>'
                            '<a href="products?sort=price#PRIVATE-FRAGMENT">ignored</a>'
                            '<a href="#PRIVATE-ANCHOR">ignored</a>'
                            '<script src="//cdn.example/vue.global.prod.js"></script></body></html>')
        links = {row["url"]: row for row in result["clues"]}
        self.assertIn("https://site.example/shop/products?sort=price", links)
        self.assertFalse(links["https://site.example/shop/products?sort=price"]["external"])
        self.assertTrue(links["https://cdn.example/vue.global.prod.js"]["external"])
        self.assertIn("Vue", self.names(result))
        self.assertNotIn("PRIVATE-FRAGMENT", json.dumps(result))
        self.assertNotIn("PRIVATE-ANCHOR", json.dumps(result))

    def test_unsafe_schemes_userinfo_controls_and_backslashes_are_filtered(self):
        unsafe = ("javascript:alert(1)", "jav&#x61;script:alert(1)", "data:text/html,PRIVATE",
                  "file:///PRIVATE", "ftp://files.example/PRIVATE", "https://user:PRIVATE@host.example/",
                  "https://u%40host.example/", "https://host.example/&#10;PRIVATE", "https:\\host.example\\PRIVATE")
        html = "<html>" + "".join('<a href="' + value + '">ignored</a>' for value in unsafe)
        html += '<a href="/allowed">ignored</a></html>'
        result = self.parse(html)
        self.assertEqual(["https://site.example/allowed"], [row["url"] for row in result["clues"]])
        self.assertIn("unsafe_locator", result["parse_errors"])
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_forms_keep_named_fields_not_values_and_preserve_duplicate_ambiguity(self):
        result = self.parse('<form method="post" action="../submit"><input name="username" value="PRIVATE-USER">'
                            '<input type="password" name="password" value="PRIVATE-PASSWORD">'
                            '<textarea name="note">PRIVATE-TEXTAREA</textarea><select name="choice">'
                            '<option value="PRIVATE-OPTION">PRIVATE-LABEL</option></select>'
                            '<input name="choice" value="PRIVATE-DUPLICATE"><input name="disabled" disabled></form>')
        form = result["clues"][0]
        self.assertEqual("https://site.example/submit", form["url"])
        self.assertEqual("POST", form["method"])
        self.assertTrue(form["ambiguous"])
        self.assertEqual(["username", "password", "note", "choice", "choice"], [row["name"] for row in form["inputs"]])
        self.assertTrue(all(row["location"] == "body" and row["selector"] == row["name"] for row in form["inputs"]))
        self.assertNotIn("PRIVATE", json.dumps(result))
        default = self.parse('<form action="/search"><input name="q" value="PRIVATE"></form>')["clues"][0]
        self.assertEqual("GET", default["method"])
        self.assertEqual("query", default["inputs"][0]["location"])

    def test_duplicate_query_names_and_attributes_do_not_become_exact_bindings(self):
        result = self.parse('<a href="/search?q=one&q=two&p%61ge=3" href="/wrong">ignored</a>'
                            '<form action="/first" action="/wrong"><input name="x"></form>')
        link = next(row for row in result["clues"] if row["kind"] == "link")
        self.assertTrue(link["ambiguous"])
        self.assertEqual(["q", "q", "page"], [row["name"] for row in link["inputs"]])
        self.assertTrue(all(set(row) == {"name", "location", "selector"} for row in link["inputs"]))
        self.assertTrue(next(row for row in result["clues"] if row["kind"] == "form")["ambiguous"])
        self.assertFalse(any(row["url"].endswith("/wrong") for row in result["clues"]))

    def test_form_owner_association_is_offline_and_duplicate_ids_remain_ambiguous(self):
        result = self.parse('<input name="before" form="checkout"><form id="checkout" method="POST" action="/pay"></form>'
                            '<input name="after" form="checkout">')
        self.assertEqual(["before", "after"], [row["name"] for row in result["clues"][0]["inputs"]])
        duplicate = self.parse('<form id="same" action="/a"></form><form id="same" action="/b"></form>'
                               '<input name="not-exact" form="same">')
        self.assertIn("ambiguous_form_owner", duplicate["parse_errors"])
        self.assertTrue(all(row["ambiguous"] and not row["inputs"] for row in duplicate["clues"]))

    def test_missing_form_action_uses_document_not_external_base(self):
        result = self.parse('<base href="https://elsewhere.example/"><form><input name="q"></form>')
        self.assertEqual(BASE, result["clues"][0]["url"])
        self.assertFalse(result["clues"][0]["external"])
        unsupported = self.parse('<form method="dialog"><input name="q"></form>')["clues"][0]
        self.assertTrue(unsupported["ambiguous"])
        self.assertNotIn("method", unsupported)

    def test_submit_override_is_an_ambiguous_additional_locator_not_an_automatic_request(self):
        result = self.parse('<form action="/ordinary" method="POST"><input name="q">'
                            '<button formaction="https://other.example/submit" formmethod="GET">submit</button></form>')
        forms = [row for row in result["clues"] if row["kind"] == "form"]
        self.assertEqual(2, len(forms))
        self.assertTrue(all(row["ambiguous"] for row in forms))
        override = next(row for row in forms if row["external"])
        self.assertEqual("GET", override["method"])
        self.assertEqual("query", override["inputs"][0]["location"])

    def test_byte_header_node_and_depth_limits_are_explicit(self):
        result = self.parse(b"<html><form><input name='q'>" + b"x" * 50, max_bytes=30)
        self.assertTrue(result["truncated"])
        self.assertIn("body_limit", result["parse_errors"])
        with patch.object(recon, "MAX_HEADERS", 2):
            result = self.parse(b"", [("Server", "nginx"), ("X-Powered-By", "PHP"), ("Server", "Apache")])
            self.assertTrue(result["truncated"])
            self.assertIn("header_limit", result["parse_errors"])
        with patch.object(recon, "MAX_HTML_NODES", 4):
            result = self.parse("<html><body>" + "<div>x</div>" * 10 + "</body></html>")
            self.assertIn("html_node_limit", result["parse_errors"])
        with patch.object(recon, "MAX_HTML_DEPTH", 3):
            result = self.parse("<html><body><div><div><div></div></div></div></body></html>")
            self.assertTrue(result["truncated"])
            self.assertIn("html_depth_limit", result["parse_errors"])

    def test_clue_limit_prioritizes_forms_and_duplicate_links_do_not_consume_capacity(self):
        with patch.object(recon, "MAX_CLUES", 3):
            body = '<form action="/login"><input name="username"></form>'
            body += '<a href="/same">ignored</a>' * 10
            body += ''.join('<a href="/route-' + str(i) + '">ignored</a>' for i in range(4))
            result = self.parse(body)
            self.assertEqual(3, len(result["clues"]))
            self.assertTrue(result["truncated"])
            self.assertTrue(any(row["kind"] == "form" for row in result["clues"]))
            self.assertEqual(1, sum(row["url"].endswith("/same") for row in result["clues"]))
        with patch.object(recon, "MAX_FORM_INPUTS", 2):
            result = self.parse('<form><input name="a"><input name="b"><input name="c"></form>')
            self.assertTrue(result["truncated"])
            self.assertTrue(result["clues"][0]["ambiguous"])
            self.assertEqual(2, len(result["clues"][0]["inputs"]))

    def test_unknown_charset_is_not_a_codec_name_to_execute_and_bad_names_are_not_repaired(self):
        result = self.parse(b'<form><input name="bad\xffname"></form>', {"Content-Type": "text/html; charset=untrusted_codec"})
        self.assertIn("unsupported_charset", result["parse_errors"])
        self.assertIn("response_decode_error", result["parse_errors"])
        self.assertEqual([], result["clues"][0]["inputs"])
        latin = self.parse(b'<form><input name="caf\xe9"></form>', {"Content-Type": "text/html; charset=iso-8859-1"})
        self.assertEqual("caf\u00e9", latin["clues"][0]["inputs"][0]["name"])
        bom = self.parse(b'\xef\xbb\xbf<html><form><input name="q"></form></html>', {})
        self.assertEqual("q", bom["clues"][0]["inputs"][0]["name"])

    def test_external_xml_entities_and_malformed_html_never_resolve_sources(self):
        source = b'<!DOCTYPE html [<!ENTITY xxe SYSTEM "file:///PRIVATE-FILE">]><html><body>&xxe;</body></html>'
        with patch.object(urllib.request, "urlopen") as fetch, patch("builtins.open") as files:
            result = self.parse(source, {"Content-Type": "application/xhtml+xml"})
            fetch.assert_not_called()
            files.assert_not_called()
        self.assertNotIn("PRIVATE-FILE", json.dumps(result))
        malformed = self.parse(b'<![arbitrary invalid declaration PRIVATE]><form action="/x">')
        self.assertTrue(all("PRIVATE" not in code for code in malformed["parse_errors"]))

    def test_invalid_inputs_fail_with_constant_errors_and_calls_share_no_mutable_state(self):
        for maximum in (0, -1, True, recon.MAX_BODY_BYTES + 1):
            with self.subTest(maximum=maximum), self.assertRaises(ValueError):
                self.parse(b"", max_bytes=maximum)
        invalid = self.parse(b"", url="https://user:PRIVATE@site.example/")
        self.assertEqual(["invalid_response_url"], invalid["parse_errors"])
        self.assertNotIn("PRIVATE", json.dumps(invalid))
        self.assertIn("invalid_response_body", recon.parse_response(BASE, {}, "not bytes")["parse_errors"])
        self.assertIn("invalid_headers", self.parse(b"", [None, ("Server", 23)])["parse_errors"])
        headers = {"Server": "nginx/1.2.3", "Content-Type": "text/html"}
        before = deepcopy(headers)
        body = bytearray(b'<form><input name="q" value="PRIVATE"></form>')
        original = bytes(body)
        self.parse(body, headers)
        self.assertEqual(before, headers)
        self.assertEqual(original, bytes(body))
        self.assertEqual([], self.parse(b"", {})["technologies"])


if __name__ == "__main__":
    unittest.main()
