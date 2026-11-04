"""Offline report fixtures: actual capture lineage, safe templates, and Chinese delivery."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import shlex
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qsl, quote, urlencode

from awa_ddd import engine, workflow
from awa_ddd.assessment import evaluate, record_finding
from awa_ddd.reporting import build_report, safe_text
from awa_ddd.store import Project, now


def observed(url, method, headers, body, timeout, max_bytes, *, response=None, status=200):
    raw = json.dumps(response if response is not None else {"ok": True}, ensure_ascii=False).encode("utf-8")
    sent = body if isinstance(body, bytes) else body.encode("utf-8") if isinstance(body, str) else \
        json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else b""
    return {"request": {"url": url, "method": method, "headers": headers, "body_base64": base64.b64encode(sent).decode()},
            "response": {"status": status, "headers": [["content-type", "application/json"]], "length": len(raw),
                         "body_base64": base64.b64encode(raw).decode()},
            "started_at": now(), "completed_at": now(), "complete": True}


class ReportReproductionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="awa-report-repro-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.base = "http://fixture.invalid"
        engine.create_project(self.root, {"project_id": "repro", "target": self.base, "allow_mutation": True})
        self.project = Project(self.root, "repro")
        self.addCleanup(self.project.close)

    def operation(self, path="/public", **extra):
        return engine.register_operation(self.project, {"url": self.base + path, "method": "GET", "auth": "public", **extra})

    def capture(self, operation, response=None, status=200, **arguments):
        with patch.object(engine, "request", side_effect=lambda *args: observed(*args, response=response, status=status)):
            return engine.capture(self.project, {"operation_id": operation["id"], **arguments})

    def finding(self, ids, category="Information Disclosure", **extra):
        return record_finding(self.project, {"mode": "analyst", "title": "已复核测试发现", "category": category,
            "impact": "实际观察的隔离测试响应", "remediation": "限制访问并校验服务端输入", "reviewer": "fixture-reviewer",
            "reason": "人工复核真实捕获", "evidence_ids": ids, **extra})

    def report(self):
        result = build_report(self.project)
        folder = Path(result["report"]).parent
        summary = json.loads(Path(result["summary"]).read_text(encoding="utf-8"))
        text = Path(result["report"]).read_text(encoding="utf-8")
        return result, folder, summary, text

    def session(self, name="alice"):
        engine.add_actor(self.project, {"actor_id": name, "subject": name, "roles": []})
        identity = self.operation("/whoami", auth="authenticated")
        session = engine.add_session(self.project, {"actor_id": name,
            "headers": {"X-Principal": "PRIVATE-" + name + "-AUTH"}, "credential_header_names": ["X-Principal"]})
        with patch.object(engine, "request", side_effect=lambda *args: observed(*args, response={"subject": name, "roles": []})):
            engine.verify_identity(self.project, {"operation_id": identity["id"], "session_id": session["id"], "subject_selector": "/subject"})
        return self.project.get("session", session["id"])

    def write(self, path, body, content_type="application/json", response=None):
        session = self.session()
        operation = self.operation(path + "/{id}", method="POST", auth="authenticated")
        resource = engine.add_resource(self.project, {"operation_id": operation["id"], "owner_actor_id": "alice",
            "external_id": "fixture-1", "request_binding": {"location": "path", "selector": "id"}})
        return self.capture(operation, response=response, url=self.base + path + "/fixture-1", session_id=session["id"],
            resource_id=resource["id"], effect="test_resource_write", headers={"Content-Type": content_type}, body=body)

    def test_chinese_findings_precede_complete_gap_details_and_snapshot_is_offline(self):
        operation = self.operation()
        evidence = self.capture(operation, response={"ok": True, "items": [1, 2]})
        finding = self.finding([evidence["id"]])
        engine.build_plan(self.project)
        counts = {kind: len(self.project.list(kind)) for kind in ("run", "evidence", "decision", "obligation")}
        with patch.object(engine, "request") as network:
            result, folder, summary, text = self.report()
        network.assert_not_called()
        self.assertEqual(counts, {kind: len(self.project.list(kind)) for kind in counts})
        self.assertEqual(5, summary["format_version"])
        self.assertEqual("zh-CN", summary["language"])
        self.assertIn("中文渗透测试报告", text)
        self.assertLess(text.index("## 漏洞详情与人工复现"), text.index("### 完整未完成义务明细"))
        detail = summary["reproduction"][finding["id"]]
        self.assertTrue(detail["available"])
        self.assertFalse(detail["executed_by_report"])
        self.assertEqual(200, detail["steps"][0]["status_code"])
        self.assertIn('"ok": true', detail["steps"][0]["response_excerpt"])
        step = detail["steps"][0]
        request = (folder / step["request_file"]).read_bytes().decode("utf-8")
        self.assertEqual(request, step["http_request"])
        self.assertIn("```http\n" + request + "\n```", Path(result["report"]).read_bytes().decode("utf-8"))
        self.assertNotIn("curl.exe", text)
        self.assertNotIn("--http1.1", text)
        self.assertEqual(result["report_sha256"], hashlib.sha256(Path(result["report"]).read_bytes()).hexdigest())

    def test_get_packet_preserves_encoded_query_host_port_and_header_body_separator(self):
        self.base = "http://fixture.invalid:8081"
        engine.create_project(self.root, {"project_id": "http-packets", "target": self.base, "allow_mutation": True})
        self.project = Project(self.root, "http-packets")
        self.addCleanup(self.project.close)
        path = "/path%2Fsegment"
        query = "q=a%2Bb&duplicate=first&duplicate=second&empty="
        evidence = self.capture(self.operation(path), url=self.base + path + "?" + query)
        finding = self.finding([evidence["id"]])
        result, folder, summary, text = self.report()
        step = summary["reproduction"][finding["id"]]["steps"][0]
        expected = "GET " + path + "?" + query + " HTTP/1.1\r\nHost: fixture.invalid:8081\r\n\r\n"
        self.assertEqual(expected.encode("utf-8"), (folder / step["request_file"]).read_bytes())
        self.assertEqual(expected, step["http_request"])
        self.assertIn("```http\n" + expected + "\n```", Path(result["report"]).read_bytes().decode("utf-8"))
        self.assertNotIn("--request", text)

    def test_post_packet_contains_full_redacted_utf8_body_with_matching_content_length(self):
        payload = {"message": "中文正文", "description": "z" * 4600, "password": "PRIVATE-REPRO-PASSWORD"}
        evidence = self.write("/full-packet", payload)
        finding = self.finding([evidence["id"]])
        result, folder, summary, text = self.report()
        step = summary["reproduction"][finding["id"]]["steps"][0]
        raw = (folder / step["request_file"]).read_bytes()
        head, body = raw.split(b"\r\n\r\n", 1)
        length = next(line.split(b":", 1)[1].strip() for line in head.split(b"\r\n")
                      if line.lower().startswith(b"content-length:"))
        self.assertEqual(len(body), int(length))
        self.assertEqual(body, (folder / step["body_file"]).read_bytes())
        document = json.loads(body)
        self.assertEqual(payload["message"], document["message"])
        self.assertEqual(payload["description"], document["description"])
        self.assertTrue(document["password"].startswith("<AWA_"))
        self.assertNotIn(b"PRIVATE-alice-AUTH", raw)
        self.assertNotIn(b"PRIVATE-REPRO-PASSWORD", raw)
        self.assertIn(b"x-principal: <awa_", head.lower())
        self.assertTrue(step["request_body_truncated"])
        self.assertEqual(raw.decode("utf-8"), step["http_request"])
        self.assertIn("```http\n" + step["http_request"] + "\n```", Path(result["report"]).read_bytes().decode("utf-8"))
        self.assertNotIn("请求正文（摘录已截断", text)
        self.assertNotIn("--data-binary", text)

    def test_packet_body_markdown_fences_do_not_escape_http_code_block(self):
        body = "before\n```http\nGET /invented HTTP/1.1\n```\nafter"
        evidence = self.capture(self.operation("/markdown-packet"), body=body,
                                headers={"Content-Type": "text/plain"}, effect="read_only")
        finding = self.finding([evidence["id"]])
        result, folder, summary, _ = self.report()
        step = summary["reproduction"][finding["id"]]["steps"][0]
        request = (folder / step["request_file"]).read_bytes().decode("utf-8")
        self.assertEqual(body, request.split("\r\n\r\n", 1)[1])
        self.assertEqual(request, step["http_request"])
        self.assertIn("````http\n" + request + "\n````", Path(result["report"]).read_bytes().decode("utf-8"))

    def test_sql_contains_exact_parameter_control_requests_and_metadata_only_commands(self):
        operation = self.operation("/api/products", inputs=[{"name": "sort", "location": "query", "consumer": "sql_order_by"}])
        engine.build_plan(self.project)
        obligation = next(item for item in self.project.list("obligation") if item["kind"] == "input_test")
        values = ["price", "extractvalue(1,concat(0x7e,database(),0x7e))", "extractvalue(1,concat(0x7e,12345,0x7e))"]
        responses = [{"items": [{"name": "normal"}]}, {"error": "~shop_fixture~"}, {"error": "no database metadata"}]
        ids = [self.capture(operation, response=response, url=self.base + "/api/products?sort=" + quote(value, safe=""))["id"]
               for value, response in zip(values, responses)]
        decision = evaluate(self.project, {"obligation_id": obligation["id"], "evidence_ids": ids,
            "oracle": {"type": "error_channel", "metadata_type": "database", "expected_value": "shop_fixture",
                       "response_pattern": r"~(?P<value>[^~]+)~"}})
        finding = record_finding(self.project, {"decision_id": decision["id"], "title": "商品 sort 参数 SQL 注入",
            "category": "SQL Injection", "impact": "取回当前数据库名 shop_fixture", "remediation": "使用服务端排序白名单"})
        _, folder, summary, text = self.report()
        detail = summary["reproduction"][finding["id"]]
        self.assertEqual(3, len(detail["steps"]))
        self.assertIn("阴性", detail["steps"][2]["role"])
        sqlmap = detail["sqlmap"]
        self.assertTrue(sqlmap["available"])
        args = shlex.split(sqlmap["commands"]["posix"])
        self.assertEqual("sort", args[args.index("-p") + 1])
        self.assertEqual(detail["steps"][0]["request_file"], args[args.index("-r") + 1])
        for option in ("--level=1", "--risk=1", "--threads=1", "--technique=BEU", "--current-db", "--current-user"):
            self.assertIn(option, args)
        self.assertNotIn("--dump", args)
        self.assertIn("AWA_SQLMAP_PATH", text)
        self.assertIn("报告新执行", text)
        request = (folder / detail["steps"][1]["request_file"]).read_text(encoding="utf-8")
        self.assertIn(quote(values[1], safe=""), request)
        self.assertIn("shop_fixture", text)

    def test_machine_and_analyst_sql_reports_offer_both_readonly_checks_without_inventing_results(self):
        for metadata_type, expression, expected in (("database", "database()", "shop_fixture"),
                                                    ("current_user", "current_user()", "fixture_user@localhost")):
            with self.subTest(metadata_type=metadata_type):
                operation = self.operation("/sql-" + metadata_type,
                    inputs=[{"name": "sort", "location": "query", "consumer": "sql_order_by"}])
                engine.build_plan(self.project)
                obligation = next(item for item in self.project.list("obligation")
                                  if item["operation_id"] == operation["id"] and item["kind"] == "input_test")
                values = ["price", "extractvalue(1,concat(0x7e," + expression + ",0x7e))",
                          "extractvalue(1,concat(0x7e,12345,0x7e))"]
                responses = [{"items": ["normal"]}, {"error": "~" + expected + "~"}, {"error": "no metadata"}]
                ids = [self.capture(operation, response=response,
                                    url=operation["url"] + "?sort=" + quote(value, safe=""))["id"]
                       for value, response in zip(values, responses)]
                decision = evaluate(self.project, {"obligation_id": obligation["id"], "evidence_ids": ids,
                    "oracle": {"type": "error_channel", "metadata_type": metadata_type, "expected_value": expected,
                               "response_pattern": r"~(?P<value>[^~]+)~"}})
                machine = record_finding(self.project, {"decision_id": decision["id"], "title": "Typed SQL " + metadata_type,
                    "category": "SQL Injection", "impact": "实际取回 " + expected, "remediation": "参数化 SQL"})
                analyst = self.finding(ids, category="SQL Injection", proof_decision_id=decision["id"])
                with patch.object(engine, "request") as network:
                    _, folder, summary, text = self.report()
                network.assert_not_called()
                for finding in (machine, analyst):
                    detail = summary["reproduction"][finding["id"]]
                    sqlmap = detail["sqlmap"]
                    self.assertTrue(sqlmap["available"])
                    args = shlex.split(sqlmap["commands"]["posix"])
                    self.assertIn("--current-db", args)
                    self.assertIn("--current-user", args)
                    self.assertIn("--current-db", sqlmap["commands"]["powershell"])
                    self.assertIn("--current-user", sqlmap["commands"]["powershell"])
                    self.assertEqual("sort", args[args.index("-p") + 1])
                    self.assertEqual(ids[0], sqlmap["baseline_evidence_id"])
                    self.assertEqual(detail["steps"][0]["request_file"], args[args.index("-r") + 1])
                    self.assertTrue((folder / sqlmap["request_file"]).is_file())
                    self.assertEqual(metadata_type, sqlmap["metadata_type"])
                    self.assertEqual(expected, sqlmap["expected_recorded_metadata"])
                    proof = self.project.get("decision", finding["decision_id"])["proof"]
                    self.assertEqual(metadata_type, proof["metadata_type"])
                    self.assertEqual(expected, proof["recovered_value"])
                    self.assertTrue(sqlmap["manual_only"])
                    self.assertFalse(sqlmap["executed_by_report"])
                    self.assertFalse(any(arg.startswith(("--dump", "--tables", "--columns", "--os-", "--sql-shell"))
                                         for arg in args))
                    section = text.split("- 漏洞 / 判定：" + finding["id"], 1)[1].split("\n### ", 1)[0]
                    label = "当前数据库名" if metadata_type == "database" else "当前数据库用户"
                    other_label = "当前数据库用户" if metadata_type == "database" else "当前数据库名"
                    self.assertIn("- 原证据获取的" + label + "：", section)
                    self.assertNotIn("- 原证据获取的" + other_label + "：", section)
                self.assertIn("--current-db", text)
                self.assertIn("--current-user", text)

    def test_post_json_and_form_sql_reports_bind_readonly_commands_to_normal_packets(self):
        session = self.session()
        for kind, media, selector in (("json", "application/json", "/sort"),
                                      ("form", "application/x-www-form-urlencoded", "sort")):
            with self.subTest(kind=kind):
                operation = self.operation("/sql-post-" + kind + "/{id}", method="POST", auth="authenticated",
                    content_type=media, inputs=[{"name": "id", "location": "path", "consumer": "resource"},
                    {"name": "sort", "location": "body", "selector": selector, "consumer": "sql_order_by"}])
                resource = engine.add_resource(self.project, {"operation_id": operation["id"], "owner_actor_id": "alice",
                    "external_id": "fixture-1", "request_binding": {"location": "path", "selector": "id"}})
                engine.build_plan(self.project)
                obligation = next(item for item in self.project.list("obligation")
                                  if item["operation_id"] == operation["id"] and item["kind"] == "input_test"
                                  and item.get("input_selector") == selector)
                values = ["price", "extractvalue(1,concat(0x7e,database(),0x7e))",
                          "extractvalue(1,concat(0x7e,12345,0x7e))"]
                responses = [{"items": ["normal"]}, {"error": "~shop_fixture~"}, {"error": "no metadata"}]
                ids = []
                for value, response in zip(values, responses):
                    document = {"sort": value, "fixed": "unchanged"}
                    ids.append(self.capture(operation, response=response,
                        url=operation["url"].replace("{id}", "fixture-1"), session_id=session["id"],
                        resource_id=resource["id"], effect="test_resource_write", headers={"Content-Type": media},
                        body=document if kind == "json" else urlencode(document))["id"])
                decision = evaluate(self.project, {"obligation_id": obligation["id"], "evidence_ids": ids,
                    "oracle": {"type": "error_channel", "metadata_type": "database", "expected_value": "shop_fixture",
                               "response_pattern": r"~(?P<value>[^~]+)~"}})
                finding = record_finding(self.project, {"decision_id": decision["id"], "title": "POST " + kind + " SQL",
                    "category": "SQL Injection", "impact": "实际数据库元信息", "remediation": "参数化 SQL"})
                _, folder, summary, text = self.report()
                detail = summary["reproduction"][finding["id"]]
                sqlmap = detail["sqlmap"]
                self.assertTrue(sqlmap["available"])
                args = shlex.split(sqlmap["commands"]["posix"])
                self.assertIn("--current-db", args)
                self.assertIn("--current-user", args)
                self.assertEqual("sort", args[args.index("-p") + 1])
                self.assertEqual(selector, sqlmap["input_selector"])
                self.assertEqual("POST", sqlmap["request_method"])
                self.assertEqual(ids[0], sqlmap["baseline_evidence_id"])
                self.assertEqual(detail["steps"][0]["request_file"], args[args.index("-r") + 1])
                packet = (folder / sqlmap["request_file"]).read_bytes()
                self.assertEqual(packet.decode("utf-8"), detail["steps"][0]["http_request"])
                body = packet.split(b"\r\n\r\n", 1)[1]
                self.assertEqual("price", json.loads(body)["sort"] if kind == "json" else
                                 dict(parse_qsl(body.decode("utf-8")))["sort"])
                self.assertIn("--current-db", text)
                self.assertIn("--current-user", text)

    def test_sql_report_does_not_use_attack_packet_when_normal_packet_cannot_be_exported(self):
        from awa_ddd import reproduction

        operation = self.operation("/sql-missing-baseline",
            inputs=[{"name": "sort", "location": "query", "consumer": "sql_order_by"}])
        engine.build_plan(self.project)
        obligation = next(item for item in self.project.list("obligation") if item["kind"] == "input_test")
        values = ["price", "extractvalue(1,concat(0x7e,database(),0x7e))", "extractvalue(1,concat(0x7e,12345,0x7e))"]
        responses = [{"items": ["normal"]}, {"error": "~shop_fixture~"}, {"error": "no metadata"}]
        ids = [self.capture(operation, response=response, url=operation["url"] + "?sort=" + quote(value, safe=""))["id"]
               for value, response in zip(values, responses)]
        decision = evaluate(self.project, {"obligation_id": obligation["id"], "evidence_ids": ids,
            "oracle": {"type": "error_channel", "metadata_type": "database", "expected_value": "shop_fixture",
                       "response_pattern": r"~(?P<value>[^~]+)~"}})
        finding = record_finding(self.project, {"decision_id": decision["id"], "title": "SQL baseline export unavailable",
            "category": "SQL Injection", "impact": "实际数据库元信息", "remediation": "参数化 SQL"})
        original = reproduction._step
        def export(project, redactor, evidence, *args):
            if evidence["id"] == ids[0]:
                raise ValueError("The normal request cannot be exported")
            return original(project, redactor, evidence, *args)
        with patch.object(reproduction, "_step", side_effect=export):
            _, _, summary, _ = self.report()
        detail = summary["reproduction"][finding["id"]]
        self.assertEqual(ids[1:], [step["evidence_id"] for step in detail["steps"]])
        self.assertFalse(detail["sqlmap"]["available"])
        self.assertNotIn("commands", detail["sqlmap"])
        self.assertIn("正常 SQL 请求", detail["sqlmap"]["reason"])

    def test_write_side_sql_report_keeps_packets_and_explains_unavailable_readonly_command(self):
        session = self.session()
        operation = self.operation("/sql-delete/{id}", method="DELETE", auth="authenticated",
            inputs=[{"name": "id", "location": "path", "selector": "id", "consumer": "sql_where"}])
        ids = []
        for value, count in (("missing", 0), ("missing' OR 1=1--", 3)):
            resource = engine.add_resource(self.project, {"operation_id": operation["id"], "owner_actor_id": "alice",
                "external_id": value, "request_binding": {"location": "path", "selector": "id"}})
            ids.append(self.capture(operation, response={"deleted_count": count},
                url=operation["url"].replace("{id}", quote(value, safe="")), session_id=session["id"],
                resource_id=resource["id"], effect="test_resource_write")["id"])
        finding = self.finding(ids, category="SQL Injection", sql_evidence={"control_evidence_id": ids[0],
            "injection_evidence_id": ids[1], "input_location": "path", "input_selector": "id",
            "response_selector": "/deleted_count", "observed_change": "测试删除条数从 0 变为 3"})
        result, folder, summary, text = self.report()
        detail = summary["reproduction"][finding["id"]]
        self.assertTrue(detail["available"])
        self.assertFalse(detail["sqlmap"]["available"])
        self.assertNotIn("commands", detail["sqlmap"])
        self.assertIn("状态写", detail["sqlmap"]["reason"])
        self.assertIn(detail["sqlmap"]["reason"], text)
        self.assertEqual(ids, [step["evidence_id"] for step in detail["steps"]])
        for step in detail["steps"]:
            packet = (folder / step["request_file"]).read_bytes().decode("utf-8")
            self.assertEqual(packet, step["http_request"])
            self.assertIn("```http\n" + packet + "\n```", Path(result["report"]).read_bytes().decode("utf-8"))

    def test_secrets_in_structures_custom_headers_actuator_and_free_text_never_export(self):
        token = "b4f34f4efe1d5414c9a01d36938d7fa9"
        evidence = self.write("/refund", {"amount": 999, "auth_token": token, "password": "PRIVATE-LOGIN-PASSWORD"}, response={
            "amount": 999, "phone": "13900002002", "content": "支付密码 393986；验证码 483729",
            "auth_token": token, "name": "shop.payment.secret", "value": "PRIVATE-PAYMENT-KEY",
            "propertySources": [{"properties": {"spring.datasource.password": {"value": "PRIVATE-DB-PASSWORD"}}}]})
        self.finding([evidence["id"]], impact="同一个令牌（" + token + "）两次成功；支付密码 393986；PRIVATE-PAYMENT-KEY")
        _, folder, summary, text = self.report()
        exported = b"\n".join(path.read_bytes() for path in folder.rglob("*") if path.is_file()).decode("utf-8")
        for secret in (token, "393986", "483729", "13900002002", "PRIVATE-alice-AUTH", "PRIVATE-LOGIN-PASSWORD",
                       "PRIVATE-PAYMENT-KEY", "PRIVATE-DB-PASSWORD"):
            self.assertNotIn(secret, exported)
        self.assertIn("<AWA_", exported)
        self.assertIn("必须替换", text)
        detail = next(iter(summary["reproduction"].values()))
        body = json.loads((folder / detail["steps"][0]["body_file"]).read_text(encoding="utf-8"))
        self.assertEqual(999, body["amount"])
        self.assertTrue(body["auth_token"].startswith("<AWA_"))
        self.assertIn("状态变更", text)

    def test_xml_keeps_captured_payload_bytes_and_body_file_command(self):
        xml = '<?xml version="1.0" encoding="UTF-8"?>\r\n<!DOCTYPE products [<!ENTITY x SYSTEM "file:///etc/hostname">]>\r\n<products><name>&x;</name></products>'
        evidence = self.write("/import", xml.encode("utf-8"), "application/xml", response={"name": "fixture-host"})
        finding = self.finding([evidence["id"]], category="XML External Entity (XXE)")
        result, folder, summary, _ = self.report()
        step = summary["reproduction"][finding["id"]]["steps"][0]
        self.assertEqual(xml.encode("utf-8"), (folder / step["body_file"]).read_bytes())
        self.assertFalse(step["body_redacted"])
        self.assertIn("--data-binary", step["curl"]["posix"])
        self.assertIn("file:///etc/hostname", step["request_body_excerpt"])
        request = (folder / step["request_file"]).read_bytes().decode("utf-8")
        self.assertEqual(xml, request.split("\r\n\r\n", 1)[1])
        self.assertEqual(request, step["http_request"])
        self.assertIn("```http\n" + request + "\n```", Path(result["report"]).read_bytes().decode("utf-8"))

    def test_bare_bearer_and_cookie_subtokens_in_prose_are_context_redacted(self):
        engine.add_actor(self.project, {"actor_id": "alice", "subject": "alice"})
        session = engine.add_session(self.project, {"actor_id": "alice", "headers": {
            "Authorization": "Bearer PRIVATE-BARE-AUTH-TOKEN", "Cookie": "sid=PRIVATE-BARE-COOKIE-TOKEN"}})
        identity = self.operation("/whoami", auth="authenticated")
        with patch.object(engine, "request", side_effect=lambda *args: observed(*args, response={"subject": "alice"})):
            engine.verify_identity(self.project, {"operation_id": identity["id"], "session_id": session["id"], "subject_selector": "/subject"})
        evidence = self.capture(self.operation(auth="authenticated"), session_id=session["id"])
        self.finding([evidence["id"]], impact="重复使用（PRIVATE-BARE-AUTH-TOKEN）或（PRIVATE-BARE-COOKIE-TOKEN）")
        _, folder, _, _ = self.report()
        exported = b"\n".join(path.read_bytes() for path in folder.rglob("*") if path.is_file()).decode("utf-8")
        self.assertNotIn("PRIVATE-BARE-AUTH-TOKEN", exported)
        self.assertNotIn("PRIVATE-BARE-COOKIE-TOKEN", exported)

    def test_multipart_secret_replacement_preserves_boundaries(self):
        multipart = ('--fixture-boundary\r\nContent-Disposition: form-data; name="password"\r\n\r\nPRIVATE-FORM-PASSWORD\r\n'
                     '--fixture-boundary\r\nContent-Disposition: form-data; name="amount"\r\n\r\n999\r\n--fixture-boundary--\r\n')
        evidence = self.write("/multipart", multipart.encode("utf-8"), "multipart/form-data; boundary=fixture-boundary")
        finding = self.finding([evidence["id"]])
        result, folder, summary, _ = self.report()
        step = summary["reproduction"][finding["id"]]["steps"][0]
        body = (folder / step["body_file"]).read_bytes()
        self.assertNotIn(b"PRIVATE-FORM-PASSWORD", body)
        self.assertEqual(3, body.count(b"--fixture-boundary"))
        self.assertIn(b"\r\n999\r\n", body)
        request = (folder / step["request_file"]).read_bytes().decode("utf-8")
        self.assertEqual(body.decode("utf-8"), request.split("\r\n\r\n", 1)[1])
        self.assertEqual(request, step["http_request"])
        self.assertIn("```http\n" + request + "\n```", Path(result["report"]).read_bytes().decode("utf-8"))

    def test_multiline_multipart_private_key_is_entirely_replaced(self):
        key = "-----BEGIN PRIVATE KEY-----\r\nPRIVATE-FIRST-KEY-LINE\r\nPRIVATE-SECOND-KEY-LINE\r\n-----END PRIVATE KEY-----"
        multipart = '--fixture-boundary\r\nContent-Disposition: form-data; name="private_key"\r\n\r\n' + key + '\r\n--fixture-boundary--\r\n'
        evidence = self.write("/key", multipart.encode(), "multipart/form-data; boundary=fixture-boundary")
        finding = self.finding([evidence["id"]], impact="材料中包含 PRIVATE-SECOND-KEY-LINE")
        _, folder, summary, _ = self.report()
        exported = b"\n".join(path.read_bytes() for path in folder.rglob("*") if path.is_file()).decode()
        self.assertNotIn("PRIVATE-FIRST-KEY-LINE", exported)
        self.assertNotIn("PRIVATE-SECOND-KEY-LINE", exported)
        body = (folder / summary["reproduction"][finding["id"]]["steps"][0]["body_file"]).read_bytes()
        self.assertEqual(2, body.count(b"--fixture-boundary"))
        self.assertNotIn(b"BEGIN PRIVATE KEY", body)

    def test_duplicate_json_secret_keys_and_nonfinite_json_fail_closed(self):
        for index, body in enumerate((b'{"signature":"PRIVATE-FIRST-SIGNATURE","signature":"<AWA_SIGNATURE_REPLACE>"}',
                                      b'{"sign":"PRIVATE-NAN-SIGN","amount":NaN}')):
            evidence = self.capture(self.operation("/ambiguous-" + str(index)), body=body,
                                    headers={"Content-Type": "application/json"}, effect="read_only")
            finding = self.finding([evidence["id"]], impact="原材料出现 PRIVATE-FIRST-SIGNATURE 与 PRIVATE-NAN-SIGN")
            _, folder, summary, _ = self.report()
            detail = summary["reproduction"][finding["id"]]
            self.assertFalse(detail["available"])
            self.assertNotIn("request_file", detail["steps"][0])
            for secret in ("PRIVATE-FIRST-SIGNATURE", "PRIVATE-NAN-SIGN"):
                if secret.encode() in body:
                    exported = b"\n".join(path.read_bytes() for path in folder.rglob("*") if path.is_file()).decode()
                    self.assertNotIn(secret, exported)

    def test_opaque_or_malformed_multipart_has_no_execution_template(self):
        from awa_ddd.store import EngineError
        bodies = [b'--fixture\r\nContent-Disposition: form-data; name="file"; filename="blob.bin"\r\nContent-Type: application/octet-stream\r\n\r\nPRIVATE-OPAQUE\r\n--fixture--\r\n',
                  b'--fixture\r\nContent-Disposition: form-data; name="password"\r\n\r\nPRIVATE-MALFORMED']
        for index, body in enumerate(bodies):
            operation = self.operation("/opaque-" + str(index))
            if index == 1:
                counts = {kind: len(self.project.list(kind)) for kind in ("run", "evidence")}
                with patch.object(engine, "request") as network, self.assertRaises(EngineError) as caught:
                    engine.capture(self.project, {"operation_id": operation["id"], "body": body,
                        "headers": {"Content-Type": "multipart/form-data; boundary=fixture"}, "effect": "read_only"})
                self.assertEqual("multipart_framing", caught.exception.code)
                network.assert_not_called()
                self.assertEqual(counts, {kind: len(self.project.list(kind)) for kind in counts})
                continue
            evidence = self.capture(operation, body=body,
                                    headers={"Content-Type": "multipart/form-data; boundary=fixture"}, effect="read_only")
            finding = self.finding([evidence["id"]])
            _, _, summary, _ = self.report()
            self.assertFalse(summary["reproduction"][finding["id"]]["available"])
            self.assertNotIn("request_file", summary["reproduction"][finding["id"]]["steps"][0])

    def test_final_secret_sweep_updates_body_http_content_length_and_commands(self):
        from awa_ddd import reproduction
        operation = self.operation("/late")
        ids = [self.capture(operation, body={"q": "PRIVATE-LATE-VALUE"}, headers={"Content-Type": "application/json", "X-Note": "PRIVATE-LATE-VALUE"})["id"]
               for _ in range(2)]
        finding = self.finding(ids)
        original = reproduction._response_observables
        calls = []
        def late(redactor, artifact, decision):
            calls.append(True)
            if len(calls) == 2:
                redactor.slot("PRIVATE-LATE-VALUE", "LATE_SECRET")
            return original(redactor, artifact, decision)
        with patch.object(reproduction, "_response_observables", side_effect=late):
            result, folder, summary, _ = self.report()
        step = summary["reproduction"][finding["id"]]["steps"][0]
        raw = (folder / step["request_file"]).read_bytes()
        head, body = raw.split(b"\r\n\r\n", 1)
        self.assertNotIn(b"PRIVATE-LATE-VALUE", raw)
        self.assertNotIn("PRIVATE-LATE-VALUE", step["curl"]["posix"])
        self.assertEqual(raw.decode("utf-8"), step["http_request"])
        self.assertIn("```http\n" + step["http_request"] + "\n```", Path(result["report"]).read_bytes().decode("utf-8"))
        length = next(line.split(b":", 1)[1].strip() for line in head.split(b"\r\n") if line.lower().startswith(b"content-length:"))
        self.assertEqual(len(body), int(length))
        self.assertEqual(body, (folder / step["body_file"]).read_bytes())

    def test_binary_request_is_explicitly_not_reproducible(self):
        operation = self.operation("/binary")
        evidence = self.capture(operation, body=b"\x00\xffPRIVATE-BINARY", effect="read_only")
        finding = self.finding([evidence["id"]])
        _, folder, summary, text = self.report()
        detail = summary["reproduction"][finding["id"]]
        self.assertFalse(detail["available"])
        self.assertNotIn("curl", detail["steps"][0])
        self.assertNotIn("http_request", detail["steps"][0])
        self.assertNotIn("request_file", detail["steps"][0])
        self.assertNotIn("```http", text)
        self.assertIn("二进制", text)
        self.assertNotIn("PRIVATE-BINARY", text)

    def test_response_excerpt_truncation_and_manifest_cover_every_export(self):
        evidence = self.capture(self.operation(), response={"observations": "z" * 5000})
        finding = self.finding([evidence["id"]])
        result, folder, summary, text = self.report()
        step = summary["reproduction"][finding["id"]]["steps"][0]
        self.assertTrue(step["response_truncated"])
        self.assertIn("已截断", text)
        manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
        listed = {item["path"] for item in manifest["files"]}
        self.assertEqual({path.relative_to(folder).as_posix() for path in folder.rglob("*") if path.is_file()} - {"manifest.json"}, listed)
        for entry in manifest["files"]:
            data = (folder / entry["path"]).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), entry["sha256"])
            self.assertEqual(len(data), entry["size_bytes"])

    def test_failed_atomic_publish_preserves_previous_snapshot_and_cleans_only_staging(self):
        evidence = self.capture(self.operation())
        self.finding([evidence["id"]])
        result, _, _, _ = self.report()
        original = Path(result["report"]).read_bytes()
        with patch("awa_ddd.reporting.os.rename", side_effect=OSError("synthetic publish failure")):
            with self.assertRaises(OSError):
                build_report(self.project)
        self.assertEqual(original, Path(result["report"]).read_bytes())
        self.assertEqual([], list((self.project.base / "reports").glob(".report-*")))

    def test_internal_artifact_paths_cannot_escape_atomic_staging(self):
        from awa_ddd import reproduction
        original = reproduction.prepare_reproduction
        evidence = self.capture(self.operation())
        self.finding([evidence["id"]])
        def escaped(*args, **kwargs):
            prepared = original(*args, **kwargs)
            prepared["files"]["../escape.txt"] = b"must-not-write"
            return prepared
        with patch.object(reproduction, "prepare_reproduction", side_effect=escaped):
            with self.assertRaisesRegex(ValueError, "escaped staging|artifact.*ledger"):
                build_report(self.project)
        self.assertFalse((self.project.base / "reports" / "escape.txt").exists())
        self.assertEqual([], list((self.project.base / "reports").glob(".report-*")))

    def test_withdrawn_or_tampered_evidence_does_not_generate_current_commands(self):
        evidence = self.capture(self.operation())
        finding = self.finding([evidence["id"]])
        workflow.update_finding(self.project, {"finding_id": finding["id"], "status": "withdrawn", "reviewer": "reviewer", "reason": "重新复核推翻影响"})
        _, _, summary, text = self.report()
        self.assertEqual(0, summary["finding_groups"]["current"])
        self.assertNotIn(finding["id"], summary["reproduction"])
        self.assertIn("历史 / 当前不可验证", text)
        workflow.update_finding(self.project, {"finding_id": finding["id"], "status": "active", "reviewer": "reviewer", "reason": "恢复待复核记录"})
        (self.project.base / evidence["artifact_path"]).write_bytes(b"{}")
        _, _, summary, _ = self.report()
        self.assertEqual(0, summary["finding_groups"]["current"])
        self.assertEqual({}, summary["reproduction"])

    def test_shell_metacharacters_are_single_quoted_arguments_not_new_commands(self):
        operation = self.operation("/query")
        url = self.base + "/query?q=" + quote("中文 ' ; $(echo UNTRUSTED)", safe="")
        evidence = self.capture(operation, url=url, headers={"X-Note": "' ; $(echo UNTRUSTED)"})
        finding = self.finding([evidence["id"]])
        _, _, summary, _ = self.report()
        command = summary["reproduction"][finding["id"]]["steps"][0]["curl"]
        arguments = shlex.split(command["posix"])
        self.assertEqual(url, arguments[arguments.index("--url") + 1])
        self.assertEqual("x-note: ' ; $(echo UNTRUSTED)", arguments[arguments.index("--header") + 1])
        self.assertIn("'' ; $(echo UNTRUSTED)", command["powershell"])

    def test_chinese_secret_labels_are_redacted_without_project_context(self):
        for text in ("支付密码 393986", "验证码为483729", "数据库口令：PRIVATE-DB-PASSWORD", "您的验证码是：7845，10分钟内有效。",
                     "您的验证码为：483729，10分钟内有效。"):
            self.assertNotIn(text.split()[-1], safe_text(text))

    def test_four_digit_sms_operator_pairs_and_other_capture_context_are_redacted(self):
        source = self.capture(self.operation("/sms/context"), response={"sms_code": "7845"})
        evidence = self.capture(self.operation("/sms/list"), response={"content": "【天积商城】您的验证码是：9631，10分钟内有效。"})
        finding = self.finding([evidence["id"]], impact="旧材料中记录了（7845）这一值；验证码为：483729，需一次性失效。")
        _, folder, summary, text = self.report()
        exported = b"\n".join(path.read_bytes() for path in folder.rglob("*") if path.is_file()).decode()
        for secret in ("7845", "9631", "483729"):
            self.assertNotIn(secret, exported)
        steps = summary["reproduction"][finding["id"]]["steps"]
        self.assertEqual([evidence["id"]], [step["evidence_id"] for step in steps])
        self.assertNotIn(source["id"], [step["evidence_id"] for step in steps])

    def test_short_code_redaction_does_not_corrupt_unrelated_evidence_ids(self):
        from awa_ddd.reproduction import Redactor
        redactor = Redactor()
        placeholder = redactor.slot("7845", "SMS_CODE")
        self.assertEqual("E-abcd7845deadbeef", redactor.replace("E-abcd7845deadbeef"))
        self.assertEqual("您的验证码是：" + placeholder, redactor.replace("您的验证码是：7845"))
        self.assertEqual(placeholder, redactor.structured({"sms_code": "7845"})["sms_code"])

    def test_sms_1234_preserves_ids_digests_and_real_file_references(self):
        from awa_ddd.reproduction import Redactor
        self.capture(self.operation("/code/context"), response={"sms_code": "1234"})
        digest = "0" * 28 + "a1234b" + "0" * 30
        original_id = self.project.id
        with patch.object(self.project, "id", side_effect=lambda prefix: prefix + "-a1234b" + "0" * 26 if prefix in {"E", "F", "D"} else original_id(prefix)):
            evidence = self.capture(self.operation("/code/observation"), response={"content": "您的验证码是：1234，10分钟内有效", "digest": digest})
            finding = self.finding([evidence["id"]])
        _, folder, summary, _ = self.report()
        self.assertEqual(finding["id"], summary["coverage"]["findings"][0]["id"])
        step = summary["reproduction"][finding["id"]]["steps"][0]
        self.assertEqual(evidence["id"], step["evidence_id"])
        self.assertEqual(evidence["sha256"], step["source_sha256"])
        self.assertTrue((folder / step["request_file"]).is_file())
        self.assertNotIn(digest, step["response_excerpt"])
        self.assertNotIn("验证码是：1234", step["response_excerpt"])
        redactor = Redactor()
        redactor.slot("1234", "SMS_CODE")
        self.assertEqual(digest, redactor.replace(digest))

    def test_manual_sqlmap_fallback_requires_unique_scalar_and_supported_profile(self):
        from awa_ddd.reproduction import _manual_sql_parameter
        for body, expected in (({"filter": {"q": "normal"}}, "q"), ({"filter": {"q": "normal"}, "other": {"q": "constant"}}, None)):
            evidence = self.write("/sql/manual" + ("/unique" if expected else "/duplicate"), body)
            step = {"evidence_id": evidence["id"], "resource_id": evidence["resource_id"]}
            if expected:
                self.assertEqual(expected, _manual_sql_parameter(self.project, step, "body", "/filter/q"))
            else:
                with self.assertRaisesRegex(ValueError, "repeated JSON"):
                    _manual_sql_parameter(self.project, step, "body", "/filter/q")
            with self.assertRaises(ValueError):
                _manual_sql_parameter(self.project, step, "graphql", "/filter/q")
            with self.assertRaises(ValueError):
                _manual_sql_parameter(self.project, step, "header", "X-SQL")

    def test_redacted_actuator_prose_preserves_names_and_following_chinese_context(self):
        evidence = self.capture(self.operation("/actuator/env"), response={"properties": {
            "spring.datasource.password": {"value": "PRIVATE-DATABASE-PASSWORD"},
            "shop.payment.secret": {"value": "PRIVATE-PAYMENT-SECRET"}}})
        impact = "接口直接回显 spring.datasource.password=PRIVATE-DATABASE-PASSWORD，shop.payment.secret=PRIVATE-PAYMENT-SECRET；支付密钥可被匿名读取。后续接口映射也被暴露。"
        finding = self.finding([evidence["id"]], impact=impact)
        _, _, summary, text = self.report()
        value = next(item for item in summary["coverage"]["findings"] if item["id"] == finding["id"])["impact"]
        for expected in ("spring.datasource.password=", "shop.payment.secret=", "支付密钥可被匿名读取", "后续接口映射也被暴露"):
            self.assertIn(expected, value)
            self.assertIn(expected, text)
        self.assertNotIn("PRIVATE-DATABASE-PASSWORD", value)
        self.assertNotIn("PRIVATE-PAYMENT-SECRET", value)


if __name__ == "__main__":
    unittest.main()
