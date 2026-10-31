"""Purely offline console, WSL probe and filesystem-only translation regressions."""
from __future__ import annotations

import copy
import json
import os
import subprocess
import unittest
from unittest.mock import patch

from awa_ddd import runtime
from awa_ddd.store import EngineError


class ConsoleDecodingTests(unittest.TestCase):
    def test_utf16_bom_console_output(self):
        text = "  NAME            STATE           VERSION\r\n* kali-linux      Running         2\r\n"
        for encoding, bom in (("utf-16-le", b"\xff\xfe"), ("utf-16-be", b"\xfe\xff")):
            with self.subTest(encoding=encoding):
                decoded, observed = runtime.decode_console(bom + text.encode(encoding))
                self.assertEqual(decoded, text)
                self.assertEqual(observed, encoding)

    def test_utf16_without_bom_is_detected_from_nul_pattern(self):
        for encoding in ("utf-16-le", "utf-16-be"):
            with self.subTest(encoding=encoding):
                text = "kali-linux Running 2\r\n"
                self.assertEqual(runtime.decode_console(text.encode(encoding)), (text, encoding))

    def test_strict_utf8_preserves_unicode(self):
        text = "中文目录 /mnt/d/评估/原始正文.json"
        self.assertEqual(runtime.decode_console(text.encode("utf-8")), (text, "utf-8"))
        self.assertEqual(runtime.decode_console(b"\xef\xbb\xbf" + text.encode("utf-8")), (text, "utf-8-sig"))

    def test_gbk_console_is_reported_as_the_gb18030_decoder(self):
        text = "正在运行的发行版"
        self.assertEqual(runtime.decode_console(text.encode("gbk")), (text, "gb18030"))

    def test_invalid_or_nonbyte_input_is_not_replaced_silently(self):
        for value in (b"\xff", b"\xff\xfe\x41", "already a string"):
            with self.subTest(value=value), self.assertRaises(EngineError) as error:
                runtime.decode_console(value)
            self.assertEqual(error.exception.code, "runtime_encoding")


class RuntimeProbeTests(unittest.TestCase):
    def metadata(self):
        return {"python_version": "3.14.7", "python_executable": "/usr/bin/python3", "os": "Linux",
                "kernel": "microsoft-standard-WSL2", "encodings": {"stdin": "utf-8", "stdout": "utf-8", "stderr": "utf-8",
                "filesystem": "utf-8", "utf8_mode": 1}, "sqlmap_script": "/usr/share/sqlmap/sqlmap.py",
                "tools": {name: None if name in {"node", "yak"} else "/usr/bin/" + name for name in runtime._TOOLS}}

    def launcher(self):
        return patch.object(runtime.shutil, "which", return_value=r"C:\Windows\System32\wsl.exe")

    def windows(self):
        # Patch the runtime's launcher decision without replacing the host Path class.
        return patch.object(runtime, "_host_has_wsl_launcher", return_value=True)

    def results(self, python_output=None):
        listing = "  NAME            STATE           VERSION\r\n* kali-linux      Running         2\r\n"
        return [subprocess.CompletedProcess([], 0, listing.encode("utf-16-le"), b""),
                subprocess.CompletedProcess([], 0, python_output if python_output is not None else json.dumps(self.metadata()).encode("utf-8"), b"")]

    def test_native_probe_does_not_launch_any_process_or_change_environment(self):
        before = dict(os.environ)
        with patch.object(runtime.subprocess, "run") as process:
            result = runtime.probe({"backend": "native"})
        process.assert_not_called()
        self.assertEqual(dict(os.environ), before)
        self.assertTrue(result["native"]["available"])
        self.assertIn("stdout", result["native"]["encodings"])
        self.assertNotIn("wsl", result)
        self.assertFalse(result["target_traffic_sent"])

    def test_wsl_probe_is_a_fixed_utf8_metadata_command_and_catalog_only(self):
        with self.windows(), self.launcher(), patch.object(runtime.subprocess, "run", side_effect=self.results()) as process:
            result = runtime.probe({"backend": "wsl", "timeout": 10})
        self.assertEqual(process.call_count, 2)
        self.assertTrue(result["wsl"]["available"])
        self.assertEqual(result["wsl"]["observed_encoding"], "utf-8")
        self.assertEqual(result["wsl"]["distribution_list"]["observed_encoding"], "utf-16-le")
        self.assertEqual(result["wsl"]["distribution_list"]["distributions"][0]["name"], "kali-linux")
        self.assertEqual(result["configuration_hint"], {"executionBackend": "wsl", "wslDistribution": "kali-linux"})
        command = process.call_args_list[1].args[0]
        self.assertEqual(command[1:6], ["--distribution", "kali-linux", "--cd", str(runtime.PACKAGE_ROOT), "--exec"])
        self.assertEqual(command[6:12], ["python3", "-E", "-s", "-X", "utf8", "-c"])
        self.assertEqual(command[12], runtime._WSL_SCRIPT)
        self.assertTrue(runtime._WSL_SCRIPT.isascii())
        for call in process.call_args_list:
            self.assertFalse(call.kwargs["shell"])
            self.assertNotIn("env", call.kwargs)
        self.assertTrue(all(item["status"] == "catalog_only" and not item["target_traffic_sent"] for item in result["wsl"]["catalog"]))
        self.assertTrue(any("Node.js" in warning for warning in result["warnings"]))
        self.assertTrue(any("localhost" in warning for warning in result["warnings"]))
        self.assertTrue(any("SQLite" in warning for warning in result["warnings"]))

    def test_distribution_and_backend_parameter_injection_is_rejected(self):
        for value in ("--exec", "kali-linux;id", "kali-linux && curl example", "kali/linux", "kali\nlinux", "卡里", "x" * 65, {}):
            with self.subTest(distribution=value), patch.object(runtime.subprocess, "run") as process, self.assertRaises(EngineError):
                runtime.probe({"distribution": value})
            process.assert_not_called()
        for value in ("shell", {}, None):
            with self.subTest(backend=value), self.assertRaises(EngineError):
                runtime.probe({"backend": value})

    def test_timeout_validation_is_bounded(self):
        for value in (0, 31, True, "5", float("nan"), float("inf")):
            with self.subTest(timeout=value), self.assertRaises(EngineError):
                runtime.probe({"timeout": value})

    def test_missing_wsl_is_a_reported_unavailability_not_a_crash(self):
        with patch.object(runtime, "_host_has_wsl_launcher", return_value=False), patch.object(runtime.subprocess, "run") as process:
            result = runtime.probe({})
        process.assert_not_called()
        self.assertTrue(result["native"]["available"])
        self.assertFalse(result["wsl"]["available"])
        self.assertEqual(result["wsl"]["reason_code"], "wsl_unavailable")

    def test_python_json_does_not_use_console_gbk_fallback(self):
        data = self.metadata()
        data["python_executable"] = "/中文/python3"
        with self.windows(), self.launcher(), patch.object(runtime.subprocess, "run", side_effect=self.results(json.dumps(data, ensure_ascii=False).encode("gbk"))):
            result = runtime.probe({"backend": "wsl"})
        self.assertFalse(result["wsl"]["available"])
        self.assertEqual(result["wsl"]["reason_code"], "runtime_encoding")

    def test_unicode_utf8_json_metadata_is_preserved(self):
        data = self.metadata()
        data["python_executable"] = "/中文/python3"
        with self.windows(), self.launcher(), patch.object(runtime.subprocess, "run", side_effect=self.results(json.dumps(data, ensure_ascii=False).encode("utf-8"))):
            result = runtime.probe({"backend": "wsl"})
        self.assertEqual(result["wsl"]["metadata"]["python_executable"], "/中文/python3")

    def test_non_json_or_wrong_shape_metadata_is_rejected(self):
        for value, code in ((b"Python 3.14.7", "runtime_encoding"), (b"[]", "runtime_protocol")):
            with self.subTest(value=value), self.windows(), self.launcher(), patch.object(runtime.subprocess, "run", side_effect=self.results(value)):
                result = runtime.probe({"backend": "wsl"})
            self.assertEqual(result["wsl"]["reason_code"], code)

    def test_probe_budget_and_timeout_are_reported(self):
        for effect, code in (([subprocess.CompletedProcess([], 0, b"x" * (runtime.MAX_CONSOLE_BYTES + 1), b"")], "runtime_output_budget"),
                             (subprocess.TimeoutExpired("wsl.exe", 2), "runtime_timeout")):
            with self.subTest(code=code), self.windows(), self.launcher(), patch.object(runtime.subprocess, "run", side_effect=effect):
                result = runtime.probe({"backend": "wsl", "timeout": 2})
            self.assertEqual(result["wsl"]["reason_code"], code)

    def test_console_error_decoding_reports_the_used_encoding(self):
        failure = subprocess.CompletedProcess([], 1, b"", "无法读取发行版".encode("gbk"))
        with self.windows(), self.launcher(), patch.object(runtime.subprocess, "run", return_value=failure):
            result = runtime.probe({"backend": "wsl"})
        self.assertEqual(result["wsl"]["stderr_encoding"], "gb18030")
        self.assertEqual(result["wsl"]["reason_code"], "wsl_list_failed")


class PathTranslationTests(unittest.TestCase):
    def test_non_wsl_and_non_drive_paths_are_unchanged(self):
        values = (r"D:\评估\body.json", "/mnt/d/body.json", r"D:relative.json", r"\\server\share\body.json", "https://example/path")
        with patch.object(runtime, "_is_wsl", return_value=False), patch.object(runtime.subprocess, "run") as process:
            for value in values:
                self.assertEqual(runtime.translate_path(value), value)
        process.assert_not_called()
        with patch.object(runtime, "_is_wsl", return_value=True), patch.object(runtime.subprocess, "run") as process:
            for value in values[1:]:
                self.assertEqual(runtime.translate_path(value), value)
        process.assert_not_called()

    def test_windows_unicode_drive_path_uses_fixed_argv_without_a_shell(self):
        value = r"D:\评估\payload; echo not-a-command.json"
        completed = subprocess.CompletedProcess([], 0, "/mnt/d/评估/payload; echo not-a-command.json\n".encode("utf-8"), b"")
        with patch.object(runtime, "_is_wsl", return_value=True), patch.object(runtime.subprocess, "run", return_value=completed) as process:
            translated = runtime.translate_path(value)
        self.assertEqual(translated, "/mnt/d/评估/payload; echo not-a-command.json")
        self.assertEqual(process.call_args.args[0], ["wslpath", "-a", "-u", value])
        self.assertEqual(process.call_args.kwargs["timeout"], 5)
        self.assertFalse(process.call_args.kwargs["shell"])

    def test_control_characters_are_rejected_on_every_backend(self):
        for value in ("D:\\body\n.json", "D:\\body\x00.json", "/tmp/body\x85.json", "D:\\body\t.json"):
            with self.subTest(value=value), patch.object(runtime.subprocess, "run") as process, self.assertRaises(EngineError):
                runtime.translate_path(value)
            process.assert_not_called()

    def test_translation_failure_never_returns_the_original_path_silently(self):
        for completed in (subprocess.CompletedProcess([], 1, b"", b"failed"),
                          subprocess.CompletedProcess([], 0, b"\xff", b""),
                          subprocess.CompletedProcess([], 0, b"relative/path\n", b""),
                          subprocess.CompletedProcess([], 0, b"/mnt/d/a\n/mnt/d/b\n", b"")):
            with self.subTest(completed=completed), patch.object(runtime, "_is_wsl", return_value=True), \
                    patch.object(runtime.subprocess, "run", return_value=completed), self.assertRaises(EngineError):
                runtime.translate_path(r"D:\body.json")

    def test_only_whitelisted_filesystem_fields_are_translated(self):
        windows_path = r"D:\原始正文\body.json"
        for action, fields in runtime._PATH_FIELDS.items():
            args = {field: windows_path for field in fields}
            args.update(url="http://localhost/api", scope=["http://localhost/"], body={"path": windows_path},
                        input={"path": windows_path}, state={"path": windows_path}, payload=windows_path)
            original = copy.deepcopy(args)
            with self.subTest(action=action), patch.object(runtime, "translate_path", return_value="/mnt/d/body.json") as translator:
                result = runtime.translate_request_paths(action, args)
            self.assertEqual(translator.call_count, len(fields))
            for field in fields:
                self.assertEqual(result[field], "/mnt/d/body.json")
            for field in ("url", "scope", "body", "input", "state", "payload"):
                self.assertEqual(result[field], original[field])
            self.assertEqual(args, original)

    def test_scenario_body_files_are_translated_without_touching_step_payloads(self):
        windows_path = r"D:\body.json"
        args = {"scenario": {"steps": [{"id": "write", "body_file": windows_path, "url": "http://localhost/api",
                                        "body": {"path": windows_path}, "extract": {"path": windows_path}},
                                       {"id": "read", "body": windows_path}]}}
        original = copy.deepcopy(args)
        with patch.object(runtime, "translate_path", return_value="/mnt/d/body.json") as translator:
            result = runtime.translate_request_paths("scenario.run", args)
        self.assertEqual(translator.call_count, 1)
        self.assertEqual(result["scenario"]["steps"][0]["body_file"], "/mnt/d/body.json")
        self.assertEqual(result["scenario"]["steps"][0]["body"], original["scenario"]["steps"][0]["body"])
        self.assertEqual(result["scenario"]["steps"][0]["extract"], original["scenario"]["steps"][0]["extract"])
        self.assertEqual(result["scenario"]["steps"][1]["body"], windows_path)
        self.assertEqual(args, original)

    def test_unknown_actions_have_no_recursive_path_rewriting(self):
        args = {"path": r"D:\body.json", "operation": {"path": r"D:\body.json"}}
        with patch.object(runtime, "translate_path") as translator:
            result = runtime.translate_request_paths("surface.register", args)
        translator.assert_not_called()
        self.assertEqual(result, args)


if __name__ == "__main__":
    unittest.main()
