"""Verified executable templates retain their backend and never replay a target."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from awa_ddd import engine, external, runtime
from awa_ddd.__main__ import dispatch
from awa_ddd.store import EngineError
import test_external_20261029 as external_fixtures
import test_runtime_20261029 as runtime_fixtures


class SqlmapPathRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = external_fixtures.ExternalFixture()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.project = self.fixture.project

    def state(self):
        return {table: [tuple(row) for row in self.project.connection.execute("SELECT * FROM " + table + " ORDER BY 1,2")]
                for table in ("entities", "events", "metadata")}

    def test_windows_linux_path_error_is_private_and_precedes_run_claim(self):
        path = "/usr/share/PRIVATE-PATH-20261104/sqlmap.py"
        before = self.state()
        with patch.object(runtime, "_windows_paths", return_value=True), patch.object(runtime, "_is_wsl", return_value=False), \
                patch.object(runtime, "_tool_file_exists") as files, patch.object(external.subprocess, "Popen") as process, \
                patch.object(engine, "request") as network, self.assertRaises(EngineError) as caught:
            external.sqlmap_run(self.project, {**self.fixture.args, "sqlmap_path": path})
        files.assert_not_called()
        process.assert_not_called()
        network.assert_not_called()
        self.assertEqual(before, self.state())
        self.assertEqual("tool_path", caught.exception.code)
        self.assertEqual("backend_mismatch", caught.exception.details["reason_code"])
        self.assertEqual("native", caught.exception.details["execution_backend"])
        self.assertEqual({"backend": "all"}, caught.exception.details["input_template"])
        self.assertNotIn("PRIVATE-PATH-20261104", str(caught.exception) + json.dumps(caught.exception.details))

    def test_overescaped_unc_is_not_silently_repaired(self):
        malformed = r"\\\\wsl.localhost\\kali-linux\\usr\\share\\sqlmap\\sqlmap.py"
        with patch.object(runtime, "_windows_paths", return_value=True), patch.object(runtime, "_is_wsl", return_value=False), \
                patch.object(runtime, "_tool_file_exists") as files, self.assertRaises(EngineError) as caught:
            external._executable(malformed, "sqlmap_path")
        files.assert_not_called()
        self.assertEqual("overescaped_path", caught.exception.details["reason_code"])
        self.assertEqual("tool_path", caught.exception.code)
        self.assertNotIn(malformed, json.dumps(caught.exception.details))

    def test_correct_native_unc_is_checked_exactly_and_accepted(self):
        correct = r"\\wsl.localhost\kali-linux\usr\share\sqlmap\sqlmap.py"
        with patch.object(runtime, "_windows_paths", return_value=True), patch.object(runtime, "_is_wsl", return_value=False), \
                patch.object(runtime, "_tool_file_exists", return_value=True) as files, \
                patch.object(runtime, "_resolved_tool_filename", return_value="sqlmap.py"):
            reason = runtime.tool_path_reason(correct, "sqlmap_path")
        files.assert_called_once_with(correct)
        self.assertIsNone(reason)

    def test_public_recovery_preserves_typed_reason_and_omits_the_submitted_path(self):
        path = "/usr/share/PRIVATE-RECOVERY-20261104/sqlmap.py"
        with patch.object(runtime, "_windows_paths", return_value=True), patch.object(runtime, "_is_wsl", return_value=False), \
                patch.object(external.subprocess, "Popen") as process, self.assertRaises(EngineError) as caught:
            dispatch(self.project.workspace, "tool.sqlmap", {"project_id": self.project.project_id,
                     **self.fixture.args, "sqlmap_path": path})
        process.assert_not_called()
        self.assertEqual("tool_path", caught.exception.code)
        self.assertEqual("backend_mismatch", caught.exception.details["reason_code"])
        self.assertEqual("sqlmap_path", caught.exception.details["path_field"])
        self.assertEqual("native", caught.exception.details["execution_backend"])
        self.assertFalse(caught.exception.details["configured"])
        self.assertEqual("runtime.probe", caught.exception.details["next_action"])
        self.assertEqual({"backend": "all"}, caught.exception.details["input_template"])
        self.assertNotIn("PRIVATE-RECOVERY-20261104", str(caught.exception) + json.dumps(caught.exception.details))

    def test_resolved_filename_keeps_the_existing_adapter_guard(self):
        with patch.object(runtime, "_resolved_tool_filename", return_value="other-script.py"), self.assertRaises(EngineError) as caught:
            external._executable(str(self.fixture.executable), "sqlmap_path")
        self.assertEqual("wrong_filename", caught.exception.details["reason_code"])

    def test_unconfigured_and_missing_file_are_distinct_despite_a_local_installation(self):
        with patch.object(runtime, "_is_wsl", return_value=False), \
                patch.object(runtime, "_fixed_sqlmap_paths", return_value=(str(self.fixture.executable),)):
            discovered = runtime.probe({"backend": "native"})
            self.assertEqual(1, len(discovered["sqlmap_candidates"]))
            self.assertIsNone(self.project.get("tool_config", "sqlmap", required=False))
            before = self.state()
            with patch.object(external.subprocess, "Popen") as process, self.assertRaises(EngineError) as unconfigured:
                external.sqlmap_run(self.project, {key: value for key, value in self.fixture.args.items() if key != "sqlmap_path"})
            process.assert_not_called()
            self.assertEqual("not_configured", unconfigured.exception.details["reason_code"])
            self.assertFalse(unconfigured.exception.details["configured"])
            missing = str(Path(self.fixture.tmp.name) / "missing" / "sqlmap.py")
            with self.assertRaises(EngineError) as absent:
                external._executable(missing, "sqlmap_path")
            self.assertEqual("file_missing", absent.exception.details["reason_code"])
            self.assertEqual(before, self.state())

    def test_relative_wrong_filename_and_invalid_paths_have_bounded_reason_codes(self):
        cases = (("sqlmap.py", "not_absolute"), (str(Path(self.fixture.tmp.name) / "sqlmap.exe"), "wrong_filename"),
                 ({"path": "private"}, "invalid_path"), ("sqlmap.py\x00private", "invalid_path"),
                 (" sqlmap.py", "invalid_path"), ("x" * 4097, "invalid_path"))
        for value, reason in cases:
            with self.subTest(reason=reason), self.assertRaises(EngineError) as caught:
                external._executable(value, "sqlmap_path")
            self.assertEqual("tool_path", caught.exception.code)
            self.assertEqual(reason, caught.exception.details["reason_code"])
            self.assertEqual({"name": "tool.probe"}, caught.exception.details["help_input"])

    def test_native_runtime_template_can_be_probed_and_reused_with_the_fixed_profile(self):
        self.fixture.executable.write_text("print('1.10.8#path-recovery-fixture')\n", encoding="utf-8")
        original = deepcopy(self.fixture.args)
        before = self.state()
        with patch.object(runtime, "_is_wsl", return_value=False), \
                patch.object(runtime, "_fixed_sqlmap_paths", return_value=(str(self.fixture.executable),)):
            discovery = runtime.probe({"backend": "native"})
            self.assertEqual(before, self.state())
            candidate = discovery["sqlmap_candidates"][0]
            self.assertTrue(candidate["verified_absolute"] and candidate["verified_file"])
            self.assertTrue(Path(candidate["path"]).is_absolute() and Path(candidate["path"]).is_file())
            self.assertEqual("native", candidate["backend"])
            self.assertEqual({"executionBackend": "native"}, candidate["configuration_hint"])
            self.assertFalse(candidate["automatic_execution_allowed"])
            self.assertTrue(discovery["native"]["catalog"][0]["available"])
            with patch.object(engine, "request") as network:
                probed = external.probe(self.project, candidate["input_template"])
            network.assert_not_called()
            self.assertTrue(probed["available"])
            self.assertFalse(probed["target_traffic_sent"])
            configuration = deepcopy(self.project.get("tool_config", "sqlmap"))
            self.assertEqual("native", configuration["execution_backend"])
            reused = {key: value for key, value in self.fixture.args.items() if key != "sqlmap_path"}
            with patch.object(external.subprocess, "Popen", side_effect=self.fixture.fake_process("current database: 'audit_db'\n")) as process:
                result = external.sqlmap_run(self.project, reused)
            command = process.call_args.args[0]
            self.assertEqual(str(self.fixture.executable.resolve()), command[3])
            self.assertEqual(original["url"], command[command.index("-u") + 1])
            self.assertEqual("sort", command[command.index("-p") + 1])
            for option in ("--level=1", "--risk=1", "--threads=1", "--technique=BEU", "--ignore-proxy",
                           "--ignore-redirects", "--current-db", "--current-user"):
                self.assertIn(option, command)
            self.assertFalse(any(option.startswith(("--crawl", "--dump", "--sql-query", "--proxy", "--os-")) for option in command))
            self.assertEqual("BEU", result["profile"]["techniques"])
            self.assertEqual(configuration, self.project.get("tool_config", "sqlmap"))
            self.assertEqual(original, self.fixture.args)

    def test_probe_saved_for_another_backend_cannot_be_reused(self):
        self.project.put("tool_config", {"id": "sqlmap", "executable": str(self.fixture.executable), "execution_backend": "wsl"})
        before = self.state()
        args = {key: value for key, value in self.fixture.args.items() if key != "sqlmap_path"}
        with patch.object(runtime, "_is_wsl", return_value=False), patch.object(external.subprocess, "Popen") as process, \
                self.assertRaises(EngineError) as caught:
            external.sqlmap_run(self.project, args)
        process.assert_not_called()
        self.assertEqual("backend_mismatch", caught.exception.details["reason_code"])
        self.assertTrue(caught.exception.details["configured"])
        self.assertEqual(before, self.state())


class WslSqlmapCandidateTests(unittest.TestCase):
    def probe(self, metadata=None, readable=()):
        fixture = runtime_fixtures.RuntimeProbeTests()
        with fixture.windows(), fixture.launcher(), patch.object(runtime, "_windows_paths", return_value=True), \
                patch.object(runtime, "_is_wsl", return_value=False), patch.object(runtime, "_fixed_sqlmap_paths", return_value=()), \
                patch.object(runtime, "_tool_file_exists", side_effect=lambda value: value in readable) as files, \
                patch.object(runtime, "_resolved_tool_filename", return_value="sqlmap.py"), \
                patch.object(runtime.subprocess, "run", side_effect=fixture.results(
                    json.dumps(metadata).encode("utf-8") if metadata is not None else None)) as process:
            result = runtime.probe({"backend": "all"})
        self.assertEqual(2, process.call_count)
        return result, files

    def test_existing_wsl_script_produces_correct_verified_native_unc_templates(self):
        expected = {r"\\wsl.localhost\kali-linux\usr\share\sqlmap\sqlmap.py", r"\\wsl$\kali-linux\usr\share\sqlmap\sqlmap.py"}
        result, files = self.probe(readable=expected)
        native = [item for item in result["sqlmap_candidates"] if item["backend"] == "native"]
        wsl = [item for item in result["sqlmap_candidates"] if item["backend"] == "wsl"]
        self.assertEqual(expected, {item["path"] for item in native})
        self.assertEqual(expected, {call.args[0] for call in files.call_args_list})
        self.assertEqual(1, len(wsl))
        self.assertEqual(runtime._SQLMAP_SCRIPT, wsl[0]["path"])
        self.assertEqual({"executionBackend": "native"}, result["configuration_hint"])
        self.assertTrue(result["native"]["catalog"][0]["available"])
        for item in native:
            self.assertEqual({"adapter": "sqlmap", "sqlmap_path": item["path"]}, item["input_template"])
            self.assertTrue(item["verified_absolute"] and item["verified_file"])
            self.assertEqual(2, len(item["path"]) - len(item["path"].lstrip("\\")))
            self.assertNotIn("\\\\", item["path"][2:])
            self.assertEqual("wsl_unc", item["discovery_source"])
            self.assertFalse(item["automatic_execution_allowed"])
        self.assertTrue(wsl[0]["workspace_isolation_required"])

    def test_unreadable_unc_does_not_become_a_native_tool_input_or_switch_backend(self):
        result, _ = self.probe()
        self.assertEqual(["wsl"], [item["backend"] for item in result["sqlmap_candidates"]])
        self.assertFalse(result["native"]["catalog"][0]["available"])
        self.assertEqual({"executionBackend": "native"}, result["configuration_hint"])

    def test_absent_or_arbitrary_metadata_path_never_becomes_a_probe_template(self):
        fixture = runtime_fixtures.RuntimeProbeTests()
        for script in (None, "/tmp/unverified/sqlmap.py", "sqlmap.py"):
            with self.subTest(script=script):
                metadata = fixture.metadata()
                metadata["sqlmap_script"] = script
                result, files = self.probe(metadata)
                self.assertEqual([], result["sqlmap_candidates"])
                files.assert_not_called()

    def test_native_discovery_ignores_missing_fixed_files_and_directories(self):
        fixture = external_fixtures.ExternalFixture()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        directory = Path(fixture.tmp.name) / "directory" / "sqlmap.py"
        directory.mkdir(parents=True)
        missing = Path(fixture.tmp.name) / "missing" / "sqlmap.py"
        with patch.object(runtime, "_is_wsl", return_value=False), \
                patch.object(runtime, "_fixed_sqlmap_paths", return_value=(str(directory), str(missing))), \
                patch.object(runtime.subprocess, "run") as process:
            result = runtime.probe({"backend": "native"})
        process.assert_not_called()
        self.assertEqual([], result["sqlmap_candidates"])
        self.assertFalse(result["native"]["catalog"][0]["available"])


if __name__ == "__main__":
    unittest.main()
