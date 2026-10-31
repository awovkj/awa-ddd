"""Offline ownership and pre-dispatch cancellation regressions for the WSL guardian."""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

from awa_ddd import runtime, wsl_runner
from awa_ddd.store import EngineError


class ControlLineTests(unittest.TestCase):
    def test_first_request_keeps_pre_read_cancel_bytes(self):
        raw = json.dumps({"action": "project.list", "args": {"label": "\u4e2d\u6587"}}, ensure_ascii=False).encode("utf-8") + b"\n"
        with patch.object(wsl_runner.os, "read", side_effect=[raw + b"CANCEL\n", b""]) as read:
            stream = wsl_runner.ControlLines(1234)
            self.assertEqual(stream.readline(4096), raw)
            self.assertEqual(bytes(stream.pending), b"CANCEL\n")
            self.assertEqual(stream.readline(65), b"CANCEL\n")
        self.assertEqual(read.call_count, 1)

    def test_fragmented_cancel_is_reassembled_without_buffered_io(self):
        with patch.object(wsl_runner.os, "read", side_effect=[b"CA", b"NC", b"EL\n"]) as read:
            self.assertEqual(wsl_runner.ControlLines(1234).readline(65), b"CANCEL\n")
        self.assertTrue(all(item.args[0] == 1234 for item in read.call_args_list))

    def test_read_budget_and_partial_eof_do_not_drop_bytes(self):
        with patch.object(wsl_runner.os, "read", side_effect=[b"x" * 65, b"tail", b""]):
            stream = wsl_runner.ControlLines(1234)
            self.assertEqual(stream.readline(65), b"x" * 65)
            self.assertEqual(stream.readline(65), b"tail")


class OwnedGroupTerminationTests(unittest.TestCase):
    def setUp(self):
        self.killpg = Mock()
        self.os_patch = patch.object(wsl_runner, "os", SimpleNamespace(killpg=self.killpg))
        self.signal_patch = patch.object(wsl_runner, "signal", SimpleNamespace(SIGTERM=15, SIGKILL=9))
        self.os_patch.start()
        self.signal_patch.start()
        self.addCleanup(self.signal_patch.stop)
        self.addCleanup(self.os_patch.stop)
        self.process = SimpleNamespace(pid=424242, wait=Mock(return_value=0))

    def test_term_and_kill_always_address_only_the_owned_group(self):
        wsl_runner._terminate(self.process)
        self.assertEqual(self.killpg.call_args_list, [call(424242, 15), call(424242, 9)])
        self.assertTrue(all(item.kwargs["timeout"] <= 0.3 for item in self.process.wait.call_args_list))

    def test_child_tools_are_killed_even_if_the_engine_parent_already_exited(self):
        self.process.wait.return_value = 0
        wsl_runner._terminate(self.process)
        self.assertEqual(self.killpg.call_args_list[-1], call(424242, 9))

    def test_term_grace_expiry_still_escalates_to_group_kill(self):
        self.process.wait.side_effect = [subprocess.TimeoutExpired("owned engine", 0.3), 0]
        wsl_runner._terminate(self.process)
        self.assertEqual(self.killpg.call_args_list, [call(424242, 15), call(424242, 9)])

    def test_already_gone_group_is_an_idempotent_cleanup(self):
        self.killpg.side_effect = ProcessLookupError()
        wsl_runner._terminate(self.process)
        self.assertEqual(self.killpg.call_count, 2)

    def test_failed_acknowledgment_is_not_reported_as_success(self):
        self.process.wait.side_effect = subprocess.TimeoutExpired("owned engine", 0.3)
        with self.assertRaises(EngineError) as error:
            wsl_runner._terminate(self.process)
        self.assertEqual(error.exception.code, "wsl_cleanup")


class ImmediateThread:
    """Run the supplied prequeued control frame deterministically without an OS thread."""
    def __init__(self, *, target, **_):
        self.target = target

    def start(self):
        self.target()

    def join(self, timeout=None):
        pass

    def is_alive(self):
        return False


class FakePosix:
    name = "posix"
    environ = {"FIXTURE": "no credentials"}
    killpg = Mock()

    def __getattr__(self, name):
        return getattr(os, name)


class GuardianPreDispatchTests(unittest.TestCase):
    def setUp(self):
        self.os_patch = patch.object(wsl_runner, "os", FakePosix())
        self.signal_patch = patch.object(wsl_runner.signal, "signal", return_value=None)
        self.os_patch.start()
        self.signal_patch.start()
        self.addCleanup(self.signal_patch.stop)
        self.addCleanup(self.os_patch.stop)
        self.request = {"action": "project.status", "args": {"project_id": "fixture"}}

    def test_prequeued_cancel_does_not_spawn_or_translate_any_action(self):
        with patch.object(wsl_runner.threading, "Thread", ImmediateThread), \
                patch.object(wsl_runner.subprocess, "Popen") as spawn, \
                patch.object(wsl_runner, "_terminate"), \
                patch.object(runtime, "translate_path", side_effect=lambda value: value) as path, \
                patch.object(runtime, "translate_request_paths", side_effect=lambda action, args: args) as paths:
            result = wsl_runner.supervise(self.request, "/tmp/owned-fixture", 15000, control=io.BytesIO(b"CANCEL\n"))
        self.assertEqual(result, 130)
        spawn.assert_not_called()
        path.assert_not_called()
        paths.assert_not_called()

    def test_prequeued_eof_does_not_dispatch_an_action(self):
        with patch.object(wsl_runner.threading, "Thread", ImmediateThread), \
                patch.object(wsl_runner.subprocess, "Popen") as spawn, \
                patch.object(wsl_runner, "_terminate"), \
                patch.object(runtime, "translate_path", side_effect=lambda value: value), \
                patch.object(runtime, "translate_request_paths", side_effect=lambda action, args: args):
            result = wsl_runner.supervise(self.request, "/tmp/owned-fixture", 15000, control=io.BytesIO())
        self.assertEqual(result, 130)
        spawn.assert_not_called()

    def test_prequeued_unknown_frame_is_not_a_command_channel(self):
        with patch.object(wsl_runner.threading, "Thread", ImmediateThread), \
                patch.object(wsl_runner.subprocess, "Popen") as spawn, \
                patch.object(wsl_runner, "_terminate"):
            result = wsl_runner.supervise(self.request, "/tmp/owned-fixture", 15000, control=io.BytesIO(b"RUN untrusted-command\n"))
        self.assertEqual(result, 130)
        spawn.assert_not_called()

    def test_already_pending_cancel_is_consumed_before_a_delayed_watcher(self):
        stream = wsl_runner.ControlLines(1234)
        stream.pending.extend(b"CANCEL\n")
        thread = Mock()
        thread.start.return_value = None
        with patch.object(wsl_runner.threading, "Thread", return_value=thread), \
                patch.object(wsl_runner.subprocess, "Popen") as spawn, \
                patch.object(wsl_runner, "_terminate"):
            result = wsl_runner.supervise(self.request, "/tmp/owned-fixture", 15000, control=stream)
        self.assertEqual(result, 130)
        spawn.assert_not_called()

    def test_invalid_deadlines_and_requests_never_spawn(self):
        for value in (999, 600001, True, "15000"):
            with self.subTest(deadline=value), patch.object(wsl_runner.subprocess, "Popen") as spawn, self.assertRaises(EngineError):
                wsl_runner.supervise(self.request, "/tmp/owned-fixture", value, control=io.BytesIO())
            spawn.assert_not_called()
        for value in ([], {"action": "project.status", "args": []}, {"action": 1, "args": {}}):
            with self.subTest(request=value), patch.object(wsl_runner.subprocess, "Popen") as spawn, self.assertRaises(EngineError):
                wsl_runner.supervise(value, "/tmp/owned-fixture", 15000, control=io.BytesIO())
            spawn.assert_not_called()

    def test_non_utf8_unicode_payload_does_not_leave_a_spawned_worker(self):
        stop = threading.Event()

        class OpenControl:
            def readline(self, limit):
                stop.wait(2)
                return b""

        with patch.object(wsl_runner.subprocess, "Popen") as spawn, patch.object(wsl_runner, "_terminate"):
            try:
                with self.assertRaises(UnicodeEncodeError):
                    wsl_runner.supervise({"action": "project.status", "args": {"project_id": "fixture", "value": "\ud800"}},
                                         "/tmp/owned-fixture", 15000, control=OpenControl())
            finally:
                stop.set()
        spawn.assert_not_called()


class WorkerProtocolTests(unittest.TestCase):
    def test_worker_uses_fixed_utf8_argv_and_preserves_payload_paths(self):
        body = {"path": r"D:\payload\not-a-filesystem-argument", "name": "\u4e2d\u6587\u4e3b\u4f53", "value": "$(not a command)"}
        request = {"action": "http.preflight", "args": {"project_id": "fixture", "body": body, "body_file": r"D:\body.json",
                                                          "url": "http://fixture.invalid/a"}}
        translated = {**request["args"], "body_file": "/mnt/d/body.json"}
        with patch.object(runtime, "translate_request_paths", return_value=translated), \
                patch.object(runtime, "translate_path", return_value="/mnt/d/owned-workspace"), \
                patch.object(wsl_runner.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
            result = wsl_runner.worker(request, r"D:\owned-workspace")
        self.assertEqual(result, 0)
        command = run.call_args.args[0]
        self.assertEqual(command, [sys.executable, "-E", "-s", "-X", "utf8", "-B", "-m", "awa_ddd", "--workspace", "/mnt/d/owned-workspace"])
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertNotIn("start_new_session", run.call_args.kwargs, "engine children stay in the worker's owned group")
        sent = json.loads(run.call_args.kwargs["input"].decode("utf-8"))
        self.assertEqual(sent["args"]["body"], body)
        self.assertEqual(sent["args"]["url"], "http://fixture.invalid/a")

    def test_main_rejects_invalid_utf8_without_console_fallback(self):
        output = io.BytesIO()
        fake_sys = SimpleNamespace(stdin=SimpleNamespace(fileno=lambda: 1234), stdout=SimpleNamespace(buffer=output))
        raw = b'{"action":"project.list","args":{"name":"\xff"}}\n'
        with patch.object(sys, "argv", ["wsl_runner", "--workspace", "/tmp/owned", "--deadline-ms", "15000"]), \
                patch.object(wsl_runner, "sys", fake_sys), patch.object(wsl_runner.os, "read", return_value=raw), \
                patch.object(wsl_runner, "supervise") as supervise, patch.object(wsl_runner, "worker") as worker:
            result = wsl_runner.main()
        self.assertEqual(result, 2)
        self.assertFalse(json.loads(output.getvalue().decode("utf-8"))["ok"])
        self.assertNotIn(b"\xff", output.getvalue())
        supervise.assert_not_called()
        worker.assert_not_called()

    def test_main_preserves_utf8_request_and_control_remainder(self):
        output = io.BytesIO()
        fake_sys = SimpleNamespace(stdin=SimpleNamespace(fileno=lambda: 1234), stdout=SimpleNamespace(buffer=output))
        request = {"action": "project.list", "args": {"label": "\u4e2d\u6587-\u7532"}}
        raw = json.dumps(request, ensure_ascii=False).encode("utf-8") + b"\nCANCEL\n"
        with patch.object(sys, "argv", ["wsl_runner", "--workspace", "/tmp/owned", "--deadline-ms", "15000"]), \
                patch.object(wsl_runner, "sys", fake_sys), patch.object(wsl_runner.os, "read", return_value=raw), \
                patch.object(wsl_runner, "supervise", return_value=130) as supervise:
            result = wsl_runner.main()
        self.assertEqual(result, 130)
        self.assertEqual(supervise.call_args.args[0], request)
        self.assertEqual(bytes(supervise.call_args.kwargs["control"].pending), b"CANCEL\n")


class BackpressureTests(unittest.TestCase):
    def exercise(self, cancel):
        entered, released, terminated = threading.Event(), threading.Event(), threading.Event()
        cancellation = threading.Event()
        result = {}

        class Input:
            def write(self, data):
                entered.set()
                released.wait(5)
                if terminated.is_set():
                    raise BrokenPipeError("the mock owned worker has stopped")
                return len(data)

            def close(self):
                pass

        class Control:
            def readline(self, limit):
                cancellation.wait(5)
                return b"CANCEL\n"

        process = SimpleNamespace(pid=424242, returncode=None, stdin=Input())
        process.poll = lambda: process.returncode

        def terminate(_):
            process.returncode = -9
            terminated.set()
            released.set()

        def run_guardian():
            try:
                result["code"] = wsl_runner.supervise(
                    {"action": "project.status", "args": {"project_id": "fixture", "padding": "x" * 70000}},
                    "/tmp/owned-fixture", 15000 if cancel else 1000, control=Control())
            except BaseException as exc:
                result["error"] = type(exc).__name__

        with patch.object(wsl_runner, "os", FakePosix()), \
                patch.object(wsl_runner.subprocess, "Popen", return_value=process), \
                patch.object(wsl_runner, "_terminate", side_effect=terminate):
            guardian = threading.Thread(target=run_guardian, daemon=True)
            guardian.start()
            try:
                self.assertTrue(entered.wait(2), "the request writer reaches simulated pipe backpressure")
                if cancel:
                    cancellation.set()
                acknowledged = terminated.wait(0.6 if cancel else 1.6)
            finally:
                released.set()
                guardian.join(2)
                cancellation.set()
                if guardian.is_alive():
                    process.returncode = -9
                    guardian.join(2)
            self.assertFalse(guardian.is_alive(), "mock threads are joined before restoring the mocked process operations")
        self.assertTrue(acknowledged, "owned group cleanup must not wait for a blocked stdin write")
        self.assertNotIn("error", result)
        self.assertEqual(result["code"], 130 if cancel else 124)

    def test_cancel_can_terminate_while_worker_stdin_is_backpressured(self):
        self.exercise(True)

    def test_deadline_can_terminate_while_worker_stdin_is_backpressured(self):
        self.exercise(False)


if __name__ == "__main__":
    unittest.main()
