"""UTF-8 WSL supervisor: one request, then a live cancellation control pipe.

The host keeps stdin open after the JSON line. EOF, CANCEL, or the local deadline
terminates only the Linux process group created for this invocation.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time

from .store import EngineError, canonical


MAX_REQUEST_BYTES = 1024 * 1024
TERMINATION_GRACE = 0.3


class ControlLines:
    """Unbuffered fd reads avoid daemon BufferedReader locks at Python shutdown."""
    def __init__(self, fd):
        self.fd = fd
        self.pending = bytearray()

    def readline(self, limit):
        while True:
            end = self.pending.find(b"\n")
            if end >= 0:
                count = min(end + 1, limit)
                line = bytes(self.pending[:count])
                del self.pending[:count]
                return line
            if len(self.pending) >= limit:
                line = bytes(self.pending[:limit])
                del self.pending[:limit]
                return line
            chunk = os.read(self.fd, min(4096, limit - len(self.pending)))
            if not chunk:
                line = bytes(self.pending)
                self.pending.clear()
                return line
            self.pending.extend(chunk)


def _terminate(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=TERMINATION_GRACE)
    except subprocess.TimeoutExpired:
        pass
    # A child tool can outlive its engine parent. Clean the owned group as well.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=TERMINATION_GRACE)
    except subprocess.TimeoutExpired:
        raise EngineError("wsl_cleanup", "The owned Linux engine did not acknowledge termination") from None


def supervise(request, workspace, deadline_ms, *, control=None):
    if os.name != "posix":
        raise EngineError("wsl_platform", "The WSL supervisor must run inside the selected Linux distribution")
    if type(deadline_ms) is not int or not 1000 <= deadline_ms <= 600000:
        raise EngineError("wsl_deadline", "WSL deadline must be 1000..600000 milliseconds")
    if not isinstance(request, dict) or not isinstance(request.get("action"), str) or not isinstance(request.get("args", {}), dict):
        raise EngineError("wsl_request", "WSL requires one JSON object with action and args")
    cancelled = threading.Event()
    deadline = time.monotonic() + deadline_ms / 1000
    for name in ("SIGTERM", "SIGHUP", "SIGINT"):
        if hasattr(signal, name) and threading.current_thread() is threading.main_thread():
            signal.signal(getattr(signal, name), lambda *_: cancelled.set())
    stream = control if control is not None else ControlLines(sys.stdin.fileno())
    listening = threading.Event()
    if isinstance(stream, ControlLines) and bytes(stream.pending).strip():
        # CANCEL may have arrived in the same fd read as the first JSON line.
        # Consume that pre-dispatch state synchronously, not at thread scheduling speed.
        return 130
    payload = (canonical(request) + "\n").encode("utf-8")
    if len(payload) > MAX_REQUEST_BYTES + 1:
        raise EngineError("wsl_input_budget", "WSL request exceeds the 1 MiB input budget")

    def watch_control():
        listening.set()
        try:
            while True:
                frame = stream.readline(65)
                # The protocol has no generic command channel. Unknown frames fail closed.
                if not frame or frame.strip():
                    cancelled.set()
                    return
        except (OSError, ValueError):
            cancelled.set()

    watcher = threading.Thread(target=watch_control, daemon=True, name="awa-wsl-control")
    watcher.start()
    listening.wait(0.05)
    if cancelled.is_set() or time.monotonic() >= deadline:
        return 130 if cancelled.is_set() else 124
    environment = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    # Even path-translation children belong to this owned group. The guardian
    # never blocks in wslpath while the host is trying to cancel the invocation.
    process = subprocess.Popen(
        [sys.executable, "-E", "-s", "-X", "utf8", "-B", "-m", "awa_ddd.wsl_runner", "--worker", "--workspace", workspace],
        stdin=subprocess.PIPE, stdout=sys.stdout.buffer, stderr=sys.stderr.buffer,
        start_new_session=True, shell=False, env=environment, bufsize=0)
    write_failed = threading.Event()

    def feed_request():
        try:
            remaining = memoryview(payload)
            while remaining:
                written = process.stdin.write(remaining)
                if not written:
                    raise OSError("The owned worker closed its request pipe")
                remaining = remaining[written:]
        except (OSError, ValueError):
            write_failed.set()
        finally:
            try:
                process.stdin.close()
            except (OSError, ValueError):
                pass

    writer = threading.Thread(target=feed_request, daemon=True, name="awa-wsl-request")
    try:
        if cancelled.is_set() or time.monotonic() >= deadline:
            _terminate(process)
            return 130 if cancelled.is_set() else 124
        writer.start()
        while process.poll() is None:
            if cancelled.is_set() or time.monotonic() >= deadline:
                _terminate(process)
                return 130 if cancelled.is_set() else 124
            if write_failed.is_set():
                _terminate(process)
                raise EngineError("wsl_io", "The owned Linux worker closed its bounded input pipe")
            time.sleep(0.02)
        exit_code = process.returncode
        _terminate(process)
        # A host closing its control pipe after completion cannot invalidate a
        # finished engine. Host-side cancellation still wins in the Node bridge.
        return exit_code
    finally:
        if process.poll() is None:
            _terminate(process)
        if writer.ident is not None:
            writer.join(timeout=TERMINATION_GRACE)


def worker(request, workspace):
    from .runtime import translate_path, translate_request_paths
    translated = {"action": request["action"], "args": translate_request_paths(request["action"], request.get("args", {}))}
    completed = subprocess.run(
        [sys.executable, "-E", "-s", "-X", "utf8", "-B", "-m", "awa_ddd", "--workspace", translate_path(workspace)],
        input=(canonical(translated) + "\n").encode("utf-8"),
        stdout=sys.stdout.buffer, stderr=sys.stderr.buffer, shell=False)
    return completed.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--deadline-ms", type=int)
    parser.add_argument("--worker", action="store_true")
    options = parser.parse_args()
    try:
        stream = ControlLines(sys.stdin.fileno())
        raw = stream.readline(MAX_REQUEST_BYTES + 2)
        if len(raw) > MAX_REQUEST_BYTES + 1 or not raw.endswith(b"\n"):
            raise EngineError("wsl_input_budget", "Expected one bounded UTF-8 JSON request line")
        request = json.loads(raw.decode("utf-8"), parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(request, dict) or not isinstance(request.get("action"), str) or not isinstance(request.get("args", {}), dict):
            raise EngineError("wsl_request", "WSL requires one JSON object with action and args")
        return worker(request, options.workspace) if options.worker else supervise(request, options.workspace, options.deadline_ms, control=stream)
    except (EngineError, OSError, ValueError, TypeError) as exc:
        error = {"code": getattr(exc, "code", "wsl_runtime"),
                 "message": str(exc) if isinstance(exc, EngineError) else "WSL could not start or decode the bounded engine request"}
        sys.stdout.buffer.write((canonical({"ok": False, "error": error}) + "\n").encode("utf-8"))
        sys.stdout.buffer.flush()
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
