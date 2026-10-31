"""Read-only native/WSL runtime metadata and narrowly scoped file-path translation."""
from __future__ import annotations

import json
import locale
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time
import unicodedata

from .store import EngineError


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
MAX_CONSOLE_BYTES = 64 * 1024
_DISTRIBUTION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")
_TOOLS = ("sqlmap", "nmap", "curl", "nikto", "nuclei", "ffuf", "gobuster", "node", "yak")
_WSL_SCRIPT = (
    "import json,os,platform,shutil,sys;"
    "tools={name:shutil.which(name) for name in " + repr(_TOOLS) + "};"
    "script='/usr/share/sqlmap/sqlmap.py';"
    "data={'python_version':platform.python_version(),'python_executable':sys.executable,"
    "'os':platform.system(),'kernel':platform.release(),"
    "'encodings':{'stdin':sys.stdin.encoding,'stdout':sys.stdout.encoding,"
    "'stderr':sys.stderr.encoding,'filesystem':sys.getfilesystemencoding(),"
    "'utf8_mode':sys.flags.utf8_mode},'tools':tools,"
    "'sqlmap_script':script if os.path.isfile(script) else None};"
    "print(json.dumps(data,ensure_ascii=True,sort_keys=True))"
)
_PATH_FIELDS = {
    "surface.import": ("path",),
    "project.import_pentest": ("source_path",),
    "report.build": ("output_dir",),
    "identity.session": ("headers_file",),
    "http.capture": ("body_file",),
    "http.preflight": ("body_file",),
    "tool.probe": ("sqlmap_path", "yak_path"),
    "tool.sqlmap": ("sqlmap_path", "yak_path"),
    "tool.yakit_replay": ("sqlmap_path", "yak_path"),
}


def decode_console(raw):
    """Return (text, decoder-used) without lossy replacement or profile changes."""
    if not isinstance(raw, bytes):
        raise EngineError("runtime_encoding", "Console decoding requires bytes")
    if raw.startswith(b"\xff\xfe"):
        encoding, data = "utf-16-le", raw[2:]
    elif raw.startswith(b"\xfe\xff"):
        encoding, data = "utf-16-be", raw[2:]
    elif raw.startswith(b"\xef\xbb\xbf"):
        encoding, data = "utf-8-sig", raw[3:]
    else:
        sample = raw[:4096]
        odd_nulls = sample[1::2].count(0)
        even_nulls = sample[::2].count(0)
        if len(raw) >= 4 and len(raw) % 2 == 0 and sample.count(0) > len(sample) // 8:
            encoding = "utf-16-le" if odd_nulls >= even_nulls else "utf-16-be"
            data = raw
        else:
            try:
                return raw.decode("utf-8", errors="strict"), "utf-8"
            except UnicodeDecodeError:
                encoding, data = "gb18030", raw
    try:
        return data.decode("utf-8" if encoding == "utf-8-sig" else encoding, errors="strict"), encoding
    except UnicodeDecodeError as exc:
        raise EngineError("runtime_encoding", "Console output is not valid " + encoding + "; no replacement decoding was applied") from exc


def _is_wsl():
    release = platform.release().lower()
    return os.name == "posix" and platform.system() == "Linux" and ("microsoft" in release or "wsl" in release)


def _control_characters(value):
    return any(unicodedata.category(character) in {"Cc", "Cs"} for character in value)


def _process_options():
    return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)} if os.name == "nt" else {}


def translate_path(value):
    if not isinstance(value, str):
        raise EngineError("runtime_path", "A filesystem path must be a string")
    if _control_characters(value):
        raise EngineError("runtime_path", "Filesystem paths must not contain control characters")
    if not _is_wsl() or not _WINDOWS_DRIVE.match(value):
        return value
    try:
        completed = subprocess.run(["wslpath", "-a", "-u", value], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
                                   check=False, shell=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EngineError("runtime_path", "WSL could not translate this Windows filesystem path; no path was rewritten") from exc
    if completed.returncode != 0 or len(completed.stdout) > MAX_CONSOLE_BYTES or len(completed.stderr) > MAX_CONSOLE_BYTES:
        raise EngineError("runtime_path", "wslpath failed or exceeded its output budget; no path was rewritten")
    try:
        translated = completed.stdout.decode("utf-8", errors="strict").rstrip("\r\n")
    except UnicodeDecodeError as exc:
        raise EngineError("runtime_path", "wslpath did not return strict UTF-8; no path was rewritten") from exc
    if not translated.startswith("/") or _control_characters(translated):
        raise EngineError("runtime_path", "wslpath did not return one absolute Linux filesystem path")
    return translated


def translate_request_paths(action, args):
    if not isinstance(action, str) or not isinstance(args, dict):
        raise EngineError("runtime_arguments", "Path translation requires an action string and argument object")
    result = dict(args)
    for field in _PATH_FIELDS.get(action, ()):
        if field in result and result[field] is not None:
            result[field] = translate_path(result[field])
    if action in {"scenario.run", "scenario.preflight"} and isinstance(result.get("scenario"), dict):
        scenario = dict(result["scenario"])
        if isinstance(scenario.get("steps"), list):
            steps = []
            for step in scenario["steps"]:
                copied = dict(step) if isinstance(step, dict) else step
                if isinstance(copied, dict) and copied.get("body_file") is not None:
                    copied["body_file"] = translate_path(copied["body_file"])
                steps.append(copied)
            scenario["steps"] = steps
        result["scenario"] = scenario
    return result


def _native_metadata():
    return {"available": True, "os": platform.system(), "kernel": platform.release(),
            "python_version": platform.python_version(), "python_executable": sys.executable,
            "encodings": {"stdin": sys.stdin.encoding, "stdout": sys.stdout.encoding,
                          "stderr": sys.stderr.encoding, "filesystem": sys.getfilesystemencoding(),
                          "locale_preferred": locale.getpreferredencoding(False), "utf8_mode": sys.flags.utf8_mode},
            "inside_wsl": _is_wsl(), "verification_level": "runtime_metadata",
            "target_traffic_sent": False}


def _run_console(command, timeout):
    completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=timeout, check=False, shell=False,
                               **_process_options())
    if len(completed.stdout) > MAX_CONSOLE_BYTES or len(completed.stderr) > MAX_CONSOLE_BYTES:
        raise EngineError("runtime_output_budget", "Runtime probe output exceeded 64 KiB")
    return completed


def _host_has_wsl_launcher():
    return os.name == "nt"


def _distribution_rows(text):
    rows = []
    for line in text.splitlines():
        match = re.fullmatch(r"\s*(\*)?\s*(\S+)\s+(.+?)\s+([12])\s*", line)
        if match:
            rows.append({"name": match.group(2), "state": match.group(3).strip(),
                         "version": int(match.group(4)), "default": bool(match.group(1))})
    return rows


def _tool_catalog(metadata):
    tools = metadata.get("tools") or {}
    catalog = []
    for name in _TOOLS:
        path = tools.get(name)
        if name == "sqlmap" and metadata.get("sqlmap_script"):
            path = metadata["sqlmap_script"]
        catalog.append({"name": name, "path": path, "available": isinstance(path, str) and bool(path),
                        "status": "catalog_only", "target_traffic_sent": False,
                        "limitation": "A local path is not a scoped execution adapter, a tool run or a completed security test."})
    return catalog


def _wsl_metadata(distribution, timeout):
    result = {"available": False, "distribution": distribution, "catalog": [],
              "verification_level": "runtime_metadata", "target_traffic_sent": False}
    executable = shutil.which("wsl.exe") if _host_has_wsl_launcher() else None
    if not executable:
        return {**result, "reason_code": "wsl_unavailable", "reason": "The native host has no Windows WSL launcher; no distribution was started."}
    deadline = time.monotonic() + timeout
    try:
        listed = _run_console([executable, "--list", "--verbose"], timeout)
        text, encoding = decode_console(listed.stdout)
        result["distribution_list"] = {"observed_encoding": encoding, "distributions": _distribution_rows(text),
                                       "text": text, "exit_code": listed.returncode}
        if listed.returncode != 0:
            error, error_encoding = decode_console(listed.stderr)
            return {**result, "reason_code": "wsl_list_failed", "reason": "WSL could not enumerate its local distributions.",
                    "stderr": error, "stderr_encoding": error_encoding}
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {**result, "reason_code": "runtime_timeout", "reason": "The read-only runtime probe exhausted its deadline."}
        command = [executable, "--distribution", distribution, "--cd", str(PACKAGE_ROOT), "--exec",
                   "python3", "-E", "-s", "-X", "utf8", "-c", _WSL_SCRIPT]
        completed = _run_console(command, remaining)
        result["exit_code"] = completed.returncode
        if completed.returncode != 0:
            error, error_encoding = decode_console(completed.stderr)
            return {**result, "reason_code": "wsl_python_unavailable", "reason": "The fixed read-only Python metadata command did not complete.",
                    "stderr": error, "stderr_encoding": error_encoding}
        # Console fallback decoders are deliberately not used for JSON or bodies.
        metadata = json.loads(completed.stdout.decode("utf-8", errors="strict"))
        if not isinstance(metadata, dict) or not isinstance(metadata.get("tools"), dict) \
                or not isinstance(metadata.get("python_version"), str) or not isinstance(metadata.get("encodings"), dict):
            raise EngineError("runtime_protocol", "The fixed WSL command returned an invalid metadata object")
        result.update(available=True, observed_encoding="utf-8", metadata=metadata, catalog=_tool_catalog(metadata))
        return result
    except subprocess.TimeoutExpired:
        return {**result, "reason_code": "runtime_timeout", "reason": "The read-only runtime probe exceeded its deadline; no security tool or target request was executed."}
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {**result, "reason_code": "runtime_encoding", "reason": "The WSL Python response was not strict UTF-8 JSON; no fallback decoding or configuration change was applied."}
    except EngineError as exc:
        return {**result, "reason_code": exc.code, "reason": str(exc)}
    except OSError:
        return {**result, "reason_code": "wsl_unavailable", "reason": "The local Windows WSL launcher could not be started."}


def probe(args):
    if not isinstance(args, dict):
        raise EngineError("runtime_arguments", "runtime.probe input must be an object")
    backend = args.get("backend", "all")
    if not isinstance(backend, str) or backend not in {"all", "native", "wsl"}:
        raise EngineError("runtime_backend", "backend must be all | native | wsl")
    distribution = args.get("distribution", "kali-linux")
    if not isinstance(distribution, str) or not _DISTRIBUTION.fullmatch(distribution):
        raise EngineError("runtime_distribution", "distribution must be a bounded alphanumeric WSL name; shell syntax and switches are not accepted")
    timeout = args.get("timeout", 15)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 1 <= timeout <= 30:
        raise EngineError("runtime_timeout", "Runtime timeout must be 1..30 seconds")
    result = {"backend": backend, "target_traffic_sent": False,
              "verification_level": "runtime_metadata", "configuration_hint": {"executionBackend": "native"},
              "warnings": [
                  "Tool catalogs are local discovery only; they do not establish supported scoped execution or completed security tests.",
                  "Windows and WSL localhost can use different network namespaces. Target URLs are never automatically rewritten.",
                  "Do not open the same SQLite assessment workspace concurrently from Windows and WSL; use isolated workspaces per execution backend.",
                  "Console decoder fallback is for local metadata only. User request bodies, payloads and saved evidence must not be silently re-encoded.",
              ]}
    if backend in {"all", "native"}:
        result["native"] = _native_metadata()
    if backend in {"all", "wsl"}:
        result["wsl"] = _wsl_metadata(distribution, float(timeout))
        if result["wsl"]["available"]:
            result["configuration_hint"] = {"executionBackend": "wsl", "wslDistribution": distribution}
            metadata = result["wsl"]["metadata"]
            if not metadata["tools"].get("node"):
                result["warnings"].append("Node.js was not found in this distribution: WSL-local browser execution and JavaScript AST discovery are unavailable.")
            if not metadata["tools"].get("yak"):
                result["warnings"].append("The Yak executable was not found in this distribution; a Yakit MCP adapter is not verified or available there.")
    return result
