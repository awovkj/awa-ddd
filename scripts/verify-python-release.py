#!/usr/bin/env python3
"""Build-independent checks for AWA Wheel and SDist fresh installs."""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_PARTS = {
    ".cache", ".env", ".git", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".tox", ".venv", "__pycache__", "backup", "backups", "build", "coverage",
    "dist", "htmlcov", "node_modules", "projects", "reports", "tests",
}
FORBIDDEN_SUFFIXES = (
    ".bak", ".backup", ".db", ".db-journal", ".db-shm", ".db-wal", ".log",
    ".orig", ".pyc", ".pyo", ".rej", ".sqlite", ".sqlite3", ".swp", ".swo",
    ".temp", ".tmp", ".tgz",
)
REQUIRED_PACKAGE_FILES = {
    "awa_ddd/__init__.py",
    "awa_ddd/__main__.py",
    "awa_ddd/contracts.py",
    "awa_ddd/execution_coordinator.py",
    "awa_ddd/ipc.py",
    "awa_ddd/provider_discovery.py",
    "awa_ddd/runtime.py",
    "awa_ddd/source_inventory.py",
    "awa_ddd/domain/__init__.py",
    "awa_ddd/execution/__init__.py",
    "awa_ddd/execution/fixture_api.py",
    "awa_ddd/planning/__init__.py",
    "awa_ddd/reporting/__init__.py",
}
RESOURCE_FILES = {
    "awa_ddd/resources/js_parser/manifest.json":
        "9cd41e076c3bcf2a4bc61bcfd52130d319b42354232d5d127c98ade42f614686",
    "awa_ddd/resources/js_parser/parse-js.mjs":
        "972badd3720729ad0336ab6d610576d2b748a8f38e7ed9c3a9cea4ba1da28210",
    "awa_ddd/resources/js_parser/vendor/acorn/LICENSE":
        "76a876cf886ff9be2a8b5e2e86514fed06223c8c9f0c1e9ee9606e93841e00b7",
    "awa_ddd/resources/js_parser/vendor/acorn/package.json":
        "04d6fecaafb5e3d20a38fc3b64fed84bb3830a7759a8c00400ebcb87331fec00",
    "awa_ddd/resources/js_parser/vendor/acorn/dist/acorn.mjs":
        "76254fc76529713b4dfd2532972d17a991ffd9aafeebb1f977445b5506b9fb0b",
}
RESOURCE_ROOT = ROOT / "awa_ddd/resources/js_parser"
EXPECTED_ACTION_COUNT = 75
PRIVATE_TEST = re.compile(r"(?:^|/)awa_ddd/tests_[^/]*\.py$")
PACKAGE_ROOT = ROOT / "awa_ddd"
SDIST_ROOT_FILES = {"LICENSE", "README.md", "pyproject.toml", "setup.py"}
SDIST_GENERATED_FILES = {
    "PKG-INFO",
    "setup.cfg",
    "awa_ddd.egg-info/PKG-INFO",
    "awa_ddd.egg-info/SOURCES.txt",
    "awa_ddd.egg-info/dependency_links.txt",
    "awa_ddd.egg-info/entry_points.txt",
    "awa_ddd.egg-info/top_level.txt",
}
WHEEL_GENERATED_FILES = {
    "licenses/LICENSE",
    "METADATA",
    "WHEEL",
    "entry_points.txt",
    "top_level.txt",
    "RECORD",
}


def run(command, *, cwd=None, env=None, input_text=None, timeout=180):
    merged = os.environ.copy()
    merged.update({
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PYTHONNOUSERSITE": "1",
    })
    if env:
        merged.update(env)
    completed = subprocess.run(
        [str(part) for part in command],
        cwd=str(cwd or ROOT),
        env=merged,
        input=input_text,
        text=True,
        encoding="utf-8",
        errors="strict",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        shell=False,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            "Command failed with exit code %d: %s\nstdout:\n%s\nstderr:\n%s"
            % (completed.returncode, " ".join(map(str, command)), completed.stdout[-6000:], completed.stderr[-6000:])
        )
    return completed


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def expected_package_files():
    """Return every intentional runtime file and its exact source path."""
    files = {}
    package_root = PACKAGE_ROOT.resolve()
    for path in PACKAGE_ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT).as_posix()
        parts = PurePosixPath(relative).parts
        if len(parts) == 2 and parts[0] == "awa_ddd" \
                and parts[1].startswith("tests_") and parts[1].endswith(".py"):
            continue
        if "__pycache__" in parts:
            continue
        if path.suffix != ".py":
            continue
        if path.is_symlink() or not path.resolve(strict=True).is_relative_to(package_root):
            raise AssertionError("Package payload must be a regular file below awa_ddd: " + relative)
        files[relative] = path
    discovered_resources = set()
    for path in RESOURCE_ROOT.rglob("*"):
        if path.is_symlink():
            raise AssertionError("Runtime resource must not be a link: " + str(path))
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT).as_posix()
        discovered_resources.add(relative)
    expected_resources = set(RESOURCE_FILES)
    if discovered_resources != expected_resources:
        raise AssertionError(
            "Runtime resource allowlist mismatch; missing=%s unexpected=%s"
            % (sorted(expected_resources - discovered_resources), sorted(discovered_resources - expected_resources))
        )
    for relative, expected_digest in RESOURCE_FILES.items():
        path = ROOT / relative
        if digest(path) != expected_digest:
            raise AssertionError("Runtime resource differs from its frozen SHA-256: " + relative)
        files[relative] = path
    return files


def check_member(raw):
    if "\\" in raw:
        raise AssertionError("Artifact member must use POSIX separators: " + raw)
    path = PurePosixPath(raw)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise AssertionError("Artifact contains an unsafe path: " + raw)
    allowed_resource = False
    parts = path.parts
    for candidate in RESOURCE_FILES:
        candidate_parts = PurePosixPath(candidate).parts
        if len(parts) >= len(candidate_parts) and parts[-len(candidate_parts):] == candidate_parts:
            allowed_resource = True
            break
    if FORBIDDEN_PARTS.intersection(part.lower() for part in path.parts[:-1]) and not allowed_resource:
        raise AssertionError("Artifact contains a forbidden directory: " + raw)
    if PRIVATE_TEST.search(raw):
        raise AssertionError("Artifact contains an in-package regression test: " + raw)
    lowered = raw.lower()
    environment = re.search(r"(?:^|/)(?:\.env|[^/]+\.env)(?:\.[^/]*)?$", lowered)
    if environment and not re.search(r"\.(?:example|sample|template)$", lowered):
        raise AssertionError("Artifact contains private environment configuration: " + raw)
    if lowered.endswith(FORBIDDEN_SUFFIXES) or ".sqlite" in lowered:
        raise AssertionError("Artifact contains generated/private data: " + raw)
    if "/awa_ddd/tests_" in "/" + raw and raw.endswith(".py"):
        raise AssertionError("Artifact contains an in-package regression test: " + raw)


def wheel_record_hashes(archive, record_name, names):
    rows = list(csv.reader(io.StringIO(archive.read(record_name).decode("utf-8"))))
    if any(len(row) != 3 for row in rows):
        raise AssertionError("Wheel RECORD has a malformed row")
    recorded = [row[0] for row in rows]
    if len(recorded) != len(set(recorded)) or set(recorded) != names:
        raise AssertionError("Wheel RECORD does not enumerate the exact archive membership")
    hashes = {}
    for name, encoded_digest, encoded_size in rows:
        if name == record_name:
            if encoded_digest or encoded_size:
                raise AssertionError("Wheel RECORD must leave its own digest and size empty")
            continue
        if not encoded_digest.startswith("sha256=") or not encoded_size.isdigit():
            raise AssertionError("Wheel RECORD must use SHA-256 for every other member")
        payload = archive.read(name)
        expected_digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode("ascii")
        if encoded_digest != "sha256=" + expected_digest:
            raise AssertionError("Wheel RECORD digest mismatch for " + name)
        if int(encoded_size) != len(payload):
            raise AssertionError("Wheel RECORD size mismatch for " + name)
        hashes[name] = expected_digest
    return hashes


def inspect_wheel(path):
    names = set()
    duplicate_names = set()
    payload_hashes = {}
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            raw = info.filename
            check_member(raw)
            if info.is_dir():
                continue
            if info.file_size > 32 * 1024 * 1024:
                raise AssertionError("Wheel member exceeds the 32 MiB budget: " + raw)
            if raw in names:
                duplicate_names.add(raw)
                continue
            names.add(raw)
            payload_hashes[raw] = hashlib.sha256(archive.read(raw)).hexdigest()
    if duplicate_names:
        raise AssertionError("Wheel contains duplicate file members: " + ", ".join(sorted(duplicate_names)))
    package = {name for name in names if name.startswith("awa_ddd/")}
    missing = REQUIRED_PACKAGE_FILES - package
    if missing:
        raise AssertionError("Wheel is missing required package files: " + ", ".join(sorted(missing)))
    expected = expected_package_files()
    if package != set(expected):
        missing = set(expected) - package
        unexpected = package - set(expected)
        raise AssertionError(
            "Wheel public package allowlist mismatch; missing=%s unexpected=%s"
            % (sorted(missing), sorted(unexpected))
        )
    metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
    if len(metadata) != 1:
        raise AssertionError("Wheel must contain exactly one METADATA member")
    dist_info = metadata[0].rsplit("/", 1)[0]
    allowed_generated = {dist_info + "/" + name for name in WHEEL_GENERATED_FILES}
    allowed = set(expected) | allowed_generated
    if names != allowed:
        missing = allowed - names
        unexpected = names - allowed
        raise AssertionError(
            "Wheel exact member allowlist mismatch; missing=%s unexpected=%s"
            % (sorted(missing), sorted(unexpected))
        )
    for relative, source in expected.items():
        if payload_hashes[relative] != digest(source):
            raise AssertionError("Wheel runtime file differs from frozen source: " + relative)
    record_name = dist_info + "/RECORD"
    with zipfile.ZipFile(path) as archive:
        record_hashes = wheel_record_hashes(archive, record_name, names)
    for name, encoded in record_hashes.items():
        expected_digest = base64.urlsafe_b64encode(bytes.fromhex(payload_hashes[name])).rstrip(b"=").decode("ascii")
        if encoded != expected_digest:
            raise AssertionError("Wheel RECORD disagrees with wheel bytes: " + name)
    return {
        "files": sorted(names),
        "runtime_files": len(expected),
        "runtime_sha256": {name: payload_hashes[name] for name in sorted(expected)},
    }


def inspect_sdist(path):
    names = set()
    payload_hashes = {}
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            check_member(member.name)
            if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                raise AssertionError("SDist contains a link or unsupported member: " + member.name)
            if member.isfile():
                if member.size > 32 * 1024 * 1024:
                    raise AssertionError("SDist member exceeds the 32 MiB budget: " + member.name)
                if member.name in names:
                    raise AssertionError("SDist contains duplicate file members: " + member.name)
                names.add(member.name)
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise AssertionError("SDist member cannot be read: " + member.name)
                payload_hashes[member.name] = hashlib.sha256(extracted.read()).hexdigest()
    roots = {PurePosixPath(name).parts[0] for name in names}
    if len(roots) != 1:
        raise AssertionError("SDist must have exactly one top-level directory")
    root = next(iter(roots))
    relative = {
        str(PurePosixPath(*PurePosixPath(name).parts[1:]))
        for name in names
        if len(PurePosixPath(name).parts) > 1
    }
    root_source_files = set(SDIST_ROOT_FILES)
    if (ROOT / "MANIFEST.in").is_file():
        root_source_files.add("MANIFEST.in")
    for required in sorted(root_source_files):
        if required not in relative:
            raise AssertionError("SDist is missing " + required)
    missing = REQUIRED_PACKAGE_FILES - relative
    if missing:
        raise AssertionError("SDist is missing required package files: " + ", ".join(sorted(missing)))
    expected = expected_package_files()
    packaged = {name for name in relative if name.startswith("awa_ddd/")}
    if packaged != set(expected):
        missing = set(expected) - packaged
        unexpected = packaged - set(expected)
        raise AssertionError(
            "SDist public package allowlist mismatch; missing=%s unexpected=%s"
            % (sorted(missing), sorted(unexpected))
        )
    allowed = set(expected) | root_source_files | SDIST_GENERATED_FILES
    if relative != allowed:
        missing = allowed - relative
        unexpected = relative - allowed
        raise AssertionError(
            "SDist exact member allowlist mismatch; missing=%s unexpected=%s"
            % (sorted(missing), sorted(unexpected))
        )
    for source_relative, source in expected.items():
        archive_name = root + "/" + source_relative
        if payload_hashes[archive_name] != digest(source):
            raise AssertionError("SDist runtime file differs from frozen source: " + source_relative)
    for source_relative in sorted(root_source_files):
        archive_name = root + "/" + source_relative
        if payload_hashes[archive_name] != digest(ROOT / source_relative):
            raise AssertionError("SDist metadata file differs from frozen source: " + source_relative)
    sources_name = root + "/awa_ddd.egg-info/SOURCES.txt"
    if sources_name in payload_hashes:
        with tarfile.open(path, "r:gz") as archive:
            extracted = archive.extractfile(sources_name)
            if extracted is None:
                raise AssertionError("SDist SOURCES.txt cannot be read")
            sources_lines = {
                line.strip() for line in extracted.read().decode("utf-8").splitlines() if line.strip()
            }
        if any(line.startswith("tests/") or "/tests_" in "/" + line for line in sources_lines):
            raise AssertionError("SDist SOURCES.txt still references excluded regression tests")
        missing_sources = set(expected) - sources_lines
        if missing_sources:
            raise AssertionError(
                "SDist SOURCES.txt omits runtime files: " + ", ".join(sorted(missing_sources))
            )
    return root, sorted(relative), {
        "runtime_files": len(expected),
        "runtime_sha256": {
            name: payload_hashes[root + "/" + name] for name in sorted(expected)
        },
    }


def create_venv(path):
    venv.EnvBuilder(with_pip=True, clear=True, symlinks=os.name != "nt").create(path)
    python = path / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    run([python, "-m", "pip", "--version"])
    return python


def verify_installed(python, artifact, workspace):
    run([python, "-I", "-m", "pip", "install", "--no-deps", "--no-cache-dir", str(artifact)], timeout=300)
    probe = r"""
import importlib.metadata
import json
import pathlib
import sys
import awa_ddd
from awa_ddd import contracts
from awa_ddd.fingerprint import core_manifest

catalog = contracts.action_help({})
core = core_manifest()
locations = sorted({
    str(pathlib.Path(row.locate_file("awa_ddd")).resolve())
    for row in importlib.metadata.distributions()
    if (row.metadata.get("Name") or "").lower().replace("_", "-") == "awa-ddd"
})
print(json.dumps({
    "version": awa_ddd.__version__,
    "module": str(pathlib.Path(awa_ddd.__file__).resolve()),
    "locations": locations,
    "action_count": catalog["action_count"],
    "has_ingest": any("tool.tscanplus_ingest" in rows for rows in catalog["groups"].values()),
    "has_report_artifact": any("report.artifact" in rows for rows in catalog["groups"].values()),
    "core_manifest_sha256": core["sha256"],
    "core_resources": [
        row["path"] for row in core["files"]
        if row["path"].startswith("awa_ddd/resources/js_parser/")
    ],
    "python": sys.version.split()[0],
}, sort_keys=True))
"""
    imported = json.loads(run([python, "-I", "-c", probe], cwd=workspace).stdout)
    expected = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))["version"]
    if imported["version"] != expected:
        raise AssertionError("Installed package version does not match package.json")
    if imported["action_count"] != EXPECTED_ACTION_COUNT or not imported["has_ingest"] \
            or not imported["has_report_artifact"]:
        raise AssertionError("Installed action catalog is incomplete")
    if len(imported["locations"]) != 1:
        raise AssertionError("Exactly one awa-ddd distribution must be importable")
    if set(imported.get("core_resources") or []) != set(RESOURCE_FILES):
        raise AssertionError("Installed core manifest omits or adds JavaScript parser resources")
    if not re.fullmatch(r"[a-f0-9]{64}", imported.get("core_manifest_sha256") or ""):
        raise AssertionError("Installed core manifest digest is malformed")
    module_path = Path(imported["module"])
    if not module_path.is_relative_to(Path(python).resolve().parents[1]):
        raise AssertionError("Imported awa_ddd escaped the fresh virtual environment")
    module_help = run([python, "-I", "-m", "awa_ddd", "--help"], cwd=workspace)
    if "--workspace" not in module_help.stdout:
        raise AssertionError("python -m awa_ddd does not expose the workspace contract")
    console = Path(python).with_name("awa-ddd.exe" if os.name == "nt" else "awa-ddd")
    if not console.is_file():
        raise AssertionError("Fresh install did not create the awa-ddd console entry")
    console_help = run([console, "--help"], cwd=workspace)
    if "--workspace" not in console_help.stdout:
        raise AssertionError("Installed awa-ddd console entry is not executable")
    request = json.dumps({"action": "action.help", "args": {}}, separators=(",", ":")) + "\n"
    result = run([python, "-I", "-m", "awa_ddd", "--workspace", workspace], cwd=workspace, input_text=request)
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    if len(rows) != 1 or not rows[0].get("ok"):
        raise AssertionError("Installed protocol did not return exactly one successful JSON result")
    help_data = rows[0]["data"]
    if help_data["action_count"] != EXPECTED_ACTION_COUNT \
            or "tool.tscanplus_ingest" not in help_data["groups"].get("awa_external", []) \
            or "report.artifact" not in help_data["groups"].get("awa_report", []):
        raise AssertionError("Installed action.help is incomplete")
    console_result = run(
        [console, "--workspace", workspace],
        cwd=workspace,
        input_text=request,
    )
    console_rows = [json.loads(line) for line in console_result.stdout.splitlines()]
    if len(console_rows) != 1 or not console_rows[0].get("ok"):
        raise AssertionError("Installed console did not return exactly one successful JSON result")
    console_help_data = console_rows[0]["data"]
    if console_help_data["action_count"] != EXPECTED_ACTION_COUNT \
            or "report.artifact" not in console_help_data["groups"].get("awa_report", []):
        raise AssertionError("Installed console action.help omits report.artifact")
    javascript_probe = workspace / "javascript-import-probe.js"
    javascript_probe.write_text(
        "fetch('https://example.invalid/profile', { method: 'GET' });\n",
        encoding="utf-8",
    )
    discovery_probe = r"""
import json
import sys
from awa_ddd.discovery import discover

result = discover(sys.argv[1], "javascript", "https://example.invalid/")
limitations = [row.get("code") for row in result.get("limitations", []) if isinstance(row, dict)]
print(json.dumps({
    "operations": result.get("operations", []),
    "limitations": limitations,
}, sort_keys=True))
"""
    discovered = json.loads(run(
        [python, "-I", "-c", discovery_probe, javascript_probe],
        cwd=workspace,
        timeout=60,
    ).stdout)
    operations = discovered.get("operations")
    if not isinstance(operations, list) or len(operations) != 1:
        raise AssertionError("Fresh install did not expose JavaScript AST discovery")
    if not isinstance(operations[0], dict) or operations[0].get("method") != "GET" \
            or "example.invalid/profile" not in str(operations[0].get("url")):
        raise AssertionError("Fresh install JavaScript discovery returned an unexpected operation")
    parser_failures = {
        "javascript_ast_parser_unavailable",
        "javascript_ast_parser_failed",
    }
    if parser_failures.intersection(discovered.get("limitations") or []):
        raise AssertionError("Fresh install JavaScript AST parser is unavailable")
    return {
        "artifact": artifact.name,
        "sha256": digest(artifact),
        "version": imported["version"],
        "python": imported["python"],
        "module": "venv-site-packages/awa_ddd",
        "one_distribution": True,
        "cli": True,
        "javascript_ast": True,
        "report_artifact": True,
        "core_manifest_resources": True,
        "core_manifest_sha256": imported["core_manifest_sha256"],
        "action_count": imported["action_count"],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", default="dist")
    parser.add_argument("--keep-venvs", action="store_true")
    args = parser.parse_args()
    dist = (ROOT / args.dist).resolve()
    wheels = sorted(dist.glob("awa_ddd-*.whl"))
    sdists = sorted(dist.glob("awa_ddd-*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise AssertionError("Expected exactly one Wheel and one SDist in " + str(dist))
    wheel, sdist = wheels[0], sdists[0]
    wheel_check = inspect_wheel(wheel)
    sdist_root, sdist_files, sdist_check = inspect_sdist(sdist)
    validation = ROOT / ".validation"
    validation.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix="python-release-", dir=validation))
    results = []
    try:
        for label, artifact in (("wheel", wheel), ("sdist", sdist)):
            environment = temporary / (label + "-venv")
            workspace = temporary / (label + "-workspace")
            workspace.mkdir()
            python = create_venv(environment)
            results.append(verify_installed(python, artifact, workspace))
    finally:
        if args.keep_venvs:
            print("Fresh virtual environments retained at " + str(temporary), file=sys.stderr)
        else:
            shutil.rmtree(temporary)
    summary = {
        "wheel": {
            "sha256": digest(wheel),
            "files": len(wheel_check["files"]),
            **{key: value for key, value in wheel_check.items() if key != "files"},
        },
        "sdist": {
            "sha256": digest(sdist),
            "root": sdist_root,
            "files": len(sdist_files),
            **sdist_check,
        },
        "installs": results,
        "private_tests_absent": True,
        "runtime_source_byte_equality": True,
        "exact_archive_membership": True,
        "javascript_ast_fresh_install": True,
        "core_manifest_resources": True,
        "fresh_install": True,
        "result": "passed",
    }
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
