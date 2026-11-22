"""Safely resolve and page immutable report artifacts."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from .store import EngineError


REPORT_ROOT = "reports"
_ARTIFACT_ROOTS = frozenset(
    {"artifacts", "reports", "evidence", "browser", "tools", "materials"}
)
_BATCH = re.compile(r"[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}")
_MAX_MANIFEST_BYTES = 2 * 1024 * 1024
_MAX_REPORT_FILE_BYTES = 16 * 1024 * 1024
_MAX_PAGE_CHARACTERS = 8000


def _link_or_reparse(path):
    if path.is_symlink():
        return True
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except FileNotFoundError:
        return False
    return bool(attributes & 0x400)


def _read_bounded(path, maximum, error_code, message):
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise EngineError(error_code, message)
    return data


def _plain_relative_path(project, value):
    if not isinstance(value, str) or not value:
        raise EngineError("report_material", "A managed artifact reference is required")
    if any(character in value for character in ("\\", "\x00", "%", "?", "#")):
        raise EngineError(
            "report_material",
            "Managed artifact references cannot contain encoded or alternate separators",
        )
    parsed = urlsplit(value)
    if (
        parsed.scheme != "artifact"
        or parsed.netloc not in _ARTIFACT_ROOTS
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.path.startswith("/")
    ):
        raise EngineError(
            "report_material", "Malformed or unsupported managed artifact reference"
        )
    relative = PurePosixPath(parsed.path).parts[1:]
    if (
        not relative
        or any(part in {"", ".", ".."} for part in relative)
        or any(len(part) > 160 for part in relative)
        or any(not all(character.isalnum() or character in "._-" for character in part)
               for part in relative)
    ):
        raise EngineError(
            "report_material", "Managed artifact reference contains an unsafe path"
        )
    root = project.base / parsed.netloc
    if _link_or_reparse(root):
        raise EngineError(
            "path_link", "Managed artifact roots cannot be links or reparse points"
        )
    target = root.joinpath(*relative)
    current = root
    for part in relative:
        current = current / part
        if _link_or_reparse(current):
            raise EngineError(
                "path_link", "Managed artifact references cannot cross links or reparse points"
            )
    try:
        resolved_project = project.base.resolve(strict=True)
        resolved_root = root.resolve(strict=True)
        resolved_root.relative_to(resolved_project)
        resolved = target.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise EngineError(
            "not_found", "The managed artifact does not exist in this project"
        ) from exc
    return parsed.netloc, tuple(relative), resolved_root, resolved


def _manifest_path(project, batch):
    root = project.base / REPORT_ROOT / batch
    target = root / "manifest.json"
    cursor = project.base / REPORT_ROOT
    for part in (batch, "manifest.json"):
        cursor = cursor / part
        if _link_or_reparse(cursor):
            raise EngineError(
                "path_link",
                "Report manifest cannot cross a link or reparse point",
            )
    try:
        resolved_project = project.base.resolve(strict=True)
        resolved_root = root.resolve(strict=True)
        resolved_root.relative_to(resolved_project)
        manifest = target.resolve(strict=True)
        manifest.relative_to(resolved_root)
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise EngineError("not_found", "The report batch manifest is missing") from exc
    if not manifest.is_file():
        raise EngineError("not_found", "The report batch manifest is missing")
    return manifest


def _manifest_entry_map(project, batch):
    manifest_path = _manifest_path(project, batch)
    data = _read_bounded(
        manifest_path,
        _MAX_MANIFEST_BYTES,
        "report_material",
        "The report manifest exceeds its read budget",
    )
    try:
        manifest = json.loads(data.decode("utf-8-sig"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise EngineError("report_material", "The report manifest is not valid UTF-8 JSON") from exc
    if not isinstance(manifest, dict):
        raise EngineError("report_material", "The report manifest must be an object")
    expected_project = project.config.get("project_id") or project.base.name
    if manifest.get("project_id") not in {None, expected_project}:
        raise EngineError(
            "report_material", "The report manifest belongs to another project"
        )
    files = manifest.get("files")
    if not isinstance(files, list):
        raise EngineError("report_material", "The report manifest requires a files array")
    entries = {}
    for entry in files:
        if not isinstance(entry, dict):
            raise EngineError("report_material", "Report manifest file entries must be objects")
        relative = entry.get("path")
        digest = entry.get("sha256")
        size_bytes = entry.get("size_bytes")
        if (
            not isinstance(relative, str)
            or not relative
            or relative.startswith("/")
            or any(part in {"", ".", ".."} for part in PurePosixPath(relative).parts)
            or any(character in relative for character in ("\\", "\x00", "%", "?", "#"))
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or type(size_bytes) is not int
            or size_bytes < 0
        ):
            raise EngineError("report_material", "The report manifest has an invalid file entry")
        if relative in entries:
            raise EngineError("report_material", "The report manifest repeats a file path")
        entries[relative] = entry
    return manifest, entries, data


def _verified_manifest_entry(project, handle, resolved_root, resolved):
    _, relative, parsed_root, parsed_target = _plain_relative_path(project, handle)
    if parsed_root != resolved_root or parsed_target != resolved:
        raise EngineError("path_escape", "Managed report reference changed during validation")
    if len(relative) < 2:
        raise EngineError(
            "report_material",
            "A report artifact handle requires a batch and a concrete file",
        )
    batch, file_parts = relative[0], relative[1:]
    if _BATCH.fullmatch(batch) is None:
        raise EngineError("report_material", "The report batch name is invalid")
    manifest, entries, manifest_bytes = _manifest_entry_map(project, batch)
    relative_file = PurePosixPath(*file_parts).as_posix()
    if relative_file == "manifest.json":
        embedded = manifest.get("manifest_sha256")
        if embedded is not None:
            facts = {
                key: value
                for key, value in manifest.items()
                if key != "manifest_sha256"
            }
            expected = hashlib.sha256(
                json.dumps(
                    facts,
                    ensure_ascii=False,
                    sort_keys=True,
                    allow_nan=False,
                ).encode("utf-8")
            ).hexdigest()
            if embedded != expected:
                raise EngineError("report_material", "The report manifest digest is invalid")
        return manifest, manifest_bytes
    entry = entries.get(relative_file)
    if entry is None:
        raise EngineError(
            "report_material", "The report artifact is not listed in its batch manifest"
        )
    data = _read_bounded(
        parsed_target,
        _MAX_REPORT_FILE_BYTES,
        "artifact_unreadable",
        "The report artifact exceeds its read budget",
    )
    if len(data) != entry["size_bytes"]:
        raise EngineError("report_material", "The report artifact size changed")
    if hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise EngineError("report_material", "The report artifact digest changed")
    return manifest, data


def managed_artifact_handle_valid(project, value):
    """Return whether a public ``artifact://`` value maps to current bytes."""
    try:
        root, _, resolved_root, resolved = _plain_relative_path(project, value)
        if not resolved.is_file():
            return False
        if root == REPORT_ROOT:
            _verified_manifest_entry(project, value, resolved_root, resolved)
        return True
    except EngineError:
        return False


def handle_for_path(project, path):
    """Map an engine-owned local path to a portable artifact reference."""
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = project.base / candidate
    for root in _ARTIFACT_ROOTS:
        root_path = project.base / root
        if _link_or_reparse(root_path):
            continue
        try:
            relative = candidate.relative_to(root_path)
        except ValueError:
            continue
        if any(part in {"", ".", ".."} for part in relative.parts):
            return None
        target = root_path.joinpath(*relative.parts)
        cursor = root_path
        for part in relative.parts:
            cursor = cursor / part
            if _link_or_reparse(cursor):
                return None
        try:
            resolved_project = project.base.resolve(strict=True)
            resolved_root = root_path.resolve(strict=True)
            resolved_root.relative_to(resolved_project)
            resolved = target.resolve(strict=True)
            resolved.relative_to(resolved_root)
        except (FileNotFoundError, OSError, ValueError):
            return None
        return "artifact://" + root + "/" + relative.as_posix()
    return None


def read_report_artifact(project, args):
    """Return one bounded UTF-8 page after manifest and byte verification."""
    handle = args["handle"]
    offset = args.get("offset", 0)
    limit = args.get("limit", 4000)
    if type(offset) is not int or offset < 0:
        raise EngineError("pagination", "offset must be a nonnegative integer")
    if type(limit) is not int or not 1 <= limit <= _MAX_PAGE_CHARACTERS:
        raise EngineError(
            "pagination", f"limit must be an integer in 1..{_MAX_PAGE_CHARACTERS}"
        )
    root, relative, resolved_root, resolved = _plain_relative_path(project, handle)
    if root != REPORT_ROOT:
        raise EngineError(
            "report_material", "report.artifact accepts report-batch handles only"
        )
    _, data = _verified_manifest_entry(
        project, handle, resolved_root, resolved
    )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EngineError(
            "artifact_unreadable", "The report artifact is not valid UTF-8"
        ) from exc
    if offset > len(text):
        raise EngineError("pagination", "offset exceeds the report artifact length")
    end = min(len(text), offset + limit)
    return {
        "handle": handle,
        "content": text[offset:end],
        "offset": offset,
        "limit": limit,
        "next_offset": end if end < len(text) else None,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "complete": end == len(text),
        "media_type": "text/markdown" if relative[-1].endswith(".md") else "application/json",
    }
