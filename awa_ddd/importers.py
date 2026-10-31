"""Bounded, read-only Pentest-Pro import; legacy conclusions remain candidates."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import stat
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from .candidates import store_candidate
from .reporting import safe_text
from .scope import normalize_url


MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_ROWS = 10000


def _plain_source(source_path):
    path = Path(os.path.abspath(source_path))
    for part in [*reversed(path.parents), path]:
        if part.is_symlink():
            raise ValueError("Legacy source may not contain symlinks")
        if part.exists() and getattr(part.lstat(), "st_file_attributes", 0) & 0x400:
            raise ValueError("Legacy source may not contain reparse points")
    if not path.is_dir():
        raise ValueError("Legacy source must be a project directory")
    return path


def _read_document(source, name, required=False):
    path = source / name
    if path.is_symlink():
        raise ValueError("Legacy documents may not be symlinks")
    if not path.exists():
        if required:
            raise ValueError("Legacy inventory.json is required")
        return None, None
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or getattr(before, "st_file_attributes", 0) & 0x400:
        raise ValueError("Legacy documents must be plain files")
    if path.resolve().parent != source.resolve():
        raise ValueError("Legacy document escaped its source directory")
    if before.st_size > MAX_DOCUMENT_BYTES:
        raise ValueError("Legacy document exceeds the byte limit")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("Legacy document changed during import")
        raw = stream.read(MAX_DOCUMENT_BYTES + 1)
    after = path.lstat()
    if len(raw) > MAX_DOCUMENT_BYTES or any(
            getattr(before, field) != getattr(after, field)
            for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns")):
        raise ValueError("Legacy document changed or exceeded the byte limit during import")
    try:
        document = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ValueError("Invalid legacy JSON document: " + name) from exc
    if not isinstance(document, dict):
        raise ValueError("Legacy documents must contain an object")
    return document, hashlib.sha256(raw).hexdigest()


def _rows(document, key):
    value = (document or {}).get(key, [])
    if not isinstance(value, list) or len(value) > MAX_ROWS or any(not isinstance(row, dict) for row in value):
        raise ValueError("Invalid or excessive legacy " + key)
    return value


def _identifier(value):
    return safe_text(value, 256)


def _reference(value):
    # A missing or redacted ID must never bind a finding to an arbitrary endpoint.
    if isinstance(value, str) and value.strip() and _identifier(value) == value:
        return value
    return None


def _operation_key(hint):
    return (normalize_url(hint["url"]), hint["method"], hint.get("protocol", "http"),
            hint.get("operation_name", ""), hint.get("content_type", ""))


def _preserve_destination(hint, existing):
    """Import can add discovery metadata, not downgrade reviewed local policy."""
    if not existing:
        return hint
    merged = dict(hint)
    for field in ("auth", "allowed_roles", "ownership", "consumer_state"):
        if field in existing:
            merged[field] = existing[field]
    keys = {(item["location"], item.get("selector", item["name"]), item.get("schema_branch"))
            for item in existing.get("inputs", [])}
    merged["inputs"] = [item for item in hint["inputs"]
                        if (item["location"], item.get("selector", item["name"]), item.get("schema_branch")) not in keys]
    return merged


def _hint(endpoint, base_url, source_hash, index):
    raw_url = endpoint.get("url")
    if not isinstance(raw_url, str) or not raw_url:
        raise ValueError("Legacy endpoint has no URL")
    url = urljoin(base_url, raw_url) if base_url else raw_url
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Legacy endpoint has an invalid or credential-bearing URL")
    # Query values may be credentials or private examples: import names only.
    url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
    method = endpoint.get("method")
    if not isinstance(method, str) or not method.strip():
        raise ValueError("Legacy endpoint method is unresolved")
    inputs, keys = [], set()
    parameters = endpoint.get("params", [])
    if not isinstance(parameters, list) or len(parameters) > MAX_ROWS:
        raise ValueError("Invalid or excessive legacy parameters")
    for parameter in parameters:
        if not isinstance(parameter, dict) or not isinstance(parameter.get("name"), str):
            continue
        location = parameter.get("in", parameter.get("location", "unknown"))
        row = {"name": _identifier(parameter["name"]), "location": _identifier(location),
               "source": "declared", "consumer": "unknown"}
        selector = parameter.get("selector", parameter.get("parameter_path"))
        if isinstance(selector, str):
            row["selector"] = _identifier(selector)
        key = (row["name"], row["location"], row.get("selector", ""))
        if key not in keys:
            inputs.append(row)
            keys.add(key)
    for name, _ in parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=MAX_ROWS):
        key = (_identifier(name), "query", "")
        if key not in keys:
            inputs.append({"name": key[0], "location": "query", "source": "declared", "consumer": "unknown"})
            keys.add(key)
    ownership = endpoint.get("ownership")
    applicable = isinstance(ownership, dict) and ownership.get("applicable") is True
    protocol = endpoint.get("protocol", "http")
    operation_name = endpoint.get("operation_name", "")
    content_type = endpoint.get("content_type", "")
    if not all(isinstance(value, str) for value in (protocol, operation_name, content_type)):
        raise ValueError("Invalid legacy operation identity")
    return {"url": url, "method": method.strip().upper(), "protocol": protocol,
            "operation_name": _identifier(operation_name), "content_type": _identifier(content_type).lower(),
            "inputs": inputs, "auth": "unknown", "ownership": applicable, "consumer_state": "unknown",
            "sources": [{"path": "inventory.json", "sha256": source_hash,
                         "locator": "/endpoints/" + str(index), "trust": "declared"}]}


def import_pentest(project, source_path):
    source = _plain_source(source_path)
    destination = Path(project.base).resolve()
    if source.resolve().is_relative_to(destination) or destination.is_relative_to(source.resolve()):
        raise ValueError("Legacy source and destination directories must not overlap")
    # Validate all document structures before the first destination write.
    inventory, inventory_hash = _read_document(source, "inventory.json", required=True)
    config, config_hash = _read_document(source, "config.json")
    findings, findings_hash = _read_document(source, "findings.json")
    endpoints, legacy_findings = _rows(inventory, "endpoints"), _rows(findings, "findings")
    base_url = (config or {}).get("target", "")
    if not isinstance(base_url, str):
        base_url = ""
    plans, skipped = [], []
    for index, endpoint in enumerate(endpoints):
        try:
            plans.append((endpoint, _hint(endpoint, base_url, inventory_hash, index)))
        except (TypeError, ValueError) as exc:
            skipped.append({"legacy_id": _identifier(endpoint.get("url_id", index)), "reason": safe_text(exc)})
    reference_counts = Counter(_reference(endpoint.get("url_id")) for endpoint in endpoints)
    # Project.put/event participate in this transaction. A failed import must not
    # leave inventory registered without its provenance/candidate batch.
    with project.transaction():
        return _apply_import(project, source, plans, skipped, legacy_findings, reference_counts,
                             inventory_hash, config_hash, findings_hash)


def _apply_import(project, source, plans, skipped, legacy_findings, reference_counts,
                  inventory_hash, config_hash, findings_hash):
    from .engine import register_operation
    mapping, imported, created_candidates, unmapped_findings = {}, [], 0, 0
    existing = {_operation_key(operation): operation for operation in project.list("operation")}
    for endpoint, hint in plans:
        try:
            key = _operation_key(hint)
            # Rejected rows cannot leave partial registration side effects.
            with project.transaction():
                operation = register_operation(project, _preserve_destination(hint, existing.get(key)))
        except ValueError:
            skipped.append({"legacy_id": _identifier(endpoint.get("url_id")),
                            "reason": "Operation rejected by the destination project contract or scope"})
            continue
        if not isinstance(operation, dict) or not operation.get("id"):
            raise ValueError("Operation registration returned no operation ID")
        imported.append(operation["id"])
        existing[key] = operation
        reference = _reference(endpoint.get("url_id"))
        if reference is not None and reference_counts[reference] == 1:
            mapping[reference] = operation["id"]
    for index, finding in enumerate(legacy_findings):
        old_id = _identifier(finding.get("finding_id", index))
        key = str(source) + "\0" + str(findings_hash) + "\0" + old_id + "\0" + str(index)
        candidate_id = "C-legacy-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:24]
        candidate = {
            "id": candidate_id, "kind": "legacy_finding", "status": "unverified",
            "title": safe_text(finding.get("name", finding.get("title", "Imported legacy finding"))),
            "category": _identifier(finding.get("category", "unknown")),
            "severity": _identifier(finding.get("severity", "unknown")),
            "origin": "imported", "legacy_id": old_id,
            "legacy_url_id": _identifier(finding.get("url_id")),
            "legacy_status": _identifier(finding.get("status", "unknown")),
            "legacy_origin": _identifier(finding.get("origin", "unknown")),
            "source": {"path": "findings.json", "sha256": findings_hash,
                       "locator": "/findings/" + str(index), "trust": "unknown"},
            "limitations": ["Historical conclusion imported as an unverified candidate; no sessions, credentials, or evidence copied."],
        }
        operation_id = mapping.get(_reference(finding.get("url_id")))
        if operation_id:
            candidate["operation_id"] = operation_id
        else:
            unmapped_findings += 1
            candidate["limitations"].append("No unique imported operation matches the legacy URL ID; manual mapping is required.")
        # 重复导入不增殖，也不覆盖人工处置（linked/dismissed 状态保留）。
        _, is_new = store_candidate(project, candidate)
        created_candidates += 1 if is_new else 0
    result = {"operations_imported": len(set(imported)), "operation_ids": sorted(set(imported)),
              "operation_mapping": mapping,
              "ambiguous_legacy_ids": sorted(key for key, count in reference_counts.items() if key is not None and count > 1),
              "unmapped_findings": unmapped_findings,
              "candidates_created": created_candidates, "legacy_findings_seen": len(legacy_findings),
              "skipped_operations": skipped, "source_hashes": {"inventory.json": inventory_hash,
                  **({"config.json": config_hash} if config_hash else {}),
                  **({"findings.json": findings_hash} if findings_hash else {})},
              "source_modified": False, "verification_inherited": False,
              "limitations": ["Only inventory and finding metadata were imported; config was used solely to resolve relative URLs.",
                  "Legacy tested/confirmed flags do not satisfy destination obligations.",
                  "Identity, tenant, consumer, and runtime evidence require fresh validation."]}
    project.event("legacy.imported", result)
    return result
