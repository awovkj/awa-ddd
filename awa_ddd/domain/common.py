"""Shared validation and identity primitives for AWA-DDD 2.0 domain objects.

The 2.0 layer stores plain JSON documents (the v1 store is document oriented),
but every document is created and mutated through these validators so that a
caller cannot smuggle caller-supplied numerators, proof scopes, or security
control overrides into an entity.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timezone

from ..error_registry import require_validator_code
from ..store import EngineError, canonical, now


MAX_TEXT = 4000
MAX_ID = 128
_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")


def fail(code: str, message: str, **details):
    raise EngineError(code, message, details or None)


def text(value, name, *, maximum=MAX_TEXT, allow_empty=False):
    code = require_validator_code("text", name)
    if not isinstance(value, str):
        fail(code, f"{name} must be a string")
    value = value.strip()
    if not allow_empty and not value:
        fail(code, f"{name} must be nonempty")
    if len(value) > maximum:
        fail(code, f"{name} exceeds {maximum} characters")
    return value


def optional_text(value, name, *, maximum=MAX_TEXT):
    if value is None:
        return None
    return text(value, name, maximum=maximum)


def identifier(value, name):
    if not isinstance(value, str) or not _ID_RE.match(value):
        # The repository has no static identifier-validator call sites, so
        # these names are intentionally left to publication's error fallback.
        fail("v2_" + name, f"{name} must be a stable identifier")
    return value


def enum(value, name, choices):
    code = require_validator_code("enum", name)
    if value not in choices:
        fail(code, f"{name} must be one of: " + ", ".join(sorted(choices)))
    return value


def integer(value, name, *, minimum=0, maximum=None):
    code = require_validator_code("integer", name)
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        fail(code, f"{name} must be an integer in {minimum}..{maximum if maximum is not None else 'inf'}")
    return value


def boolean(value, name):
    code = require_validator_code("boolean", name)
    if type(value) is not bool:
        fail(code, f"{name} must be a boolean")
    return value


def mapping(value, name):
    code = require_validator_code("mapping", name)
    if not isinstance(value, dict):
        fail(code, f"{name} must be an object")
    return value


def sequence(value, name, *, maximum=4096):
    code = require_validator_code("sequence", name)
    if not isinstance(value, list) or len(value) > maximum:
        fail(code, f"{name} must be an array of at most {maximum} entries")
    return value


def string_list(value, name, *, maximum=256, allowed=None):
    code = require_validator_code("text", name)
    sequence(value, name, maximum=maximum)
    result = []
    for item in value:
        item = text(item, name, maximum=256)
        if allowed is not None and item not in allowed:
            fail(code, f"{name} contains unsupported value")
        if item not in result:
            result.append(item)
    return result


def timestamp(value, name="timestamp"):
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError()
        return parsed
    except (TypeError, ValueError):
        fail("v2_timestamp", f"{name} must be a timezone-aware ISO-8601 timestamp")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def stable_id(prefix, value, *, length=24):
    return prefix + "-" + digest(value)[:length]


def clone(value):
    return json.loads(canonical(value))


def finite_number(value, name):
    if type(value) not in {int, float} or not math.isfinite(value):
        fail("v2_" + name, f"{name} must be a finite number")
    return value


def public_ref(kind, identity, *, digest_value=None):
    row = {"kind": kind, "id": identity}
    if digest_value:
        row["sha256"] = digest_value
    return row
