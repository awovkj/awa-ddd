"""Compatibility shim for the legacy reporting module plus 2.0 matrix exports.

Existing imports such as ``from awa_ddd.reporting import build_report`` keep
working; new code imports the multi-dimensional matrix from this package.
"""
from __future__ import annotations

# Keep the legacy module's module-level handles patchable through this package
# (tests and integrations patch awa_ddd.reporting.os/time directly).
import os
import time

# Re-export the exact legacy surface (including the private key set used by
# publication) so moving the module into a package does not change callers.
from ..reporting_legacy import (
    _PRIVATE_KEYS,
    _check_plain_path,
    _publish_report,
    build_report,
    coverage,
    public_integrity_metadata,
    safe_metadata,
    safe_text,
    safe_url,
)
from .matrix import build_v2_report, compare, matrix

__all__ = [
    "build_report", "build_v2_report", "compare", "coverage", "matrix",
    "public_integrity_metadata", "safe_metadata", "safe_text", "safe_url",
]
