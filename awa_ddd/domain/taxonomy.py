"""Canonical security-family taxonomy shared by V1, V2 and publication.

Family values are machine identifiers.  Legacy compatibility is deliberately
exact: aliases, translated labels and free-form hint text are not guessed into
security families.  Callers may use :func:`canonical_family` and handle ``None``
or use :func:`require_family` when an unknown value is an input error.
"""
from __future__ import annotations


FAMILIES = (
    "access_control",
    "sql_injection",
    "xss",
    "ssrf",
    "xxe",
    "path_traversal",
    "command_injection",
    "template_injection",
    "deserialization",
    "file_upload",
    "business_logic",
    "generic",
)

# V1 predates the explicit access-control family.  The other identifiers are
# intentionally identical so there is one canonical spelling in both models.
V1_FAMILIES = tuple(family for family in FAMILIES if family != "access_control")
V1_TO_V2 = {family: family for family in V1_FAMILIES}
V2_TO_V1 = {family: family for family in V1_FAMILIES}

FAMILY_LABELS = {
    "access_control": "Identity, role and resource authorization",
    "sql_injection": "SQL injection",
    "xss": "Cross-site scripting",
    "ssrf": "Server-side request forgery",
    "xxe": "XML external entity",
    "path_traversal": "Path traversal and file read",
    "command_injection": "Command injection",
    "template_injection": "Template injection",
    "deserialization": "Unsafe deserialization",
    "file_upload": "File upload",
    "business_logic": "Business logic and state transitions",
    "generic": "Unclassified input hypothesis",
}

# The channel describes what evidence can accept the family.  It never claims
# that a particular request or payload is sufficient.
PROOF_CHANNELS = {
    "access_control": ("authorization",),
    "sql_injection": ("sql_metadata", "error_channel"),
    "xss": ("browser_runtime",),
    "ssrf": ("extraction",),
    "xxe": ("extraction",),
    "path_traversal": ("extraction",),
    "command_injection": ("bounded_side_effect", "semantic_negative"),
    "template_injection": ("unexpected_expression_evaluation",),
    "deserialization": ("unsafe_type_instantiation",),
    "file_upload": ("upload_path_escape",),
    "business_logic": ("state_transition", "semantic_negative"),
    "generic": ("semantic_negative",),
}

FAMILY_ORACLE = {
    "access_control": "authorization",
    "sql_injection": "sql_metadata",
    "xss": "browser_runtime",
    "ssrf": "extraction",
    "xxe": "extraction",
    "path_traversal": "extraction",
    "command_injection": "bounded_side_effect",
    "template_injection": "unexpected_expression_evaluation",
    "deserialization": "unsafe_type_instantiation",
    "file_upload": "upload_path_escape",
    "business_logic": "state_transition",
    "generic": "semantic_negative",
}


def canonical_family(value, *, allow_v1=True):
    """Return the exact canonical family or ``None``.

    The function performs no case folding, prefix matching or natural-language
    inference.  Unknown and free-form values must remain unclassified.
    """
    if not isinstance(value, str):
        return None
    if value in FAMILIES:
        return value
    if allow_v1:
        return V1_TO_V2.get(value)
    return None


def require_family(value, *, error_prefix="v2_family"):
    """Return a canonical family or raise the project's typed input error."""
    family = canonical_family(value)
    if family is None:
        from .common import fail

        fail(error_prefix, "Unknown security family: " + repr(value))
    return family


def normalize_families(values, *, allow_v1=True, require_nonempty=True):
    """Validate, deduplicate and sort an exact family list without guessing."""
    if not isinstance(values, list) or len(values) > len(FAMILIES):
        from .common import fail

        fail("v2_family_list", "Security families must be a bounded array")
    normalized = []
    for value in values:
        family = canonical_family(value, allow_v1=allow_v1)
        if family is None:
            from .common import fail

            fail("v2_family", "Unknown security family: " + repr(value))
        normalized.append(family)
    normalized = sorted(set(normalized))
    if require_nonempty and not normalized:
        from .common import fail

        fail("v2_family_list", "At least one exact security family is required")
    return normalized


def family_to_v1(family):
    """Project a V2 family into V1, or ``None`` when V1 has no exact unit."""
    return V2_TO_V1.get(family)


def family_from_v1(family):
    """Map an exact V1 family into V2 without accepting new V1 inputs."""
    return V1_TO_V2.get(family)


def label(family):
    canonical = require_family(family)
    return FAMILY_LABELS[canonical]


def proof_channels(family):
    canonical = require_family(family)
    return list(PROOF_CHANNELS[canonical])
