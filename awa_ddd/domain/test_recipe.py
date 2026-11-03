"""Immutable TestRecipe revisions with a private executable capsule.

A recipe binds every fact that could change the meaning of an experiment:
operation signature, scope epoch, session generation, fixture revision, oracle
version, rule/provider versions and the exact control requests.  Public
projections carry only references and bounded control descriptors; the
executable bytes stay in the private capsule.
"""
from __future__ import annotations

import re

from .common import clone, digest, enum, fail, integer, mapping, optional_text, sequence, stable_id, string_list, text, utc_now

PROVIDERS = {"http", "browser", "scenario", "external"}
EFFECTS = {"read_only", "test_resource_write"}
ORACLE_TYPES = {
    "baseline", "authorization", "semantic_negative", "state_invariant", "state_transition",
    "extraction", "error_channel", "sql_metadata", "expression_evaluation",
    "parser_identification", "unexpected_expression_evaluation", "unsafe_type_instantiation",
    "bounded_side_effect", "upload_path_escape", "browser_runtime", "race", "token_lifecycle",
}
PROOF_SCOPES = {
    "baseline_observation", "authorization_boundary", "semantic_refutation",
    "state_invariant_observation", "state_transition", "extraction_observation",
    "error_channel_observation", "sql_metadata_observation", "parser_identification",
    "unexpected_expression_evaluation", "unsafe_type_instantiation", "bounded_side_effect",
    "upload_path_escape", "browser_runtime_xss", "race_condition", "token_lifecycle",
}
CONTROL_ROLES = ("normal", "attack", "negative")
VARIABLE_RE = re.compile(r"\{\{([a-z][a-z0-9_]{0,63})\}\}")


def new_recipe(*, hypothesis, provider, bindings, control_groups, oracle, steps, limits,
               variables=None, private_manifest=None, created_by="engine", revision=1):
    """Create a frozen recipe.  The caller cannot pass a precomputed spec_hash."""
    provider = mapping(provider, "provider")
    enum(provider.get("name"), "provider_name", PROVIDERS)
    text(provider.get("profile", ""), "provider_profile", maximum=128)
    text(provider.get("version", "1"), "provider_version", maximum=64)
    bindings = mapping(bindings, "bindings")
    for field in ("scope_epoch", "target_build", "operation_id", "operation_signature"):
        text(bindings.get(field), "binding_" + field, maximum=256)
    groups = sequence(control_groups, "control_groups", maximum=8)
    if not groups:
        fail("v2_recipe_controls", "At least one control group is required")
    group_ids = set()
    for group in groups:
        mapping(group, "control_group")
        group_id = text(group.get("id"), "control_group_id", maximum=64)
        if group_id in group_ids:
            fail("v2_recipe_controls", "Control group IDs must be unique")
        group_ids.add(group_id)
        text(group.get("identity_role"), "control_group_identity", maximum=64)
        controls = sequence(group.get("controls"), "controls", maximum=8)
        roles = []
        for control in controls:
            mapping(control, "control")
            role = enum(control.get("role"), "control_role", set(CONTROL_ROLES) | {"sensitivity"})
            roles.append(role)
            request = mapping(control.get("request"), "control_request")
            text(request.get("url"), "control_url", maximum=8192)
            text(request.get("method"), "control_method", maximum=16)
        if "normal" not in roles or "attack" not in roles or "negative" not in roles:
            fail("v2_recipe_controls", f"Control group {group_id} needs normal, attack and negative controls")
    oracle = mapping(oracle, "oracle")
    enum(oracle.get("type"), "oracle_type", ORACLE_TYPES)
    enum(oracle.get("proof_scope"), "proof_scope", PROOF_SCOPES)
    text(oracle.get("version", "1"), "oracle_version", maximum=64)
    sequence(steps, "steps", maximum=25)
    limits = mapping(limits, "limits")
    integer(limits.get("step_total", len(steps)), "step_total", minimum=1, maximum=25)
    integer(limits.get("time_ms", 120000), "time_ms", minimum=100, maximum=600000)
    writes = integer(limits.get("max_writes", 0), "max_writes", minimum=0, maximum=1)
    effect = enum(limits.get("effect", "read_only"), "effect", EFFECTS)
    if effect == "test_resource_write":
        if writes != 1:
            fail("v2_recipe_effect", "Write recipes require max_writes:1")
        if not bindings.get("fixture"):
            fail("v2_recipe_fixture", "Write recipes require a frozen fixture binding")
    elif writes != 0:
        fail("v2_recipe_effect", "Read-only recipes cannot declare writes")
    variables = mapping(variables or {}, "variables")
    for name, rule in variables.items():
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name):
            fail("v2_recipe_variable", "Variable names must be lowercase identifiers")
        mapping(rule, "variable_rule")
        enum(rule.get("source", "caller"), "variable_source", {"caller"})
        integer(rule.get("max_length", 64), "variable_max_length", minimum=1, maximum=1024)
        if rule.get("pattern") is not None:
            text(rule["pattern"], "variable_pattern", maximum=256)
            try:
                re.compile(rule["pattern"])
            except re.error:
                fail("v2_recipe_variable", "Variable pattern is not a valid regular expression")
    private = private_manifest if isinstance(private_manifest, dict) else {}
    if not private:
        private = {"control_groups": clone(groups), "bindings": clone(bindings), "oracle": clone(oracle)}
    _validate_variable_placement(variables, private)
    spec = {
        "hypothesis_id": hypothesis["id"],
        "revision": integer(revision, "revision", minimum=1, maximum=100000),
        "provider": {"name": provider["name"], "profile": provider.get("profile", ""),
                     "version": provider.get("version", "1")},
        "bindings": clone(bindings),
        "control_groups": clone(groups),
        "oracle": clone(oracle),
        "steps": clone(steps),
        "limits": clone(limits),
        "variables": clone(variables),
        "private": clone(private),
        "rule_version": "2.0",
        "created_by": text(created_by, "created_by", maximum=64),
    }
    spec_hash = digest(spec)
    public_spec = {key: spec[key] for key in ("hypothesis_id", "revision", "provider", "bindings",
                                              "control_groups", "oracle", "steps", "limits",
                                              "variables", "rule_version")}
    recipe = {
        "schema": 2,
        "id": stable_id("REC", {"hypothesis": hypothesis["id"], "spec": spec_hash}, length=24),
        "hypothesis_id": hypothesis["id"],
        "family": hypothesis.get("family"),
        "revision": spec["revision"],
        "spec_hash": spec_hash,
        "public_hash": digest(public_spec),
        "provider": spec["provider"],
        "bindings": spec["bindings"],
        "control_groups": spec["control_groups"],
        "controls": [dict(control, group_id=group.get("id"))
                     for group in spec["control_groups"] for control in group.get("controls", [])],
        "oracle": spec["oracle"],
        "expected": spec["oracle"].get("expected_value"),
        "steps": spec["steps"],
        "limits": spec["limits"],
        "variables": spec["variables"],
        "private_capsule": spec["private"],
        "rule_version": spec["rule_version"],
        "created_by": spec["created_by"],
        "immutable": True,
        "created_at": utc_now(),
        "superseded": False,
        "superseded_by": None,
    }
    return recipe


def _validate_variable_placement(variables, private):
    """Placeholders may only change declared data values, never security controls."""

    def walk(node, path):
        if isinstance(node, dict):
            for key, value in node.items():
                key_text = str(key)
                if "{{" in key_text:
                    fail("v2_recipe_variable", "Variables cannot appear in object keys")
                walk(value, path + [key_text])
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, path + [str(index)])
        elif isinstance(node, str):
            names = VARIABLE_RE.findall(node)
            if not names:
                return
            lowered = [part.lower() for part in path]
            if any(part in {"method", "session_id", "resource_id", "operation_id", "effect",
                            "oracle", "expected", "expected_value", "provider"} for part in lowered):
                fail("v2_recipe_variable", "Variables cannot select a security control or oracle")
            if "headers" in lowered:
                fail("v2_recipe_variable", "Variables cannot rewrite authentication headers")
            for name in names:
                if name not in variables:
                    fail("v2_recipe_variable", f"Undeclared recipe variable: {name}")
            if "url" in lowered:
                before_query = node.split("?", 1)[0]
                if "{{" in before_query:
                    fail("v2_recipe_variable", "Variables may appear only in query values, not URL paths or hosts")

    walk(private, [])


def assert_override_allowed(recipe, overrides):
    """Only declared caller data variables may be overridden."""
    if overrides is None:
        return {}
    mapping(overrides, "overrides")
    unknown = sorted(set(overrides) - set(recipe.get("variables") or {}))
    if unknown:
        fail("v2_recipe_override", "Unsupported recipe overrides: " + ", ".join(unknown),
             allowed=sorted(recipe.get("variables") or {}))
    result = {}
    for name, value in overrides.items():
        rule = recipe["variables"][name]
        value = text(value, "variable_value", maximum=int(rule.get("max_length", 64)), allow_empty=True)
        if rule.get("pattern") and not re.fullmatch(rule["pattern"], value):
            fail("v2_recipe_override", f"Override {name} does not match its declared pattern")
        result[name] = value
    return result


def render(recipe, overrides=None):
    """Return the executable private manifest with only declared variables substituted."""
    values = assert_override_allowed(recipe, overrides)

    def substitute(node):
        if isinstance(node, dict):
            return {key: substitute(value) for key, value in node.items()}
        if isinstance(node, list):
            return [substitute(value) for value in node]
        if isinstance(node, str):
            return VARIABLE_RE.sub(lambda match: values.get(match.group(1), match.group(0)), node)
        return node

    return substitute(clone(recipe["private_capsule"]))


def assert_current(recipe, context):
    """Validate all frozen bindings against a current execution context."""
    bindings = recipe.get("bindings", {})
    current = mapping(context, "context")
    checks = {
        "scope_epoch": "scope_epoch",
        "target_build": "target_build",
        "operation_signature": "operation_signature",
    }
    for binding_key, context_key in checks.items():
        if bindings.get(binding_key) != current.get(context_key):
            fail("v2_recipe_stale", f"Recipe binding {binding_key} is stale; recompile the recipe",
                 binding=binding_key)
    session = bindings.get("session")
    if session:
        actual = current.get("session") or {}
        for key in ("session_id", "generation", "actor_id"):
            if session.get(key) != actual.get(key):
                fail("v2_recipe_stale", "Session generation or actor changed; recompile the recipe",
                     binding="session." + key)
    resource = bindings.get("resource")
    if resource:
        actual = current.get("resource") or {}
        if resource.get("resource_id") != actual.get("resource_id") \
                or resource.get("revision") != actual.get("revision"):
            fail("v2_recipe_stale", "Resource binding changed; recompile the recipe", binding="resource")
    fixture = bindings.get("fixture")
    if fixture:
        actual = current.get("fixture") or {}
        if fixture.get("fixture_id") != actual.get("fixture_id") \
                or fixture.get("revision") != actual.get("revision"):
            fail("v2_recipe_stale", "Fixture revision changed; recompile the recipe", binding="fixture")
    return True


def _request_shape(node):
    """Hash only request structure, never low-entropy values that could leak secrets."""
    if isinstance(node, dict):
        return {str(key): _request_shape(value) for key, value in node.items()}
    if isinstance(node, list):
        return [_request_shape(value) for value in node]
    if node is None:
        return "null"
    if isinstance(node, bool):
        return "bool"
    if isinstance(node, (int, float)):
        return "number"
    return "string"


def public_view(recipe, *, max_bytes=16384):
    """Bounded public capsule: references and control IDs, never credentials or request bodies."""
    view = {
        "id": recipe["id"],
        "hypothesis_id": recipe["hypothesis_id"],
        "family": recipe.get("family"),
        "revision": recipe.get("revision"),
        "spec_hash": recipe.get("public_hash"),
        "provider": dict(recipe.get("provider", {})),
        "oracle": {key: recipe.get("oracle", {}).get(key) for key in
                   ("id", "type", "version", "proof_scope", "expected_value", "selector")},
        "limits": dict(recipe.get("limits", {})),
        "control_groups": [
            {"id": group.get("id"), "identity_role": group.get("identity_role"),
             "resource_version": group.get("resource_version"),
             "controls": [{"id": control.get("id"), "role": control.get("role"),
                           "request_locator_sha256": digest(_request_shape(control.get("request", {})))[:32]}
                          for control in group.get("controls", [])]}
            for group in recipe.get("control_groups", [])
        ],
        "steps": [step if isinstance(step, str) else step.get("id") for step in recipe.get("steps", [])],
        "variable_names": sorted((recipe.get("variables") or {}).keys()),
        "private_ref": {"kind": "test_recipe", "id": recipe["id"],
                        "public_hash": recipe.get("public_hash")},
        "executable": False,
        "detail_action": {"action": "test.inspect", "input": {"recipe_id": recipe["id"]}},
        "notice": "Private request manifest and credentials stay in the protected local capsule. This projection is not executable.",
    }
    encoded = len(__import__("json").dumps(view, ensure_ascii=False, sort_keys=True).encode("utf-8"))
    if encoded > max_bytes:
        view["control_groups"] = view["control_groups"][:2]
        view["steps"] = view["steps"][:8]
        view["render_truncated"] = True
    return view
