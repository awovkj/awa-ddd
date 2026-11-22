"""Evidence-bound reviewed detection for mechanisms without V1 machine oracles.

The conclusions are deliberately narrow. Three request controls and actual
consumer/readback material are required; prose and profile flags cannot supply
an observation. Both facades use this verifier.
"""
from __future__ import annotations

import base64
import hashlib
import json
import posixpath
import re
from urllib.parse import unquote, urlsplit

from .store import EngineError, canonical, now

SCHEMA = "awa-reviewed-detection/v1"
PROFILES = {"template_injection": "unexpected_expression_evaluation", "command_injection": "bounded_side_effect",
            "deserialization": "unsafe_type_instantiation", "file_upload": "upload_path_escape"}
_EXPRESSION = re.compile(r"(\{\{|\$\{|<%=)\s*([0-9]{1,3})\s*([*+\-])\s*([0-9]{1,3})\s*(\}\}|\}|%>)")


def _sha(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _same(left, right):
    from .transport import json_equal
    return json_equal(left, right) or type(left) is str and type(right) in {int, float} and left == str(right)


def _controls(project, item, spec):
    from .assessment import _observations, _input_controls, _input_view
    from .engine import operation_signature
    operation = project.get("operation", item["operation_id"])
    family = item.get("test_family") or item.get("family")
    if family not in PROFILES or spec.get("profile") != PROFILES[family]:
        raise EngineError("reviewed_profile", "Reviewed proof requires the exact implemented family profile")
    if item.get("superseded") or item.get("kind") not in {"input_test", "hypothesis"}:
        raise EngineError("reviewed_binding", "Use one current mechanism-specific input obligation")
    ids = spec.get("evidence_ids")
    if not isinstance(ids, list) or len(ids) != 3 or any(not isinstance(identity, str) or not identity
            or len(identity) > 200 for identity in ids):
        raise EngineError("reviewed_controls", "Supply normal, attack and negative evidence IDs in that order")
    observations = _observations(project, ids, item)
    _input_controls(observations, item, operation)
    if any(not 200 <= artifact["response"]["status"] < 300 for _, artifact in observations):
        raise EngineError("reviewed_controls", "The selected profile requires successful normal, attack and negative controls")
    if len({meta.get("resource_id") for meta, _ in observations}) != 1:
        raise EngineError("reviewed_identity", "All request controls must use the same concrete resource")
    bindings = {"operation_id": operation["id"], "operation_signature": operation_signature(operation),
                "input_location": item.get("input_location"), "input_selector": item.get("input_selector"),
                "schema_branch": item.get("schema_branch"), "test_family": family,
                "actor_id": observations[0][0].get("actor_id"), "session_id": observations[0][0].get("session_id"),
                "session_generation": observations[0][0].get("session_generation"), "resource_id": observations[0][0].get("resource_id")}
    values = [_input_view(observation, item, operation)[0] for observation in observations]
    return operation, bindings, observations, values


def _readback(project, identity, source, *, selector):
    from .engine import verify_current_evidence
    from .assessment import _value
    meta, artifact = verify_current_evidence(project, identity)
    if meta["operation_id"] == source[0]["operation_id"] or artifact["request"]["method"] not in {"GET", "HEAD"}:
        raise EngineError("reviewed_readback", "Consumer readback must be a distinct read-only operation")
    for key in ("actor_id", "session_id", "session_generation"):
        if meta.get(key) != source[0].get(key):
            raise EngineError("reviewed_identity", "Readback must preserve the source control's identity")
    source_resource = project.get("resource", source[0].get("resource_id"), required=False)
    read_resource = project.get("resource", meta.get("resource_id"), required=False)
    if source_resource is None or read_resource is None or any(source_resource.get(key) != read_resource.get(key)
            for key in ("owner_actor_id", "tenant_id", "external_id")):
        raise EngineError("reviewed_identity", "Readback must observe the same owned concrete fixture")
    if meta.get("effect", "read_only") != "read_only" or not 200 <= artifact["response"]["status"] < 300:
        raise EngineError("reviewed_readback", "Consumer readback must be a complete successful read")
    from .engine import stamp
    if stamp(artifact.get("started_at")) < stamp(source[1].get("completed_at")):
        raise EngineError("reviewed_order", "A readback before its request control does not observe that effect")
    return (meta, artifact), _value((meta, artifact), selector)


def validate_reviewed_detection(project, item, spec):
    from .assessment import _value
    if not isinstance(spec, dict) or spec.get("schema", SCHEMA) != SCHEMA:
        raise EngineError("reviewed_proof", "A typed reviewed detection specification is required")
    if not isinstance(spec.get("reviewer"), str) or not spec["reviewer"].strip() \
            or not isinstance(spec.get("reason"), str) or not spec["reason"].strip():
        raise EngineError("reviewed_reviewer", "Reviewed detection needs an explicit recorded reviewer and interpretation")
    if spec.get("reviewer_type", "agent_recorded") != "agent_recorded":
        raise EngineError("reviewed_reviewer", "The tool context cannot authenticate independent human approval")
    operation, bindings, observations, values = _controls(project, item, spec)
    family, profile = bindings["test_family"], spec["profile"]
    selector = spec.get("selector")
    if not isinstance(selector, str) or not selector.startswith("/"):
        raise EngineError("reviewed_selector", "Use the exact observed JSON consumer selector")
    normal, attack, negative = [_value(observation, selector) for observation in observations]
    all_observations = list(observations)
    not_proven = ["arbitrary_code_execution", "other_inputs_or_deployments"]
    if family == "template_injection":
        expression = spec.get("expression")
        matched = _EXPRESSION.fullmatch(expression) if isinstance(expression, str) else None
        if not matched or values[1] != expression or {"{{": "}}", "${": "}", "<%=": "%>"}[matched[1]] != matched[5]:
            raise EngineError("reviewed_expression", "Bind one bounded arithmetic canary to the actual attack input")
        left, right = int(matched[2]), int(matched[4])
        expected = left * right if matched[3] == "*" else left + right if matched[3] == "+" else left - right
        if str(expected) in expression or not _same(attack, expected) or not _same(normal, values[0]) \
                or not _same(negative, values[2]) or _EXPRESSION.fullmatch(str(values[2])):
            raise EngineError("reviewed_expression", "Actual normal and negative literals must discriminate evaluation from reflection")
        consumer = next((entry.get("consumer", "") for entry in operation.get("inputs", [])
                         if entry.get("location") == bindings["input_location"] and entry.get("selector") == bindings["input_selector"]
                         and entry.get("schema_branch") == bindings["schema_branch"]), "")
        if any(term in str(consumer).lower() for term in ("calculator", "formula", "arithmetic_feature")):
            raise EngineError("reviewed_expression", "An intentionally declared arithmetic feature is not a template injection proof")
        observation = {"normal": normal, "attack": attack, "negative": negative, "expected_arithmetic_result": expected}
    elif family in {"command_injection", "deserialization"}:
        marker = spec.get("marker")
        readbacks = spec.get("readback_evidence_ids")
        resource = project.get("resource", bindings["resource_id"], required=False) if bindings["resource_id"] else None
        if not isinstance(marker, str) or not re.fullmatch(r"AWA-CANARY-[a-zA-Z0-9_-]{12,96}", marker) \
                or not isinstance(readbacks, list) or len(readbacks) != 3 or not resource:
            raise EngineError("reviewed_canary", "Side effects require an isolated registered fixture and three actual canary readbacks")
        if bindings["actor_id"] != resource.get("owner_actor_id"):
            raise EngineError("reviewed_identity", "Bounded canary evidence must be observed by the fixture owner")
        if family == "command_injection" and (not isinstance(values[1], str) or marker not in values[1]
                or not any(delimiter in values[1] for delimiter in (";", "|", "&&", "$("))):
            raise EngineError("reviewed_canary", "Command evidence must bind the isolated marker to the actual injected command input")
        consumer_values = []
        for role, source, input_value, identity in zip(("normal", "attack", "negative"), observations, values, readbacks):
            readback, value = _readback(project, identity, source, selector=spec.get("readback_selector", "/canary"))
            expected_effect = role == "attack"
            expected_mechanism = "command_executor" if family == "command_injection" else "unsafe_type_instantiation"
            if not isinstance(value, dict) or value.get("schema") != "awa-canary/v1" or value.get("marker") != marker \
                    or value.get("resource_id") != resource["id"] or value.get("mechanism") != expected_mechanism \
                    or value.get("input_sha256") != _sha(input_value) or value.get("effect") is not expected_effect:
                raise EngineError("reviewed_canary", "The independent readback must authenticate the exact input and isolated canary effect")
            if family == "deserialization" and role == "attack":
                try:
                    parsed = json.loads(input_value) if isinstance(input_value, str) else input_value
                except ValueError:
                    raise EngineError("reviewed_canary", "Unsafe type input must be actual structured JSON") from None
                if not isinstance(parsed, dict) or not isinstance(parsed.get("@type"), str) or value.get("instantiated_type") != parsed["@type"]:
                    raise EngineError("reviewed_canary", "Unsafe type proof must bind the actual instantiated attack type")
            all_observations.append(readback)
            consumer_values.append(value)
        if len({meta["operation_id"] for meta, _ in all_observations[3:]}) != 1:
            raise EngineError("reviewed_readback", "Canary readbacks must use the same independent consumer")
        observation = {"readbacks": consumer_values}
        not_proven.append("unbounded_command_or_gadget_chains")
    else:
        root, marker = spec.get("allowed_root"), spec.get("marker")
        if not isinstance(root, str) or not root.startswith("/") or root == "/" or "\x00" in root \
                or not isinstance(marker, str) or not re.fullmatch(r"AWA-UPLOAD-[a-zA-Z0-9_-]{12,96}", marker):
            raise EngineError("reviewed_upload", "Upload review needs a declared absolute storage root and isolated content marker")
        root = posixpath.normpath(root)
        paths = [posixpath.normpath(unquote(str(value))) for value in (normal, attack, negative)]
        if not paths[0].startswith(root + "/") or not paths[2].startswith(root + "/") \
                or not paths[1].startswith("/") or paths[1] == root or paths[1].startswith(root + "/"):
            raise EngineError("reviewed_upload", "Actual normal/negative storage paths must stay inside the root and the attack must escape it")
        body = base64.b64decode(observations[1][1]["request"].get("body_base64", ""), validate=True)
        if marker.encode("utf-8") not in body or marker in str(values[1]) or not bindings["resource_id"]:
            raise EngineError("reviewed_upload", "Owned content must be independent of the selected filename and bound to a fixture")
        resource = project.get("resource", bindings["resource_id"])
        if bindings["actor_id"] != resource.get("owner_actor_id"):
            raise EngineError("reviewed_identity", "Upload path review requires the disposable fixture owner")
        readback, content = _readback(project, spec.get("readback_evidence_id"), observations[1], selector=spec.get("readback_selector", "/content"))
        if content != marker or posixpath.normpath(unquote(urlsplit(readback[1]["request"]["url"]).path)) != paths[1]:
            raise EngineError("reviewed_upload", "Read back the owned exact content at the observed escaped path")
        all_observations.append(readback)
        observation = {"allowed_root": root, "normal_path": paths[0], "attack_path": paths[1], "negative_path": paths[2], "readback_sha256": _sha(content)}
    ids = [meta["id"] for meta, _ in all_observations]
    if len(set(ids)) != len(ids):
        raise EngineError("reviewed_controls", "Request controls and consumer readbacks must be distinct executions")
    return {"schema": SCHEMA, "profile": profile, "bindings": bindings, "evidence_ids": ids,
            "digests": {meta["id"]: meta["sha256"] for meta, _ in all_observations},
            "proof_scope": profile, "not_proven": not_proven, "observation_sha256": _sha(observation),
            "reviewer_assurance": "agent_recorded", "machine_proof": False, "rules_version": 1}


def prepare(project, item, spec):
    """Validate a reviewed detection without persisting any authority."""
    verified = validate_reviewed_detection(project, item, spec)
    material_bytes = canonical(spec).encode("utf-8")
    material_digest = hashlib.sha256(material_bytes).hexdigest()
    material_id = "MAT-" + material_digest
    facts = {
        **verified,
        "subject_id": item["id"],
        "material_id": material_id,
        "material_sha256": material_digest,
        "scope_sha256": _sha([
            project.config.get("scope"), project.config.get("exclude")]),
    }
    identity = "RPR-" + _sha(facts)
    receipt = {"id": identity, **facts, "created_at": now()}
    return {"receipt": receipt, "material_bytes": material_bytes}


def persist(project, prepared):
    """Persist one already validated review proof inside the caller transaction."""
    if not isinstance(prepared, dict) or not isinstance(prepared.get("receipt"), dict) \
            or not isinstance(prepared.get("material_bytes"), bytes):
        raise EngineError("reviewed_proof", "A prepared reviewed proof is required")
    material = project.material(prepared["material_bytes"])
    receipt = prepared["receipt"]
    if material["id"] != receipt.get("material_id") \
            or material["sha256"] != receipt.get("material_sha256"):
        raise EngineError("reviewed_receipt", "Prepared reviewed material changed before persistence")
    if not project.get("review_proof_receipt", receipt["id"], required=False):
        project.put("review_proof_receipt", receipt, create_only=True)
    return receipt


def accept(project, item, spec):
    prepared = prepare(project, item, spec)
    return persist(project, prepared)


def current(project, decision, category=None):
    from .assessment import _category_family
    receipt = project.get("review_proof_receipt", decision.get("review_proof_receipt_id"))
    facts = {key: value for key, value in receipt.items() if key not in {"id", "created_at"}}
    if receipt["id"] != "RPR-" + _sha(facts):
        raise EngineError("reviewed_receipt", "Reviewed proof receipt identity changed")
    material, spec = project.read_material(receipt["material_id"])
    item = project.get("obligation", receipt["subject_id"], required=False)
    if item is None:
        item = project.get("v2_hypothesis", receipt["subject_id"], required=False)
    if item is None:
        raise EngineError("reviewed_binding", "Reviewed proof subject no longer exists")
    verified = validate_reviewed_detection(project, item, spec)
    expected_proof = {key: receipt[key] for key in
                      ("schema", "profile", "proof_scope", "not_proven", "reviewer_assurance", "machine_proof")}
    if any(canonical(receipt.get(key)) != canonical(value) for key, value in verified.items()) \
            or receipt["material_sha256"] != material["sha256"] \
            or receipt["scope_sha256"] != _sha([project.config.get("scope"), project.config.get("exclude")]) \
            or decision.get("obligation_id") != item["id"] or decision.get("evidence_ids") != receipt["evidence_ids"] \
            or decision.get("proof") != expected_proof or decision.get("operation_id") != receipt["bindings"]["operation_id"] \
            or decision.get("operation_signature") != receipt["bindings"]["operation_signature"] \
            or decision.get("oracle") != {"type": "reviewed_detection", "test_family": receipt["bindings"]["test_family"]}:
        raise EngineError("reviewed_receipt", "Reviewed proof no longer matches current material and exact input")
    if category is not None and _category_family(category) != receipt["bindings"]["test_family"]:
        raise EngineError("oracle_family", "Finding category differs from the reviewed mechanism")
    return receipt
