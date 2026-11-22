"""Deploy-bound, exact-input applicability; ordinary responses are not exclusions."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from .store import EngineError, canonical, now

SCHEMA = "awa-applicability/v1"


def _proof_shape(proof):
    required = ("build_evidence_id", "build_selector", "deployment_id", "manifest_sha256_selector",
                "predicate_selector", "reviewer", "reason")
    if not isinstance(proof, dict) or proof.get("type") != "deployment_manifest":
        raise EngineError("applicability_verifier", "Use a typed deployment manifest and a current deployment observation")
    for key in required:
        value = proof.get(key)
        if not isinstance(value, str) or not value.strip() or len(value) > (4000 if key == "reason" else 2048) \
                or any(ord(char) < 32 for char in value):
            raise EngineError("applicability_review" if key in {"reviewer", "reason"} else "applicability_binding",
                              "Applicability requires a bounded " + key)
    for key in ("build_selector", "manifest_sha256_selector", "predicate_selector"):
        if not proof[key].startswith("/"):
            raise EngineError("applicability_selector", "Applicability selectors must be exact JSON pointers")
    if proof.get("reviewer_type", "agent_recorded") != "agent_recorded":
        raise EngineError("applicability_review", "The tool context cannot authenticate independent human approval")


def _pointer(value, selector):
    if not isinstance(selector, str) or not selector.startswith("/") or len(selector) > 2048:
        raise EngineError("applicability_selector", "Applicability requires an exact JSON pointer")
    for part in selector[1:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        try:
            value = value[int(part)] if isinstance(value, list) else value[part]
        except (KeyError, IndexError, ValueError, TypeError):
            raise EngineError("applicability_predicate", "Missing or unobserved values do not prove inapplicability") from None
    return value


def binding(project, item):
    from .engine import operation_signature
    from .completeness import obligation_family
    operation = project.get("operation", item["operation_id"])
    family = item.get("family") or obligation_family(item, operation)
    if family in {"generic", "access_control", "business_logic"} or item.get("kind") not in {"input_test", "hypothesis"}:
        raise EngineError("applicability_scope", "Applicability only excludes one mechanism-specific input property")
    if item.get("input_location") not in {"query", "body", "path", "header", "cookie"} \
            or not isinstance(item.get("input_selector"), str) or not item["input_selector"]:
        raise EngineError("applicability_scope", "Applicability needs a precise registered input selector")
    return {"operation_id": operation["id"], "operation_signature": operation_signature(operation),
            "input_location": item.get("input_location"), "input_selector": item.get("input_selector"),
            "schema_branch": item.get("schema_branch"), "test_family": family}


def _build(project, proof, expected_bindings, material_sha256):
    from .engine import verify_current_evidence
    from .transport import response_json
    evidence, artifact = verify_current_evidence(project, proof["build_evidence_id"])
    if evidence["operation_id"] != expected_bindings["operation_id"]:
        raise EngineError("applicability_binding", "Deployment observation must belong to the same exact operation")
    actual_build = _pointer(response_json(artifact), proof["build_selector"])
    if not isinstance(actual_build, str) or not actual_build or actual_build != proof.get("deployment_id"):
        raise EngineError("applicability_build", "Manifest deployment does not match the current observed build")
    actual_digest = _pointer(response_json(artifact), proof.get("manifest_sha256_selector"))
    if not isinstance(actual_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", actual_digest) or actual_digest != material_sha256:
        raise EngineError("applicability_material", "The deployed response must authenticate the exact manifest SHA-256")
    # New deployment observations invalidate old receipts even when the old
    # response remains a valid historical artifact with the same operation ID.
    with project._lock:
        later = project.connection.execute(
            "SELECT id FROM entities WHERE kind='evidence' AND json_extract(document,'$.operation_id')=? "
            "AND created_at>(SELECT created_at FROM entities WHERE kind='evidence' AND id=?) ORDER BY created_at DESC,id DESC",
            (expected_bindings["operation_id"], evidence["id"])).fetchall()
    for row in later:
        try:
            _, observed = verify_current_evidence(project, row[0])
            observed_json = response_json(observed)
            newer_build = _pointer(observed_json, proof["build_selector"])
            newer_digest = _pointer(observed_json, proof["manifest_sha256_selector"])
        except (EngineError, KeyError, ValueError, TypeError, OSError):
            continue
        if newer_build != actual_build or newer_digest != actual_digest:
            raise EngineError("applicability_build", "A newer deployment observation supersedes this applicability material")
        break
    return evidence


def validate_manifest(project, item, proof, manifest, *, material_sha256=None):
    _proof_shape(proof)
    exact = binding(project, item)
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA or manifest.get("bindings") != exact \
            or manifest.get("deployment_id") != proof.get("deployment_id"):
        raise EngineError("applicability_binding", "Manifest must bind the exact deployed operation, input branch and test family")
    if not isinstance(proof.get("reviewer"), str) or not proof["reviewer"].strip() \
            or not isinstance(proof.get("reason"), str) or not proof["reason"].strip():
        raise EngineError("applicability_review", "Applicability needs an explicit reviewer and the source interpretation")
    material_sha256 = material_sha256 or hashlib.sha256(canonical(manifest).encode("utf-8")).hexdigest()
    evidence = _build(project, proof, exact, material_sha256)
    # A declared whitebox fact must be present and exactly false. Neither an
    # omitted property nor a normal HTTP output permits an entire family waiver.
    if _pointer(manifest, proof.get("predicate_selector")) is not False:
        raise EngineError("applicability_predicate", "The exact manifest precondition must be explicitly false")
    return exact, evidence


def capture_manifest(project, item, proof):
    """Shared validation/material capture; the facade owns its receipt type."""
    if not isinstance(proof, dict) or not isinstance(proof.get("path"), str):
        raise EngineError("applicability_material", "Applicability requires an explicit local deployment manifest")
    _proof_shape(proof)
    path = Path(proof["path"])
    if path.is_symlink() or path.name.lower().startswith(".env") or path.suffix.lower() in {".pem", ".key"}:
        raise EngineError("applicability_material", "Secret files and links are not applicability manifests")
    try:
        path = path.resolve(strict=True)
    except (OSError, ValueError) as exc:
        raise EngineError("applicability_material", "Applicability manifest could not be read") from exc
    if not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise EngineError("applicability_material", "Manifest must be a UTF-8 JSON file of at most 1 MiB")
    data = path.read_bytes()
    if len(data) > 1024 * 1024:
        raise EngineError("applicability_material", "Manifest exceeds its byte budget")
    try:
        manifest = json.loads(data.decode("utf-8-sig"))
    except (UnicodeError, ValueError) as exc:
        raise EngineError("applicability_material", "Applicability manifest must be strict UTF-8 JSON") from exc
    exact, evidence = validate_manifest(project, item, proof, manifest, material_sha256=hashlib.sha256(data).hexdigest())
    material = project.material(data)
    public_proof = {key: proof[key] for key in ("type", "build_evidence_id", "build_selector", "deployment_id",
                                              "manifest_sha256_selector", "predicate_selector", "reviewer", "reason")}
    return exact, evidence, material, public_proof


def accept(project, item, proof):
    exact, evidence, material, public_proof = capture_manifest(project, item, proof)
    facts = {"schema": SCHEMA, "subject_id": item["id"], "bindings": exact, "material_id": material["id"],
             "material_sha256": material["sha256"], "build_evidence_sha256": evidence["sha256"],
             "proof": public_proof, "scope_sha256": hashlib.sha256(canonical([project.config.get("scope"),
                 project.config.get("exclude")]).encode("utf-8")).hexdigest(), "decision": "accepted",
             "reviewer_assurance": "agent_recorded", "machine_proof": False,
             "counts_as_tested": False, "site_wide_discovery_allowed": False}
    identity = "AR-" + hashlib.sha256(canonical(facts).encode("utf-8")).hexdigest()
    receipt = {"id": identity, **facts, "created_at": now()}
    if not project.get("applicability_receipt", identity, required=False):
        project.put("applicability_receipt", receipt, create_only=True)
    return receipt


def current(project, item):
    try:
        receipt = project.get("applicability_receipt", item.get("applicability_receipt_id"))
        material, manifest = project.read_material(receipt["material_id"])
        exact, evidence = validate_manifest(project, item, receipt["proof"], manifest, material_sha256=material["sha256"])
        expected_scope = hashlib.sha256(canonical([project.config.get("scope"), project.config.get("exclude")]).encode("utf-8")).hexdigest()
        facts = {key: value for key, value in receipt.items() if key not in {"id", "created_at"}}
        if receipt["id"] != "AR-" + hashlib.sha256(canonical(facts).encode("utf-8")).hexdigest():
            return False
        return receipt["subject_id"] == item["id"] and receipt["bindings"] == exact \
            and receipt["build_evidence_sha256"] == evidence["sha256"] and receipt["scope_sha256"] == expected_scope \
            and receipt["material_sha256"] == material["sha256"]
    except (EngineError, OSError, ValueError, KeyError, TypeError):
        return False


def v2_receipt_current(project, receipt):
    """Revalidate a V2 applicability receipt against live bytes and deployment."""
    try:
        if receipt.get("schema") != 2 or receipt.get("kind") != "applicability" \
                or receipt.get("decision") != "accepted":
            return False, "applicability receipt schema or decision is invalid"
        bindings = receipt.get("bindings") or {}
        branch = receipt.get("input_branch") or {}
        item = {
            "id": receipt["hypothesis_id"],
            "kind": "hypothesis",
            "operation_id": bindings["operation_id"],
            "family": bindings["test_family"],
            "input_location": bindings["input_location"],
            "input_selector": bindings["input_selector"],
            "schema_branch": bindings.get("schema_branch"),
        }
        if branch != {
                "location": item["input_location"],
                "selector": item["input_selector"],
                "schema_branch": item["schema_branch"]}:
            return False, "applicability input branch changed"
        manifest_material = receipt.get("manifest_material") or {}
        material, manifest = project.read_material(manifest_material["material_id"])
        if material.get("sha256") != manifest_material.get("material_sha256"):
            return False, "applicability manifest material changed"
        exact, evidence = validate_manifest(
            project, item, receipt["proof"], manifest,
            material_sha256=material["sha256"],
        )
        if exact != bindings:
            return False, "applicability operation or input binding changed"
        if evidence.get("sha256") != manifest_material.get("build_evidence_sha256"):
            return False, "applicability build observation changed"
        return True, "current"
    except (EngineError, OSError, ValueError, KeyError, TypeError):
        return False, "applicability material or deployment observation is invalid"
