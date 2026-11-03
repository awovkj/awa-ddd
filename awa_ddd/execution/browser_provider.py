"""Browser provider: real Playwright visits and application-triggered XSS evidence.

Imported MCP observations never satisfy authenticated typed closure; only a
locally verified visit with application-triggered dialogs and same-identity
controls can feed the ``browser_runtime`` oracle.
"""
from __future__ import annotations

from .. import browser, engine
from ..domain.common import digest, fail
from . import oracle_profiles


def visit(project, args):
    result = browser.visit(project, args)
    return result


def evaluate_xss(project, *, consumer_url, marker, attack_visit_id, normal_visit_id,
                 writer_attack_evidence_id, writer_normal_evidence_id):
    """Evaluate a cross-role stored/reflected XSS chain from real observations."""
    marker = str(marker or "").strip()
    if not marker or len(marker) > 128:
        fail("v2_browser_marker", "Application-triggered marker is required")
    try:
        attack_record, attack = browser._verified_visit(project, attack_visit_id, consumer_url)
        normal_record, normal = browser._verified_visit(project, normal_visit_id, consumer_url)
    except (engine.EngineError, OSError, ValueError, KeyError) as exc:
        fail("v2_browser_visit", "Browser visits must be current, successful and on the consumer page")
    if attack_record.get("source") != "local_playwright" or normal_record.get("source") != "local_playwright":
        fail("v2_browser_visit", "Authenticated XSS typed closure requires locally recorded Playwright visits, not imported MCP JSON")
    attack_dialogs = [row for row in attack.get("dialogs", []) if marker in str(row.get("message", ""))]
    normal_dialogs = [row for row in normal.get("dialogs", []) if marker in str(row.get("message", ""))]
    writer_attack = project.get("evidence", writer_attack_evidence_id)
    writer_normal = project.get("evidence", writer_normal_evidence_id)
    same_identity = attack_record.get("actor_id") == normal_record.get("actor_id") and \
        attack_record.get("session_id") == normal_record.get("session_id")
    observations = {
        "trigger_source": "application" if attack_dialogs else "none",
        "application_triggered": bool(attack_dialogs),
        "attack_dialog": bool(attack_dialogs),
        "normal_dialog": bool(normal_dialogs),
        "consumer_page": consumer_url,
        "same_identity": bool(same_identity),
        "content_version": digest({"attack": writer_attack.get("sha256"), "normal": writer_normal.get("sha256")}),
        "writer_attack_evidence": writer_attack["id"],
        "writer_normal_evidence": writer_normal["id"],
    }
    result = oracle_profiles.evaluate("browser_runtime", observations)
    result["observations"] = observations
    return result
