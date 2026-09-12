"""Step 8c: the Evidence Auditor — every evidentiary claim must cite a real artifact.

Builds the incident report from the investigation trace (each claim already
carries the artifact_id it came from) plus the decision/response reasoning
(administrative, not evidentiary — exempt from citation). Then audits it:
any evidentiary claim whose artifact_id isn't in the case's evidence store is
stripped and flagged. Target hallucinated-claim rate: 0.
"""
from __future__ import annotations


def build_report(investigation: dict, decision: dict, response: dict) -> dict:
    claims = [
        {"text": f"Verdict: {investigation['verdict']} "
                 f"(confidence {investigation['confidence']:.2f})",
         "artifact_id": None, "requires_citation": False},
    ]
    for step in investigation["trace"]:
        claims.append({
            "text": step["evidence_reason"],
            "artifact_id": step.get("artifact_id"),
            "requires_citation": True,
        })
    claims.append({
        "text": f"Response decision: {decision['reason']}",
        "artifact_id": None, "requires_citation": False,
    })
    for entry in response.get("action_log", []):
        claims.append({
            "text": f"{entry.get('step')}: {entry.get('summary', '')}",
            "artifact_id": entry.get("artifact_id"),
            "requires_citation": True,
        })
    return {"incident_id": investigation["incident_id"], "claims": claims}


def audit(report: dict, evidence_ids: set[str]) -> dict:
    """Split claims into verified vs. flagged (uncited or citing a nonexistent artifact)."""
    verified, flagged = [], []
    for claim in report["claims"]:
        if not claim["requires_citation"]:
            verified.append(claim)
        elif claim["artifact_id"] and claim["artifact_id"] in evidence_ids:
            verified.append(claim)
        else:
            flagged.append(claim)
    return {
        "incident_id": report["incident_id"],
        "verified_claims": verified,
        "flagged_claims": flagged,
        "hallucination_rate": len(flagged) / len(report["claims"]) if report["claims"] else 0.0,
    }


if __name__ == "__main__":
    # self-check: a claim citing a real artifact survives; a fabricated one is stripped
    report = {
        "incident_id": "TEST",
        "claims": [
            {"text": "real", "artifact_id": "cmdb_10.2.1.1", "requires_citation": True},
            {"text": "fabricated", "artifact_id": "cmdb_99.99.99.99", "requires_citation": True},
            {"text": "admin note", "artifact_id": None, "requires_citation": False},
        ],
    }
    out = audit(report, evidence_ids={"cmdb_10.2.1.1"})
    assert len(out["verified_claims"]) == 2
    assert len(out["flagged_claims"]) == 1
    assert out["flagged_claims"][0]["text"] == "fabricated"
    print("auditor self-check passed:", out)
