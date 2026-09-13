"""Phase 3 acceptance self-check.

Roadmap gate: all three injections fire mid-run and the agent recovers from
each without a restart; injection 3 must end in an automatic rollback. Also
covers the base containment path and the Evidence Auditor. Fully offline.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from verdict.agent.injections import (
    inject_action_failure,
    inject_evidence_reversal,
    inject_override_scenario,
)
from verdict.agent.loop import investigate, watch
from verdict.agent.respond import close_case
from verdict.env.loader import load_world


def test_base_containment_path():
    """A normal SUCCEEDED case: narrow rule, verified, clean report."""
    w = load_world("A-1000")
    inv = investigate(w, mode="rule", persist=False)
    out = close_case(w, inv, w.alert, persist=False)
    assert out["response"]["status"] == "contained"
    assert out["response"]["verified"] is True
    assert out["decision"]["rule"]["scope"] == "tuple"
    assert len(out["report"]["flagged_claims"]) == 0


def test_false_positive_and_failed_close_without_action():
    """FAILED/FALSE_POSITIVE verdicts must never trigger a firewall rule."""
    for iid, expected_tier in [("A-1014", "monitor"), ("A-1030", "monitor"), ("A-1036", "close")]:
        w = load_world(iid)
        inv = investigate(w, mode="rule", persist=False)
        out = close_case(w, inv, w.alert, persist=False)
        assert out["decision"]["tier"] == expected_tier, (iid, out["decision"])
        assert out["response"]["status"] in ("closed",), (iid, out["response"]["status"])
        assert w.firewall == [], f"{iid}: a non-contain verdict must apply zero firewall rules"


def test_injection_1_evidence_reversal_reopens_and_flips():
    w = load_world("A-1014")   # FAILED ground truth
    inv = investigate(w, mode="rule", persist=False)
    assert inv["verdict"] == "FAILED"

    inject_evidence_reversal(w, w.alert)
    result = watch(w, inv, mode="rule")

    assert result["reopened"] is True
    assert result["new_verdict"] == "SUCCEEDED"


def test_injection_2_silent_firewall_falls_back_to_edr():
    w = load_world("A-1000")   # SUCCEEDED -> containment path
    inv = investigate(w, mode="rule", persist=False)
    inject_action_failure(w)

    out = close_case(w, inv, w.alert, persist=False)

    assert out["response"]["quarantine_used"] is True
    assert out["response"]["verified"] is True
    assert out["response"]["status"] == "contained"
    # every fw_apply attempt must show committed=False under silent_fail
    applies = [e for e in out["response"]["action_log"] if e["step"].startswith("fw_apply")]
    assert len(applies) >= 2
    assert all("committed=False" in e["summary"] for e in applies)


def test_injection_3_override_then_autorollback():
    w = load_world("A-1000")
    inv = investigate(w, mode="rule", persist=False)
    inject_override_scenario(w, w.alert)

    # without override: must escalate, never touch the firewall
    out1 = close_case(w, inv, w.alert, override=False, persist=False)
    assert out1["response"]["status"] == "escalated"
    assert out1["decision"]["escalate"] is True
    assert w.firewall == []

    # judge overrides: agent complies, then detects collateral and rolls back
    out2 = close_case(w, inv, w.alert, override=True, persist=False)
    assert out2["response"]["rolled_back"] is True
    assert out2["response"]["status"] == "rolled_back_to_narrow"
    # rollback_reason is populated on FAILURE/skip only; null means clean success
    assert out2["response"]["rollback_reason"] is None
    assert any(s["step"] == "fw_remove (rollback)" for s in out2["response"]["action_log"])
    # the final committed rule must be the narrow one, not the broad IP block
    committed = [r for r in w.firewall if r["committed"]]
    assert committed, "no committed rule survived"
    assert committed[-1]["scope"] == "tuple"


def test_auditor_zero_hallucination_on_real_runs():
    """Every claim on a real (uninjected) run must cite a real artifact."""
    for iid in ("A-1000", "A-1014", "A-1030"):
        w = load_world(iid)
        inv = investigate(w, mode="rule", persist=False)
        out = close_case(w, inv, w.alert, persist=False)
        assert out["report"]["hallucination_rate"] == 0.0, iid


if __name__ == "__main__":
    test_base_containment_path()
    test_false_positive_and_failed_close_without_action()
    test_injection_1_evidence_reversal_reopens_and_flips()
    test_injection_2_silent_firewall_falls_back_to_edr()
    test_injection_3_override_then_autorollback()
    test_auditor_zero_hallucination_on_real_runs()
    print("PHASE 3 ACCEPTANCE: all checks passed.")
