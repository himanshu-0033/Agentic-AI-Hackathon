"""Phase 2 acceptance self-check.

Roadmap gate: rule-mode agent verdict accuracy > 75%, mean tool calls < 10,
and the loop must never call the same (tool, args) twice. Runs fully offline —
no API key. If accuracy regresses, the ledger factors or planner policy moved.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from verdict.agent.loop import investigate
from verdict.env import generate
from verdict.env.loader import all_incident_ids, load_incident, load_world
from verdict.eval.baseline import baseline_verdict


def test_agent_beats_bar_and_baseline():
    generate.main()
    ids = all_incident_ids()
    correct = base = calls = 0
    for iid in ids:
        gt = load_incident(iid)["ground_truth"]["verdict"]
        res = investigate(load_world(iid), mode="rule", persist=False)
        correct += res["verdict"] == gt
        base += baseline_verdict(load_incident(iid)["alert"]) == gt
        calls += res["tool_calls"]
    n = len(ids)
    acc, mean_calls = correct / n, calls / n
    assert acc > 0.75, f"accuracy {acc:.0%} below the 75% bar"
    assert mean_calls < 10, f"mean tool calls {mean_calls:.1f} over budget"
    assert acc > base / n, "agent must beat the label-only baseline"


def test_no_duplicate_tool_calls():
    """The loop's no-progress guard: every (tool, args) in a run is unique."""
    for iid in all_incident_ids():
        res = investigate(load_world(iid), mode="rule", persist=False)
        keys = [(s["tool"], tuple(sorted(s["args"].items()))) for s in res["trace"]]
        assert len(keys) == len(set(keys)), f"{iid} repeated a tool call: {keys}"


def test_adversarial_cases_solved():
    """The cases where the label lies must still land on the true verdict."""
    for iid in all_incident_ids():
        inc = load_incident(iid)
        if not inc["adversarial"]:
            continue
        res = investigate(load_world(iid), mode="rule", persist=False)
        assert res["verdict"] == inc["ground_truth"]["verdict"], \
            f"{iid} adversarial miss: {res['verdict']} != {inc['ground_truth']['verdict']}"


if __name__ == "__main__":
    test_agent_beats_bar_and_baseline()
    test_no_duplicate_tool_calls()
    test_adversarial_cases_solved()
    print("PHASE 2 ACCEPTANCE: all checks passed.")
