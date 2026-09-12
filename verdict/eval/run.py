"""Batch the agent over all 40 incidents and print the scoreboard.

Default mode is 'rule' — offline, deterministic, no API key. This is the
number that goes in the deck. `--mode llm` runs the Claude planner (needs a key)
for a sample or the full set.

    python -m verdict.eval.run                 # all 40, rule mode
    python -m verdict.eval.run --mode llm -n 5 # 5 incidents, LLM planner
"""
from __future__ import annotations

import argparse
import json

from ..agent.loop import investigate
from ..agent.planner import DEFAULT_MODEL
from ..env.loader import all_incident_ids, load_incident, load_world
from .baseline import baseline_verdict


def run(mode: str = "rule", limit: int | None = None, model: str = DEFAULT_MODEL) -> dict:
    ids = all_incident_ids()
    if limit:
        ids = ids[:limit]

    agent_correct = base_correct = 0
    adv_total = adv_agent_correct = 0
    total_calls = 0
    rows = []

    for iid in ids:
        inc = load_incident(iid)
        gt = inc["ground_truth"]["verdict"]
        adv = inc["adversarial"]

        res = investigate(load_world(iid), mode=mode, model=model, persist=True)
        base = baseline_verdict(inc["alert"])

        a_ok = res["verdict"] == gt
        b_ok = base == gt
        agent_correct += a_ok
        base_correct += b_ok
        total_calls += res["tool_calls"]
        if adv:
            adv_total += 1
            adv_agent_correct += a_ok
        rows.append((iid, gt, res["verdict"], a_ok, base, b_ok, res["tool_calls"], adv))

    n = len(ids)
    summary = {
        "n": n,
        "agent_accuracy": agent_correct / n,
        "baseline_accuracy": base_correct / n,
        "mean_tool_calls": total_calls / n,
        "adversarial_accuracy": (adv_agent_correct / adv_total) if adv_total else None,
        "mode": mode,
    }
    _print(rows, summary)
    return summary


def _print(rows, s) -> None:
    print(f"\n{'incident':10} {'ground_truth':16} {'agent':16} {'ok':3} "
          f"{'baseline':16} {'ok':3} {'calls':5} adv")
    print("-" * 92)
    for iid, gt, av, aok, bv, bok, calls, adv in rows:
        print(f"{iid:10} {gt:16} {av:16} {'Y' if aok else '.':3} "
              f"{bv:16} {'Y' if bok else '.':3} {calls:<5} {'*' if adv else ''}")
    print("-" * 92)
    print(f"VERDICT agent accuracy : {s['agent_accuracy']:.0%}  ({s['mode']} mode)")
    print(f"baseline (label-only)  : {s['baseline_accuracy']:.0%}")
    print(f"mean tool calls        : {s['mean_tool_calls']:.1f}")
    if s["adversarial_accuracy"] is not None:
        print(f"adversarial accuracy   : {s['adversarial_accuracy']:.0%}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["rule", "llm"], default="rule")
    ap.add_argument("-n", "--limit", type=int, default=None)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--json", action="store_true", help="print the summary as JSON too")
    args = ap.parse_args()
    out = run(mode=args.mode, limit=args.limit, model=args.model)
    if args.json:
        print(json.dumps(out, indent=2))
