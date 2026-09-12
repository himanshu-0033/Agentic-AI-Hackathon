"""The investigation loop (Phase 2: steps 1-5 of the 9-step design).

    1 INGEST      read the alert, initialise the ledger at uniform priors
    2 PLAN        pick the next tool by information gain (planner.py)
    3 ACT         call that one read tool
    4 OBSERVE     store the artifact, update the ledger
    5 STOP-CHECK  max confidence > threshold, or tool budget spent

DECIDE / EXECUTE / VERIFY / WATCH (steps 6-9) arrive in Phase 3. The loop
persists its full state per case so those phases — and the UI — can read it.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..env import tools as toolmod
from ..env.world import World
from . import planner
from .ledger import Ledger, interpret

STATE_DIR = Path(__file__).resolve().parents[1] / "state"
STOP_CONFIDENCE = 0.85
TOOL_BUDGET = 12


def investigate(world: World, mode: str = "rule", model: str = planner.DEFAULT_MODEL,
                persist: bool = True) -> dict:
    ledger = Ledger()
    evidence: dict[str, dict] = {}          # tool name -> latest artifact
    evidence_by_id: dict[str, dict] = {}    # artifact_id -> artifact (audit trail)
    called: set[tuple] = set()
    trace: list[dict] = []

    # 1. INGEST — index [0] is always the canonical alert; see nids_alerts docstring
    alert = toolmod.nids_alerts(world)["alerts"][0]

    stop_reason = "budget_exhausted"
    for _ in range(TOOL_BUDGET):
        # 2. PLAN
        action = planner.next_action(alert, ledger, evidence, called, mode=mode, model=model)
        if action is None:
            stop_reason = "planner_done"
            break

        tool, args = action["tool"], action["args"]
        key = (tool, tuple(sorted(args.items())))
        if key in called:                    # 2b. no-progress guard
            stop_reason = "no_new_action"
            break
        called.add(key)

        # 3. ACT
        artifact = toolmod.READ_TOOLS[tool](world, **args)

        # 4. OBSERVE
        evidence[tool] = artifact
        evidence_by_id[artifact.get("artifact_id", f"{tool}_{len(trace)}")] = artifact
        factors, reason = interpret(tool, artifact, alert)
        ledger.update(factors, reason, tool)
        trace.append({
            "tool": tool, "args": args, "rationale": action.get("rationale", ""),
            "artifact_id": artifact.get("artifact_id"),
            "evidence_reason": reason, "confidence": dict(ledger.conf),
        })

        # 5. STOP-CHECK
        if ledger.top_conf() > STOP_CONFIDENCE:
            stop_reason = "confident"
            break

    result = {
        "incident_id": world.incident_id,
        "mode": mode,
        "verdict": ledger.verdict(),
        "confidence": ledger.top_conf(),
        "top_hypothesis": ledger.top(),
        "tool_calls": len(called),
        "stop_reason": stop_reason,
        "ledger": ledger.snapshot(),
        "trace": trace,
        "evidence_ids": sorted(evidence_by_id),
    }
    if persist:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        (STATE_DIR / f"{world.incident_id}.json").write_text(
            json.dumps(result, indent=2), encoding="utf-8"
        )
    return result


def watch(world: World, prior: dict, mode: str = "rule", model: str = "") -> dict:
    """Step 9: re-run the investigation from scratch against the (possibly
    mutated) world and check whether new evidence overturns the prior verdict.

    A fresh investigate() call naturally re-derives from current world state —
    no separate 'watch' state machine needed. Reopening a closed case IS just
    investigating again and diffing the verdict.
    """
    kwargs = {"mode": mode, "persist": False}
    if model:
        kwargs["model"] = model
    fresh = investigate(world, **kwargs)
    return {
        "reopened": fresh["verdict"] != prior["verdict"],
        "prior_verdict": prior["verdict"],
        "new_verdict": fresh["verdict"],
        "new_investigation": fresh,
    }


if __name__ == "__main__":
    import sys
    from ..env.loader import load_world

    iid = sys.argv[1] if len(sys.argv) > 1 else "A-1000"
    res = investigate(load_world(iid), mode="rule")
    print(f"{res['incident_id']}: {res['verdict']} "
          f"(conf {res['confidence']:.2f}, {res['tool_calls']} calls, {res['stop_reason']})")
    for step in res["trace"]:
        print(f"  -> {step['tool']}: {step['rationale']}")
        print(f"     obs: {step['evidence_reason']}")
