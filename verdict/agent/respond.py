"""Steps 6-8: decide -> execute -> verify, with retry, EDR fallback, and
override -> auto-rollback. This is the module the three injections exercise.

close_case() is the single entry point: given an investigation result (from
loop.investigate) and the World it ran against, it decides a response tier,
enforces the blast-radius gate, executes the narrowest action, verifies the
real effect (never trusts a 200 OK), and produces an audited report.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..env import tools as toolmod
from ..env.world import World
from .auditor import audit, build_report
from .decide import decide

STATE_DIR = Path(__file__).resolve().parents[1] / "state"
MAX_FW_ATTEMPTS = 2


def close_case(world: World, investigation: dict, alert: dict, override: bool = False,
               persist: bool = True) -> dict:
    decision = decide(investigation["top_hypothesis"], alert, world)
    log: list[dict] = []

    if decision["tier"] != "contain":
        response = {"status": "closed", "action_log": log, "rolled_back": False}
        return _finish(world, investigation, decision, response, persist)

    if decision["escalate"] and not override:
        response = {"status": "escalated", "action_log": log, "rolled_back": False}
        return _finish(world, investigation, decision, response, persist)

    # execute + verify, with retry and EDR fallback (injection #2)
    rule = decision["rule"]
    committed = False
    last_apply = None
    for attempt in range(1, MAX_FW_ATTEMPTS + 1):
        last_apply = toolmod.fw_apply(world, rule)
        log.append({"step": f"fw_apply (attempt {attempt})", "artifact_id": last_apply["artifact_id"],
                    "summary": f"rule {last_apply['rule_id']} committed={last_apply['committed']}"})
        probe = toolmod.env_probe(world, alert["src"], alert["dst"], alert["dst_port"])
        log.append({"step": f"env_probe (attempt {attempt})", "artifact_id": probe["artifact_id"],
                    "summary": f"malicious traffic now {probe['result']}"})
        if probe["result"] == "DROP":
            committed = True
            break

    quarantine_used = False
    if not committed:
        host = world.assets.get(alert["dst"], {}).get("host")
        q = toolmod.edr_quarantine(world, host)
        log.append({"step": "edr_quarantine (fallback)", "artifact_id": q["artifact_id"],
                    "summary": f"firewall verification failed twice; quarantined {host}"})
        quarantine_used = q.get("quarantined", False)

    verified = committed or quarantine_used
    rolled_back = False
    rollback_reason = None

    # override -> post-action collateral check -> auto-rollback (injection #3)
    if override and committed:
        legit = next((s for s in world.sessions
                     if s.get("legit") and World._session_blocked(rule, s)), None)
        if legit is not None:
            p2 = toolmod.env_probe(world, legit["src"], legit["dst"], legit["port"])
            log.append({"step": "env_probe (post-action collateral check)", "artifact_id": p2["artifact_id"],
                        "summary": f"legitimate session {legit['src']}->{legit['dst']}:{legit['port']} now {p2['result']}"})
            if p2["result"] == "DROP":
                rm = toolmod.fw_remove(world, last_apply["rule_id"])
                log.append({"step": "fw_remove (rollback)", "artifact_id": rm["artifact_id"],
                            "summary": f"removed overly broad rule {last_apply['rule_id']}"})
                narrow = {"action": "block", "src": alert["src"], "dst": alert["dst"],
                         "port": alert["dst_port"], "scope": "tuple"}
                r2 = toolmod.fw_apply(world, narrow)
                log.append({"step": "fw_apply (narrow replacement)", "artifact_id": r2["artifact_id"],
                            "summary": f"replaced with narrow rule {r2['rule_id']}"})
                p3 = toolmod.env_probe(world, legit["src"], legit["dst"], legit["port"])
                log.append({"step": "env_probe (rollback verification)", "artifact_id": p3["artifact_id"],
                            "summary": f"legitimate session restored to {p3['result']}"})
                rolled_back = True
                rollback_reason = (
                    "human override caused unacceptable collateral "
                    f"(a legitimate session was dropped); auto-rolled back to the narrow rule"
                )

    status = "rolled_back_to_narrow" if rolled_back else ("contained" if verified else "failed")
    response = {
        "status": status, "action_log": log, "verified": verified,
        "quarantine_used": quarantine_used, "rolled_back": rolled_back,
        "rollback_reason": rollback_reason, "override_used": override,
    }
    return _finish(world, investigation, decision, response, persist)


def _finish(world: World, investigation: dict, decision: dict, response: dict, persist: bool) -> dict:
    evidence_ids = set(investigation.get("evidence_ids", [])) | {
        e["artifact_id"] for e in response["action_log"] if e.get("artifact_id")
    }
    report = build_report(investigation, decision, response)
    audited = audit(report, evidence_ids)

    result = {
        "incident_id": world.incident_id,
        "investigation": investigation,
        "decision": decision,
        "response": response,
        "report": audited,
    }
    if persist:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        (STATE_DIR / f"{world.incident_id}.json").write_text(
            json.dumps(result, indent=2), encoding="utf-8"
        )
    return result


if __name__ == "__main__":
    import sys

    from ..env.loader import load_world
    from .loop import investigate

    iid = sys.argv[1] if len(sys.argv) > 1 else "A-1000"
    world = load_world(iid)
    inv = investigate(world, mode="rule", persist=False)
    out = close_case(world, inv, world.alert, persist=False)
    print(f"{iid}: verdict={inv['verdict']} tier={out['decision']['tier']} "
          f"status={out['response']['status']}")
    print(f"  decision: {out['decision']['reason']}")
    for step in out["response"]["action_log"]:
        print(f"  -> {step['step']}: {step['summary']}")
    print(f"  report: {len(out['report']['verified_claims'])} verified, "
          f"{len(out['report']['flagged_claims'])} flagged "
          f"(hallucination rate {out['report']['hallucination_rate']:.0%})")
