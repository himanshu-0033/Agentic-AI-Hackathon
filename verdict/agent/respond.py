"""Steps 6-8: decide -> execute -> verify, with retry, EDR fallback, and
override -> auto-rollback. This is the module the three injections exercise.

close_case() is the single entry point: given an investigation result (from
loop.investigate) and the World it ran against, it decides a response tier,
enforces the blast-radius gate, executes the narrowest action, verifies every
execution effect via probes, and produces an audited report.
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


def _is_rule_committed(world, rule_id: str) -> bool:
    state = toolmod.fw_state(world)
    for r in state["rules"]:
        if r["id"] == rule_id and r.get("committed") is True:
            return True
    return False


def _first_blocked_session(world: World, rule: dict, alert: dict) -> dict | None:
    """Find a session the rule would block, preferring one not matching the alert."""
    alert_key = (alert.get("src"), alert.get("dst"), alert.get("dst_port"))
    fallback = None
    for s in world.sessions:
        if not World._session_blocked(rule, s):
            continue
        key = (s.get("src"), s.get("dst"), s.get("port"))
        if key != alert_key:
            return s
        if fallback is None:
            fallback = s
    return fallback


def _session_key(session: dict) -> tuple[str, str, int | str | None]:
    return (session.get("src"), session.get("dst"), session.get("port"))


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
        rule_id = last_apply["rule_id"]
        applied = _is_rule_committed(world, rule_id)
        log.append({
            "step": f"fw_apply (attempt {attempt})",
            "artifact_id": last_apply["artifact_id"],
            "summary": f"rule {rule_id} committed={applied}",
        })

        probe = toolmod.env_probe(world, alert["src"], alert["dst"], alert["dst_port"])
        log.append({
            "step": f"env_probe (attempt {attempt})",
            "artifact_id": probe["artifact_id"],
            "summary": f"malicious traffic now {probe['result']}",
        })
        if probe["result"] == "DROP" and applied:
            committed = True
            break
        if probe["result"] == "DROP":
            log.append({
                "step": f"env_verify (attempt {attempt})",
                "artifact_id": probe["artifact_id"],
                "summary": "malicious traffic dropped but rule not in committed set; treating as unresolved",
            })

    quarantine_used = False
    quarantine_verified = False
    if not committed:
        host = world.assets.get(alert["dst"], {}).get("host")
        q = toolmod.edr_quarantine(world, host)
        log.append({
            "step": "edr_quarantine (fallback)",
            "artifact_id": q["artifact_id"],
            "summary": f"firewall verification failed twice; quarantined {host}",
        })
        quarantine_used = q.get("quarantined", False)
        if quarantine_used and host:
            q_probe = toolmod.env_probe(world, alert["src"], alert["dst"], alert["dst_port"])
            log.append({
                "step": "env_probe (edr fallback verification)",
                "artifact_id": q_probe["artifact_id"],
                "summary": f"malicious traffic after quarantine now {q_probe['result']}",
            })
            quarantine_verified = q_probe["result"] == "DROP"

    verified = committed or quarantine_verified
    rolled_back = False
    rollback_reason = None
    rollback_attempted = False

    # override -> post-action collateral check -> auto-rollback (injection #3)
    if override and decision["escalate"] and decision["rule"] and committed:
        rollback_attempted = True
        collateral_session = _first_blocked_session(world, decision["rule"], alert)

        if collateral_session is None:
            rollback_reason = "override requested, but no blocked collateral session was observable for rollback verification"
        else:
            p2 = toolmod.env_probe(
                world,
                collateral_session["src"],
                collateral_session["dst"],
                collateral_session["port"],
            )
            log.append({
                "step": "env_probe (post-action collateral check)",
                "artifact_id": p2["artifact_id"],
                "summary": (
                    f"blocked session {collateral_session['src']}->{collateral_session['dst']}:"
                    f"{collateral_session['port']} now {p2['result']}"
                ),
            })

            if p2["result"] == "DROP":
                rm = toolmod.fw_remove(world, last_apply["rule_id"])
                log.append({
                    "step": "fw_remove (rollback)",
                    "artifact_id": rm["artifact_id"],
                    "summary": f"removed broad rule {last_apply['rule_id']}",
                })
                narrow = {
                    "action": "block",
                    "src": alert["src"],
                    "dst": alert["dst"],
                    "port": alert["dst_port"],
                    "scope": "tuple",
                }
                r2 = toolmod.fw_apply(world, narrow)
                log.append({
                    "step": "fw_apply (narrow replacement)",
                    "artifact_id": r2["artifact_id"],
                    "summary": f"replaced with narrow rule {r2['rule_id']}",
                })
                narrow_applied = _is_rule_committed(world, r2["rule_id"]) and toolmod.env_probe(
                    world,
                    alert["src"],
                    alert["dst"],
                    alert["dst_port"],
                )["result"] == "DROP"

                collateral_ok = True
                if _session_key(collateral_session) != (alert["src"], alert["dst"], alert["dst_port"]):
                    p3 = toolmod.env_probe(world,
                                           collateral_session["src"],
                                           collateral_session["dst"],
                                           collateral_session["port"])
                    log.append({
                        "step": "env_probe (rollback verification)",
                        "artifact_id": p3["artifact_id"],
                        "summary": (
                            f"blocked session {collateral_session['src']}->{collateral_session['dst']}:"
                            f"{collateral_session['port']} now {p3['result']}"
                        ),
                    })
                    collateral_ok = p3["result"] == "PASS"

                if rm["removed"] and narrow_applied and collateral_ok:
                    rolled_back = True
                    verified = True
                    rollback_reason = None
                else:
                    verified = False
                    rollback_reason = (
                        "override rollback failed: wide rule was not removed cleanly, "
                        "replacement did not commit, or collateral session did not recover"
                    )
            else:
                verified = False
                rollback_reason = (
                    "override rollback skipped because the sampled collateral session "
                    "was not actually impacted by the action"
                )

    status = "rolled_back_to_narrow" if rolled_back else (
        "rollback_failed" if rollback_attempted else ("contained" if verified else "failed")
    )
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
