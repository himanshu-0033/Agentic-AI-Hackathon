"""Step 6: turn a verdict into the narrowest safe response, with a blast-radius gate.

Response tier comes from the top hypothesis, not just the coarse verdict, so
scanner-noise (monitor) and benign (close) are handled differently even though
both are 'FALSE_POSITIVE':

    H1 succeeded   -> contain   (propose a firewall rule)
    H2 failed      -> monitor   (watch rule, no block)
    H3 scanner     -> monitor
    H4 benign      -> close

For containment we compute collateral BEFORE acting. The default is the
narrowest rule that stops the attack: a src->dst:port tuple. Only when the
attacker is hitting multiple destinations does a broader src-IP block become
necessary — and that is exactly when blast radius can explode (a shared NAT
egress), so the gate escalates instead of executing autonomously.
"""
from __future__ import annotations

from ..env.world import World

TIER = {"H1": "contain", "H2": "monitor", "H3": "monitor", "H4": "close"}


def _malicious_dsts(world: World, src: str) -> set[str]:
    return {s["dst"] for s in world.sessions
            if s.get("src") == src and not s.get("legit", True)}


def decide(top: str, alert: dict, world: World) -> dict:
    tier = TIER[top]
    decision = {
        "top": top, "tier": tier, "rule": None,
        "escalate": False, "collateral": None, "reason": "",
    }
    if tier != "contain":
        decision["reason"] = f"{tier}: no enforcement action required"
        return decision

    src, dst, port = alert["src"], alert["dst"], alert["dst_port"]

    # narrowest first; widen to a src-IP block only if the attacker is spraying
    if len(_malicious_dsts(world, src)) > 1:
        rule = {"action": "block", "src": src, "dst": "*", "port": "*", "scope": "ip"}
        scope_note = "attacker is hitting multiple targets; a per-tuple block would not contain it"
    else:
        rule = {"action": "block", "src": src, "dst": dst, "port": port, "scope": "tuple"}
        scope_note = "single target; a narrow src->dst:port block suffices"

    coll = world.collateral(rule)
    decision["rule"] = rule
    decision["collateral"] = coll

    if coll["legit_dropped"] > 0 or coll["users_affected"] > 0:
        decision["escalate"] = True
        decision["reason"] = (
            f"{scope_note}, but blast radius is unacceptable "
            f"(legit sessions dropped={coll['legit_dropped']}, users affected={coll['users_affected']}); "
            f"escalating to a human instead of acting autonomously"
        )
    else:
        decision["reason"] = f"{scope_note}; no collateral, executing autonomously"
    return decision
