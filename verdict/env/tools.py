"""The 9 tools the agent may call against a World.

Every tool returns a dict carrying a stable `artifact_id`. That id is the
currency of the Evidence Auditor: any claim in the final report must cite an
artifact_id that was actually returned here. Tool signatures are the agent's
whole action space — read tools during investigation, the two state-changing
tools (fw_apply, edr_quarantine) only after a verdict.

All functions take the World as the first argument. That keeps them pure w.r.t.
a case and trivial to unit-test in a REPL (the Phase 1 acceptance test).
"""
from __future__ import annotations

from typing import Any

from .world import World, vtuple

# --- read tools --------------------------------------------------------------


def nids_alerts(world: World) -> dict:
    """The alert(s) currently visible for this case, newest last."""
    alerts = [world.alert] + world.alert.get("_late", [])
    return {"artifact_id": f"alert_{world.incident_id}", "alerts": alerts}


def pcap_flow(world: World, flow_id: str) -> dict:
    """Flow metadata: direction, byte counts, duration, TCP end-state."""
    flow = world.flows.get(flow_id)
    if flow is None:
        return {"artifact_id": f"pcap_{flow_id}", "error": "no such flow"}
    return {"artifact_id": f"pcap_{flow_id}", **flow}


def cmdb_asset(world: World, ip: str) -> dict:
    """Asset facts: host, OS, running services+versions, criticality, peers.

    This is usually the highest-information first call: it reveals whether the
    destination even runs the service the alert claims to exploit, and on which
    version — the input cve_match needs.
    """
    asset = world.assets.get(ip)
    if asset is None:
        return {"artifact_id": f"cmdb_{ip}", "error": "unknown asset"}
    return {"artifact_id": f"cmdb_{ip}", **asset}


def cve_match(world: World, product: str, version: str) -> dict:
    """Is `product` at `version` exploitable by a known CVE in this world?

    Exploitable iff a CVE targets that product AND the installed version is
    strictly below its patched_in version. This is the pivot that separates
    'attempted' from 'succeeded' for most incidents.
    """
    hits = []
    for cid, cve in world.cves.items():
        if cve["product"] != product:
            continue
        vulnerable = vtuple(version) < vtuple(cve["patched_in"])
        hits.append(
            {
                "cve": cid,
                "vulnerable": vulnerable,
                "installed": version,
                "patched_in": cve["patched_in"],
                "exploit_maturity": cve.get("exploit_maturity", "unknown"),
            }
        )
    exploitable = any(h["vulnerable"] for h in hits)
    return {
        "artifact_id": f"cvematch_{product}_{version}",
        "product": product,
        "exploitable": exploitable,
        "matches": hits,
    }


def logs_query(world: World, host: str, window: str = "", grep: str = "") -> dict:
    """Grep a host's log lines. `window` is advisory; matching is substring."""
    lines = world.logs.get(host, [])
    if grep:
        lines = [ln for ln in lines if grep.lower() in ln.lower()]
    return {"artifact_id": f"logs_{host}_{grep or 'all'}", "host": host, "lines": lines}


def edr_processtree(world: World, host: str, t: str = "") -> dict:
    """Process tree for a host. Reveals attacker-spawned shells / persistence."""
    tree = world.proc_trees.get(host)
    if tree is None:
        return {"artifact_id": f"proctree_{host}", "error": "no EDR coverage"}
    return {"artifact_id": f"proctree_{host}", "host": host, **tree}


def env_probe(world: World, src: str, dst: str, port: Any) -> dict:
    """THE VERIFIER. Does traffic src->dst:port pass right now? PASS/DROP.

    Reads only committed firewall rules, so it exposes a silent staged-only
    rule as still-PASS. Twenty lines that separate 'the agent said it blocked'
    from 'the block is real'.
    """
    result = world.probe(src, dst, port)
    return {
        "artifact_id": f"probe_{src}_{dst}_{port}",
        "src": src,
        "dst": dst,
        "port": port,
        "result": result,
    }


# --- state-changing tools ----------------------------------------------------


def fw_apply(world: World, rule: dict) -> dict:
    """Apply a firewall rule. Returns 200 even when the world silently fails.

    On silent_fail the rule is stored as staged (not committed): the API says
    OK, fw_state and env_probe reveal the truth. That gap is injection #2.
    """
    stored = world.add_rule(rule)
    return {
        "artifact_id": stored["id"],
        "status": "200 OK",
        "rule_id": stored["id"],
        "committed": stored["committed"],
    }


def fw_state(world: World) -> dict:
    """The live firewall ruleset, with each rule's committed flag."""
    return {"artifact_id": f"fwstate_{world.incident_id}", "rules": list(world.firewall)}


def fw_remove(world: World, rule_id: str) -> dict:
    """Roll back a previously applied rule (used by the override->rollback path)."""
    removed = world.remove_rule(rule_id)
    return {"artifact_id": f"fwremove_{rule_id}", "removed": removed}


def edr_quarantine(world: World, host: str) -> dict:
    """Host-level containment. The fallback when firewall enforcement fails."""
    world.quarantined.add(host)
    return {"artifact_id": f"quarantine_{host}", "host": host, "quarantined": True}


# Registry the planner/loop iterate over. read-only ones are safe pre-verdict.
READ_TOOLS = {
    "nids_alerts": nids_alerts,
    "pcap_flow": pcap_flow,
    "cmdb_asset": cmdb_asset,
    "cve_match": cve_match,
    "logs_query": logs_query,
    "edr_processtree": edr_processtree,
    "env_probe": env_probe,
}
ACTION_TOOLS = {
    "fw_apply": fw_apply,
    "fw_state": fw_state,
    "fw_remove": fw_remove,
    "edr_quarantine": edr_quarantine,
}
ALL_TOOLS = {**READ_TOOLS, **ACTION_TOOLS}
