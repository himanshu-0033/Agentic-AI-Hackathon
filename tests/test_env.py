"""Phase 1 acceptance self-check.

The rule from the roadmap: if a human cannot solve an incident from the
available evidence, the agent cannot either. So this test *is* the human,
calling tools by hand and asserting the evidence points at the ground truth.
It also checks the firewall enforcement invariants (probe, silent-fail,
collateral) that the whole verification story rests on.

Run:  python -m pytest tests/ -q       (or)   python tests/test_env.py
No framework required beyond the asserts.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from verdict.env import generate, tools
from verdict.env.loader import all_incident_ids, load_world
from verdict.env.world import World


def _gt(iid):
    import json
    from verdict.env.loader import INCIDENTS_DIR
    return json.loads((INCIDENTS_DIR / f"{iid}.json").read_text())["ground_truth"]["verdict"]


def solve_by_hand(w: World) -> str:
    """A minimal human playbook, using only tools. Returns a verdict label.

    is the destination service even exploitable? -> cve_match
    did the host actually get compromised?       -> proc tree + flow
    """
    alert = tools.nids_alerts(w)["alerts"][-1]
    dst, port = alert["dst"], str(alert["dst_port"])
    asset = tools.cmdb_asset(w, dst)
    svc = asset.get("services", {}).get(port)

    if svc is None:
        return "FALSE_POSITIVE"          # nothing listening on the alerted port

    if alert.get("claimed_cve") is None:
        # no CVE claim: benign unless the flow/logs say otherwise
        tree = tools.edr_processtree(w, asset["host"])
        return "SUCCEEDED" if tree.get("suspicious") else "FALSE_POSITIVE"

    match = tools.cve_match(w, svc["product"], svc["version"])
    if not match["exploitable"]:
        return "FAILED"                  # patched / wrong version

    tree = tools.edr_processtree(w, asset["host"])
    return "SUCCEEDED" if tree.get("suspicious") else "FAILED"


def test_incidents_exist_and_distribute():
    generate.main()
    ids = all_incident_ids()
    assert len(ids) == 40, f"expected 40 incidents, got {len(ids)}"
    verdicts = [_gt(i) for i in ids]
    assert verdicts.count("SUCCEEDED") == 14
    assert verdicts.count("FAILED") == 16
    assert verdicts.count("FALSE_POSITIVE") == 10   # 6 scanner + 4 benign
    import json
    from verdict.env.loader import INCIDENTS_DIR
    adv = sum(json.loads((INCIDENTS_DIR / f"{i}.json").read_text())["adversarial"] for i in ids)
    assert adv >= 6, f"need >=6 adversarial, got {adv}"


def test_human_can_solve_every_incident():
    """The strong acceptance test: the hand playbook matches ground truth on ALL 40.

    If this passes, the environment is solvable from evidence alone. If it ever
    fails, fix the environment, not the agent.
    """
    generate.main()
    wrong = []
    for iid in all_incident_ids():
        w = load_world(iid)
        if solve_by_hand(w) != _gt(iid):
            wrong.append((iid, solve_by_hand(w), _gt(iid)))
    assert not wrong, f"unsolvable incidents: {wrong}"


def test_probe_and_silent_fail():
    """env_probe is the verifier; a silent-fail firewall must still read PASS."""
    w = load_world(all_incident_ids()[0])
    src, dst, port = "203.0.113.9", list(w.assets)[0], 8080

    # committed block -> DROP
    w.silent_fail = False
    r = tools.fw_apply(w, {"action": "block", "src": src, "dst": dst, "port": port})
    assert r["committed"] is True
    assert tools.env_probe(w, src, dst, port)["result"] == "DROP"

    # silent-fail block -> API says OK but probe still PASS (injection #2)
    w2 = load_world(all_incident_ids()[0])
    w2.silent_fail = True
    r2 = tools.fw_apply(w2, {"action": "block", "src": src, "dst": dst, "port": port})
    assert r2["status"] == "200 OK" and r2["committed"] is False
    assert tools.env_probe(w2, src, dst, port)["result"] == "PASS", "silent fail not exposed!"


def test_collateral_flags_shared_nat():
    """Blocking a shared-NAT source by IP must report affected users (blast radius)."""
    w = load_world(all_incident_ids()[0])
    w.assets["10.9.9.1"] = {"host": "office-nat", "is_shared_nat": True,
                            "users_behind": 340, "services": {}, "peers": []}
    w.sessions.append({"src": "10.9.9.1", "dst": "10.2.1.50", "port": 443, "legit": True})
    c = w.collateral({"action": "block", "src": "10.9.9.1", "dst": "*", "port": "*", "scope": "ip"})
    assert c["users_affected"] == 340
    assert c["legit_dropped"] >= 1


if __name__ == "__main__":
    test_incidents_exist_and_distribute()
    test_human_can_solve_every_incident()
    test_probe_and_silent_fail()
    test_collateral_flags_shared_nat()
    print("PHASE 1 ACCEPTANCE: all checks passed.")
