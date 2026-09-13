"""The simulated world for one incident.

Everything the agent can observe or change lives in a World: assets and their
services, CVE facts, packet flows, host logs, process trees, the live firewall
ruleset, and the session table. One incident == one self-contained World, so
incidents are independent and the eval harness can run them in any order.

The World is deliberately dumb: it stores state and enforces the firewall. All
*reasoning* lives in the agent; all *ground truth* lives in the incident JSON.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


def vtuple(version: str) -> tuple[int, ...]:
    """Parse a version string into a comparable integer tuple.

    '2.14.1' -> (2, 14, 1). Non-numeric junk is dropped, so 'v2.17.0-rc1'
    -> (2, 17, 0, 1). Good enough for the < comparison cve_match needs.
    """
    return tuple(int(x) for x in re.findall(r"\d+", version)) or (0,)


@dataclass
class World:
    """Mutable state for a single case. Built from an incident dict."""

    incident_id: str
    alert: dict[str, Any]
    assets: dict[str, dict] = field(default_factory=dict)      # ip -> asset
    cves: dict[str, dict] = field(default_factory=dict)        # cve_id -> fact
    flows: dict[str, dict] = field(default_factory=dict)       # flow_id -> flow
    logs: dict[str, list[str]] = field(default_factory=dict)   # host -> lines
    proc_trees: dict[str, dict] = field(default_factory=dict)  # host -> tree
    sessions: list[dict] = field(default_factory=list)         # live connections
    firewall: list[dict] = field(default_factory=list)         # rules
    quarantined: set[str] = field(default_factory=set)         # host ids
    silent_fail: bool = False   # fw.apply returns 200 but never commits
    _rule_seq: int = 0

    # --- firewall enforcement -------------------------------------------------

    def add_rule(self, rule: dict) -> dict:
        """Stage or commit a firewall rule. Honors silent_fail.

        A committed rule affects env_probe and the session table. A staged
        rule (silent_fail) does not — that is the whole point of injection #2.
        """
        self._rule_seq += 1
        stored = {
            "id": f"fw_{self._rule_seq}",
            "action": rule.get("action", "block"),
            "src": rule.get("src", "*"),
            "dst": rule.get("dst", "*"),
            "port": rule.get("port", "*"),
            "scope": rule.get("scope", "tuple"),
            "committed": not self.silent_fail,
        }
        self.firewall.append(stored)
        return stored

    def remove_rule(self, rule_id: str) -> bool:
        before = len(self.firewall)
        self.firewall = [r for r in self.firewall if r["id"] != rule_id]
        return len(self.firewall) < before

    def _rule_matches(self, rule: dict, src: str, dst: str, port: Any) -> bool:
        return (
            rule["action"] == "block"
            and rule["committed"]
            and _match(rule["src"], src)
            and _match(rule["dst"], dst)
            and _match(rule["port"], port)
        )

    def probe(self, src: str, dst: str, port: Any) -> str:
        """Would a packet src->dst:port pass right now? PASS or DROP.

        This is the verifier. It reads ONLY committed rules, so a staged rule
        (silent firewall failure) correctly reports PASS — traffic still flows.
        """
        dst_host = self.assets.get(dst, {}).get("host")
        if dst_host in self.quarantined:
            return "DROP"
        for rule in self.firewall:
            if self._rule_matches(rule, src, dst, port):
                return "DROP"
        return "PASS"

    def collateral(self, rule: dict) -> dict:
        """How much legitimate traffic would this committed-style rule kill?

        Walks the session table. A rule is scored as if committed so the gate
        can decide BEFORE applying. Returns dropped legit/malicious counts and
        the affected user estimate for shared-NAT sources.
        """
        legit = mal = 0
        for s in self.sessions:
            if self._session_blocked(rule, s):
                if s.get("legit", True):
                    legit += 1
                else:
                    mal += 1
        users = 0
        src_asset = self.assets.get(rule.get("src", ""))
        if rule.get("scope") == "ip" and src_asset and src_asset.get("is_shared_nat"):
            users = src_asset.get("users_behind", 0)
        return {"legit_dropped": legit, "malicious_dropped": mal, "users_affected": users}

    @staticmethod
    def _session_blocked(rule: dict, s: dict) -> bool:
        return (
            rule["action"] == "block"
            and _match(rule["src"], s.get("src"))
            and _match(rule["dst"], s.get("dst"))
            and _match(rule["port"], s.get("port"))
        )

    # --- (de)serialisation ----------------------------------------------------

    @classmethod
    def from_incident(cls, inc: dict) -> "World":
        w = inc["world"]
        return cls(
            incident_id=inc["id"],
            alert=inc["alert"],
            assets=w.get("assets", {}),
            cves=w.get("cves", {}),
            flows=w.get("flows", {}),
            logs=w.get("logs", {}),
            proc_trees=w.get("proc_trees", {}),
            sessions=w.get("sessions", []),
            firewall=list(w.get("firewall", [])),
            silent_fail=w.get("silent_fail", False),
        )


def _match(pattern: Any, value: Any) -> bool:
    """'*' matches anything; otherwise string-equal."""
    return pattern == "*" or str(pattern) == str(value)
