"""The straw man: trust the alert label.

If an alert names a CVE and is medium+ severity, call it a real attack and
block. This is what a non-agentic 'classifier with extra steps' does. Its
accuracy on the same 40 incidents is the number VERDICT's scoreboard beats —
especially on the adversarial cases, where the label lies.
"""
from __future__ import annotations


def baseline_verdict(alert: dict) -> str:
    sev = alert.get("severity", "low")
    if alert.get("claimed_cve") and sev in ("medium", "high", "critical"):
        return "SUCCEEDED"          # naive: a scary alert means a real hit
    return "FALSE_POSITIVE"
