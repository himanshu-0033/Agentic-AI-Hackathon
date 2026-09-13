"""Next-action selection: which single tool most separates the live hypotheses.

Two modes, one interface:

  rule  — deterministic evidence-priority policy. Free, offline, reproducible.
          This is what the eval scoreboard runs on.
  llm   — an LLM (Groq, OpenAI-compatible API) picks the tool and explains why,
          for the demo. Args are still resolved deterministically from real
          evidence, so the model chooses *what to look at* but can never invent
          an IP or version.

An action is {"tool", "args", "rationale"} or None to stop investigating.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional

from ..env import tools as toolmod
from .ledger import HYPOTHESES, Ledger

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


def _load_dotenv() -> None:
    """Minimal .env reader so `GROQ_API_KEY=...` in a project .env just works.

    No python-dotenv dependency; only sets keys not already in the environment.
    """
    env = Path(__file__).resolve().parents[2] / ".env"
    if not env.exists():
        return
    for line in env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_dotenv()

DEFAULT_MODEL = os.getenv("VERDICT_MODEL", "openai/gpt-oss-120b")

Action = Optional[dict]


# --- shared: resolve grounded args for a chosen read tool --------------------

def resolve_args(tool: str, alert: dict, ev: dict) -> Optional[dict]:
    """Fill a tool's args from the alert and evidence gathered so far.

    Returns None when prerequisites are missing (e.g. cve_match before we know
    the service version) — the caller treats that as 'not yet callable'.
    """
    dst = alert.get("dst")
    asset = ev.get("cmdb_asset")
    host = asset.get("host") if asset else None
    port = str(alert.get("dst_port"))

    if tool == "cmdb_asset":
        return {"ip": dst}
    if tool == "cve_match":
        if not asset:
            return None
        svc = asset.get("services", {}).get(port)
        if not svc:
            return None
        return {"product": svc["product"], "version": svc["version"]}
    if tool == "pcap_flow":
        fid = alert.get("flow_id")
        return {"flow_id": fid} if fid else None
    if tool == "logs_query":
        return {"host": host} if host else None
    if tool == "edr_processtree":
        return {"host": host} if host else None
    return None


# --- rule mode ---------------------------------------------------------------

def _rule_next(alert: dict, ledger: Ledger, ev: dict, called: set) -> Action:
    """Deterministic policy that prioritizes the next most informative query."""
    def act(tool, why):
        args = resolve_args(tool, alert, ev)
        if args is None or (tool, _key(args)) in called:
            return None
        return {"tool": tool, "args": args, "rationale": why}

    # 1. establish the attack surface first — usually the highest-value evidence
    if "cmdb_asset" not in ev:
        return act("cmdb_asset",
                   "Unknown whether the target even runs the alerted service. "
                   "Asset facts separate H3 (noise) from the exploit hypotheses.")

    asset = ev["cmdb_asset"]
    port = str(alert.get("dst_port"))
    svc = asset.get("services", {}).get(port)

    # 2. nothing listening on that port -> lean scanner; confirm with the flow
    if not svc:
        a = act("pcap_flow", "No service on the alerted port; a REFUSED/tiny flow "
                             "would confirm H3 (sweep) over a real exploit.")
        return a  # None -> stop and decide on argmax

    # 3. CVE-claiming alert: is the running version actually exploitable?
    if alert.get("claimed_cve"):
        if "cve_match" not in ev:
            return act("cve_match",
                       "Service present; exploitability is the pivot between "
                       "H1 (succeeded) and H2 (attempted-failed).")
        exploitable = ev["cve_match"].get("exploitable")
        if exploitable:
            # 4. viable exploit -> did it actually land? proc tree, then flow
            if "edr_processtree" not in ev:
                return act("edr_processtree",
                           "Exploit is viable; a spawned shell / persistence "
                           "would confirm H1 over H2.")
            return act("pcap_flow",
                       "Corroborate compromise with an outbound beacon/exfil flow.")
        # 5. not exploitable -> confirm the failed attempt via the flow
        if "pcap_flow" not in ev:
            return act("pcap_flow",
                       "Target patched; a RST/no-data flow confirms H2 (attempt failed).")
        # 5b. but a patched target showing a live beacon is a contradiction —
        # don't take 'patched' at face value, check for compromise via another
        # vector (this is what lets late/reversing evidence actually be acted on)
        flow = ev["pcap_flow"]
        if flow.get("state") == "ESTABLISHED" and flow.get("bytes_out", 0) > 10000:
            return act("edr_processtree",
                       "Patched-but-active beacon contradicts a clean failed attempt; "
                       "checking for compromise via another vector before closing H2.")
        return None  # clean RST/no-data confirms H2; nothing more to gather

    # 6. no CVE claim -> benign vs. something: logs then process tree
    if "logs_query" not in ev:
        return act("logs_query",
                   "No CVE claimed; auth/deploy logs separate H4 (benign admin) "
                   "from a real intrusion.")
    return act("edr_processtree",
               "Confirm H4 with a clean process tree, or overturn it if not.")


# --- llm mode ----------------------------------------------------------------

_LLM_SYSTEM = (
    "You are a SOC investigation planner. You hold four competing hypotheses "
    "about a security alert and must choose the SINGLE next read-only tool whose "
    "result would most reduce your uncertainty — the highest information gain — "
    "not walk a fixed checklist. Stop as soon as one hypothesis is clearly "
    "dominant. Reply with ONLY a JSON object: "
    '{"tool": <name|null>, "rationale": <one sentence>}. '
    "tool=null means stop investigating. Do not include any other text."
)


def _call_groq(system: str, user: str, model: str) -> str:
    """One chat completion against Groq's OpenAI-compatible endpoint (stdlib only)."""
    key = os.getenv("GROQ_API_KEY")
    if not key:
        raise RuntimeError("GROQ_API_KEY not set")
    body = json.dumps({
        "model": model,
        "temperature": 0,
        "max_tokens": 512,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }).encode("utf-8")
    req = urllib.request.Request(
        GROQ_URL, data=body,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            # Groq's Cloudflare edge 403s the default Python-urllib UA (error 1010).
            "User-Agent": "verdict-soc-agent/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    return payload["choices"][0]["message"]["content"].strip()


def _llm_next(alert: dict, ledger: Ledger, ev: dict, called: set, model: str) -> Action:
    available = [t for t in toolmod.READ_TOOLS if t != "env_probe"]
    seen = {t: _summarise(t, a) for t, a in ev.items()}
    prompt = {
        "alert": {k: alert.get(k) for k in
                  ("src", "dst", "dst_port", "signature", "claimed_cve", "severity")},
        "hypotheses": HYPOTHESES,
        "confidence": ledger.conf,
        "evidence_so_far": seen,
        "tools_available": available,
        "tools_already_called": sorted({t for t, _ in called}),
    }
    text = _call_groq(_LLM_SYSTEM, json.dumps(prompt), model)
    choice = _parse_choice(text)
    if choice is None or choice.get("tool") in (None, "null"):
        return None
    tool = choice["tool"]
    if tool not in toolmod.READ_TOOLS or tool == "env_probe":
        return _rule_next(alert, ledger, ev, called)   # fall back on a bad pick
    args = resolve_args(tool, alert, ev)
    if args is None or (tool, _key(args)) in called:
        return _rule_next(alert, ledger, ev, called)
    return {"tool": tool, "args": args, "rationale": choice.get("rationale", "")}


def _parse_choice(text: str) -> Optional[dict]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if 0 <= start < end:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                return None
    return None


def _summarise(tool: str, artifact: dict) -> Any:
    """A compact view of an artifact for the planner prompt (keeps tokens down)."""
    keep = {
        "cmdb_asset": ("services", "criticality"),
        "cve_match": ("exploitable", "product"),
        "edr_processtree": ("suspicious", "persistence"),
        "pcap_flow": ("state", "bytes_out", "note"),
        "logs_query": ("lines",),
    }.get(tool)
    if not keep:
        return {"artifact_id": artifact.get("artifact_id")}
    return {k: artifact.get(k) for k in keep if k in artifact}


def _key(args: dict) -> tuple:
    return tuple(sorted(args.items()))


# --- entry point -------------------------------------------------------------

def next_action(alert, ledger, ev, called, mode: str = "rule",
                model: str = DEFAULT_MODEL) -> Action:
    if mode == "llm":
        try:
            return _llm_next(alert, ledger, ev, called, model)
        except Exception:
            return _rule_next(alert, ledger, ev, called)   # never let the demo die on an API hiccup
    return _rule_next(alert, ledger, ev, called)


def default_mode() -> str:
    """LLM if a Groq key is configured and the caller opts in; rule otherwise."""
    return "llm" if os.getenv("GROQ_API_KEY") and os.getenv("VERDICT_PLANNER") == "llm" else "rule"
