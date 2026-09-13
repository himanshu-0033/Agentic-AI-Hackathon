"""Phase 4 demo UI: FastAPI backend driving investigate -> inject -> close.

Each case runs its full investigation synchronously (rule mode: milliseconds;
llm mode: a couple of API calls) and buffers every reasoning/action step as an
event. The SSE endpoint then replays buffered events with a short delay so
the browser animates the ledger — no live threading, no websockets, just a
finite event log replayed on demand. That's the whole animation trick.

Run:  python -m verdict.ui.app        then open http://127.0.0.1:8000
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse

from ..agent.injections import (
    inject_action_failure,
    inject_evidence_reversal,
    inject_override_scenario,
)
from ..agent.loop import investigate, watch
from ..agent.respond import close_case
from ..env.loader import all_incident_ids, load_incident, load_world

app = FastAPI(title="VERDICT")
CASES: dict[str, dict[str, Any]] = {}
STEP_DELAY = 0.55  # seconds between SSE events, tuned for readable animation

INJECTIONS = {
    "evidence_reversal": inject_evidence_reversal,
    "firewall_failure": inject_action_failure,
    "override_scenario": inject_override_scenario,
}


def _push(case: dict, type_: str, payload: dict) -> None:
    case["events"].append({"type": type_, "payload": payload})


def _snapshot(case: dict) -> dict:
    inv = case["investigation"]
    resp = case["response"]
    return {
        "iid": case["iid"], "mode": case["mode"], "status": case["status"],
        "verdict": inv["verdict"] if inv else None,
        "confidence": inv["confidence"] if inv else None,
        "top_hypothesis": inv["top_hypothesis"] if inv else None,
        "tier": resp["decision"]["tier"] if resp else None,
        "escalate": resp["decision"]["escalate"] if resp else False,
        "event_count": len(case["events"]),
        "injections_used": case["injections_used"],
    }


def _get_case(iid: str) -> dict:
    case = CASES.get(iid)
    if case is None:
        raise HTTPException(404, f"no active case for {iid}; call /start first")
    return case


# --- static page --------------------------------------------------------

@app.get("/")
def index() -> FileResponse:
    return FileResponse(Path(__file__).parent / "index.html")


# --- incidents -----------------------------------------------------------

@app.get("/api/incidents")
def list_incidents() -> list[dict]:
    out = []
    for iid in all_incident_ids():
        a = load_incident(iid)["alert"]
        out.append({
            "id": iid, "src": a["src"], "dst": a["dst"], "dst_port": a["dst_port"],
            "signature": a["signature"], "claimed_cve": a.get("claimed_cve"),
            "severity": a["severity"],
        })
    return out


# --- case lifecycle --------------------------------------------------------

@app.post("/api/cases/{iid}/start")
def start_case(iid: str, mode: str = "rule") -> dict:
    mode = mode.lower()
    if mode not in {"rule", "llm"}:
        raise HTTPException(400, f"invalid mode {mode!r}; expected 'rule' or 'llm'")
    world = load_world(iid)
    case = {
        "iid": iid, "world": world, "mode": mode,
        "investigation": None, "response": None, "status": "idle",
        "events": [], "injections_used": [],
    }
    CASES[iid] = case

    inv = investigate(world, mode=mode, persist=False)
    case["investigation"] = inv
    for step in inv["trace"]:
        _push(case, "tool_call", step)
    _push(case, "verdict", {
        "verdict": inv["verdict"], "confidence": inv["confidence"],
        "top_hypothesis": inv["top_hypothesis"], "stop_reason": inv["stop_reason"],
        "tool_calls": inv["tool_calls"],
    })
    case["status"] = "investigated"
    return _snapshot(case)


@app.post("/api/cases/{iid}/inject/{name}")
def inject(iid: str, name: str) -> dict:
    fn = INJECTIONS.get(name)
    if fn is None:
        raise HTTPException(400, f"unknown injection {name!r}")
    case = _get_case(iid)
    world, alert = case["world"], case["world"].alert

    msg = fn(world, alert) if name != "firewall_failure" else fn(world)
    _push(case, "injection", {"name": name, "message": msg})
    case["injections_used"].append(name)

    if name == "evidence_reversal":
        result = watch(world, case["investigation"], mode=case["mode"] or "rule")
        if result["reopened"]:
            new_inv = result["new_investigation"]
            case["investigation"] = new_inv
            for step in new_inv["trace"]:
                _push(case, "tool_call", step)
            _push(case, "verdict", {
                "verdict": new_inv["verdict"], "confidence": new_inv["confidence"],
                "top_hypothesis": new_inv["top_hypothesis"], "stop_reason": new_inv["stop_reason"],
                "tool_calls": new_inv["tool_calls"], "reopened": True,
                "prior_verdict": result["prior_verdict"],
            })
            case["status"] = "investigated"  # ready to be closed again under the new verdict
        else:
            _push(case, "verdict", {"reopened": False,
                                    "note": "new evidence did not overturn the closed verdict"})
    return _snapshot(case)


@app.post("/api/cases/{iid}/close")
def close(iid: str, override: bool = False) -> dict:
    case = _get_case(iid)
    if case["investigation"] is None:
        raise HTTPException(400, "no investigation to close; call /start first")

    world = case["world"]
    out = close_case(world, case["investigation"], world.alert, override=override, persist=True)
    case["response"] = out

    _push(case, "decision", out["decision"])
    for entry in out["response"]["action_log"]:
        _push(case, "action", entry)
    _push(case, "response_status", {
        k: out["response"][k] for k in
        ("status", "verified", "quarantine_used", "rolled_back", "rollback_reason", "override_used")
        if k in out["response"]
    })
    _push(case, "report", {
        "verified": len(out["report"]["verified_claims"]),
        "flagged": len(out["report"]["flagged_claims"]),
        "hallucination_rate": out["report"]["hallucination_rate"],
    })
    case["status"] = out["response"]["status"]
    return _snapshot(case)


@app.get("/api/cases/{iid}")
def get_case(iid: str) -> dict:
    return _snapshot(_get_case(iid))


@app.get("/api/cases/{iid}/stream")
async def stream(iid: str, since: int = 0):
    case = _get_case(iid)
    events = case["events"][since:]

    async def gen():
        for e in events:
            yield f"data: {json.dumps(e)}\n\n"
            await asyncio.sleep(STEP_DELAY)
        yield "event: done\ndata: {}\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
