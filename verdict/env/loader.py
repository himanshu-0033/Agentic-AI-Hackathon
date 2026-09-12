"""Load incident JSON into a World."""
from __future__ import annotations

import json
from pathlib import Path

from .world import World

INCIDENTS_DIR = Path(__file__).parent / "incidents"


def load_incident(incident_id: str) -> dict:
    return json.loads((INCIDENTS_DIR / f"{incident_id}.json").read_text(encoding="utf-8"))


def load_world(incident_id: str) -> World:
    return World.from_incident(load_incident(incident_id))


def all_incident_ids() -> list[str]:
    return sorted(p.stem for p in INCIDENTS_DIR.glob("A-*.json"))
