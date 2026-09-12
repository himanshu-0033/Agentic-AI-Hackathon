# VERDICT — Submission Package

**Team name:** Verdict
**Track 5: Cybersecurity — Problem Statement 9** (Autonomous SOC Investigation & Response Agent)

The hackathon brief requires every submitted file named `TeamName_Github/Agentic`
style (their example: `Techrebels_video_agentic`). Use this table when
uploading to the submission portal.

| Deliverable | What it is | File to submit | Rename to |
|---|---|---|---|
| Source code / GitHub repo | This repository | share the URL below | — (repos aren't renamed, just linked) |
| Presentation summary | `PITCH_DECK.html` — 10-slide deck, arrow-key/click navigation | `PITCH_DECK.html` (or the artifact link) | `Verdict_deck_agentic.html` |
| Demo video | **Not yet recorded** — see below | *(you record this)* | `Verdict_video_agentic.<ext>` |
| Runnable version | The repo itself (`python -m verdict.ui.app`) | — optional per the brief | — |

---

## Links

- **GitHub repository:** https://github.com/himanshu-0033/Agentic-AI-Hackathon
- **Pitch deck (live, clickable):** https://claude.ai/code/artifact/44072c5a-2e09-4dfd-b2db-ccd8fd7da519
  *(private by default — open it and use the share menu if the portal needs a public link, or submit the `PITCH_DECK.html` file directly instead)*

---

## What's done

- ✅ Full agent: environment, ledger, planner (rule + LLM via Groq), decide/execute/verify, blast-radius gate, Evidence Auditor, all 3 adaptation injections
- ✅ Demo UI (`python -m verdict.ui.app`) — every judge interaction is a real button, not a script
- ✅ 40-incident eval: **100% accuracy, 2.85 mean tool calls, 6/6 adversarial, 0% hallucination**, vs **35%** for a label-only baseline
- ✅ `tests/test_env.py`, `tests/test_agent.py`, `tests/test_respond.py` — all passing, run before every commit
- ✅ Pitch deck, 10 slides, matches the product's own visual language
- ✅ `DEMO_SCRIPT.md` — shot-by-shot script for the video, verified against the live running UI

## What's left — genuinely on you, not scriptable

1. **Record the demo video.** Follow `DEMO_SCRIPT.md` exactly — it names real incident IDs, real button labels, and real numbers, all checked against the running app. Any screen recorder works (OBS, `Win+Alt+R`, QuickTime). Target 3-4 minutes.
2. **Upload to the portal** using the renamed files from the table above.
3. If the portal wants the deck as a PDF/PPTX instead of HTML: open `PITCH_DECK.html` in a browser and use **Print → Save as PDF** (it's laid out as fixed 16:9 slides, so this prints cleanly one slide per page).

---

## Quick verification before you submit

```bash
python tests/test_env.py && python tests/test_agent.py && python tests/test_respond.py
python -m verdict.eval.run
```

All three test files should print `ACCEPTANCE: all checks passed.` and the
eval should show `100%` agent accuracy. If any of that doesn't match, something
changed — don't submit until it's green again.
