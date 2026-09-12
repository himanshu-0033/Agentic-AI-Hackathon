# VERDICT — Build Roadmap

Four phases. Each phase has an **acceptance test** — do not move to the next phase until it passes.

The ordering rule for the whole build: **the environment is built before the agent.** A thin sandbox produces a thin agent, and no amount of prompt work recovers from it. If the schedule slips, cut agent sophistication, never environment fidelity.

---

## Phase 0 — Setup (1 hour)

| # | Task | Done |
|---|------|:----:|
| 0.1 | Lock the team name and the submission naming format: `TeamName_video_agentic`, `TeamName_github_agentic` | ☐ |
| 0.2 | Python 3.11 venv, `requirements.txt` — only `anthropic`, `fastapi`, `uvicorn`, `pydantic` | ☐ |
| 0.3 | API key in `.env`, `.env` in `.gitignore`. **Never commit a key.** | ☐ |
| 0.4 | Agree the repo layout below and push a skeleton so everyone pulls the same tree | ☐ |

```
verdict/
  env/          simulator — all synthetic state lives here
    world.py      the world: assets, CVEs, logs, firewall state
    tools.py      the 9 tool functions the agent may call
    injections.py the 3 disruptions, toggled by flags
    incidents/    40 labelled JSON incidents + ground truth
  agent/
    loop.py       the 9-step loop
    ledger.py     hypothesis state + confidence updates
    planner.py    information-gain tool selection
    decide.py     verdict -> response tier + blast-radius gate
    auditor.py    Evidence Auditor (citation verification)
  eval/
    run.py        batch over incidents/, emits the scoreboard
    baseline.py   alert-label-only classifier for comparison
  ui/
    app.py        FastAPI + one HTML page
  tests/
    test_loop.py  the one runnable self-check
```

**Acceptance:** every team member can run `python -m verdict.env.world` and see synthetic state print.

---

## Phase 1 — The environment (Day 1, morning · ~5 hours)

This is the phase that decides whether you win. Budget generously.

| # | Task | Owner | Done |
|---|------|-------|:----:|
| 1.1 | `world.py` — in-memory state: 12 assets with OS, installed package versions, criticality, owner, **peer dependencies**; 8 synthetic CVEs; firewall ruleset; session table | | ☐ |
| 1.2 | `tools.py` — all 9 tools from the README table, each returning a dict with a stable artifact ID | | ☐ |
| 1.3 | `env.probe(src, dst, port)` — evaluates the live ruleset and returns `PASS` / `DROP`. **~20 lines. The entire verification story depends on it.** | | ☐ |
| 1.4 | `fw.apply(rule)` with a `silent_fail` flag: returns `200 OK`, writes the rule as `staged`, never commits | | ☐ |
| 1.5 | Write **40 labelled incidents**. Distribution: 14 succeeded, 16 attempted-and-failed, 6 scanner noise, 4 benign admin. Each carries `ground_truth_verdict` and `ground_truth_action` | | ☐ |
| 1.6 | Make at least 6 incidents **adversarial**: a critical-severity alert whose target was patched, and a low-severity alert that actually succeeded. These break naive classifiers | | ☐ |

**Acceptance:** a human can manually call tools in a REPL and correctly solve 3 incidents by hand. If a human cannot solve it from the available evidence, the agent cannot either — fix the environment, not the prompt.

---

## Phase 2 — The agent loop (Day 1, afternoon · ~6 hours)

| # | Task | Owner | Done |
|---|------|-------|:----:|
| 2.1 | `ledger.py` — four hypotheses, confidences summing to 1.0, `update(evidence) -> new confidences + reason string`. Every update appends to a history list | | ☐ |
| 2.2 | `planner.py` — given the ledger and tools already called, ask the model which single tool most separates the surviving hypotheses, and why. Returns `(tool, args, rationale)` | | ☐ |
| 2.3 | Loop steps 1–5 in `loop.py`. Stop at confidence > 0.85 or a 12-call budget | | ☐ |
| 2.4 | Guard: never call the same tool with identical args twice. Force progress | | ☐ |
| 2.5 | Persist `ledger`, `evidence_store`, `action_log`, `case_status` to a JSON file per case — this is the "persistent task state" requirement, made literal and inspectable | | ☐ |
| 2.6 | Run against all 40 incidents. Log verdict accuracy. **Do not tune prompts until you have this first number.** | | ☐ |

**Acceptance:** verdict accuracy above 75% and mean tool calls under 10, with no code that special-cases a specific incident ID.

---

## Phase 3 — Decide, act, verify (Day 2, morning · ~5 hours)

| # | Task | Owner | Done |
|---|------|-------|:----:|
| 3.1 | `decide.py` — verdict maps to response tier (close / monitor / contain) | | ☐ |
| 3.2 | Blast-radius calculator — walk CMDB peer dependencies, count affected users and services, return a collateral score | | ☐ |
| 3.3 | Gate: collateral above threshold means propose the narrowest alternative and escalate, never execute | | ☐ |
| 3.4 | Execute + verify: `fw.apply` then `fw.state` then `env.probe`. A mismatch feeds back into the loop as new evidence | | ☐ |
| 3.5 | Fallback path: firewall verification fails twice, so fall back to `edr.quarantine`, then re-verify | | ☐ |
| 3.6 | `auditor.py` — parse the report, extract claims, check each carries an artifact ID present in the evidence store, strip or flag anything uncited | | ☐ |
| 3.7 | `injections.py` — the three disruptions as runtime flags, triggerable mid-run | | ☐ |
| 3.8 | Rollback: store the pre-action ruleset, and if post-action probing shows collateral, restore it and report | | ☐ |

**Acceptance:** all three injections fire mid-run and the agent recovers from each without a restart. Injection 3 must end in an automatic rollback.

---

## Phase 4 — UI, eval, submission (Day 2, afternoon · ~6 hours)

| # | Task | Owner | Done |
|---|------|-------|:----:|
| 4.1 | Single-page UI: left is the live reasoning trace, centre is the hypothesis bars plus evidence graph, right is the action queue | | ☐ |
| 4.2 | **Judge controls**: three injection buttons plus an "Override — block anyway" button. These must be clickable during the live demo | | ☐ |
| 4.3 | Server-sent events so the ledger animates as the agent reasons. A static page that refreshes at the end wastes the whole autonomy story | | ☐ |
| 4.4 | `eval/run.py` — batch all 40, emit the scoreboard table | | ☐ |
| 4.5 | `eval/baseline.py` — trust the alert label, always block. Report its accuracy for the comparison row | | ☐ |
| 4.6 | `tests/test_loop.py` — one assert-based self-check: a known-failed incident must not produce a block | | ☐ |
| 4.7 | Record the demo video against the 7 beats in the README. Judge presses the buttons on camera | | ☐ |
| 4.8 | Presentation deck: approach, solution, challenges, conclusion. **Include the scoreboard slide with the baseline row** | | ☐ |
| 4.9 | Rename all files to `TeamName_*_agentic` and submit | | ☐ |

**Acceptance:** a judge who has never seen the code can break the agent with a button and watch it recover, without anyone touching a terminal.

---

## Parallelisation for a team of three

| Person | Phase 1 | Phase 2 | Phase 3 | Phase 4 |
|--------|---------|---------|---------|---------|
| **A — Environment** | `world.py`, `tools.py`, `env.probe` | 40 incidents + adversarial cases | `injections.py`, rollback | `eval/run.py`, baseline |
| **B — Agent** | incident schema | ledger, planner, loop | decide, blast radius, verify | prompt tuning, self-check |
| **C — Interface** | repo skeleton, state schema | JSON state viewer (CLI is fine) | auditor | UI, SSE, judge buttons, video |

C should build the state viewer early. Being able to *see* the ledger is what makes phase 2 debuggable.

---

## Explicitly out of scope

Cut these on sight. None of them move a single rubric line.

- LangGraph, CrewAI, AutoGen — a plain `while` loop is clearer and debuggable at 2am
- A vector database — 8 CVEs fit in a dict
- Real PCAP parsing — synthetic flow metadata is enough
- Authentication, multi-tenancy, user accounts
- Docker, CI, deployment
- More than two agents — the brief states agent count earns zero points
- Any real network action of any kind

---

## Risk register

| Risk | Mitigation |
|------|------------|
| Environment is too thin, so the agent has nothing to reason over | Phase 1 acceptance test: a human must be able to solve incidents by hand |
| Agent loops without converging | Hard 12-call budget, plus the no-duplicate-call guard |
| Demo depends on a live API and the venue wifi fails | Record a backup video, and cache a full replayable run to JSON |
| Judges suspect the scenarios are hardcoded | Hand them the button, and run an incident they choose from the set |
| Prompt tuning eats the whole of day 2 | Accuracy is measured at the end of phase 2, before any tuning begins |

---

## The one thing to protect

If the schedule collapses, the minimum submission that still scores well is:

**the loop + the ledger + `env.probe` verification + injection 3 (override and rollback).**

Ship that and skip the UI polish, the baseline comparison, and half the incidents. That core is what the 25% autonomy and 15% adaptation weights are actually measuring.
