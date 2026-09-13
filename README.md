# VERDICT

**An autonomous SOC agent that proves whether an attack actually succeeded — then takes the narrowest safe response.**

Built for **Tech Zephyr 4.0 — Agentic AI Hackathon, IIT Bhubaneswar**
Track 5: Cybersecurity · **Problem Statement 9** — Autonomous SOC Investigation & Response Agent
Team **Verdict**

**Status: complete.** Code, tests, UI, pitch deck, and demo video are all done —
see [SUBMISSION.md](SUBMISSION.md) for the delivered package and links.

---

## The problem with every other SOC "AI"

A NIDS alert is a **hypothesis**, not a verdict. The overwhelming majority of alerts are attempts fired at targets that were never exploitable in the first place — wrong version, already patched, port closed, service not even running.

A system that reads `Critical: Log4Shell` and blocks the source IP is a classifier with extra steps. It is not an agent.

**VERDICT treats every alert as an open question and buys evidence until the question closes.**

---

## Three mechanisms that carry the whole submission

### 1. Hypothesis ledger + evidence-prioritized tool selection

The agent maintains four live, competing hypotheses with confidences:

| ID | Hypothesis |
|----|-----------|
| `H1` | Attack **succeeded** and established persistence |
| `H2` | Attack was **attempted and failed** (target not exploitable) |
| `H3` | **Scanner noise** / opportunistic spray |
| `H4` | **Benign** admin or automation activity |

Before every tool call the agent asks: *which single query most separates my surviving hypotheses?* It uses a deterministic policy designed to prioritize high-value evidence first.

The confidence bars move on screen after each observation. That is the autonomy score, made visible.

### 2. Blast-radius gate on state-changing actions

Blocking is not free. Before any enforcement, the agent computes collateral impact from the CMDB:

- source IP is a **shared NAT egress** → blocking takes 340 users offline
- destination is a **prod database peer** → blocking breaks payments

The agent proposes the **narrowest sufficient** enforcement (a `src:dst:port` tuple, host quarantine, or a rate-limit) and escalates to a human rather than nuking the network.

### 3. Evidence Auditor

A second verification pass over the final incident report. Every claim must cite a retrieved artifact ID (`pcap_88`, `cve_match_3`, `authlog_line_412`). Uncited sentences are stripped and flagged.

**Hallucinated-claim rate is a reported metric, and its target is zero.**

---

## The agent loop

```
GOAL: "Close alert #A-1042 with an evidence-backed verdict
       and the narrowest safe response."

 ┌─ 1. INGEST      alert -> structured claim (src, dst, sig, claimed_cve, ts)
 │                 initialise ledger: H1..H4 at prior confidence
 │
 ├─ 2. PLAN        pick next tool by expected information gain
 │                 "What single fact most collapses my hypothesis set?"
 │                 typically first: is dst even running a vulnerable version?
 │
 ├─ 3. ACT         call ONE tool (read-only during investigation)
 │
 ├─ 4. OBSERVE     write artifact to evidence store with a stable ID
 │                 update ledger confidences + a written reason string
 │
 ├─ 5. STOP-CHECK  max confidence > 0.85  OR  tool budget exhausted?
 │                 no  -> loop to 2        (typical run: around 3 tool calls, 2.85 average)
 │                 yes -> continue
 │
 ├─ 6. DECIDE      verdict -> response tier
 │                   FAILED / FALSE POSITIVE -> close, no action
 │                   ATTEMPTED               -> monitor rule, no block
 │                   SUCCEEDED               -> contain
 │                 blast-radius gate:
 │                   high collateral -> propose + ESCALATE to human
 │                   low  collateral -> execute autonomously
 │
 ├─ 7. EXECUTE     fw_apply(rule)          <- state-changing
 │
 ├─ 8. VERIFY      (a) re-read firewall state - is the rule committed AND live?
 │                 (b) env_probe() - does traffic actually drop now?
 │                 (c) Evidence Auditor - is every report claim cited?
 │                 any failure -> back to 2, with the failure as new evidence
 │
 └─ 9. WATCH       environment keeps streaming. New evidence that contradicts
                   a closed verdict REOPENS the case -> back to 2.
```

Persistent state across the whole loop: `ledger`, `evidence_store`, `action_log`, `case_status`.

---

## The three live disruptions

These are wired to **buttons the judges press**. They are not scripted video.

| # | Injection | Required agent behaviour |
|---|-----------|--------------------------|
| **1. Evidence reversal** | After the agent closes `FAILED — target patched to 2.17`, a late syslog batch arrives showing an outbound beacon to the same C2 on a 60s interval | Reopen the case, flip `H2 -> H1`, recognise the patch was reverted or a second vector exists, escalate to containment |
| **2. Action failure** | The firewall API returns `200 OK` but the rule is staged, never committed — a silent partial apply | The verify step catches it. The agent does **not** declare success. Retries, fails again, falls back to host-level EDR quarantine, re-verifies |
| **3. Override + rollback** | The agent refuses to block a shared NAT IP (blast radius: 340 users) and escalates. **The judge clicks "Override — block anyway."** | The agent complies. Post-action verification then detects collateral impact and the agent **auto-rolls back** to the scoped tuple rule, reporting damage to the human |

**Scenario 3 is the winning moment.** An agent that obeys a human, notices the human was wrong, and safely undoes it is a level above anything else in the room.

---

## Sandbox environment

All synthetic. No real hosts, no real credentials, no traffic leaves the simulator.

| Tool | Returns | State-changing |
|------|---------|:--------------:|
| `nids_alerts()` | Suricata-format alert stream | no |
| `pcap_flow(flow_id)` | payload snippet, bytes in/out, duration, direction | no |
| `cmdb_asset(ip)` | host, OS, installed versions, criticality, owner, **peer dependencies** | no |
| `cve_match(product, version)` | exploitable?, patch status, exploit maturity | no |
| `logs_query(host, window, grep)` | web / auth / syslog lines | no |
| `edr_processtree(host, t)` | spawned processes, persistence artifacts | no |
| `fw_apply(rule)` / `fw_state()` | commit result — **fails on demand** | **yes** |
| `edr_quarantine(host)` | fallback enforcement path | **yes** |
| `env_probe(src, dst, port)` | does traffic actually pass right now? | no — this is the verifier |

`env_probe` is the entire verification story and costs about twenty lines. It is what separates *"the agent said it blocked"* from *"the block is real."* Do not skip it.

---

## Evaluation scoreboard

Run **40 labelled synthetic incidents** with ground truth. Report:

| Metric | Target |
|--------|--------|
| Verdict accuracy vs ground truth (succeeded / failed / FP) | > 90% |
| Mean tool calls to verdict | 2–4 (2.85 average) |
| Hallucinated-claim rate | **0** |
| Unsafe-action rate | **0** |
| Recovery success rate across the 3 injections | 3 / 3 |
| **Baseline: alert-label-only classifier, same incident set** | **35% verdict accuracy** |

That last row is the single most persuasive number in the submission.

---

## Demo video

**Done — delivered as `Verdict_video_agentic.webm`.** It's a real recording of
the actual app running (a headless-browser automation script drove the live
UI through the sequence below; Chromium's native recorder captured it), not a
mockup or a slideshow. Maps 1:1 onto the brief's required sequence:

1. **Goal** — incident `A-1000` (ProxyLogon SSRF, severity *low* — one of the
   6 adversarial cases). "Close it with an evidence-backed verdict."
2. **Decision** — the reasoning trace animates live: `cmdb_asset` → `cve_match`
   → `edr_processtree`. Not a fixed chain — each step is chosen because it's
   the next-most-informative question, not because it's next on a list.
3. **Action** — verdict `SUCCEEDED`, 99% confidence, 3 tool calls. Close Case
   runs decide → execute → verify: the narrowest rule, then `env_probe`
   re-checks the traffic is actually gone.
4. **Intermediate result** — the Evidence Auditor panel: every claim cites a
   real artifact ID, 0% hallucination rate, measured live.
5. **Adaptation ×3** — incident `A-1014` closes `FAILED`, then late evidence
   reopens it to `SUCCEEDED` (unprompted). A fresh case's firewall silently
   fails twice, caught by `env_probe`, falls back to EDR quarantine. A third
   case escalates on blast radius (340 users behind a shared NAT); a human
   overrides; the agent complies, then catches its own collateral damage and
   **auto-rolls back** to the narrow rule.
6. **Final outcome** — the 40-incident scoreboard: 100% accuracy vs. 35%
   baseline, printed live from `python -m verdict.eval.run`, not staged.

See [DEMO_SCRIPT.md](DEMO_SCRIPT.md) for the full shot-by-shot breakdown.

---

## Architecture

**One orchestrator agent + one Evidence Auditor verifier.** That is the whole thing.

The brief states explicitly that agent count earns zero points. A six-agent mesh would only consume debugging time we do not have.

---

## Rubric coverage

| Criterion | Weight | How VERDICT earns it |
|-----------|:------:|----------------------|
| Agentic workflow & autonomy | 25% | Hypothesis ledger, information-gain planning, dynamic stop condition |
| Tool / environment interaction | 15% | 9 tools, 2 state-changing, real dependency graph in the CMDB |
| Adaptation & failure recovery | 15% | 3 judge-triggered injections: evidence reversal, silent action failure, override + rollback |
| Technical implementation | 15% | Deterministic simulator, persistent state, reproducible eval harness |
| Problem relevance & innovation | 10% | Exploitability adjudication + blast-radius gating — not alert classification |
| Prototype functionality & UX | 10% | Single screen: live ledger, evidence graph, judge injection buttons |
| Evaluation, verification & robustness | 10% | `env_probe` action verification, Evidence Auditor claim verification, 40-case scoreboard with baseline |

---

## Running the demo

```bash
pip install -r requirements.txt
python -m verdict.ui.app
# open http://127.0.0.1:8000
```

Pick an incident, choose the planner (rule = offline/deterministic, llm = Groq
`openai/gpt-oss-120b`, needs `GROQ_API_KEY` in `.env`), hit **Start
Investigation** to watch the hypothesis ledger animate, **Close Case** to run
decide/execute/verify, then use the three judge buttons — Evidence Reversal,
Silent Firewall Failure, Broad-Blast Scenario (escalates → click **Override**
to watch the auto-rollback) — to break the agent live and watch it recover.

No UI needed to reproduce the scoreboard:

```bash
python -m verdict.eval.run              # all 40 incidents, rule mode
python tests/test_respond.py            # Phase 3 acceptance: all 3 injections
```

---

## Guardrails

- All activity is confined to the provided sandbox. No production systems, no real credentials, no real network changes.
- All data is synthetic.
- Every autonomous enforcement action is reversible and logged, and high-blast-radius actions require human approval.

---

See **[ROADMAP.md](ROADMAP.md)** for the build plan (all 4 phases built and tested),
**[PITCH_DECK.html](PITCH_DECK.html)** for the presentation, **[DEMO_SCRIPT.md](DEMO_SCRIPT.md)**
for the shot-by-shot breakdown behind the delivered video, and **[SUBMISSION.md](SUBMISSION.md)**
for the full submission package, links, and file naming.
