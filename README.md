# VERDICT

**An autonomous SOC agent that proves whether an attack actually succeeded — then takes the narrowest safe response.**

Built for **Tech Zephyr 4.0 — Agentic AI Hackathon, IIT Bhubaneswar**
Track 5: Cybersecurity · **Problem Statement 9** — Autonomous SOC Investigation & Response Agent

---

## The problem with every other SOC "AI"

A NIDS alert is a **hypothesis**, not a verdict. The overwhelming majority of alerts are attempts fired at targets that were never exploitable in the first place — wrong version, already patched, port closed, service not even running.

A system that reads `Critical: Log4Shell` and blocks the source IP is a classifier with extra steps. It is not an agent.

**VERDICT treats every alert as an open question and buys evidence until the question closes.**

---

## Three mechanisms that carry the whole submission

### 1. Hypothesis ledger + information-gain tool selection

The agent maintains four live, competing hypotheses with confidences:

| ID | Hypothesis |
|----|-----------|
| `H1` | Attack **succeeded** and established persistence |
| `H2` | Attack was **attempted and failed** (target not exploitable) |
| `H3` | **Scanner noise** / opportunistic spray |
| `H4` | **Benign** admin or automation activity |

Before every tool call the agent asks: *which single query most separates my surviving hypotheses?* It does **not** walk a fixed chain. This is the direct, demonstrable answer to the brief's requirement that "a fixed prompt chain without meaningful autonomous action won't qualify."

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
 │                 no  -> loop to 2        (typical run: 5-9 tool calls)
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
 ├─ 7. EXECUTE     fw.apply(rule)          <- state-changing
 │
 ├─ 8. VERIFY      (a) re-read firewall state - is the rule committed AND live?
 │                 (b) env.probe() - does traffic actually drop now?
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
| **3. Override + rollback** | The agent refuses to block a shared NAT IP (blast radius: 340 users) and escalates. **The judge clicks "Override — block anyway."** | The agent complies. Post-action verification then detects 40 dropped legitimate sessions. The agent **auto-rolls back** to the scoped tuple rule and reports the collateral damage to the human |

**Scenario 3 is the winning moment.** An agent that obeys a human, notices the human was wrong, and safely undoes it is a level above anything else in the room.

---

## Sandbox environment

All synthetic. No real hosts, no real credentials, no traffic leaves the simulator.

| Tool | Returns | State-changing |
|------|---------|:--------------:|
| `nids.alerts()` | Suricata-format alert stream | no |
| `pcap.flow(id)` | payload snippet, bytes in/out, duration, direction | no |
| `cmdb.asset(ip)` | host, OS, installed versions, criticality, owner, **peer dependencies** | no |
| `cve.match(product, version)` | exploitable?, patch status, exploit maturity | no |
| `logs.query(host, window, grep)` | web / auth / syslog lines | no |
| `edr.processtree(host, t)` | spawned processes, persistence artifacts | no |
| `fw.apply(rule)` / `fw.state()` | commit result — **fails on demand** | **yes** |
| `edr.quarantine(host)` | fallback enforcement path | **yes** |
| `env.probe(src, dst, port)` | does traffic actually pass right now? | no — this is the verifier |

`env.probe` is the entire verification story and costs about twenty lines. It is what separates *"the agent said it blocked"* from *"the block is real."* Do not skip it.

---

## Evaluation scoreboard

Run **40 labelled synthetic incidents** with ground truth. Report:

| Metric | Target |
|--------|--------|
| Verdict accuracy vs ground truth (succeeded / failed / FP) | > 90% |
| Mean tool calls to verdict | 5–9 (proves it is not brute-forcing every tool) |
| Hallucinated-claim rate | **0** |
| Unsafe-action rate | **0** |
| Recovery success rate across the 3 injections | 3 / 3 |
| **Baseline: alert-label-only classifier, same incident set** | **~55% verdict accuracy** |

That last row is the single most persuasive number in the submission.

---

## Demo video beats

Maps 1:1 onto the brief's required sequence.

1. **Goal** — "Close A-1042 safely." Ledger shows four hypotheses, near-even.
2. **Decision** — *"Highest information gain: is `10.2.4.19` even running a vulnerable version?"* Not a fixed chain.
3. **Action** — `cmdb.asset` then `cve.match`. `H2` jumps to 0.7.
4. **Intermediate result** — *"0.7 is below my 0.85 threshold; a patched banner can lie. Checking EDR."*
5. **Adaptation** — judge fires injection #1. Case reopens live, verdict flips, containment plan forms.
6. **Adaptation ×2** — firewall silently fails, verify catches it, EDR quarantine fallback succeeds.
7. **Final outcome** — evidence-cited incident report, probe confirms traffic dropped, case closed with a full action log.

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
| Evaluation, verification & robustness | 10% | `env.probe` action verification, Evidence Auditor claim verification, 40-case scoreboard with baseline |

---

## Guardrails

- All activity is confined to the provided sandbox. No production systems, no real credentials, no real network changes.
- All data is synthetic.
- Every autonomous enforcement action is reversible and logged, and high-blast-radius actions require human approval.

---

See **[ROADMAP.md](ROADMAP.md)** for the build plan.
