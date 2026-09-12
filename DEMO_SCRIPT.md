# VERDICT — Demo Video Script

A shot-by-shot script against the real, running UI (`python -m verdict.ui.app` →
`http://127.0.0.1:8000`). Every incident ID, button label, and number below
was verified live against the actual code — nothing here is aspirational.
Follow it with any screen recorder (OBS, Windows Game Bar `Win+Alt+R`, or your
OS's built-in tool). Target length: **3-4 minutes**.

Maps 1:1 to the hackathon's required sequence: **Goal → Decision → Action →
Intermediate Result → Adaptation → Final Outcome.**

---

## Setup (before you hit record)

```bash
pip install -r requirements.txt
python -m verdict.ui.app
```

Open `http://127.0.0.1:8000`. Have the incident dropdown visible. Zoom the
browser to ~110% so on-screen text reads clearly on a recording.

---

## Beat 1 — Goal (0:00–0:20)

**Say:** *"This is VERDICT — an autonomous SOC agent for Problem Statement 9.
Every other approach treats a NIDS alert as a verdict. We treat it as a
hypothesis, and the agent has to prove it before it acts."*

**Do:** Select incident **A-1000** in the dropdown (ProxyLogon SSRF alert,
severity **low**, CVE-2021-26855). Point out the severity is *low* — this is
one of our adversarial cases.

Select **Planner: rule (offline)** for a deterministic run.

Click **▶ Start Investigation**.

---

## Beat 2 — Decision (0:20–0:50)

**Say:** *"Watch the reasoning trace. The agent isn't following a fixed
checklist — at every step it's choosing whichever tool most separates its
four live hypotheses."*

**Do:** As the trace animates (via SSE, ~0.5s per step), narrate each line as
it appears:
1. `cmdb_asset` → *"First question: does the target even run the alerted
   service? If not, this is scanner noise — cheapest question first."*
2. `cve_match` → *"Service confirmed. Now the pivot: is the installed version
   actually exploitable?"*
3. `edr_processtree` → *"Exploitable. Now: did it actually land?"*

Point at the **Hypothesis Ledger** bars filling in real time (H1 red rising).

---

## Beat 3 — Action / Intermediate Result (0:50–1:20)

**Say:** *"Verdict: SUCCEEDED, 99% confidence, in 3 tool calls. A label-only
classifier would have called this alert benign — it's severity 'low'. Our
baseline over all 40 incidents scores 35%. VERDICT scores 100%, including
100% on the 6 cases where the label actively lies."*

**Do:** Point at the verdict box (SUCCEEDED, confidence, tool_calls, stop
reason).

Click **✅ Close Case**.

Narrate as the Decision & Action panels fill: *"Tier: contain. But look at the
rule — it's the narrowest possible block, source-to-destination-to-port, not
a wholesale IP ban. And it doesn't just apply the firewall rule and trust it —
`env_probe` re-checks that the traffic is actually gone before calling it
done."*

Point at the **Evidence Auditor** panel: *"Every claim in that report cites a
real artifact ID. Zero hallucinated claims — that's a hard measured number,
not a promise."*

---

## Beat 4 — Adaptation #1: Evidence Reversal (1:20–2:00)

**Say:** *"Now the part every other submission will fake with a script — we
built it as three buttons that actually mutate the live environment."*

**Do:** Select incident **A-1014** (a **FAILED**-verdict case — patched
target). Click **Start Investigation**, then **Close Case**. Status: `closed`,
tier `monitor`, no firewall action taken.

Click **💥 Evidence Reversal**.

**Say:** *"Late syslog evidence just arrived: a beacon and a persistence
mechanism on a host we'd already cleared."*

**Do:** Watch the trace re-run live and the verdict box show:
**"REOPENED: prior verdict FAILED → new evidence changes this to SUCCEEDED."**

*"The agent didn't just accept new data — it re-derived from scratch and the
verdict flipped, unprompted."*

---

## Beat 5 — Adaptation #2: Silent Firewall Failure (2:00–2:30)

**Do:** Start a fresh incident, e.g. **A-1001** (SUCCEEDED). Before closing,
click **🛑 Silent Firewall Failure**.

**Say:** *"Now the firewall API is compromised — it returns 200 OK but never
actually commits the rule. This happens in real infrastructure."*

**Do:** Click **Close Case**. Narrate the action log: two `fw_apply` attempts
both showing `committed=False`, `env_probe` catching that traffic still
passes both times, then the automatic fallback to `edr_quarantine`.

*"The agent never trusted the 200 OK. It verified the actual effect, caught
the lie, and fell back to host-level containment."*

---

## Beat 6 — Adaptation #3: Override → Auto-Rollback (2:30–3:20)

**This is the moment to slow down for.**

**Do:** Start a fresh incident, e.g. **A-1002** (SUCCEEDED). Click
**🏙️ Broad-Blast Scenario**.

**Say:** *"This attacker is now hitting two targets through a shared office
NAT serving 340 real users."*

**Do:** Click **Close Case**.

**Say:** *"The agent refuses to act autonomously — it escalates. Read the
reason on screen: it computed the blast radius BEFORE touching anything."*

**Do:** Click **⚠️ Override — Block Anyway**.

**Say:** *"Now I, the human, override it. Watch what happens next."*

**Do:** Narrate the action log as it appears: the broad rule commits, then —
critically — the agent **re-probes a legitimate session it would have just
broken**, sees it got dropped, and **automatically rolls back** to the narrow
rule, restoring the legitimate session, and reports exactly why.

**Say:** *"An agent that obeys a human, catches the human's mistake, and
safely undoes it. That's the whole thesis in one sequence."*

---

## Beat 7 — Final Outcome (3:20–3:45)

**Say, over the scoreboard or terminal:**

*"Across 40 labelled synthetic incidents: 100% verdict accuracy, 2.85 mean
tool calls to close a case, versus 35% for an alert-label-only baseline.
Zero hallucinated claims. All three adaptation scenarios recover without a
restart, and the riskiest one ends in an automatic rollback. This is VERDICT,
for Problem Statement 9."*

**Do (optional closing shot):** Run in a terminal, on screen, for 5 seconds:

```bash
python -m verdict.eval.run
```

Let the scoreboard table print — real, reproducible, not staged.

---

## B-roll / backup shots (if you have extra time)

- `python tests/test_respond.py` printing `PHASE 3 ACCEPTANCE: all checks passed.`
- The GitHub repo's commit history (shows the phased build, not a single dump)
- The `ROADMAP.md` with every phase checkbox ticked

---

## Recording checklist

- [ ] Server running (`python -m verdict.ui.app`), page loaded, zoomed to ~110%
- [ ] Screen recorder capturing browser + terminal
- [ ] Audio/narration matches the beats above (adapt wording, keep the structure)
- [ ] Export, then rename to **`Verdict_video_agentic.<ext>`** per the submission format
