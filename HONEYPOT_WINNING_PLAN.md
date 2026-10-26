# Project "MIRAGE" — The Honeypot That Learns Who's Lying
Winning plan + Antigravity prompt pack for IOTA X Enigma, Cybersecurity Track, Problem Statement 2.

Name is a suggestion. Rename freely. Everything below is stack-agnostic: Prompt 0 makes Antigravity inspect your existing site and adapt.

---

## PART 1 — What exists today (research) and what we steal from each

### 1.1 Open-source honeypots
| Platform | What it does (functions) | Tech | What we borrow |
|---|---|---|---|
| **Cowrie** | Medium/high-interaction SSH/Telnet honeypot. Fake shell + fake filesystem, logs every command, records sessions for replay, captures downloaded files | Python, Twisted, JSON logs | **Session replay** of attacker inside the decoy; fake filesystem idea → fake admin data. Research on Cowrie showed changing the fake credential database changes how long attackers stay, so decoy "believability" is tunable |
| **T-Pot** (Deutsche Telekom) | Bundles 20+ honeypots in one platform with Elastic stack + ready dashboards | Docker, Debian, Elasticsearch/Kibana | **Dashboard-first presentation**: attack map, counters, live feed |
| **OpenCanary / Thinkst Canary** | Lightweight daemon emulating services incl. HTTP login pages; **Canarytokens** = fake API keys/docs/URLs that alert when touched; philosophy "every alert is real" | Python | **Canary tokens inside decoy data** (fake API key, fake backup download). Any touch = 100% confirmed attacker. Low-noise alerts |
| **SNARE + TANNER** | SNARE clones a web page as a trap; TANNER analyses each request and decides the response dynamically | Python, aiohttp | **Decision engine separated from the web layer** (exactly our "adaptive responder") |
| **Dionaea / Honeytrap / Glutton** | Malware capture, protocol-agnostic TCP traps | C/Python | Not needed. Mention as out of scope |

### 1.2 Commercial deception platforms
| Platform | Functions | Lesson for us |
|---|---|---|
| **Acalvio ShadowPlex** | AI-driven playbooks that adapt deception to attacker behaviour, realistic baits and lures | **Adaptive playbooks** → our "deception ladder + bandit" |
| **SentinelOne Hologram (ex-Attivo)** | Network deception with strong identity-threat focus; Attivo added native automated response | **Auto-response + identity focus** |
| **Proofpoint (ex-Illusive)** | Fake credentials/paths that stop lateral movement | **Honey credentials/accounts** |
| **CounterCraft** | Campaign-based, customizable deception, deception-powered threat intel | **Campaign clustering**: group sessions into one attacker campaign |
| **Thinkst Canary** | Set-and-forget, tokens, very low noise | Keep alert quality high; show *confidence*, not noise |

### 1.3 Behavioural bot / credential-stuffing defences
| Platform / idea | Functions | What we borrow |
|---|---|---|
| **Synapse Shield (open-source, PyPI)** | Mouse jerk, cursor straightness, Fitts's-law, keystroke interval variance, risk bands (<50 human / 50–70 suspicious / ≥70 bot), proof-of-work for gray area, accessibility mode, no keystroke characters collected, Poisson flood detection | **Risk bands + gray-area challenge + privacy-first (timing only) + accessibility mode** |
| **HALT** (Aug 2026 talk, DRDO internship project) | Scores each auth request, silently redirects high-risk users to a honeypot, SOC dashboard | **Closest prior art. Differentiate**: we *learn online*, choose decoy strategy with a bandit, cluster campaigns, fingerprint tooling, and protect *real accounts even when the password is correct* |
| **Hidden-field honeypots** | Invisible form fields only bots fill | Cheap tripwire signal |
| **Honey accounts** | Accounts no human uses; any login attempt is unauthorized (MITRE T1110.004) | Confidence = ~100% signal |
| **Browser-level detection (e.g. Memcyco-style)** | Capture failed AND successful logins plus interaction nuance in the browser | Client sensor + server signals fused |
| **Academic: per-user credential-stuffing detection** | Anomaly detection tracking suspicious logins per account | **Per-username tracking across all IPs** = catches slow distributed guessing |
| **Black Hat EU-17 "Becoming You"** | Sophisticated bots use distributed IPs, low rate, randomized UA, browser impersonation, session replay, recorded human behaviour | Why static lockout fails; our threat model |

### 1.4 The gap we win in
Existing tools either **block** (attacker learns and adapts) or **redirect once** (static). Nobody in the open-source space shows a system that: (1) accumulates evidence across a whole *campaign*, (2) *learns which decoy keeps the attacker talking*, (3) *never* punishes a forgetful human, and (4) *proves it with numbers*. That is our pitch.

---

## PART 2 — Technology catalogue (pick from this)

| Layer | Recommended | Alternatives |
|---|---|---|
| Backend | **Python FastAPI** (async, WebSockets) | Node/Express, Flask |
| Storage | **SQLite** (zero setup, demo-safe) | Postgres, Redis for counters |
| Realtime | **WebSocket / SSE** to dashboard | Polling (fallback) |
| Scoring | Hand-written Bayesian log-odds + **online logistic regression (SGD)**, pure Python/NumPy | scikit-learn `SGDClassifier.partial_fit` |
| Decoy strategy learning | **Thompson-sampling bandit** (Beta distributions) | epsilon-greedy |
| Browser sensors | Vanilla JS: `keydown/keyup` timestamps, `mousemove`, `paste`, focus order, `navigator.webdriver`, paint timing | — |
| Frontend | React + Vite + Tailwind **or** vanilla + Tailwind CDN | Next.js |
| Charts / graph | **Chart.js** or Recharts, **Cytoscape.js** or D3-force (campaign graph), **Leaflet** (attack map) | ECharts |
| Animation | Framer Motion / CSS | GSAP |
| Containers | Docker Compose (one-command demo) | plain `uvicorn` |
| Testing / eval | pytest + your own simulator | — |
| Intel export | JSON IOC export, MITRE ATT&CK mapping, webhook to Discord/Slack | STIX 2.1 (stretch) |
| Optional | LLM-written attacker dossier (behind a feature flag; template fallback) | — |

Privacy rule to state out loud: **only timing deltas are captured, never typed characters.**

---

## PART 3 — Product design: what the judges see

### 3.1 Core concept
**"Same login. Two realities."** Humans get a smooth real app. Suspected attackers get a convincing fake world that is instrumented to teach us about them. Even a *correct* stolen password lands in the fake world if behaviour says "attacker".

### 3.2 The Deception Ladder (adaptive response)
| Trust score (attacker probability) | Response |
|---|---|
| 0.00–0.30 | **Real app**, zero friction |
| 0.30–0.55 | **Invisible friction**: small jittered latency, silent proof-of-work (accessibility-safe) |
| 0.55–0.80 | **Soft deception**: inconsistent errors ("wrong password" / "try again later" / generic 500), randomized delays, fake rate-limit |
| 0.80–1.00 or any honey-trap hit | **Decoy realm**: fake "success" → fake admin dashboard with fake data + canary tokens |
| Confirmed (canary touched) | **Tarpit + capture**: slow drip responses, keep them busy, full capture |

Hysteresis + decay: score changes gradually, a human who recovers drops back down.

### 3.3 Signals (all explainable, each shown in the UI with its weight)
**Request/session**
- Inter-request timing regularity (coefficient of variation; bots are too even)
- Time from page load to submit (< ~400 ms = scripted)
- Keystroke interval variance, paste-only password, zero mouse movement
- Hidden honeypot field filled; `navigator.webdriver`; missing sensor payload
- Header anomalies (UA vs client-hint mismatch, missing Accept-Language, odd header order)

**Identity-level (catches slow & distributed)**
- Failures per *username* aggregated across all IPs and sessions
- Distinct usernames tried per IP / per tooling fingerprint (spraying)
- Same password tried across many usernames
- Honey usernames hit (`admin`, `backup`, `svc_deploy`, `test`)
- Credential order looks like a sorted breach list

**Error recovery (forgetful human vs patient attacker)**
- Human: pauses after an error, retries the same username with a *small edit* of the password (edit distance ≤ 2), uses backspace/corrections, eventually hits "forgot password"
- Attacker: instant or perfectly timed retry, jumps to a different username, no corrections

### 3.4 Learning (the "learns" in the title — make it visible)
1. **Within a session**: log-odds updated after *every* request; the gauge moves live.
2. **Across sessions**: online logistic regression updates weights from *confirmed labels*:
   - confirmed attacker = honey account hit, canary token touched, hidden field filled
   - confirmed human = real login + trusted device + normal behaviour
3. **Decoy strategy learning**: Thompson-sampling bandit picks which decoy (fake success / fake lockout / delayed error / tarpit) maximises *attacker dwell time + new intel*. Show the arms' win-rates converging on a chart.

### 3.5 Intelligence gathered (instrumented decoys)
- **Tooling fingerprint**: UA, header order, HTTP version, timing signature, retry behaviour → label such as "python-requests style script", "headless browser", "curl/hydra-like tool", "human browser" with confidence
- **Strategy classification**: brute force / password spraying / credential stuffing / slow-and-low, mapped to MITRE ATT&CK T1110.001 / .003 / .004
- **Campaign clustering**: sessions from different IPs sharing a fingerprint + wordlist pattern are merged into one campaign (graph)
- **Wordlist inference**: which passwords/usernames they try, in what order
- **Canary tokens in the decoy**: fake API key, fake `backup.sql` download, fake password-reset link, tracked URL on *our own server*
- **Session replay** of everything they did in the decoy
- **Exports**: IOC JSON, per-attacker dossier, webhook alert

### 3.6 Protecting legitimate users (this wins Q&A)
- Trusted-device cookie caps the score
- Uncertain band gets *friction*, never decoys
- Decoy only above a high threshold, with hysteresis
- Decoy dashboard has a subtle "Not what you expected? Verify identity" lane that leads to a real challenge (an attacker clicking it is also logged)
- Accessibility mode (slow typists, assistive devices) widens timing tolerances
- The Results page shows a **false-positive rate on simulated forgetful humans**

---

## PART 4 — Website structure (what to build and how to present it)

Design language: dark SOC aesthetic, one accent colour (cyan or green), monospace for data, large clean typography, smooth transitions. **Every number on screen must be explainable in one click.**

| Page | Purpose | Wow element |
|---|---|---|
| **1. Landing / Story** `/` | 20-second pitch for judges | Animated hero: one login form splits into "Human world" and "Attacker world" |
| **2. Real app** `/app` | The protected product (simple, clean) | Feels real, minimal |
| **3. Live Demo Lab** `/lab` | The demo page | **Split screen**: left = what the attacker sees, right = what the defender sees, same requests. Buttons: *Run brute force*, *Run slow distributed*, *Run credential stuffing*, *Run headless bot*, *Act like a forgetful human* |
| **4. SOC Console** `/soc` | Defender view | Live event feed, **risk gauge per session with "why" panel**, ladder visualization, campaign graph, attack map, tooling leaderboard, bandit learning chart, replay |
| **5. Decoy realm** `/decoy/*` | What attackers get | Believable fake admin dashboard (never real data) |
| **6. Results** `/results` | Proof | Detection rate, false-positive rate, time-to-detect, attacker dwell time, learning curve (from `evaluate.py`) |
| **7. How it works** `/how` | Architecture (slide 4) | Animated pipeline diagram |

### The 5 "wow" moments (rehearse these)
1. **Split-reality demo**: same stolen-but-correct password; human logs into real app, bot lands in fake world — on the same screen.
2. **Live gauge with reasons**: risk climbs request by request with each signal labelled ("identical 500 ms cadence +0.22", "same password across 9 users +0.31").
3. **Slow-and-low reveal**: 40 attempts from 40 IPs over simulated hours; static lockout never fires; MIRAGE links them into one campaign graph.
4. **Learning curve**: bandit shifts from random to the best decoy; attacker dwell time rises.
5. **Dossier export**: one click produces an attacker profile with ATT&CK mapping and IOC JSON.

---

## PART 5 — Target repo structure

```
mirage/
├─ README.md                  # problem, idea, architecture diagram, run steps, results
├─ docker-compose.yml
├─ backend/
│  ├─ app/
│  │  ├─ main.py              # FastAPI entry, routes, WebSocket
│  │  ├─ config.py            # thresholds, honey usernames, feature flags
│  │  ├─ middleware/gateway.py        # intercepts auth requests, orchestrates pipeline
│  │  ├─ sensors/ingest.py            # parses client telemetry payload
│  │  ├─ signals/
│  │  │   ├─ timing.py  headers.py  identity.py  recovery.py  traps.py
│  │  ├─ scoring/
│  │  │   ├─ engine.py            # log-odds accumulation, decay, hysteresis
│  │  │   ├─ online_model.py      # SGD logistic regression, label feedback
│  │  │   └─ explain.py           # per-signal contribution list
│  │  ├─ deception/
│  │  │   ├─ ladder.py  responders.py  bandit.py  canary.py  decoy_data.py  tarpit.py
│  │  ├─ intel/
│  │  │   ├─ fingerprint.py  campaign.py  mitre.py  report.py  export.py
│  │  ├─ storage/db.py  models.py
│  │  └─ realtime/events.py       # push to dashboard
│  └─ tests/
├─ frontend/
│  ├─ public/sensor.js            # client telemetry (timing only)
│  ├─ pages/ (landing, app, lab, soc, decoy, results, how)
│  └─ components/ (RiskGauge, EventFeed, CampaignGraph, AttackMap, SplitScreen, BanditChart, Replay)
├─ simulator/
│  ├─ attackers/ brute_force.py  spraying.py  stuffing.py  slow_distributed.py  headless.py
│  ├─ humans/ forgetful_human.py  fast_typist.py  password_manager.py  accessibility_user.py
│  ├─ baseline_lockout.py         # naive "lock after N" for comparison
│  └─ evaluate.py                 # outputs results.json for /results
└─ docs/ (architecture.png, slides outline, demo script)
```

### Architecture (slide 4 diagram, text version)
```
Browser (sensor.js) ──► Gateway middleware ──► Signal extractors
                                      │                 │
                                      ▼                 ▼
                              Scoring engine ◄── Online model (learns from labels)
                                      │
                                      ▼
                         Deception orchestrator (ladder + bandit)
                       ┌──────────────┼───────────────┐
                       ▼              ▼               ▼
                   Real app     Friction/soft      Decoy realm (+ canaries, tarpit)
                                  deception              │
                                                         ▼
                              Intel layer (fingerprint, campaign, MITRE, dossier)
                                                         │
                                       Event store ──► WebSocket ──► SOC Console
```

---

## PART 6 — HOW TO DRIVE ANTIGRAVITY SO IT ACTUALLY CHANGES THE FILES

You said it sometimes doesn't apply changes. Do this:

1. **Save this file in your repo root** as `HONEYPOT_WINNING_PLAN.md` so Antigravity can read it. If your version supports project rules, add the "Verification protocol" below as a rule.
2. **One phase per prompt.** Do not paste everything at once.
3. **Commit before each phase** (`git add -A && git commit -m "before phase N"`). After each phase run `git diff --stat` yourself. If nothing changed, the agent only talked. Reply with the "Nothing changed" prompt below.
4. Always paste the **Verification protocol** at the top of each prompt.
5. Use the strongest model available in Antigravity for Phases 2–4 (scoring/learning), a faster one for UI polish.

### Verification protocol (paste at top of EVERY prompt)
```
RULES FOR THIS TASK
- Edit the files in THIS existing workspace directly. Do not create a new project folder or a parallel copy.
- Do not rewrite unrelated files. Keep existing routes and styling unless told otherwise.
- Work in small steps. After the changes: (a) run the app, (b) run the tests, (c) run `git status` and `git diff --stat`.
- In your final message list: every file created, every file modified, the exact commands you ran, and their real output. If anything failed, say so and fix it before finishing.
- Do not say "done" unless the acceptance checks at the bottom pass when you actually run them.
- If the change seems to have not applied, re-read the file from disk and confirm the new code is present.
```

### "Nothing changed" recovery prompt
```
git diff shows no changes. You described the work but did not apply it. Open the actual files in the workspace, apply the edits now, save them, then show me `git diff --stat` and the output of the acceptance checks. Do not summarize before the files are saved.
```

---

## PART 7 — THE PROMPTS (run in order)

### Prompt 0 — Inspect and adapt
```
[PASTE VERIFICATION PROTOCOL]

Read HONEYPOT_WINNING_PLAN.md in the repo root fully. Then inspect my existing website: list the stack (frontend framework, backend if any, how login works today), existing routes/pages, and styling approach.
Do NOT change code yet. Produce IMPLEMENTATION_NOTES.md in the repo root containing:
1. Detected stack and how login currently works.
2. A mapping from the target structure in the plan to this repo (which folders/files will be created or reused).
3. If there is no backend, choose Python FastAPI under /backend; if a backend exists, keep it and port the design to it.
4. Any risks or conflicts.
Acceptance: IMPLEMENTATION_NOTES.md exists and is accurate to the real files.
```

### Prompt 1 — Gateway, sensors, event store
```
[PASTE VERIFICATION PROTOCOL]

Implement Phase 1 from HONEYPOT_WINNING_PLAN.md using IMPLEMENTATION_NOTES.md.
1. Add a gateway layer that intercepts every login/auth request before the real handler.
2. Create frontend/public/sensor.js loaded on the login page. It records ONLY timing, never characters: keydown/keyup timestamps per field, mousemove sample count and path straightness, paste events, backspace count, focus order, time from page load to submit, navigator.webdriver, and a hidden honeypot form field value (hidden with CSS, tabindex=-1, autocomplete=off). It attaches this as a telemetry object to the login POST.
3. Create an SQLite store with tables: sessions, events (request-level: ts, session_id, ip, username_tried, outcome, features JSON), decisions, canary_hits.
4. Log every login attempt as an event. Add a WebSocket (or SSE) endpoint /ws/events that pushes each new event as JSON.
5. Keep the real login working exactly as before for now.
Acceptance (run them): start the app; submit the login form; show a row in events with telemetry fields populated; connect to /ws/events and show a live event arriving.
```

### Prompt 2 — Signals + explainable scoring
```
[PASTE VERIFICATION PROTOCOL]

Implement Phase 2. Create backend/app/signals/* and backend/app/scoring/engine.py + explain.py.
Signals (each returns a value in [0,1] and a human-readable reason):
- timing regularity (coefficient of variation of inter-request gaps per session; low = suspicious)
- fast submit (<400 ms after load), no mouse movement, paste-only password, near-zero keystroke variance
- hidden field filled, webdriver true, missing telemetry
- header anomalies (UA vs sec-ch-ua mismatch, missing Accept-Language)
- identity-level: failures per USERNAME across all IPs in a sliding window; distinct usernames per IP and per fingerprint; same password across many usernames; honey usernames (config list: admin, backup, svc_deploy, test)
- error recovery: after a failed login, measure pause length, whether the next password is within edit distance 2 of the previous (human-like typo fix), and whether the username changed
Scoring: Bayesian log-odds. score = prior + sum(weight_i * signal_i), passed through a sigmoid. Update the score after EVERY request in a session. Add exponential decay and hysteresis so a human who recovers drops back. A trusted-device cookie caps the score at 0.25. Return {score, band, contributions:[{signal, value, weight, delta, reason}]}.
Put all weights and thresholds in config.py.
Add pytest tests: a scripted bot sequence reaches >0.8; a forgetful-human sequence (2 typos, pauses, correction) stays <0.5.
Acceptance: pytest passes; show a printed explain output for both sequences.
```

### Prompt 3 — Deception ladder + decoy realm
```
[PASTE VERIFICATION PROTOCOL]

Implement Phase 3: deception/ladder.py, responders.py, decoy_data.py, canary.py, tarpit.py and the decoy frontend routes.
Ladder from the plan: <0.30 real app; 0.30-0.55 invisible friction (jittered delay + silent proof-of-work, accessibility-safe); 0.55-0.80 soft deception (randomly chosen: wrong-password message, "too many attempts" message, generic 500, variable delay, all inconsistent); >=0.80 or honey hit -> decoy realm; canary touched -> tarpit.
Decoy realm: after a fake "success", route to /decoy/dashboard, a believable fake admin console with entirely FAKE generated data (fake users, fake invoices, fake system status). Include canary tokens: a fake API key shown in settings, a "Download backup.sql" link, a fake password-reset link. Each is a unique URL on OUR server; any request to it logs a canary_hit with the session and returns slow-drip content.
IMPORTANT: a correct real password with a high score must still go to the decoy, never the real account. Never serve decoys when a trusted-device cookie is present. Add a "Not what you expected? Verify identity" link in the decoy that goes to a real challenge page (and logs the click).
Acceptance: with a script, show (1) normal login -> real app, (2) bot-like requests with the CORRECT password -> decoy dashboard, (3) hitting the canary URL creates a canary_hits row and slows responses.
```

### Prompt 4 — Learning (online model + bandit)
```
[PASTE VERIFICATION PROTOCOL]

Implement Phase 4: scoring/online_model.py and deception/bandit.py.
1. Online logistic regression over the signal vector, trained by SGD. Add a function that records labels: confirmed_attacker (honey username hit, canary touched, hidden field filled) and confirmed_human (successful real login with trusted device and low score). After each labeled session, update the weights and store a weights history with timestamps.
2. Blend: final_score = 0.5*bayesian + 0.5*online_model initially, with the online share growing as labeled data accumulates (cap 0.8). Keep the rule-based score as the explainable part.
3. Thompson-sampling bandit with arms = {fake_success, fake_lockout, delayed_error, tarpit}. Reward = number of extra requests the attacker makes after the decoy plus count of NEW intel features revealed (new tool fingerprint, new wordlist pattern). Persist alpha/beta per arm.
4. Expose GET /api/learning with weight history, arm statistics and a rolling dwell-time series.
Acceptance: run a script that generates 300 labeled sessions; show weights changing, bandit arm win-rates diverging, and the /api/learning JSON.
```

### Prompt 5 — Intelligence layer
```
[PASTE VERIFICATION PROTOCOL]

Implement Phase 5 in backend/app/intel/.
- fingerprint.py: build a tooling fingerprint from UA, header order, HTTP version, timing signature, retry behavior, telemetry presence. Classify into: human browser, python-requests-style script, curl/hydra-like tool, headless browser, unknown, with a confidence.
- campaign.py: cluster sessions from different IPs into one campaign when they share fingerprint + wordlist pattern + target usernames. Output nodes/edges for a graph.
- mitre.py: classify strategy as brute force (T1110.001), password spraying (T1110.003) or credential stuffing (T1110.004) with the evidence.
- report.py/export.py: per-attacker dossier (timeline, tooling, strategy, ATT&CK, wordlist guesses, canary hits) as JSON and as Markdown, plus an IOC JSON export. Optional webhook (Discord/Slack URL from env) on first decoy entry. LLM summary behind a feature flag with a template fallback.
- API: GET /api/campaigns, GET /api/attackers/{id}/dossier, GET /api/export/iocs.
Acceptance: run the simulator-style script to generate 3 distinct attackers; show campaigns merging distributed IPs into one, and a dossier JSON for each.
```

### Prompt 6 — Attack and human simulator + evaluation
```
[PASTE VERIFICATION PROTOCOL]

Create /simulator.
Attackers (all must target ONLY our local test server): brute_force, password_spraying, credential_stuffing (list of fake pairs), slow_distributed (many fake source IPs via an X-Forwarded-For test header enabled only in test mode, spaced over simulated time), headless_like (perfect timings + webdriver flag).
Humans: forgetful_human (typos, pauses, retries with small edits, then "forgot password"), fast_typist, password_manager_paste, accessibility_user (slow, irregular).
baseline_lockout.py: naive "lock after 5 failures per IP" so we can compare.
evaluate.py: run N=200 sessions of each type; output results.json with: detection rate per attacker type, false-positive rate per human type, median requests-to-detect, mean attacker dwell time in decoy, and baseline lockout results (expect it to miss slow_distributed and wrongly lock forgetful_human). Make it deterministic with a seed.
Acceptance: `python simulator/evaluate.py` prints a table and writes results.json. Report the real numbers honestly, even if imperfect, and list the failure cases.
```

### Prompt 7 — Frontend: Landing, Lab, SOC Console
```
[PASTE VERIFICATION PROTOCOL]

Read the "PART 4" design in HONEYPOT_WINNING_PLAN.md. Build the pages using my existing frontend stack and styling; add libraries only if needed (Chart.js, Cytoscape.js, Leaflet via CDN or npm).
1. /lab: split screen. Left panel "What the attacker sees" (embedded login + decoy), right panel "What the defender sees" (live gauge + signal reasons). Buttons call simulator endpoints (enabled only in demo mode) to run: brute force, slow distributed, credential stuffing, headless bot, forgetful human. Use /ws/events for live updates.
2. /soc: live event feed; per-session RiskGauge with a "why" panel listing signal contributions; ladder visualization highlighting the current rung; campaign graph (Cytoscape) from /api/campaigns; attack map (Leaflet, use simulated coordinates); tooling leaderboard; bandit learning chart and weight history from /api/learning; session replay timeline; buttons "Export dossier" and "Export IOCs".
3. Landing page: animated hero where one login splits into two worlds, a 3-step explainer, and a "Try the live lab" button.
Design: dark SOC look, one accent colour, monospace for data, subtle animation, fully responsive, no layout jumps. Every number must show its explanation on hover or click.
Acceptance: run the app, open each page, run each simulator button, and describe what visibly changed. Provide screenshots if you can.
```

### Prompt 8 — Results page, How-it-works, polish, README
```
[PASTE VERIFICATION PROTOCOL]

1. /results: read simulator/results.json and render charts: detection by attacker type, false positives by human type, MIRAGE vs naive lockout comparison, requests-to-detect, dwell time, learning curve. Add an "Honest limitations" card (see below).
2. /how: animated pipeline diagram matching the architecture in the plan, each box clickable with a 2-line explanation.
3. Add a demo mode toggle (env DEMO_MODE) that enables simulator endpoints and a "Reset demo" button that clears state and pre-seeds a little history so the SOC Console is not empty.
4. Write README.md: problem, idea, architecture diagram, run instructions (docker compose up and non-docker), how to run the simulator, results table, limitations, next steps.
5. Add docker-compose.yml so `docker compose up` starts everything.
Limitations to include honestly: tested on simulated attackers and synthetic humans; TLS/JA3 fingerprinting needs a reverse proxy and is not included; a determined attacker can fingerprint decoys; thresholds need tuning on real traffic; behavioural data has privacy and accessibility implications (we store timing only, with an accessibility mode).
Acceptance: fresh clone -> `docker compose up` -> /lab works end to end. Show the commands and output.
```

### Prompt 9 — Final audit (run before presenting)
```
[PASTE VERIFICATION PROTOCOL]

Act as a strict reviewer. Check the repo against HONEYPOT_WINNING_PLAN.md: list each planned feature as DONE / PARTIAL / MISSING with the file path as evidence. Run all tests and the simulator. Find bugs, dead buttons, console errors, broken pages, and hard-coded fake numbers on the Results page (all numbers must come from results.json). Fix everything you find, then re-run and show the output. Confirm there is no real user data anywhere in decoys and that sensor.js never captures typed characters.
```

---

## PART 8 — Presentation (7 slides, ~5 min)

| # | Slide | Say / show | Time |
|---|---|---|---|
| 1 | Title | MIRAGE, team, PS2 | 15s |
| 2 | Problem | Lockout rules fail both ways: slow distributed guessing slips past, forgetful humans get locked out. Bots now use distributed IPs, low rates and mimic humans | 30s |
| 3 | Idea | "Same login, two realities." Learn from behaviour, serve decoys, learn which decoy works, never punish humans. Contrast: block (attacker adapts) vs deceive (attacker teaches us) | 45s |
| 4 | How it works | Architecture diagram from Part 5 | 45s |
| 5 | Demo | See script below | 90s |
| 6 | Results & limits | Numbers from `results.json` vs naive lockout; honest gaps | 45s |
| 7 | Next steps | Reverse-proxy TLS fingerprinting, real-traffic tuning, SIEM export, GitHub link | 30s |

### 90-second demo script
1. (10s) Open `/lab`. "Left: attacker. Right: defender."
2. (20s) Click **Forgetful human**: two typos, pauses, then success. Gauge stays low. "Static lockout would have locked this person."
3. (25s) Click **Slow distributed**: 40 IPs, one attempt each. "Lockout never fires." The campaign graph merges them into one attacker.
4. (20s) Click **Credential stuffing with the correct password**: gauge climbs with reasons, attacker lands in the fake dashboard; touches the fake API key → canary fires.
5. (15s) Click **Export dossier**: tooling, strategy, ATT&CK T1110.004. Close on the learning curve.

Record this as a backup video. Live demos fail.

### Likely judge questions
- **"How is this different from HALT or a WAF?"** They score and redirect. We learn online, pick decoys with a bandit, cluster campaigns, and protect the real account even with a correct password.
- **"What if you flag a real user?"** Friction only in the uncertain band; decoys only at high confidence; trusted-device cap; verify-identity lane; measured false-positive rate.
- **"Can attackers detect the decoy?"** Possibly, that is a known honeypot risk. The bandit shifts away from decoys that end sessions early, and we state this limitation.
- **"Privacy?"** Timing only, no characters, accessibility mode.
- **"Is the data real?"** Simulated attackers and humans; we say so and show how to replay on real logs.

---

## PART 9 — Priority if time is short

**Must have (wins the track):** gateway + sensors, explainable score, ladder + decoy dashboard with canary, simulator + evaluate.py, SOC console with live gauge, split-screen lab.
**Should have:** bandit learning chart, campaign graph, dossier export, results page.
**Nice to have:** attack map, LLM dossier summary, webhook alerts, STIX export, session replay.

Build order: Prompts 0 → 1 → 2 → 3 → 6 → 7 → 4 → 5 → 8 → 9. (Get a working demo and numbers early, then deepen.)

## Safety notes
- Decoys contain only fabricated data; no real user data, ever.
- Simulators target only your own local server.
- Canary URLs point to your own server; no hack-back, no payloads sent to the attacker.
