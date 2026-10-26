# HoneyShield: Research, Architecture and Winning Implementation Blueprint

**Prepared:** 26 October 2026  
**Scope:** IOTA × Enigma Hackathon Cybersecurity Track — Problem Statement 2, *The Honeypot That Learns Who's Lying*  
**Purpose:** research relevant open-source platforms, map their capabilities and technologies to HoneyShield, define the differentiators and UI, and provide an implementation-first Antigravity prompt queue.

> **Important accuracy boundary:** The hackathon PDF is the authority for the problem requirements. Platform capabilities below are taken from official project repositories/documentation where available. Ideas marked **HoneyShield proposal** are design recommendations, not existing capabilities. The latest HoneyShield source code has not been audited in this research pass; Antigravity must inspect it and preserve what already works.

## Executive recommendation

Do not turn HoneyShield into a large collection of copied honeypots. Build a focused web-login deception product whose central claim is:

**“HoneyShield distinguishes likely human recovery from suspicious session behaviour, changes the experience as evidence accumulates, and produces an explainable replayable trail of what happened.”**

The strongest combination for a hackathon is:

1. **Adaptive behavioural assessment** — use evolving within-session evidence, not just a fixed count of bad passwords.
2. **An explicit deception policy/state machine** — normal experience for low suspicion, a measured intermediate response for ambiguous sessions, and a session-isolated synthetic decoy for high suspicion.
3. **A session flight recorder** — every assessment has its supporting events and a timeline.
4. **Synthetic canary objects** — fictional privileged records in the decoy trigger high-confidence interaction events.
5. **Scenario Lab** — demonstrate a forgetful human, rapid guessing, slow regular guessing, username sweep and changing cadence; produce metrics from real recorded runs.
6. **Automated regression and edge-case tests** — evidence that random inputs do not crash routes, corrupt scores, leak sessions or fabricate dashboard metrics.

Keep Flask + SQLite unless the source-code audit proves there is a concrete blocker. Do not add Docker, a cloud dependency, a separate frontend framework, a real ML model, or a network-facing honeypot protocol service just for appearance. An explainable baseline + test coverage is stronger than an unvalidated “AI detector.”

---

## 1. Exact problem statement requirements

The supplied PDF describes the problem as **“The Honeypot That Learns Who's Lying.”** It says static authentication rules (such as lockout after N failures) can be bypassed by slow/distributed guessing and can lock out legitimate users. The challenge is a deceptive login layer for a simple web app that:

- infers behaviour from **behaviour alone**, including timing, request patterns, error recovery, and optionally keystroke/input cadence;
- learns as a session unfolds;
- adapts responses for suspicious sessions, including decoy responses, fake-success pages/data, delays or carefully chosen inconsistent errors;
- lets legitimate users have a smooth experience; and
- instruments the decoy to gather intelligence about the attacker's tooling and strategy.

The PDF also mandates a five-minute presentation plus Q&A, using seven slides: Title (15s), Problem (30s), Idea and differentiation (45s), Architecture (45s), Demo (90s), Results/limitations (45s), Next steps/repo (30s). The exact slide timing totals five minutes.

### Consequence for HoneyShield

A rule that says “three failures always means attacker” does **not** solve the problem by itself. Three failures should be one piece of evidence. A convincing demo should compare two sessions with the same number of failures but different recovery/cadence patterns: a human-like correction should remain normal or low-risk, while a scripted or patient pattern can accumulate higher risk. A deterministic scripted scenario is useful for judging, but should be presented as a reproducible simulation—not proof of real-world attacker accuracy.

---

## 2. Research landscape: related platforms and their transferable ideas

The list is a curated set of close analogues, infrastructure references, and test tools, not a claim that every security tool in existence has been enumerated. “Use in HoneyShield” below means a pattern to implement; it does not mean embedding another full project.

### 2.1 Honeypots and deception platforms

| Platform | What it does (documented capability) | Technology / architecture noted in project materials | Transfer to HoneyShield | Do not do |
|---|---|---|---|---|
| **SNARE + Tanner** — https://github.com/mushorg/snare and https://github.com/mushorg/tanner | SNARE is a web application honeypot sensor; it can clone a page/surface. Its documented model describes lightweight SNARE sensors and Tanner as a central decision-maker. | SNARE README documents Python 3.6 and Linux-oriented setup; that setup is old, so inspect current compatibility/dependencies before reuse. Sensor/master split. | Borrow “web surface + central decision policy” as an architecture pattern; keep our existing synthetic login UI and make its response policy configurable. Collect only local/synthetic traffic. | Do not clone third-party login pages or expose an unisolated cloned site. Do not transplant dated dependencies without a review. |
| **Cowrie** — https://github.com/cowrie/cowrie / https://docs.cowrie.org/ | SSH/Telnet honeypot; fake shell/filesystem; captures login attempts and interaction; stores session logs suitable for replay; JSON logging and output integrations; LLM backend is described as experimental in docs. | Python; emulated shell or proxy mode; JSONL-style events and playback tooling; plugins for log destinations. | Borrow session IDs, structured event schema, ordered timeline/replay, synthetic fake records and clear “we observed X” evidence. | Do not add SSH/Telnet or execute shell commands in the time-limited web product. Do not imply that an LLM is needed. |
| **OpenCanary** — https://github.com/thinkst/opencanary | Lightweight multi-protocol honeypot that mimics services and emits alerts; documented modules include SSH, FTP, Git, HTTP/HTTPS, proxy, MSSQL, MySQL, Telnet, SNMP and SIP, with optional modules depending on platform. | Python package (current README says Python 3.10+); configurable services and alert handlers; some optional modules are OS-dependent. | Borrow configurable deception surfaces and alert/event configuration. Could later add an adapter interface if HoneyShield grows beyond web login. | Do not add unrelated network listeners to a web-only hackathon demo. Keep local, isolate ports and avoid privileged bindings. |
| **T-Pot** — https://github.com/telekom-security/tpotce | Multi-honeypot platform with many service honeypots; dashboards/attack map; supports event analytics and network-security monitoring tools. | Docker/Docker Compose; Elasticsearch for storage, Logstash for ingest, Kibana for visualisation; NGINX fronting tools; also lists Suricata, p0f/FATT and many honeypots. Requires materially more resources/ops than the current prototype. | Borrow event aggregation, dashboard layout, persistence/retention concepts and attack-sequence visualisation. Use the style of a SOC console, not its deployment footprint. | Do not install the entire stack for this sprint; it is heavy and solves a broader network-level problem. |
| **Honeytrap** — https://github.com/honeytrap/honeytrap | Extensible honeypot framework; multiple services can be combined; sensor/agent and central service concepts; payload-based routing; modular service handlers and output integrations (including Elasticsearch/Kafka/Splunk in its repo description). | Go codebase; extensible event and service architecture; external data sinks. Check current maintenance and compatibility before direct dependency use. | Borrow an event adapter/interface and a clear split between observing requests and deciding response policy. | Do not build a distributed agent architecture for a local demo. |
| **Canarytokens** — https://github.com/thinkst/canarytokens | Creates honeytokens that alert when an instrumented resource/link is touched; repository discusses HTTP/DNS-style token triggers and notification configuration; supports self-hosted setup with Docker. | Self-hosted frontend/switchboard settings and database/notification configuration; exact internals should be checked at the version used. | Implement **local synthetic canary records** inside HoneyShield’s fake dashboard. Opening a fictional “Privileged Payroll Export” or “API Credentials Inventory” should emit a distinct event associated with the session. | Do not use real credentials, external callbacks, real internal addresses, or outbound token infrastructure for a checkpoint. A local record ID is sufficient. |
| **Small adaptive-honeypot research repo** — https://github.com/0xhroot/adaptive-honeypot | The repository describes an asyncio-based SSH/HTTP/FTP emulator, structured telemetry, SQLite persistence, clustering/anomaly detection and an adaptive response layer. | The README describes Python asyncio, SQLite, Flask dashboard, feature extraction/clustering and response strategies. It is a small community repository, so inspect code/tests before trusting any claimed ML quality. | Use the architecture as a conceptual checklist: events → features → session profiles → response strategy → dashboard. Reuse individual ideas only after code/licence review. | Do not claim “ML-driven” detection just because a README says so; do not make a small untested repo a core dependency. |
| **Wazuh** — https://github.com/wazuh/wazuh | Open security platform with endpoint agents, central manager, event/log analysis, rules, alerting, vulnerability/configuration assessment, indexer and dashboard. | Agent → manager/normalisation/rules → indexer → dashboard/integrations. | Borrow severity levels, normalised fields, rules with evidence, alert lifecycle and an audit-first dashboard. It could be a future sink for event export. | Do not integrate a full SIEM into the project; expose an export format instead. |
| **OWASP Juice Shop** — https://owasp.org/www-project-juice-shop/ | Deliberately vulnerable training application covering many web security flaws/challenges; useful as a security-tool test target. | TypeScript/JavaScript, Node.js, Express and Angular according to OWASP project information. | Borrow tester mindset: malformed inputs, access-control checks, unexpected routes, business logic and repeatable challenge scenarios. Keep our own testing within local sandbox. | Do not copy vulnerabilities into HoneyShield or expose Juice Shop as part of the deployed app. |

**Correction to avoid misleading research:** an earlier conversation mentioned “Heimdall Community” as a honeypot dashboard. Current web results surfaced an unrelated Minecraft/Discord product under that name. It is not included as a valid HoneyShield analogue.

### 2.2 Test, security and quality platforms

| Tool | Primary function | Technology / input | How HoneyShield should use it | Scope caveat |
|---|---|---|---|---|
| **pytest** — https://docs.pytest.org/ | Fast unit/integration test runner for Python. | Python tests and fixtures. | Verify routes, risk policy, event storage, session isolation, reset and database lifecycle. First line of defence. | No tool can test inputs that are not generated or specified; assertions must encode requirements. |
| **Hypothesis** — https://hypothesis.readthedocs.io/ / https://github.com/HypothesisWorks/hypothesis | Property-based tests generate many input combinations and shrink failures to simpler examples. | Python strategies and property assertions. | Test score bounds, event orderings, timestamps, repeated events, usernames, malformed inputs and policy invariants. | Random generation supplements, not replaces, hand-written scenario cases. |
| **Playwright** — https://playwright.dev/python/ | Real browser automation and end-to-end tests; supports Chromium, Firefox and WebKit. | Python/pytest plugin or other supported language runners. | Verify login → assessment → decoy → canary interaction → admin timeline; reloads, back button, cookies and cross-session isolation. | Browser engine installs may take time; start with Chromium only, then expand if stable. |
| **Schemathesis** — https://schemathesis.readthedocs.io/ / https://github.com/schemathesis/schemathesis | Property-based API testing generated from OpenAPI/GraphQL, including chained stateful workflows. | Requires an accurate API schema; sends real state-changing requests. | Add only if project has or can generate a truthful OpenAPI schema. Use isolated test DB and low request rate. | Do not manufacture an API schema just to use this tool. Never aim it at production. |
| **OWASP ZAP** — https://www.zaproxy.org/ | Dynamic web application scanning, passive analysis, spidering and active testing, with a YAML automation framework. | Local application URL; can use an automation plan. | Run a restrained local scan against a disposable test environment; triage findings manually; capture report. | Active scan can change data or trigger deception; do not scan third-party systems or a live deployment without authorisation. |
| **OWASP ASVS 5.0** — https://asvs.owasp.org/ | Security verification requirements for web apps/services. | Standard/checklist (PDF, DOCX, CSV available). | Select relevant checks for authentication, session management, input validation, logging, access control and security configuration. | It is a framework, not automatic certification or proof of production readiness. |
| **OWASP Cheat Sheet Series** — https://cheatsheetseries.owasp.org/ | Developer-focused guidance on authentication, session management, logging, CSRF, input/output handling and more. | Reference guidance. | Use during code review, particularly session cookies, CSRF and event hygiene. | Follow requirements appropriate to the app, deployment and threat model. |

### 2.3 Technologies recommended for the current HoneyShield project

| Layer | Recommended technology | Why | Sprint decision |
|---|---|---|---|
| Application server | Existing Flask/Python | Matches the current app; fastest to improve and test. | Keep. No rewrite. |
| Templates/UI | Existing HTML/CSS/JavaScript | Current dark navy/cyan dashboard is already visually polished. | Keep; refine hierarchy and add meaningful views. |
| Persistence | Existing SQLite with migrations or safe idempotent schema init | Simple local demo, no cloud credentials, persistent records. | Keep for hackathon; use per-test temporary DB. |
| Behaviour policy | Small pure-Python service with explicit config | Explainable, deterministic and testable. | Build a stable baseline first; don't add unvalidated ML. |
| Unit/property tests | pytest + Hypothesis | Strong coverage of generated edge cases and invariants. | Add as development dependencies. |
| Browser regression | Playwright + pytest | Verifies actual routes and browser state. | Add after core flow is stable. |
| Static/security checks | Bandit, pip-audit, Ruff (if compatible) | Find common Python security/dependency/style issues. | Add if install and run cost is modest; document output. |
| Dynamic scan | OWASP ZAP baseline/passive first | Finds potential web findings locally. | Optional after a stable test instance; active scan only with isolated DB. |
| API fuzzer | Schemathesis | Useful if OpenAPI exists. | Optional, schema-gated. |
| Data/export | JSON and CSV | Easy investigator export, no new service. | Implement. |
| Future production datastore | PostgreSQL plus migrations | Better concurrent multi-user operation than a single local SQLite file. | Not needed in a 10-hour local sprint; design boundary only. |

---

## 3. The product architecture to implement

Keep the existing application entry point and adapt these conceptual components to the actual repository. Do not duplicate the app or force this exact directory layout if the current structure already separates responsibilities.

```text
Browser / synthetic judge scenarios
            |
            v
Flask routes + authentication/session middleware
            |
            +--> Telemetry collector (no passwords, no raw keystrokes)
            |          |
            |          v
            |    Event normaliser / session feature extractor
            |          |
            |          v
            |    Incremental behavioural assessment
            |    - cadence and timing
            |    - failure/recovery sequence
            |    - request/path pattern
            |    - within-session change
            |          |
            |          v
            |    Decision + confidence + reason codes
            |          |
            |          v
            |    Response policy state machine
            |    NORMAL | AMBIGUOUS | DECOY | REVIEW
            |
            +--> Decoy service with synthetic dashboard and canary records
            |
            v
       Normalised event store (SQLite)
            |
            +--> Admin live summary
            +--> Session investigation timeline / replay
            +--> Evidence export + integrity verification
            +--> Scenario Lab / benchmark reports
            |
            v
       pytest + Hypothesis + Playwright + optional local ZAP scan
```

### Recommended session state machine

- **NORMAL:** no meaningful suspicious evidence; genuine valid demo login follows the normal route; mistakes get a usable correction path.
- **OBSERVING / AMBIGUOUS:** behaviour is unusual but insufficiently conclusive; collect more evidence, preserve user recovery path, and optionally use a measured consistent delay/neutral error policy.
- **DECOY_ACTIVE:** only when the configured policy meets a threshold or strong local canary evidence; all pages and actions are synthetic and isolated to this session.
- **RESOLVED / RESET:** session is closed or test data reset under an authorised demo-only action.

Never implement “three failures always means attacker” as the sole policy. The test harness can include a three-failure scripted suspicious case, but it should also include a forgetful user with three mistakes and recovery. The policy should compare timing, pattern regularity, changes after feedback and subsequent action sequences. The system can make a probabilistic assessment, not infer a person's identity or prove malicious intent.

### Behaviour features to implement (privacy-aware)

1. Failure count in a rolling window, plus spacing between attempts.
2. Inter-arrival intervals and regularity (for example median interval and variability), not just request volume.
3. Recovery pattern after error: does behaviour adapt to feedback, or repeat essentially identical attempts?
4. Identifier diversity/pattern: count and optional keyed hash of attempted identifiers if required; do not store passwords and avoid exposing raw attempted identifiers in dashboard logs.
5. Navigation/request sequence: repeated enumeration of synthetic routes, unusual endpoint order, retries that fail to respond to errors.
6. Within-session change: starts human-like then becomes highly regular, or starts rapid then shifts to slow regular attempts.
7. Optional input-cadence aggregate: only if justified and implemented carefully; store timings/count aggregates only—never raw keystrokes, field contents or clipboard content.
8. Known decoy/canary interaction: high-confidence signal, with exact event + object ID; it must not be the only detection feature.

### Score and confidence semantics

- `risk_score`: numeric 0–100, derived from transparent configured features.
- `risk_band`: config-matched band; no mismatch with thresholds.
- `confidence`: distinct from risk. It reflects the amount/quality of evidence and must not be presented as a calibrated probability unless calibrated.
- `reason_codes`: machine-readable rule IDs plus human-readable explanations and evidence references.
- `policy_decision`: NORMAL, OBSERVE, or DECOY with a policy version.
- Store a risk assessment when material evidence changes; don't fabricate metrics in JavaScript.

### Event schema minimum

Each stored event should include: `event_id`, `session_id`, `timestamp_utc`, `event_type`, `route_or_action`, `outcome`, `risk_before`, `risk_after`, `reason_codes`, `request_method`, safe/truncated user-agent metadata where available, timing feature summary, `decoy_state`, `object_id` if canary-related, and `scenario_run_id` where applicable. Do **not** include passwords, password hashes of submitted values, raw input field values, session cookie values, CSRF tokens, or secrets in event detail.

### Suggested logical data tables

- `users`: only the existing demo account / account metadata required by the app, with properly hashed password.
- `sessions`: session state, creation/last-seen/closed times, current risk band/score, policy version and scenario label where synthetic.
- `events`: append-only event records with unique IDs, session association and indexes on timestamp/session/type.
- `risk_assessments`: snapshot of score, confidence, feature values, reason codes, decision and rule/policy version.
- `decoy_interactions`: session, object ID, action, timestamp and event ID.
- `scenario_runs`: scenario ID, seed/config, expected class (synthetic ground truth), actual decision and metric context.
- Optional `event_chain`: previous hash and event hash for tamper-evident chain validation. This only makes later modification detectable if the chain head/anchor is also protected; never call it fully tamper-proof.

Use migrations or safe idempotent schema initialisation instead of ad-hoc schema mutation every app start. Add appropriate unique constraints and indexes. Use transactions for event + risk snapshot changes so the dashboard cannot show partial truth.

---

## 4. “Wow” features that support the problem instead of distracting from it

### A. Behavioural X-Ray (high priority)

**User-facing presentation:** on the selected session, show a risk timeline with each event. Beside it, show the factors that contributed to score changes, their magnitude, their time window, and the evidence records. Selecting a factor highlights supporting events.

**Why it impresses:** judges can see the system reasoning, not just a red badge. It supports explanation, debugging and trustworthy results.

### B. Adaptive Deception Ladder (core differentiator)

**User-facing presentation:** a horizontal session state strip (Normal → Observing → Decoy Active). For each transition, show “why this changed” with evidence IDs. The admin sees the state; the decoy user sees only a plausible synthetic interface. Do not reveal the decision criteria to the decoy surface.

**Policy:** low risk remains normal; ambiguous patterns are observed and may receive carefully chosen consistent friction; high evidence enters a separate synthetic decoy. Policy configuration is visible to the administrator, but not the suspicious session.

### C. Session Flight Recorder (high priority)

**User-facing presentation:** a timeline you can replay step by step, showing event, interval, risk before/after, policy transition and decoy interaction. Include a scrubber/Play button only if it is driven by persisted event timestamps and state—not hardcoded animations.

**Why it impresses:** the judge can inspect “what the session did” and correlate it with the decision.

### D. Canary Trail (high priority)

**User-facing presentation:** the synthetic decoy includes fictional privileged-looking objects (e.g. “Internal API Inventory”, “Quarterly Payroll Export”, “Backup Manifest”). Each carries a unique local object ID, never a real secret. Opening/downloading/previewing it creates a high-specificity `CANARY_OBJECT_ACCESSED` event. The detail view shows the timeline connection and the triggered alert.

**Why it impresses:** this demonstrates deception telemetry beyond login failure counts. Keep the action entirely local and synthetic; no outbound callback or real credential.

### E. Forgetful Human vs. Patient Guesser Lab (best demonstration feature)

**User-facing presentation:** an admin-only scenario lab with selectable profiles:
- `FORGETFUL_HUMAN`: multiple mistakes followed by correction/recovery; natural variation.
- `RAPID_BURST`: many failures in a short window with highly regular cadence.
- `SLOW_REGULAR`: low-frequency, consistent attempts over longer intervals.
- `IDENTIFIER_SWEEP`: varied attempted identifiers plus repetitive timing (store no passwords).
- `FEEDBACK_IGNORING`: same pattern persists despite error feedback.
- `ADAPTIVE_CADENCE`: behaviour starts regular then intentionally varies to test detection limitations.

Each run must create actual event records via production backend services, with a `scenario_run_id` and reproducible seed/config. It must not manipulate dashboard totals directly. The comparison report displays confusion matrix and precision/recall on labelled **synthetic test scenarios only**. Say “synthetic evaluation,” not “real-world detection accuracy.”

### F. Policy Playground / Counterfactual (high-value if time allows)

Replay a recorded synthetic trace under alternate thresholds/weights and show how the decision would change without touching original records. Show “Original policy” versus “Alternative policy”, with false-positive/false-negative trade-offs on the scenario corpus. This is an offline simulation, not a change to the active session.

### G. Tamper-evident evidence ledger (optional)

Hash-chain canonicalised event payloads (`event_hash = SHA256(previous_hash || canonical_event)`). Add an admin “Verify ledger” action that checks the chain and reports first bad entry. Keep the chain head/anchor in an independent location if possible; otherwise describe the feature accurately as tamper-evident within the local DB, not tamper-proof. Do not allow UI edits to past events.

### H. Judge Mode / Guided Demo (high priority)

One-click scenario cards with a progress checklist (seed session → observe behavior → decision → decoy interaction → investigate). The interface should clearly label generated demo scenarios. A reset creates a clean demo state but preserves the account/configuration. The guided demo helps judges focus on core value without reducing the application to scripted fake metrics.

---

## 5. UI structure: keep the existing design, improve the story

Use the existing dark navy/cyan style, typographic system and dashboard components. Do not rebuild just because a new layout sounds attractive.

### Global navigation

`HoneyShield` · `Control Room` · `Sessions` · `Scenario Lab` · `Evidence / Exports` · `System Health`.

Only show admin links to authorised admin/demo role. Normal users should not see the investigation tooling.

### Control Room (first screen)

Top metrics: Total observed sessions, currently observing, decoy-active sessions, canary interactions, high-risk events in selected time range. Each metric is linked to a filtered list. Include honest “last updated” and event-store health status from actual backend/database queries.

Main area:
- **Live Event Stream** with event type, session short ID, time, observed action, risk change and decoy state.
- **Session Risk Overview** with risk trend and filters.
- **Detection Explanations** summary of top observed reason codes.
- **Scenario Lab quick launch**.

Empty state: invite user to run a local scenario. Never show “active” without an active persisted session.

### Session Investigation page

- Header: session ID, lifecycle, risk, confidence, policy decision, created/last seen time.
- Timeline: attempt, response, recovery, cadence, decision, decoy, canary events.
- Risk history graph with markers for state transitions.
- Evidence panel: reason code, actual window/features and linked event IDs.
- Behaviour summary: cadence variability, failure/recovery sequence, path/action sequence.
- Actions: export this session, replay events, mark synthetic scenario note (must not rewrite raw events).

### Decoy dashboard

Make it plausible and coherent, with synthetic records and navigation. Keep all actions local. Each object ID is unique. Add no real secrets or connections to internal services. No visible “you are in a honeypot” banner to the decoy session; the admin can see the state in Control Room.

### Scenario Lab

Scenario cards have: label, purpose, timeline preview, “Run scenario”, and expected evaluation class. A completed run displays captured events, final score, decision, response chosen and any deviations. Include a repeat/reseed control. It must call backend scenario services rather than populate front-end values.

### Evidence Export

JSON/CSV export should filter to selected session/time range and omit sensitive fields. Display export time, filter scope and schema version. Use safe filenames and proper content types.

### System Health

Show database connectivity, schema version, app version/commit if available, last successful scenario/test run and a test summary from stored test results only if the testing runner actually wrote them. Do not start arbitrary shell commands from a web UI.

### Accessibility and usability

Keyboard navigation, visible focus, semantic labels, chart/table alternatives, good contrast, readable error messages for genuine users, no colour-only state distinctions, responsive layout. Show loading/error/empty states and prevent double submissions on state-mutating actions.

---

## 6. Automated test strategy for random and edge cases

No one can guarantee every arbitrary test passes. The goal is to encode invariants, systematically generate input variations, run critical browser journeys, and turn every discovered defect into a regression test.

### Core invariants (pytest + Hypothesis)

- Risk is always within 0–100; invalid config is rejected or safely defaulted.
- Risk band always matches configured boundaries, including exact edges.
- Same event trace + same policy version yields the same deterministic result unless an explicitly seeded stochastic component exists.
- Events are uniquely identified, timestamped consistently and attached to the correct session.
- Re-evaluating the same event does not double-count it.
- Passwords and secret fields are absent from stored events, reports and logs.
- A decoy state from session A is not inherited by session B.
- Normal login and human recovery traces are not automatically diverted based only on a fixed failure count.
- Decoy interactions always refer to an existing session/object and create an event in one consistent transaction.
- Reset is idempotent in demo mode and does not delete the demo account or schema.
- Malformed input produces controlled 4xx/validation errors, not 500 tracebacks.
- Time windows handle events exactly at boundaries, out-of-order events, equal timestamps and timezone normalisation.

### Browser flows (Playwright)

1. Fresh app + DB initialisation.
2. Valid demo login → normal dashboard.
3. Single typo and multiple human-like recovery attempts → usable recovery flow.
4. Rapid suspicious scenario → risk escalates and state changes according to policy.
5. Slow, regular scenario → risk analysis uses cadence across enough observations; do not assume three quick failures are required.
6. High-suspicion scenario → decoy redirect, decoy page, canary access, admin investigation.
7. Fresh second session → no decoy state leak.
8. Refresh, back button, logout, expired/missing session, repeated button clicks.
9. Reset, then demo account still works and counts are consistent.
10. Export data → valid CSV/JSON with no secrets.

### Edge-case corpus

Empty and whitespace inputs; Unicode; very long but bounded strings; null/missing fields; arrays/dictionaries where strings are expected; encoded special characters; duplicate submissions; 0/1/many events; extreme timestamps; event sequence permutations; threshold edges; missing/invalid session IDs; deleted canary object; database busy/locked errors; reset during scenario; browser refresh at redirect; repeated decoy click; expired session; same browser with two isolated contexts. Use rate limits to control test costs and do not generate unlimited traffic.

### Security checks

- password hashing using existing framework's proven password helpers; never log submitted secret;
- regenerate/rotate session identifiers after successful authentication where supported;
- cookies: HttpOnly and SameSite; Secure in HTTPS deployment; appropriate expiry;
- CSRF protection for state-changing forms/actions;
- parameterised DB queries and safe HTML escaping;
- role/route protection and per-session object authorization;
- rate limiting as defence-in-depth, not as the only detector;
- safe local binding for demo; don't deploy externally without hardening/review;
- dependency audit and static lint/security scans if compatible;
- local ZAP passive/baseline scan first; active scan only on disposable test DB.

---

## 7. Suggested repository structure (adapt to existing code; do not blindly recreate)

```text
HoneyShield/
  app.py or existing entry point
  config.py (validated thresholds/policy config)
  requirements.txt
  requirements-dev.txt (pytest, hypothesis, playwright, coverage, etc.)
  README.md
  docs/
    ARCHITECTURE.md
    THREAT_MODEL.md
    FEATURE_STATUS.md
    TEST_REPORT.md
    DEMO_SCRIPT.md
  honeysheild/ or existing package/
    auth/ (login, password hashing, session lifecycle)
    telemetry/ (request observations, timing aggregates, normalised events)
    detection/ (feature extraction, score, confidence, reason codes)
    policy/ (response state machine, policy version)
    decoy/ (synthetic pages, fake records, canary interactions)
    storage/ (DB access, schema/migrations, transaction methods)
    investigations/ (timeline, replay, exports, ledger verification)
    scenarios/ (seeded scenario definitions + runner)
  templates/ (reuse existing templates)
  static/ (reuse existing CSS/JS)
  tests/
    unit/
    property/
    integration/
    e2e/
    fixtures/
  scripts/ (safe startup/test commands; no destructive unknown scripts)
  data/ (demo DB only; exclude credentials/secrets from repo)
```

Do not move every file just to match this tree. Build a feature-to-file map from the actual repository and work in place. Maintain one authoritative app entry point, one database schema path and one risk engine.

---

## 8. Implementation phases and acceptance gates

| Phase | Implement | Mandatory acceptance gate before the next phase |
|---|---|---|
| 0 — Baseline and architecture fit | Inspect repo, record current routes/models/tests, identify true entry point and current bug; add a safe test fixture; fix blockers discovered while auditing. | App starts, current routes are documented, baseline tests run, no duplicate app created, actual test report saved. |
| 1 — Canonical event/session model | Normalised events, consistent session ID, safe event payload, transaction boundaries, schema indexes. | Repeated events persist correctly; no password appears in DB/log; temporary DB tests pass. |
| 2 — Adaptive feature extraction | Windowed cadence, recovery, regularity, route sequence, within-session changes, bounded score and reason codes. | Human-recovery and patient/regular scenarios differ for explained reasons; boundary and property tests pass. |
| 3 — Deception policy | Explicit policy states, server-side per-session decoy state, safe redirects and synthetic-only decoy actions. | High-evidence scenario redirects; normal session is unaffected; new session does not inherit decoy state. |
| 4 — Canary + investigation | Synthetic canary objects, timeline, evidence explanation, replay/export. | Every canary event references session/object and is visible after refresh; export omits secrets. |
| 5 — Scenario Lab/metrics | Deterministic seeded profiles and an offline policy evaluator. | Actual event store is populated by scenario service; metrics computed from labeled scenario outcomes, no mock counters. |
| 6 — Automated testing | pytest/Hypothesis/Playwright; optional Schemathesis if schema exists. | Test command runs reproducibly; all critical tests pass or blockers are documented and fixed before proceeding. |
| 7 — Security/robustness | Access control, cookie/CSRF, DB validation, safe output, static and local dynamic scan. | High-severity findings fixed or explicitly documented; no claim of certification. |
| 8 — UI and demo polish | Session detail, visual hierarchy, empty/loading states, judge mode. | Every visible control works; keyboard/basic responsive check; screenshot evidence. |
| 9 — Final freeze | Clean-start, reset, regression, docs, archive hygiene, seven-slide demo story. | Clean copy starts; tests are repeatable; no secrets/database artifacts in deliverable; test report matches actual run. |

---

## 9. Metrics worth reporting honestly

The demo must not claim real-world detection performance from a few manually generated sessions. Use a reproducible labelled synthetic corpus and state exactly how many cases were tested.

- **True positive (TP):** synthetic suspicious scenario detected as suspicious/decoy per policy.
- **False positive (FP):** synthetic human-recovery scenario unnecessarily routed into decoy.
- **True negative (TN):** synthetic normal/human case remains normal per expected class.
- **False negative (FN):** synthetic suspicious case remains normal when the scenario's labelled expected action requires detection.
- **Precision** = TP/(TP+FP); **Recall** = TP/(TP+FN); **F1** = harmonic mean of precision and recall. Guard zero-denominator cases.
- **Detection latency:** elapsed from the first synthetic event that makes the scenario suspicious under the expected label/policy to the recorded decision, with definition stated clearly.
- **Decision trace completeness:** proportion of decisions with reason codes and linked evidence event IDs.
- **Event persistence correctness:** generated events recover after refresh/restart in persistence tests.

Do not use accuracy alone; class imbalance can hide false positives. Do not claim detection of distributed multi-host attacks in a single local demo unless there is actually a correlation layer and a test for it. It is acceptable to say distributed correlation is a future limitation.

---

## 10. Five-minute judging story (from the PDF's required structure)

1. **Title (15s):** HoneyShield — Adaptive Deception That Learns from Session Behaviour.
2. **Problem (30s):** static lockouts punish forgetful users and miss patient slow guessing; fixed thresholds alone are insufficient.
3. **Idea/differentiation (45s):** behaviour-only session assessment, explanation of why evidence matters, adaptive response ladder, synthetic decoy + canary telemetry.
4. **Architecture (45s):** browser → telemetry → session features → risk/decision → response policy → decoy → event store → investigation timeline; testing layer alongside.
5. **Demo (90s):** show a human-like recovery session first; then run slow/regular or scripted suspicious scenario; show state change, click a synthetic canary object, return to session replay and explain the evidence. If the live app is unreliable, use a recorded run as allowed by the PDF but disclose it as a recording; do not fabricate a success.
6. **Results and limitations (45s):** show test counts and metrics from labelled synthetic cases, mention what the results cover and what they don't; state known limitations honestly.
7. **Next steps/repository (30s):** show architecture, tests, reproducible setup and public code repo.

The wow moment should be *the same number of failed attempts producing different outcomes because the behaviour and recovery evidence differs*—not simply a red screen after the third password failure.

---

## 11. Research source register

Official/project sources consulted (features can change; check the linked current docs before relying on version-specific instructions):

- SNARE: https://github.com/mushorg/snare — web honeypot sensor; repository documents Python 3.6 setup and a sensor/master model with Tanner.
- Cowrie docs: https://docs.cowrie.org/en/stable/README.html and https://cowrie.org/ — SSH/Telnet honeypot, fake shell/filesystem, session recording/replay and JSON logs.
- OpenCanary: https://github.com/thinkst/opencanary — multi-service honeypot and alerting; Python package.
- T-Pot: https://github.com/telekom-security/tpotce — Docker/Compose multi-honeypot system, Elasticsearch/Logstash/Kibana, attack-map and network monitoring components.
- Honeytrap: https://github.com/honeytrap/honeytrap — extensible open-source honeypot framework and output integrations.
- Canarytokens: https://github.com/thinkst/canarytokens — instrumented resources that alert when touched; self-hosting configuration.
- Adaptive honeypot example: https://github.com/0xhroot/adaptive-honeypot — repository's own description of Python asyncio, SQLite, Flask dashboard and behavior/adaptation layers; claims not independently benchmarked.
- Wazuh: https://github.com/wazuh/wazuh and https://documentation.wazuh.com/current/getting-started/architecture.html — open source security platform, agent/manager/indexer/dashboard.
- OWASP Juice Shop: https://owasp.org/www-project-juice-shop/ — deliberately vulnerable testing/training app; Node.js/Express/Angular per OWASP project description.
- Hypothesis: https://github.com/HypothesisWorks/hypothesis — property-based testing and shrinking of failures.
- Playwright Python: https://playwright.dev/python/docs/intro — browser-based end-to-end tests.
- Schemathesis: https://github.com/schemathesis/schemathesis — schema-driven OpenAPI/GraphQL API testing; generated requests can mutate data, so use disposable test environments.
- OWASP ZAP automation: https://www.zaproxy.org/docs/automate/automation-framework/ — YAML-driven dynamic scan workflow.
- OWASP ASVS 5.0: https://asvs.owasp.org/ — web app security requirements standard (5.0.0 stable release shown by official site in the research session).
- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/ — session management, logging, CSRF, input handling and related developer guidance.

### Research caveats

- A platform README indicates intended/documented capabilities, not that its every feature is currently reliable or secure.
- “All platforms” is not finite. This report selects the closest and most useful open-source projects and tools for the chosen PS, separating direct competitors, conceptual references and test tools.
- Do not embed external platform code without checking its license, dependencies, security posture and compatibility. For this sprint, copy concepts/patterns rather than add heavyweight services.


# HoneyShield UI Blueprint and Judge Wow Moments

## Design thesis
A judge should understand the product in 15 seconds: **HoneyShield observes how a login session behaves, adapts the response, and leaves an investigation trail.** Keep the current navy/cyan look. Make it evidence-dense without making it confusing.

## Navigation
- Control Room — global overview / live event stream.
- Sessions — searchable session registry.
- Session Detail — event timeline, risk trend, evidence, decision history.
- Scenario Lab — human vs attacker-like synthetic profiles.
- Evidence Export — session JSON/CSV exports and ledger checks.
- System Health — DB status, app/policy version, latest test run.
- Normal dashboard — only normal user experience.

## First screen wireframe
```text
HONEYSHIELD   Control Room | Sessions | Scenario Lab | Evidence

[Observed sessions] [Observing now] [Decoys active] [Canary interactions] [Events in range]

┌ Live evidence stream ───────────────────┐ ┌ Risk / state distribution ──────────┐
│ time  session  action  score delta      │ │ normal | observing | decoy           │
│ ... persisted event rows ...            │ │ actual counts from DB               │
└─────────────────────────────────────────┘ └─────────────────────────────────────┘

┌ Recent sessions / search / filters / bands / reason code ───────────────────────┐
│ session id | pattern summary | risk | confidence/evidence | state | inspect      │
└─────────────────────────────────────────────────────────────────────────────────┘

[Run forgetful-human] [Run slow-regular] [Run adaptive-cadence] [Reset demo]
```

## Session detail view
- **Identity:** session ID, scenario label if seeded synthetic, first/last seen, lifecycle.
- **Decision strip:** NORMAL / OBSERVING / DECOY_ACTIVE with timestamps.
- **Risk history:** line/step plot from stored risk assessments; markers at state transitions.
- **Behavioural X-Ray:** observed intervals, regularity summary, recovery evidence, route/action pattern, distinct identifier count if safely captured.
- **Why this decision:** reason code, threshold/policy version, event IDs and a concise explanation.
- **Flight recorder:** chronological timeline with Play/Step only when tied to stored events.
- **Canary trail:** synthetic object opened and corresponding event ID.
- **Export:** JSON/CSV with secret-field omission.

## Best judge wow moment (90 seconds)
1. Open scenario lab; choose `FORGETFUL_HUMAN`, run it and show mistakes followed by recovery. It remains on the normal path.
2. Choose `SLOW_REGULAR`; run the same approximate number of failures with highly regular timing/repetitive behaviour. Explain the factors before showing state transition.
3. Follow the suspicious session into the synthetic decoy. Open a privileged-looking canary record.
4. Return to its session detail; show the canary event, time, score/decision and prior evidence in the flight recorder.
5. Open the synthetic evaluation summary and clearly state sample size and limitations.

Never stage this by directly setting UI numbers. The scenario runner has to produce rows through the real backend. If live interaction is still flaky, use a clearly labelled recording rather than fabricating success.

## Wow features ranked by value/cost
| Feature | Judge value | Implementation risk | Priority |
|---|---:|---:|---|
| Explainable risk / reason codes | Very high | Low-medium | P0 |
| Session-specific adaptive decoy | Very high | Medium | P0 |
| Persisted event timeline/replay | Very high | Medium | P0 |
| Canary object interactions | High | Low-medium | P1 |
| Forgetful human vs slow regular lab | Very high | Medium | P1 |
| Synthetic benchmark/confusion matrix | High | Medium | P1, only with labelled scenarios |
| Hash-chained event ledger verification | Medium-high | Medium | P2, optional; label tamper-evident only |
| LLM generates response content | Medium | High | Skip unless the core and test suite are solid |
| Add SSH/FTP/Telnet listeners | Low for this exact PS | High | Skip |
| New frontend framework/animation overhaul | Low | High | Skip |

## Suggested six data contract types
- `SessionSnapshot`: score, band, evidence quality, state, timestamps and policy version.
- `BehaviorFeatures`: only computed, privacy-minimised features; no secrets/raw keystrokes.
- `RiskAssessment`: score, confidence semantics, reason codes, supporting event IDs.
- `SecurityEvent`: normalized event schema and session association.
- `DecoyObject`: local synthetic object ID/type/content fixture.
- `ScenarioRun`: label, seed, expected class, run time, actual backend events and decision.

## Presentation mapping
Use the official seven slide times from the supplied problem statement. The demo is the core story, architecture explains how it is made safe, and measured synthetic results plus limitations demonstrate maturity.
