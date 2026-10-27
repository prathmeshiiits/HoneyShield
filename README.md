# HoneyShield

**The Honeypot That Learns Who's Lying** — a local hackathon proof of concept that evaluates login-session behaviour, routes high-risk sessions into a controlled synthetic decoy, and records an explainable event trail for an administrator.

> **Safety and honesty:** HoneyShield is a localhost-only demonstration, not production authentication. Demo records are fabricated. The score is an interpretable heuristic, not machine learning, proof of identity, or proof of malicious intent. No external target is contacted. Never enter real credentials or personal information.

## What is implemented

- **Normal sign-in path:** a seeded `demo` account stored as a password hash; valid sign-in opens the synthetic workspace.
- **Behavioural risk engine:** rolling-window scoring from failed-login timing, distinct per-session username fingerprints, regular retry cadence, repeated principal patterns, and gradual backoff.
- **Adaptive decoy:** sessions reaching the configurable high-risk threshold are sent to a synthetic operations console instead of a simple block page.
- **Decoy instrumentation:** opening the console and selecting fake records, reports, or an admin resource creates timestamped events tied to the session ID; failure-event intervals appear in the control-room timeline.
- **Admin control room:** actual local SQLite counts, score/band, evidence reasons, session filters, recent event timeline, and decoy inspection links.
- **Backend-driven demo scenarios:** the suspicious and normal buttons feed events through the same storage/scoring functions as the app's login flow.
- **Reset, health check, export-free local runtime:** Reset clears demo sessions/events while preserving the seeded account; `/healthz` checks application and SQLite readiness.
- **Privacy-minded event model:** submitted passwords and raw attempted usernames are not stored in event rows. Attempted usernames are transformed into per-session keyed fingerprints.
- **Polished navigation and disclosure:** accessible left-side navigation drawer, a first-load local-prototype disclosure on the sign-in page, and keyboard/escape handling.
- **Portable local setup:** Flask + Python standard library, SQLite file created on first launch, Windows PowerShell and batch scripts, and standard-library `unittest` tests.

## Project layout

```text
HoneyShield/
├── app.py                       # Flask app, SQLite storage, risk engine, scenarios
├── requirements.txt             # One pinned dependency: Flask
├── run.ps1                      # Recommended Windows PowerShell launcher
├── run.bat                      # Optional double-click/Command Prompt launcher
├── test.ps1                     # Creates environment if needed and runs tests
├── README.md
├── .env.example                 # Optional examples; not required
├── .gitignore
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── user_dashboard.html
│   ├── decoy_dashboard.html
│   └── admin_dashboard.html
├── static/
│   ├── css/style.css
│   └── js/app.js
├── tests/test_app.py
├── docs/architecture.md
└── data/.gitkeep                # Runtime SQLite DB will be created in this folder
```

The ZIP intentionally does **not** contain `.venv`, cached bytecode, or a pre-populated runtime database. The database path is resolved relative to the extracted project directory, so moving the project folder is supported.

## Run it on Windows 11

### Recommended: one command, no activation required

1. Extract `HoneyShield.zip` to a normal folder you can edit.
2. Open **the extracted `HoneyShield` folder itself** in VS Code or Antigravity. `README.md` and `app.py` should be directly inside that folder.
3. Open a terminal with PowerShell in that folder and run:

```powershell
.\run.ps1
```

The script selects Python 3.12 or 3.11 if installed (otherwise it tries the available Python launcher), creates `.venv` if needed, installs `requirements.txt` into that environment, and starts the application. It does not activate the environment, so PowerShell virtual-environment activation policies are not a blocker.

If PowerShell's execution policy blocks running the script, use a one-process bypass (it does not permanently change your policy):

```powershell
powershell -ExecutionPolicy Bypass -File .\run.ps1
```

### Alternative: direct commands without environment activation

Run the commands from the `HoneyShield` folder. If you have Python 3.12:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

If Python 3.12 is not installed, replace `py -3.12` with `py -3.11` (or `python` for the Python installation available on your machine). You can also double-click `run.bat`.

### Where it opens

Default URL: **http://127.0.0.1:5000**

Key Application URLs:
- **Product Landing Page & Sign-In:** [http://127.0.0.1:5000/](http://127.0.0.1:5000/)
- **Standalone Sign-In:** [http://127.0.0.1:5000/login](http://127.0.0.1:5000/login)
- **Normal User Workspace:** [http://127.0.0.1:5000/dashboard](http://127.0.0.1:5000/dashboard) (requires authenticated session)
- **Admin SOC Control Room:** [http://127.0.0.1:5000/admin](http://127.0.0.1:5000/admin) (shared filter bar, real SVG charts, sessions)
- **Session Flight Recorder:** `http://127.0.0.1:5000/admin/session/<key>` (deterministic attack-path pipeline and explainable heuristics)
- **One-Click Evidence Export:** `http://127.0.0.1:5000/admin/session/<key>/export?format=json` and `format=csv`
- **Scenario Lab & What-If Analyzer:** [http://127.0.0.1:5000/lab](http://127.0.0.1:5000/lab) (8 deterministic benchmarks & threshold analyzer)
- **Honeypot Decoy Console:** [http://127.0.0.1:5000/decoy](http://127.0.0.1:5000/decoy) (activated on high-risk threshold)
- **Health Check & Diagnostics:** [http://127.0.0.1:5000/healthz](http://127.0.0.1:5000/healthz)

The terminal prints the exact URL on startup. The server binds to loopback by default and is not intended to be shared over a network. If port 5000 is occupied, HoneyShield prints a clear error. To use another port in PowerShell:

```powershell
$env:HONEYSHIELD_PORT = '5001'
.\run.ps1
```

The port setting lasts for that PowerShell window. Optional configuration variables are:

| Variable | Default | Purpose |
|---|---|---|
| `HONEYSHIELD_PORT` | `5000` | Local development-server port |
| `HONEYSHIELD_HOST` | `127.0.0.1` | Loopback only (`127.0.0.1`, `localhost`, or `::1`) |
| `HONEYSHIELD_HIGH_RISK_THRESHOLD` | `50` | Risk score that activates the decoy; must be 1–100 |
| `HONEYSHIELD_SECRET_KEY` | Development-only value | Flask session signing key; change before any deployment |

No `.env` file is required. `.env.example` is informational; the app does not load it automatically.

## Demo credentials

- **Username:** `demo`
- **Password:** `ShieldDemo!2026`

These are deliberately public demo credentials, not real credentials. The database stores a salted `scrypt` password hash, never the raw password. Both the landing page and the sign-in page include an **"⚡ Auto-fill demo credentials"** button for quick hackathon demonstrations.

## Complete 90-Second Judge Demo Script

### Journey 1: Behavioural Escalation & Silent Decoy Containment
1. **Visit Product Landing Page (`http://127.0.0.1:5000/`):**
   - Note the cybersecurity landing page and the embedded sign-in card with demo credentials (`demo` / `ShieldDemo!2026`).
   - Attempt 1: Enter username `demo` and wrong password `wrong1`. Fails normally; session risk remains `0/100` (`LOW`).
   - Attempt 2: Enter username `demo` and wrong password `wrong2`. Fails normally; telemetry notes retry cadence.
   - Attempt 3: Enter username `demo` and wrong password `wrong3`. Risk crosses the configured threshold (`50/100`), triggers `HIGH` risk, and **silently diverts the session into the synthetic decoy console (`/decoy`)**!
2. **Interact with Decoy Canary Assets (`/decoy`):**
   - Click **"Open ↗"** on `HS-2048` (Customer record) or **"Export ↗"** on `HS-2051` (Audit log backup).
   - Show that synthetic decoy interactions generate forensic telemetry in SQLite without the attacker knowing they are trapped.

### Journey 2: SOC Investigation & Deterministic Attack Path
1. **Open the SOC Control Room (`http://127.0.0.1:5000/admin`):**
   - Inspect the **Authentication Attempts Over Time** chart (failed attempts in coral, accepted logins in cyan).
   - Use the **Unified Shared Filter Bar**: toggle between time windows (`5m`, `15m`, `1h`, `All`), filter by risk band (`HIGH`), or search by session ID.
   - Click the **High Risk Sessions KPI card** or distribution bar segments to filter the session table automatically.
2. **Inspect the Session Flight Recorder (`/admin/session/<key>`):**
   - Click **"Inspect Flight Recorder"** on the trapped session.
   - Walk through the **Deterministic Attack-Path Reconstruction**: *Login Failed → Rapid Retries → Risk Threshold Reached → Decoy Activated → Decoy Canary Accessed*.
   - View the **7 Explainable Heuristic Signals** showing exact point contributions (`+30 TRIGGERED`, etc.).
   - Expand raw event details on the timeline to inspect UTC timestamps and HMAC principal fingerprints.
3. **One-Click Evidence Export:**
   - Click **"Export JSON"** or **"Export CSV"** to download the complete, sanitized forensic evidence package.

### Journey 3: Scenario Lab & Policy What-If Analysis
1. **Open Scenario Lab (`http://127.0.0.1:5000/lab`):**
   - Run the **Deterministic 8-Pattern Benchmark Suite**; verify the confusion matrix (TP, TN, FP, FN) and 100% ground-truth accuracy.
   - Adjust the **What-If Policy Threshold Slider** to evaluate policy changes instantly in-memory without mutating the live database.

## Validation Status

- **Automated Test Suite:** **142 of 142 tests passing** (`powershell -ExecutionPolicy Bypass -File tests/run_tests.ps1`).
- **Playwright End-to-End Tests:** 6 headless Chromium browser journeys passed (0 failures).
- **Hypothesis Property-Based Fuzzing:** 27 boundary invariant tests passed.
- **Schemathesis OpenAPI Contracts:** 17 negative and boundary contract tests passed.
- **OWASP Defensive Posture:** Security headers, session isolation, HMAC username privacy, and zero plaintext secret storage verified.
- **Python Compatibility:** Verified with Python 3.13, 3.12, and 3.11 on Windows 11.
- **Server Startup & Routes:** Verified running locally on `http://127.0.0.1:5000/`.

## Run tests

### Automated Test Suites

HoneyShield provides a complete testing suite covering property-based fuzzing, browser end-to-end automation, API contract validation, and OWASP defensive security checks.

#### 1. Full Comprehensive Test Runner (142 tests)

Run the unified PowerShell test runner:

```powershell
powershell -ExecutionPolicy Bypass -File tests\run_tests.ps1
```

Or run via Pytest directly:

```powershell
.\.venv\Scripts\pytest.exe tests -v
```

This runs all 7 testing modules:
- **`tests/test_master_build.py`**: Targeted integration suite verifying landing page routing, shared filter parameters, attack-path construction, JSON/CSV exports, and privacy guarantees.
- **`tests/test_hypothesis_risk.py`**: Hypothesis property-based testing and exact boundary checks (0, 34, 35, 49, 50, 64, 65, 100), unordered timestamps, duplicate submissions, and input validation fuzzing.
- **`tests/test_e2e_playwright.py`**: Headless Chromium end-to-end browser journeys testing real user login, 3-failure policy escalation and decoy redirection, decoy telemetry logging, admin investigation/reset, session isolation, and browser Back-button access controls.
- **`tests/test_api_contracts.py`**: Schemathesis contract tests and negative API validation testing missing fields, oversized payloads, unexpected HTTP methods (405), and nonexistent IDs (404) against `docs/openapi.json`.
- **`tests/test_security_posture.py`**: OWASP defensive audits verifying `nosniff`, `SAMEORIGIN`, `strict-origin-when-cross-origin`, CSP headers, `HttpOnly` and `SameSite=Lax` cookie flags, password non-leakage, HMAC-SHA256 username fingerprinting, and SQL injection / XSS resistance.
- **`tests/test_scenario_lab.py`**: Scenario Lab benchmarks, isolation safety, and non-destructive What-If threshold analysis.
- **`tests/test_app.py` & `tests/test_static_integrity.py`**: Core integration and static AST integrity tests.

#### 2. Fast Core Unit Test Suite (28 tests)

To run the standard library unittest suite without extra development tools:

```powershell
.\test.ps1
```

## Risk-score explanation

The score is recomputed after events using recent failed logins in a rolling 180-second window. The implementation uses configurable `RISK_WEIGHTS` in `risk_engine.py`:

- **+30:** three or more failures within 60 seconds (rapid failures)
- **+20:** three or more distinct username fingerprints for the session (credential stuffing)
- **+20:** three or more failures against one target username (targeted brute force)
- **+20:** at least three short, very similar time gaps (automation cadence; coefficient of variation ≤ 0.22)
- **+10:** steadily lengthening retry intervals in a repeated backoff pattern

The result is capped at 100. `LOW` is 0–34, `ELEVATED` is 35–49, and `HIGH` begins at the configured threshold (default 50). Three consecutive failed attempts within 60 seconds (either against one username or multiple usernames) reach 50, trigger the `HIGH` risk band, set `decoy_active = 1`, and redirect the session to `/decoy`.

## Architecture and data handling

- Flask routes render Jinja templates and accept form posts.
- SQLite stores the seeded demo-user hash, server-side authentication/session state, risk summaries, and event details.
- The scoring function inspects only recent failed-login events and updates a session's score/band after each new event.
- The decoy flag is set by the score threshold. Decoy actions are recorded with event type, UTC timestamp, session ID, and an allow-listed action label.
- Attempted usernames are converted into a per-session HMAC fingerprint before event storage. Raw passwords are used only for verification and are not written to the DB or application event stream.
- The scenarios are entirely local: they create synthetic event records through the same event/scoring code and never make outbound requests.

## Limitations and production requirements

This prototype is designed for a local hackathon presentation. It is **not** professionally audited and is not production-grade authentication. It intentionally has no administrator login, CSRF protection, production session-hardening, deployment server, account recovery flow, external monitoring, validated machine-learning model, keystroke/input-cadence tracking, or decoy delay/response variation. The development Flask server must not be exposed to a public network. Before any real deployment, implement an appropriate authentication architecture, strong secret management, hardened cookie/session settings, CSRF protection, rate limiting, safe operational logging, monitoring/alerting, data-retention controls, and a professional security review. Remove or replace all public demo credentials and synthetic decoy material before integrating with real services.

## Troubleshooting

- **`py` or `python` not found:** install Python 3.11 or 3.12, ensure the Python launcher is installed, then reopen PowerShell.
- **Dependency installation fails:** verify pip can access the configured package index once. After Flask is installed in `.venv`, running the app itself makes no external API calls.
- **Port unavailable:** set `$env:HONEYSHIELD_PORT = '5001'` and rerun.
- **Database needs a clean demo:** use **Reset demo** in the Control room. To remove all local runtime state manually, stop the app and delete `data/honeyshield.sqlite3` (the next launch recreates the schema and demo user).
- **App will not launch in IDE:** open the directory containing `app.py` and `requirements.txt`, not its parent folder. Normal usage does not require an IDE extension or Administrator permissions.
