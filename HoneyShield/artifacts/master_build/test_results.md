# Automated Test Execution Results — Master Build

**Date**: 2026-10-27  
**Test Suite**: HoneyShield Defensive Test Suite  
**Runner Command**: `powershell -ExecutionPolicy Bypass -File tests/run_tests.ps1`  
**Underlying Command**: `.venv\Scripts\pytest.exe tests -v --tb=short`  
**Execution Duration**: 60.54 seconds (Pytest time: 57.78 seconds)  
**Overall Result**: **ALL TEST SUITES PASSED (Exit Code: 0)**

---

## 1. Summary Metrics

| Metric | Result |
| :--- | :--- |
| **Total Tests Executed** | **142** |
| **Passed** | **142** |
| **Failed** | **0** |
| **Skipped / Blocked** | **0** |
| **Pass Rate** | **100.0%** |
| **Exit Code** | `0` |

---

## 2. Test Module Breakdown

| Module | Test File | Tests Passed | Status |
| :--- | :--- | :---: | :---: |
| **Master Build Core** | `tests/test_master_build.py` | 12 / 12 | **PASS** |
| **Unittest Integration & Lifecycle** | `tests/test_app.py` | 15 / 15 | **PASS** |
| **Static & Template Integrity** | `tests/test_static_integrity.py` | 8 / 8 | **PASS** |
| **Master Workflow End-to-End** | `tests/test_master_workflow_audit.py` | 5 / 5 | **PASS** |
| **Chart Data-Wiring & Rendering** | `tests/test_chart_data_wiring.py` | 7 / 7 | **PASS** |
| **Flight Recorder & Canary Access** | `tests/test_flight_recorder_canaries.py` | 7 / 7 | **PASS** |
| **Scenario Lab & Benchmarking** | `tests/test_scenario_lab.py` | 13 / 13 | **PASS** |
| **Risk Scoring Engine** | `tests/test_risk_engine.py` | 4 / 4 | **PASS** |
| **Hypothesis Property-Based** | `tests/test_hypothesis_risk.py` | 27 / 27 | **PASS** |
| **Playwright Chromium E2E** | `tests/test_e2e_playwright.py` | 5 / 5 | **PASS** |
| **API Contracts & Schemathesis** | `tests/test_api_contracts.py` | 17 / 17 | **PASS** |
| **OWASP Security & Privacy** | `tests/test_security_posture.py` | 8 / 8 | **PASS** |
| **Live Judge Scenarios** | `tests/test_live_judge_inputs.py` | 14 / 14 | **PASS** |
| **Total** | | **142 / 142** | **PASS** |

---

## 3. Master Build Targeted Test Cases (`tests/test_master_build.py`)

1. `test_landing_page_renders_headline_and_features` — PASSED  
   *Verified `GET /` renders headline "Trust the behaviour. Not just the password.", animated shield SVG, 4 feature pillars, 5-step workflow, and demo CTAs.*
2. `test_login_route_preserved_and_functional` — PASSED  
   *Verified `GET /login` renders login form with CSRF token and `POST /login` correctly validates demo credentials.*
3. `test_post_to_root_delegates_to_login` — PASSED  
   *Verified backwards compatibility: POST to `/` transparently processes authentication.*
4. `test_shared_filter_bar_elements_present` — PASSED  
   *Verified `.soc-filter-panel`, time pills (5m, 15m, 1h, 24h, all), risk band select, source select, search input, and filter tags.*
5. `test_shared_filter_by_band` — PASSED  
   *Verified filter `?band=HIGH` restricts sessions and events exclusively to HIGH risk band records.*
6. `test_shared_filter_by_source` — PASSED  
   *Verified filter `?source=simulator` isolates simulation runs from browser events.*
7. `test_chart_attempts_accepts_source_filter` — PASSED  
   *Verified `/api/chart/attempts?source=simulator` filters time-series buckets to matching sources without fabricating data.*
8. `test_session_flight_recorder_and_attack_path` — PASSED  
   *Verified `/admin/session/<key>` displays Deterministic Attack-Path Reconstruction, Explainable heuristic signals, Chronological session flight recorder, and raw telemetry details.*
9. `test_export_json_contract_and_content` — PASSED  
   *Verified `/admin/session/<key>/export?format=json` serves valid JSON with ISO-8601 timestamps, heuristic contributions, timeline, and `is_derived` markers.*
10. `test_export_csv_contract_and_content` — PASSED  
    *Verified `/admin/session/<key>/export?format=csv` serves RFC 4180 CSV with sanitized headers and matching event counts.*
11. `test_export_nonexistent_session_returns_404` — PASSED  
    *Verified invalid session keys return HTTP 404.*
12. `test_privacy_guarantee_passwords_never_in_exports` — PASSED  
    *Verified exports strictly exclude passwords, submitted credentials, or secrets.*

---

## 4. Visual Evidence Artifacts

The following visual artifacts were captured from the running application and saved to `artifacts/master_build/`:
- `landing_page.png` — 1440x900 full-page view of the dedicated cybersecurity landing page.
- `desktop_control_room.png` — 1440x900 view of the SOC Control Room showing working SVG time-series charts, risk distribution bar, and shared filter bar.
- `session_investigation.png` — 1440x900 view of the Session Flight Recorder showing the deterministic attack-path pipeline and explainable heuristics.
- `mobile_view.png` — 390x844 responsive mobile audit showing stacked cards and zero horizontal overflow.
- `sample_export.json` & `sample_export.csv` — Authentic export files generated from a live suspicious session.
