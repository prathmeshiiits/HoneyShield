"""
Automated Verification Suite for HoneyShield Master Build.
Verifies:
1. Dedicated Public Landing Page (/) & Preserved Login (/login)
2. SOC Control Room Shared Filter Bar & Query Parameter Synchronization
3. Deep-Dive Session Investigation & Deterministic Attack-Path Reconstruction
4. One-Click JSON and CSV Evidence Export with Privacy Guarantees
5. Zero Password / Secret Leakage In Telemetry and Exports
"""
import csv
import io
import json
import sqlite3
import pytest
from app import create_app, DEMO_USERNAME, DEMO_PASSWORD


@pytest.fixture
def master_client(tmp_path):
    """Provides an isolated Flask test client with a clean temporary SQLite database."""
    db_file = tmp_path / "test_master_build.sqlite3"
    app = create_app({
        "TESTING": True,
        "DATABASE": str(db_file),
        "SECRET_KEY": "test-master-build-secret-2026",
        "HIGH_RISK_THRESHOLD": 50,
        "DEMO_MODE": True,
    })
    with app.test_client() as client:
        yield client, app, db_file


class TestLandingPageAndRouting:
    """Verifies Phase 6 requirements: Public Landing Page and Route Preservation."""

    def test_landing_page_renders_headline_and_features(self, master_client):
        client, _, _ = master_client
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)

        # Headline
        assert "Trust the" in html
        assert "Not just the password." in html

        # Adaptive deception layer marker (crucial for P0 contract)
        assert "Adaptive deception layer" in html

        # 4 Required Core Features
        assert "Adaptive Risk Scoring" in html
        assert "Evidence-Led Investigation" in html
        assert "Synthetic Decoy Environment" in html
        assert "Scenario Lab &amp; Policy Benchmark" in html or "Scenario Lab & Policy Benchmark" in html

        # How It Works Sequence
        assert "Observe Behaviour" in html
        assert "Assess Evidence" in html
        assert "Enforce Configured Policy" in html
        assert "Record Events" in html
        assert "Investigate &amp; Export" in html or "Investigate & Export" in html

        # CTAs
        assert "/admin" in html
        assert "/login" in html
        assert "/lab" in html

        # Privacy disclaimer
        assert "Zero plaintext secrets" in html or "Running locally" in html

    def test_login_route_preserved_and_functional(self, master_client):
        client, _, _ = master_client
        resp = client.get("/login")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert 'id="username"' in html
        assert 'id="password"' in html
        assert "Sign in to continue" in html

    def test_post_to_root_delegates_to_login(self, master_client):
        client, _, _ = master_client
        # Successful login POST to "/"
        resp = client.post("/", data={"username": DEMO_USERNAME, "password": DEMO_PASSWORD})
        assert resp.status_code == 302
        assert "/dashboard" in resp.headers["Location"]


class TestSharedFilterBarAndControlRoom:
    """Verifies Phase 3 requirements: Shared Interactive Control-Room Filter Bar."""

    def test_shared_filter_bar_elements_present(self, master_client):
        client, _, _ = master_client
        resp = client.get("/admin")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)

        assert 'id="socSharedFilterForm"' in html
        assert 'name="time"' in html or 'id="sharedTimeFilter"' in html
        assert 'name="band"' in html
        assert 'name="source"' in html
        assert 'name="session"' in html
        assert "Apply filters" in html
        assert "Clear filters" in html
        assert "clickable-kpi" in html

    def test_shared_filter_by_band(self, master_client):
        client, app, _ = master_client
        # Generate one normal and one suspicious session
        with app.app_context():
            app.run_demo_scenario("normal")
            app.run_demo_scenario("suspicious")

        # Unfiltered: should show both
        resp_all = client.get("/admin")
        assert resp_all.status_code == 200

        # Filter by HIGH risk
        resp_high = client.get("/admin?band=HIGH")
        assert resp_high.status_code == 200
        html_high = resp_high.get_data(as_text=True)
        assert "Active:" in html_high
        assert "Band: <strong>HIGH</strong>" in html_high

        # Filter by LOW risk
        resp_low = client.get("/admin?band=LOW")
        assert resp_low.status_code == 200
        html_low = resp_low.get_data(as_text=True)
        assert "Band: <strong>LOW</strong>" in html_low

    def test_shared_filter_by_source(self, master_client):
        client, app, _ = master_client
        # 1. Browser session with a failed login
        client.post("/login", data={"username": "demo", "password": "WrongPassword!"})
        # 2. Simulated scenario
        with app.app_context():
            app.run_demo_scenario("suspicious")

        resp_sim = client.get("/admin?source=simulation")
        assert resp_sim.status_code == 200
        html_sim = resp_sim.get_data(as_text=True)
        assert "Source: <strong>Simulation</strong>" in html_sim

        resp_browser = client.get("/admin?source=browser")
        assert resp_browser.status_code == 200
        html_browser = resp_browser.get_data(as_text=True)
        assert "Source: <strong>Browser</strong>" in html_browser

    def test_chart_attempts_accepts_source_filter(self, master_client):
        client, app, _ = master_client
        # Browser attempt
        client.post("/login", data={"username": "demo", "password": "WrongPassword!"})
        # Simulation scenario
        with app.app_context():
            app.run_demo_scenario("suspicious")

        # Query all
        resp_all = client.get("/api/chart/attempts?window=all")
        assert resp_all.status_code == 200
        data_all = resp_all.get_json()
        assert data_all["total_attempts"] >= 2

        # Query browser only
        resp_browser = client.get("/api/chart/attempts?window=all&source=browser")
        assert resp_browser.status_code == 200
        data_browser = resp_browser.get_json()
        assert data_browser["status"] == "ok"
        # Total attempts for browser only should be 1
        assert data_browser["total_attempts"] == 1


class TestSessionInvestigationAndAttackPath:
    """Verifies Phase 4: Session Flight Recorder and Deterministic Attack-Path Visualization."""

    def test_session_flight_recorder_and_attack_path(self, master_client):
        client, app, db_file = master_client
        # Trigger suspicious scenario
        with app.app_context():
            res = app.run_demo_scenario("suspicious")
            sid = res["session_key"]

        # 1. HTML Flight Recorder
        resp = client.get(f"/admin/session/{sid}")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)

        assert "Deterministic Attack-Path Reconstruction" in html
        assert "Explainable heuristic signals" in html
        assert "Chronological session flight recorder" in html
        assert "Export JSON" in html
        assert "Export CSV" in html
        assert "RECORDED EVIDENCE" in html
        assert "CALCULATED INTERPRETATION" in html

        # 2. JSON API Session Detail
        resp_api = client.get(f"/api/session/{sid}")
        assert resp_api.status_code == 200
        api_data = resp_api.get_json()
        assert api_data["status"] == "ok"
        sess = api_data["session"]
        assert sess["session_key"] == sid
        assert sess["risk_score"] >= 50
        assert sess["risk_band"] == "HIGH"
        assert sess["decoy_active"] is True

        # Attack Path verification
        assert "attack_path" in sess
        attack_path = sess["attack_path"]
        assert len(attack_path) >= 4
        # Step 1: Ingress
        assert attack_path[0]["badge"] in ("INGRESS", "REGISTERED")
        # Step 2: Retry Pattern / Attempts
        assert "Authentication Pattern" in attack_path[1]["title"]
        # Step 3: Evaluation
        assert "Risk Engine Evaluation" in attack_path[2]["title"]
        # Step 4: Containment
        assert attack_path[3]["badge"] == "CONTAINED"


class TestEvidenceExport:
    """Verifies Phase 5: One-Click JSON and CSV Evidence Export."""

    def test_export_json_contract_and_content(self, master_client):
        client, app, _ = master_client
        with app.app_context():
            res = app.run_demo_scenario("suspicious")
            sid = res["session_key"]

        resp = client.get(f"/admin/session/{sid}/export?format=json")
        assert resp.status_code == 200
        assert "application/json" in resp.headers["Content-Type"]
        assert "attachment; filename=" in resp.headers["Content-Disposition"]
        assert f"honeyshield-investigation-{sid[:24]}" in resp.headers["Content-Disposition"]

        data = json.loads(resp.get_data(as_text=True))
        assert data["export_type"] == "honeyshield_session_investigation"
        assert "privacy_notice" in data
        assert "derived_vs_recorded" in data
        assert data["session_overview"]["session_key"] == sid
        assert data["session_overview"]["risk_score"] == res["risk_score"]
        assert data["session_overview"]["decoy_active"] is True
        assert len(data["explainable_signals"]) >= 1
        assert len(data["attack_path"]) >= 4
        assert len(data["recorded_events"]) >= 1

    def test_export_csv_contract_and_content(self, master_client):
        client, app, _ = master_client
        with app.app_context():
            res = app.run_demo_scenario("suspicious")
            sid = res["session_key"]

        resp = client.get(f"/admin/session/{sid}/export?format=csv")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["Content-Type"]
        assert "attachment; filename=" in resp.headers["Content-Disposition"]

        csv_text = resp.get_data(as_text=True)
        reader = csv.reader(io.StringIO(csv_text))
        rows = list(reader)
        assert len(rows) >= 2  # Header + at least 1 event row

        header = rows[0]
        assert "Session_ID" in header
        assert "Source_Type" in header
        assert "Assessed_Risk" in header
        assert "Risk_Band" in header
        assert "Policy_Threshold" in header
        assert "Policy_Verdict" in header
        assert "Decoy_Active" in header
        assert "Event_ID" in header
        assert "Timestamp_UTC" in header
        assert "Event_Type" in header

        # Verify data row matches selected session
        data_row = rows[1]
        assert data_row[0] == sid
        assert int(data_row[2]) == res["risk_score"]
        assert data_row[3] == "HIGH"
        assert data_row[6] == "True"

    def test_export_nonexistent_session_returns_404(self, master_client):
        client, _, _ = master_client
        resp = client.get("/admin/session/non-existent-session-id/export?format=json")
        assert resp.status_code == 404

    def test_privacy_guarantee_passwords_never_in_exports(self, master_client):
        client, app, db_file = master_client
        secret_password = "SuperSecretPlainTextPassword999!"
        # Attempt failed login with secret password
        client.post("/login", data={"username": "demo", "password": secret_password})

        # Get session ID from cookie / DB
        conn = sqlite3.connect(str(db_file))
        row = conn.execute("SELECT session_key FROM sessions ORDER BY created_at DESC LIMIT 1").fetchone()
        assert row is not None
        sid = row[0]
        conn.close()

        # Check JSON export
        resp_json = client.get(f"/admin/session/{sid}/export?format=json")
        assert resp_json.status_code == 200
        assert secret_password not in resp_json.get_data(as_text=True)

        # Check CSV export
        resp_csv = client.get(f"/admin/session/{sid}/export?format=csv")
        assert resp_csv.status_code == 200
        assert secret_password not in resp_csv.get_data(as_text=True)
