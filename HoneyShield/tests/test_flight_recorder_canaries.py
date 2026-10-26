"""Tests for Session Flight Recorder, Decoy Isolation, and Synthetic Canaries (Prompt 05)."""
import json
import sqlite3
import pytest
from app import create_app, connect_database, DEMO_USERNAME, DEMO_PASSWORD


@pytest.fixture
def isolated_client(tmp_path):
    """Provides an isolated Flask test client with a fresh temporary SQLite DB."""
    db_file = tmp_path / "test_canaries.sqlite3"
    app = create_app({"TESTING": True, "DATABASE": str(db_file), "SECRET_KEY": "test-canary-secret-2026"})
    with app.test_client() as client:
        yield client


class TestFlightRecorderAndCanaries:
    def test_unauthorized_decoy_and_canary_access_prevented(self, isolated_client):
        """A normal unauthenticated or non-decoy user cannot access decoy or canaries."""
        # 1. Accessing /decoy redirects to /login (which routes to '/')
        r_decoy = isolated_client.get("/decoy")
        assert r_decoy.status_code == 302
        assert r_decoy.headers["Location"] in ("/", "/login")

        # 2. Accessing canary download without decoy activation returns 403
        r_down = isolated_client.get("/decoy/download/backup_manifest")
        assert r_down.status_code in (403, 302)

        # 3. Accessing canary view without decoy activation returns 403
        r_view = isolated_client.get("/decoy/canary/api_inventory")
        assert r_view.status_code in (403, 302)

        # 4. Valid normal login still does not grant access to decoy
        isolated_client.post("/login", data={"username": DEMO_USERNAME, "password": DEMO_PASSWORD})
        r_decoy_auth = isolated_client.get("/decoy")
        assert r_decoy_auth.status_code == 302
        assert r_decoy_auth.headers["Location"] in ("/", "/login")

    def test_authorized_decoy_can_access_and_download_canaries(self, isolated_client):
        """An authorized decoy session can view and download synthetic canary objects."""
        # Escalate session to decoy via 3 failed logins
        for i in range(3):
            isolated_client.post("/login", data={"username": "demo", "password": f"WrongPass{i}"})

        # Decoy dashboard is accessible
        r_decoy = isolated_client.get("/decoy")
        assert r_decoy.status_code == 200
        assert b"Controlled decoy environment" in r_decoy.data
        assert b"Quarterly Privilege Report" in r_decoy.data
        assert b"Backup Manifest" in r_decoy.data
        assert b"Synthetic API Inventory" in r_decoy.data

        # 1. Download Backup Manifest Canary
        r_bk = isolated_client.get("/decoy/download/backup_manifest")
        assert r_bk.status_code == 200
        assert "attachment; filename=\"backup_manifest.json\"" in r_bk.headers.get("Content-Disposition", "")
        assert r_bk.headers.get("X-HoneyShield-Synthetic") == "Canary-Object"
        data_bk = json.loads(r_bk.data.decode("utf-8"))
        assert data_bk["canary_id"] == "HS-CANARY-BAK-2026"
        assert "SYNTHETIC DECOY ARTIFACT" in data_bk["canary_notice"]
        assert "checksum" in data_bk["manifest"]

        # 2. Download Privilege Report Canary
        r_priv = isolated_client.get("/decoy/download/privilege_report")
        assert r_priv.status_code == 200
        assert "attachment; filename=\"quarterly_privilege_report.json\"" in r_priv.headers.get("Content-Disposition", "")
        data_priv = json.loads(r_priv.data.decode("utf-8"))
        assert data_priv["canary_id"] == "HS-CANARY-PRIV-2026"
        assert len(data_priv["report"]["assignments"]) >= 2

        # 3. View Synthetic API Inventory Canary Token
        r_api = isolated_client.get("/decoy/canary/api_inventory")
        assert r_api.status_code == 200
        data_api = json.loads(r_api.data.decode("utf-8"))
        assert data_api["status"] == "ok"
        canary_info = data_api["canary"]
        assert canary_info["canary_token"] == "hs_canary_sec_prod_99a8b7c6d5e4_nonfunctional"
        assert "NON-FUNCTIONAL" in canary_info["classification"]

        # Verify all canary actions were persisted in SQLite
        with isolated_client.application.app_context():
            conn = connect_database(isolated_client.application.config["DATABASE"])
            events = [dict(r) for r in conn.execute("SELECT event_type, details_json FROM events").fetchall()]
            conn.close()

        types = {e["event_type"] for e in events}
        assert "decoy_activated" in types
        assert "decoy_canary_backup_downloaded" in types
        assert "decoy_canary_privilege_report_viewed" in types
        assert "decoy_canary_token_accessed" in types

    def test_malformed_and_unknown_canary_ids_do_not_crash(self, isolated_client):
        """Invalid, unknown, or malformed object IDs return 400 and do not crash."""
        # Escalate to decoy
        for i in range(3):
            isolated_client.post("/login", data={"username": "demo", "password": f"WrongPass{i}"})

        # Unknown download ID returns 400
        r1 = isolated_client.get("/decoy/download/nonexistent_backup_file")
        assert r1.status_code == 400

        # Unknown canary view ID returns 400
        r2 = isolated_client.get("/decoy/canary/nonexistent_token_id")
        assert r2.status_code == 400

        # Malformed path characters return 400 or 404
        r3 = isolated_client.get("/decoy/download/..%2F..%2Fetc%2Fpasswd")
        assert r3.status_code in (400, 404)

        # Oversized object ID returns 400
        r4 = isolated_client.get(f"/decoy/download/{'A' * 200}")
        assert r4.status_code == 400

    def test_session_isolation_canary_state(self, tmp_path):
        """Attacker actions in Session A do not leak into or affect Session B."""
        db_file = tmp_path / "test_isolation.sqlite3"
        app = create_app({"TESTING": True, "DATABASE": str(db_file), "SECRET_KEY": "isolation-test-key"})

        client_attacker = app.test_client()
        client_victim = app.test_client()

        # Attacker fails 3 times and downloads canary
        for i in range(3):
            client_attacker.post("/login", data={"username": "victim", "password": f"Attack{i}"})
        r_att = client_attacker.get("/decoy/download/backup_manifest")
        assert r_att.status_code == 200

        # Normal victim enters valid password
        r_vic = client_victim.post("/login", data={"username": DEMO_USERNAME, "password": DEMO_PASSWORD}, follow_redirects=True)
        assert r_vic.status_code == 200
        assert b"Workspace overview" in r_vic.data

        # Victim cannot access decoy or canaries
        r_vic_decoy = client_victim.get("/decoy")
        assert r_vic_decoy.status_code == 302
        assert r_vic_decoy.headers["Location"] in ("/", "/login")

        # Verify SQLite states: Attacker is HIGH/decoy_active=1, Victim is LOW/decoy_active=0
        with app.app_context():
            conn = connect_database(str(db_file))
            sessions = [dict(r) for r in conn.execute("SELECT session_key, risk_score, risk_band, decoy_active, authenticated FROM sessions").fetchall()]
            conn.close()

        assert len(sessions) == 2
        attacker_sess = [s for s in sessions if s["decoy_active"] == 1][0]
        victim_sess = [s for s in sessions if s["authenticated"] == 1][0]

        assert attacker_sess["risk_score"] >= 50
        assert attacker_sess["risk_band"] == "HIGH"
        assert victim_sess["risk_score"] == 0
        assert victim_sess["risk_band"] == "LOW"

    def test_admin_session_flight_recorder_page(self, isolated_client):
        """GET /admin/session/<session_key> renders complete chronological flight recorder."""
        # 1. 404 on nonexistent session
        r_404 = isolated_client.get("/admin/session/nonexistent-session-key-404")
        assert r_404.status_code == 404

        # 2. Create session with full lifecycle: login failed x3 -> canary interaction -> logout
        for i in range(3):
            isolated_client.post("/login", data={"username": "demo", "password": f"BruteForce{i}"})
        isolated_client.get("/decoy/download/backup_manifest")
        isolated_client.get("/logout")

        # Get the session key
        with isolated_client.application.app_context():
            conn = connect_database(isolated_client.application.config["DATABASE"])
            sid = conn.execute("SELECT session_key FROM sessions LIMIT 1").fetchone()[0]
            conn.close()

        # 3. Request Flight Recorder page
        resp = isolated_client.get(f"/admin/session/{sid}")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)

        assert sid in html
        assert "SESSION FLIGHT RECORDER" in html
        assert "Chronological session flight recorder" in html
        assert "Explainable heuristic signals" in html
        assert "Login Failed" in html
        assert "Decoy Activated" in html
        assert "Decoy Canary Backup Downloaded" in html
        assert "User Logged Out" in html

        # Verify passwords and real secrets are not leaked
        assert "BruteForce0" not in html
        assert "BruteForce1" not in html
        assert "ShieldDemo!2026" not in html

    def test_session_timeline_stable_ordering_and_reset(self, isolated_client):
        """Timeline events remain in strict chronological order and reset is safe."""
        # Create events
        for i in range(3):
            isolated_client.post("/login", data={"username": "demo", "password": f"Pass{i}"})
        isolated_client.get("/decoy/download/backup_manifest")

        # Fetch investigation JSON via API
        with isolated_client.application.app_context():
            conn = connect_database(isolated_client.application.config["DATABASE"])
            sid = conn.execute("SELECT session_key FROM sessions LIMIT 1").fetchone()[0]
            conn.close()

        resp = isolated_client.get(f"/api/session/{sid}")
        assert resp.status_code == 200
        data = resp.get_json()["session"]
        events = data["events"]

        # Check ascending chronological timestamps
        timestamps = [e["event_at"] for e in events]
        assert timestamps == sorted(timestamps)

        # Reset demo
        r_reset = isolated_client.post("/admin/reset", follow_redirects=True)
        assert r_reset.status_code == 200

        # DB is clean; demo user remains
        with isolated_client.application.app_context():
            conn = connect_database(isolated_client.application.config["DATABASE"])
            n_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            n_sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
            n_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            conn.close()

        assert n_events == 0
        assert n_sessions == 0
        assert n_users == 1
