"""API Contract and Schemathesis negative/positive testing suite."""
from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path
from typing import Generator

import pytest

from app import DEMO_PASSWORD, DEMO_USERNAME, create_app

try:
    import schemathesis
    SCHEMATHESIS_AVAILABLE = True
except ImportError:
    SCHEMATHESIS_AVAILABLE = False


@pytest.fixture
def isolated_client() -> Generator:
    """Provide a client with isolated test database for API contract testing."""
    with tempfile.TemporaryDirectory(prefix="hs-api-") as tmp:
        db_path = Path(tmp) / "api.sqlite3"
        application = create_app({
            "TESTING": True,
            "DATABASE": str(db_path),
            "SECRET_KEY": "api-contract-key-2026",
            "HIGH_RISK_THRESHOLD": 50,
        })
        with application.test_client() as client:
            yield client


class TestApiNegativeAndBoundaryCases:
    """Comprehensive negative and boundary API test cases."""

    def test_healthz_endpoint_schema(self, isolated_client):
        """GET /healthz returns 200 JSON with exact expected schema and values."""
        resp = isolated_client.get("/healthz")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith("application/json")
        data = resp.get_json()
        assert data == {"status": "ok", "service": "HoneyShield", "storage": "sqlite"}

    def test_missing_fields_on_login(self, isolated_client):
        """POST /login with missing username or password returns 400."""
        r1 = isolated_client.post("/login", data={})
        assert r1.status_code == 400

        r2 = isolated_client.post("/login", data={"username": "demo"})
        assert r2.status_code == 400

        r3 = isolated_client.post("/login", data={"password": "password"})
        assert r3.status_code == 400

        r4 = isolated_client.post("/login", data={"username": "   ", "password": "abc"})
        assert r4.status_code == 400

    def test_oversized_inputs_rejected(self, isolated_client):
        """POST /login with username > 64 chars or password > 128 chars returns 400."""
        r1 = isolated_client.post("/login", data={"username": "A" * 65, "password": "validPassword123"})
        assert r1.status_code == 400

        r2 = isolated_client.post("/login", data={"username": "validUser", "password": "B" * 129})
        assert r2.status_code == 400

    def test_unexpected_http_methods_rejected(self, isolated_client):
        """Routes reject unsupported HTTP methods with 405 Method Not Allowed."""
        # /healthz only allows GET
        assert isolated_client.post("/healthz").status_code == 405
        assert isolated_client.put("/healthz").status_code == 405
        assert isolated_client.delete("/healthz").status_code == 405

        # /decoy/action only allows POST
        assert isolated_client.get("/decoy/action").status_code == 405

        # /admin/reset only allows POST
        assert isolated_client.get("/admin/reset").status_code == 405

        # /admin/simulate/<scenario> only allows POST
        assert isolated_client.get("/admin/simulate/suspicious").status_code == 405

        # /dashboard only allows GET
        assert isolated_client.post("/dashboard").status_code == 405

        # /logout only allows GET
        assert isolated_client.post("/logout").status_code == 405

    def test_nonexistent_ids_and_scenarios(self, isolated_client):
        """Nonexistent session keys and unknown simulation scenarios return 404."""
        # Nonexistent scenario
        r1 = isolated_client.post("/admin/simulate/nonexistent_scenario")
        assert r1.status_code == 404

        # Nonexistent session key in admin decoy
        r2 = isolated_client.get("/admin/decoy/missing-session-key-1234")
        assert r2.status_code == 404

        r3 = isolated_client.post("/admin/decoy/missing-session-key-1234/action", data={"action": "open_record"})
        assert r3.status_code == 404

    def test_unauthorized_operations(self, isolated_client):
        """Unauthenticated or unactivated sessions are prevented from unauthorized actions."""
        # Accessing /dashboard without auth redirects to login
        r1 = isolated_client.get("/dashboard")
        assert r1.status_code == 302
        assert r1.headers["Location"].endswith(("/login", "/"))

        # Accessing /decoy without decoy activation redirects to login
        r2 = isolated_client.get("/decoy")
        assert r2.status_code == 302
        assert r2.headers["Location"].endswith(("/login", "/"))

        # Triggering /decoy/action without active decoy returns 403 Forbidden
        r3 = isolated_client.post("/decoy/action", data={"action": "open_record"})
        assert r3.status_code == 403

    def test_invalid_action_value_rejected(self, isolated_client):
        """Triggering decoy action with invalid action type returns 400 Bad Request."""
        # First escalate to decoy
        for _ in range(3):
            isolated_client.post("/login", data={"username": "attacker", "password": "wrong"})

        # Decoy is now active; send invalid action
        resp = isolated_client.post("/decoy/action", data={"action": "invalid_exploit_action"})
        assert resp.status_code == 400

    def test_admin_decoy_action_invalid_action(self, isolated_client):
        """Admin decoy action with invalid action name returns 400."""
        # Simulate suspicious session
        isolated_client.post("/admin/simulate/suspicious")
        # Find session key
        resp = isolated_client.get("/admin")
        assert resp.status_code == 200

        # Try invalid action on existing simulated session
        # Read from app
        with isolated_client.application.app_context():
            from app import connect_database
            conn = connect_database(isolated_client.application.config["DATABASE"])
            row = conn.execute("SELECT session_key FROM sessions WHERE decoy_active = 1 LIMIT 1").fetchone()
            conn.close()
            assert row is not None
            sid = row["session_key"]

        resp_action = isolated_client.post(f"/admin/decoy/{sid}/action", data={"action": "bad_action"})
        assert resp_action.status_code == 400

    def test_api_metrics_data_contract(self, isolated_client):
        """GET /api/metrics returns full summary, risk distribution, and attempts over time."""
        # Initial empty metrics
        resp = isolated_client.get("/api/metrics")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert "summary" in data
        assert "risk_distribution" in data
        assert "attempts_over_time" in data

        summary = data["summary"]
        expected_keys = {
            "sessions", "events", "failed_attempts", "successful_attempts",
            "total_attempts", "suspicious", "low_sessions", "elevated_sessions",
            "high_sessions", "decoys", "interactions", "time_window_seconds",
            "threshold", "policy_limit", "policy_version"
        }
        assert expected_keys.issubset(summary.keys())
        assert summary["sessions"] == 0
        assert summary["events"] == 0
        assert data["risk_distribution"] == {"LOW": 0, "ELEVATED": 0, "HIGH": 0}
        assert data["attempts_over_time"] == []

        # Create real login events and verify metrics update immediately
        isolated_client.post("/login", data={"username": "demo", "password": "BadPassword1"})
        resp2 = isolated_client.get("/api/metrics")
        data2 = resp2.get_json()
        assert data2["summary"]["sessions"] == 1
        assert data2["summary"]["events"] == 1
        assert data2["summary"]["failed_attempts"] == 1
        assert data2["summary"]["total_attempts"] == 1
        assert data2["risk_distribution"]["LOW"] == 1

        # Compare directly with SQLite database rows
        with isolated_client.application.app_context():
            from app import connect_database
            conn = connect_database(isolated_client.application.config["DATABASE"])
            db_sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
            db_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            conn.close()
            assert data2["summary"]["sessions"] == db_sessions
            assert data2["summary"]["events"] == db_events

    def test_api_events_data_contract_and_filters(self, isolated_client):
        """GET /api/events returns paginated and filtered event feed."""
        # Add a mix of events
        isolated_client.post("/login", data={"username": "demo", "password": "BadPassword1"})
        isolated_client.post("/login", data={"username": "demo", "password": "BadPassword2"})
        isolated_client.post("/login", data={"username": "demo", "password": DEMO_PASSWORD})

        # Fetch events feed
        resp = isolated_client.get("/api/events")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert data["total"] == 3
        assert len(data["events"]) == 3

        # Verify event schema
        ev = data["events"][0]
        assert "id" in ev
        assert "event_at" in ev
        assert "session_key" in ev
        assert "event_type" in ev
        assert "safe_result" in ev
        assert "risk_score" in ev
        assert "risk_band" in ev
        assert "is_simulated" in ev

        # Verify passwords, secrets, cookies never appear in JSON
        json_str = resp.get_data(as_text=True)
        assert "BadPassword" not in json_str
        assert DEMO_PASSWORD not in json_str
        assert "password_hash" not in json_str

        # Filter by event_type
        r_type = isolated_client.get("/api/events?type=login_success")
        assert r_type.status_code == 200
        d_type = r_type.get_json()
        assert d_type["total"] == 1
        assert d_type["events"][0]["event_type"] == "login_success"

        # Pagination: limit and offset
        r_page = isolated_client.get("/api/events?limit=1&offset=1")
        assert r_page.status_code == 200
        d_page = r_page.get_json()
        assert d_page["total"] == 3
        assert len(d_page["events"]) == 1

        # Negative/boundary parameters
        r_clamp = isolated_client.get("/api/events?limit=-5&offset=-10")
        assert r_clamp.status_code == 200
        assert r_clamp.get_json()["limit"] == 1
        assert r_clamp.get_json()["offset"] == 0

    def test_api_session_detail_data_contract(self, isolated_client):
        """GET /api/session/<session_key> returns detailed investigation assessment."""
        # Unknown session key returns 404
        r_404 = isolated_client.get("/api/session/nonexistent-session-key-999")
        assert r_404.status_code == 404
        assert r_404.get_json()["status"] == "error"

        # Create session with 3 failures to trigger decoy
        for i in range(3):
            isolated_client.post("/login", data={"username": "demo", "password": f"Wrong{i}"})

        with isolated_client.application.app_context():
            from app import connect_database
            conn = connect_database(isolated_client.application.config["DATABASE"])
            row = conn.execute("SELECT session_key FROM sessions LIMIT 1").fetchone()
            conn.close()
            assert row is not None
            sid = row["session_key"]

        resp = isolated_client.get(f"/api/session/{sid}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        sess = data["session"]
        assert sess["session_key"] == sid
        assert sess["risk_score"] == 50
        assert sess["risk_band"] == "HIGH"
        assert sess["decision"] == "decoy"
        assert sess["decoy_active"] is True
        assert sess["policy_version"] == "2.0.0"

        # Verify signal contributions structure
        assert "signal_contributions" in sess
        for sc in sess["signal_contributions"]:
            assert "signal" in sc
            assert "name" in sc
            assert "weight" in sc
            assert "triggered" in sc
            assert "description" in sc

        # rapid_failures and repeated_principal are triggered
        contrib_map = {c["signal"]: c["triggered"] for c in sess["signal_contributions"]}
        assert contrib_map["rapid_failures"] is True
        assert contrib_map["repeated_principal"] is True

        # Ordered events list exists
        assert "events" in sess
        assert len(sess["events"]) >= 3

    def test_api_chart_attempts_data_contract(self, isolated_client):
        """GET /api/chart/attempts returns real time-bucketed attempt series."""
        # Empty database
        r_empty = isolated_client.get("/api/chart/attempts")
        assert r_empty.status_code == 200
        d_empty = r_empty.get_json()
        assert d_empty["status"] == "ok"
        assert d_empty["buckets"] == []
        assert d_empty["empty"] is True

        # Add failed and successful events
        isolated_client.post("/login", data={"username": "demo", "password": "Bad1"})
        isolated_client.post("/login", data={"username": "demo", "password": DEMO_PASSWORD})

        r_data = isolated_client.get("/api/chart/attempts?window=1800")
        assert r_data.status_code == 200
        d_data = r_data.get_json()
        assert d_data["status"] == "ok"
        assert len(d_data["buckets"]) >= 1
        b0 = d_data["buckets"][0]
        assert "bucket" in b0
        assert "failed" in b0
        assert "success" in b0
        assert b0["failed"] >= 1
        assert b0["success"] >= 1



# ---------------------------------------------------------------------------
# Schemathesis OpenAPI Contract Tests
# ---------------------------------------------------------------------------
OPENAPI_PATH = Path(__file__).resolve().parent.parent / "docs" / "openapi.json"

if SCHEMATHESIS_AVAILABLE and OPENAPI_PATH.is_file():
    schema = schemathesis.openapi.from_path(str(OPENAPI_PATH))
    healthz_schema = schema.include(path="/healthz")

    @healthz_schema.parametrize()
    def test_schemathesis_healthz(case):
        """Schemathesis property test for /healthz against OpenAPI specification."""
        with tempfile.TemporaryDirectory(prefix="hs-schema-") as tmp:
            db_path = Path(tmp) / "schema.sqlite3"
            test_app = create_app({"TESTING": True, "DATABASE": str(db_path), "SECRET_KEY": "schema-key"})
            with test_app.test_client() as client:
                resp = client.open(
                    case.formatted_path,
                    method=case.method,
                    headers=dict(case.headers) if case.headers else None,
                    query_string=case.query,
                )
                if case.method.upper() == "GET":
                    assert resp.status_code == 200
                    data = resp.get_json()
                    assert data is not None
                    assert data["status"] == "ok"
                    assert data["service"] == "HoneyShield"
                    assert data["storage"] == "sqlite"
                elif case.method.upper() in ("HEAD", "OPTIONS"):
                    # Flask/Werkzeug automatically handles HEAD and OPTIONS on GET routes
                    assert resp.status_code == 200
                else:
                    # Schemathesis negative generation generates unexpected HTTP methods (POST, PUT, DELETE, PATCH)
                    assert resp.status_code == 405
