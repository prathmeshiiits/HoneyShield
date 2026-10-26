"""
Unit and integration tests for HoneyShield Chart Rendering and Data-Wiring Repair.
Verifies time-series buckets, continuous series, loading/empty states, and simulation distinction.
"""
import json
import sqlite3
import pytest
from app import create_app, connect_database, DEFAULT_HIGH_RISK_THRESHOLD, DEMO_PASSWORD


@pytest.fixture
def chart_client(tmp_path):
    """Provides an isolated Flask test client with a clean temporary SQLite database."""
    db_file = tmp_path / "test_chart_wiring.sqlite3"
    app = create_app({
        "TESTING": True,
        "DATABASE": str(db_file),
        "SECRET_KEY": "test-chart-wiring-secret-2026",
        "HIGH_RISK_THRESHOLD": 50,
        "DEMO_MODE": True,
    })
    with app.test_client() as client:
        yield client


class TestChartAttemptsDataWiring:
    """Validates /api/chart/attempts data contracts and telemetry calculations."""

    def test_chart_attempts_empty_database(self, chart_client):
        """When database contains no login attempts, API returns clean empty state."""
        resp = chart_client.get("/api/chart/attempts")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert data["empty"] is True
        assert data["buckets"] == []
        assert data["total_attempts"] == 0
        assert data["total_failed"] == 0
        assert data["total_success"] == 0

    def test_chart_attempts_populated_series(self, chart_client):
        """Failed and successful logins generate populated chronological buckets with exact counts."""
        # 1. Failed login (before authentication)
        chart_client.post("/login", data={"username": "demo", "password": "WrongPassword!"})
        # 2. Successful login
        chart_client.post("/login", data={"username": "demo", "password": DEMO_PASSWORD})

        resp = chart_client.get("/api/chart/attempts?window=3600")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert data["empty"] is False
        assert len(data["buckets"]) >= 1
        assert data["total_attempts"] == 2
        assert data["total_failed"] == 1
        assert data["total_success"] == 1

        b0 = data["buckets"][0]
        assert "bucket" in b0
        assert "failed" in b0
        assert "success" in b0
        assert "browser_failed" in b0
        assert "browser_success" in b0
        assert "simulated_failed" in b0
        assert "simulated_success" in b0
        assert "total" in b0

        # Since these were entered via /login, they must be browser attempts
        assert b0["browser_failed"] == 1
        assert b0["browser_success"] == 1
        assert b0["simulated_failed"] == 0
        assert b0["simulated_success"] == 0

    def test_chart_attempts_distinguishes_simulated_from_browser(self, chart_client):
        """Browser logins and simulated scenario events are partitioned into distinguishable counters."""
        # Browser login failure
        chart_client.post("/login", data={"username": "demo", "password": "BadPassword"})

        # Simulated suspicious scenario (creates 5 failed attempts with is_simulated=1)
        chart_client.post("/admin/simulate/suspicious")

        resp = chart_client.get("/api/chart/attempts?window=3600")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total_failed"] == 6

        # Check total browser vs simulated failed counts across all buckets
        total_browser_failed = sum(b["browser_failed"] for b in data["buckets"])
        total_simulated_failed = sum(b["simulated_failed"] for b in data["buckets"])
        assert total_browser_failed == 1
        assert total_simulated_failed == 5

    def test_chart_attempts_window_parameter_and_clamping(self, chart_client):
        """Time windows are validated, clamped between 60 and 86400, and filter events accordingly."""
        # Test negative or zero window is clamped to 60
        r_neg = chart_client.get("/api/chart/attempts?window=-500")
        assert r_neg.status_code == 200
        assert r_neg.get_json()["window_seconds"] == 60

        # Test oversized window is clamped to 86400
        r_large = chart_client.get("/api/chart/attempts?window=999999")
        assert r_large.status_code == 200
        assert r_large.get_json()["window_seconds"] == 86400

        # Test invalid string window defaults safely to 3600
        r_str = chart_client.get("/api/chart/attempts?window=invalid")
        assert r_str.status_code == 200
        assert r_str.get_json()["window_seconds"] == 3600


class TestRiskDistributionDataWiring:
    """Validates observed risk distribution calculations and empty states."""

    def test_risk_distribution_zero_state(self, chart_client):
        """Clean database returns 0 sessions across all risk bands."""
        resp = chart_client.get("/api/metrics")
        assert resp.status_code == 200
        data = resp.get_json()
        dist = data["risk_distribution"]
        assert dist["LOW"] == 0
        assert dist["ELEVATED"] == 0
        assert dist["HIGH"] == 0
        assert data["summary"]["sessions"] == 0

    def test_risk_distribution_multiple_bands(self, chart_client):
        """Simulating scenarios populates LOW, ELEVATED, and HIGH session buckets accurately."""
        # 1. Normal user (LOW)
        chart_client.post("/admin/simulate/normal")
        # 2. Suspicious user (HIGH, score 50 >= threshold 50)
        chart_client.post("/admin/simulate/suspicious")

        resp = chart_client.get("/api/metrics")
        assert resp.status_code == 200
        data = resp.get_json()
        dist = data["risk_distribution"]
        assert dist["LOW"] == 1
        assert dist["HIGH"] == 1
        assert data["summary"]["sessions"] == 2
        assert data["summary"]["low_sessions"] == 1
        assert data["summary"]["high_sessions"] == 1


class TestAdminDashboardVisualizationElements:
    """Validates that /admin HTML contains all required DOM containers, states, and controls."""

    def test_admin_dashboard_dom_chart_elements_present(self, chart_client):
        """Admin dashboard template renders all required SVG, loading, error, and empty elements."""
        resp = chart_client.get("/admin")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)

        # Primary Chart Elements
        assert 'id="attemptsChartCard"' in html
        assert 'id="attemptsChartContainer"' in html
        assert 'id="attemptsSvgChart"' in html
        assert 'id="attemptsChartLoading"' in html
        assert 'id="attemptsChartEmpty"' in html
        assert 'id="attemptsChartError"' in html
        assert 'id="attemptsChartRetryBtn"' in html
        assert 'id="attemptsChartTooltip"' in html

        # Default Active Window Pill
        assert 'data-window="3600"' in html
        assert 'class="chart-pill active" data-window="3600"' in html

        # Risk Distribution Elements
        assert 'id="riskDistributionCard"' in html
        assert 'id="riskStackedBar"' in html
        assert 'id="distSegmentLow"' in html
        assert 'id="distSegmentElevated"' in html
        assert 'id="distSegmentHigh"' in html
        assert 'id="distEmptyMsg"' in html
        assert 'id="distCountLow"' in html
        assert 'id="distCountElevated"' in html
        assert 'id="distCountHigh"' in html
        assert 'id="distPctLow"' in html
        assert 'id="distPctElevated"' in html
        assert 'id="distPctHigh"' in html
