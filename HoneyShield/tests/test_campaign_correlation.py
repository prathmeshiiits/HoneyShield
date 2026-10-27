import json
import sqlite3
import pytest
from app import create_app, connect_database, get_correlated_campaigns, iso_time


@pytest.fixture
def corr_app(tmp_path):
    db_file = tmp_path / "test_corr.sqlite3"
    app = create_app({
        "TESTING": True,
        "DATABASE": str(db_file),
        "SECRET_KEY": "test-secret-key-deterministic-correlation",
        "HIGH_RISK_THRESHOLD": 50,
        "DEMO_MODE": True,
    })
    app.db_path = str(db_file)
    return app


@pytest.fixture
def corr_client(corr_app):
    return corr_app.test_client()


class TestCampaignCorrelation:
    def test_controlled_three_session_correlation(self, corr_app, corr_client):
        """
        Controlled local synthetic dataset:
        - Session A: synthetic suspicious activity with fingerprint 'sim-fingerprint-shared-01'
        - Session B: separate synthetic suspicious activity with same fingerprint 'sim-fingerprint-shared-01'
        - Session C: unrelated synthetic activity with fingerprint 'sim-fingerprint-unrelated-99'

        Expected:
        - Sessions A and B are grouped into a campaign.
        - Session C remains completely separate and is not grouped with A and B.
        - Displayed UI count and API agree.
        - Campaign explanation identifies the shared HMAC fingerprint evidence.
        """
        now = iso_time()
        shared_fp = "sim-fingerprint-shared-01"
        unrelated_fp = "sim-fingerprint-unrelated-99"

        with connect_database(corr_app.db_path) as conn:
            # Insert Session A
            conn.execute(
                """INSERT INTO sessions (session_key, created_at, updated_at, risk_score, risk_band, decoy_active, is_simulated, is_isolated)
                   VALUES ('sim-sess-a', ?, ?, 50, 'HIGH', 1, 1, 0)""",
                (now, now)
            )
            conn.execute(
                """INSERT INTO events (session_key, event_at, event_type, interval_seconds, username_fingerprint, details_json, is_isolated)
                   VALUES ('sim-sess-a', ?, 'login_failed', 1.2, ?, '{"source":"simulator","attempt":1}', 0)""",
                (now, shared_fp)
            )

            # Insert Session B (separate session, shared fingerprint)
            conn.execute(
                """INSERT INTO sessions (session_key, created_at, updated_at, risk_score, risk_band, decoy_active, is_simulated, is_isolated)
                   VALUES ('sim-sess-b', ?, ?, 50, 'HIGH', 1, 1, 0)""",
                (now, now)
            )
            conn.execute(
                """INSERT INTO events (session_key, event_at, event_type, interval_seconds, username_fingerprint, details_json, is_isolated)
                   VALUES ('sim-sess-b', ?, 'login_failed', 1.5, ?, '{"source":"simulator","attempt":1}', 0)""",
                (now, shared_fp)
            )

            # Insert Session C (unrelated session, distinct fingerprint)
            conn.execute(
                """INSERT INTO sessions (session_key, created_at, updated_at, risk_score, risk_band, decoy_active, is_simulated, is_isolated)
                   VALUES ('sim-sess-c', ?, ?, 20, 'LOW', 0, 1, 0)""",
                (now, now)
            )
            conn.execute(
                """INSERT INTO events (session_key, event_at, event_type, interval_seconds, username_fingerprint, details_json, is_isolated)
                   VALUES ('sim-sess-c', ?, 'login_failed', 3.0, ?, '{"source":"simulator","attempt":1}', 0)""",
                (now, unrelated_fp)
            )
            conn.commit()

            # 1. Backend function evaluation
            campaigns = get_correlated_campaigns(conn, include_isolated=False)
            assert len(campaigns) == 1, "Only Sessions A and B sharing the fingerprint must form a campaign"
            camp = campaigns[0]
            assert camp["fingerprint"] == shared_fp
            assert camp["session_count"] == 2
            assert set(camp["session_keys"]) == {"sim-sess-a", "sim-sess-b"}
            assert "sim-sess-c" not in camp["session_keys"], "Unrelated Session C must NOT be grouped"
            assert "Identical HMAC target fingerprint" in camp["confidence"]

        # 2. API verification
        resp = corr_client.get("/api/campaigns")
        assert resp.status_code == 200
        api_data = resp.get_json()
        assert api_data["status"] == "ok"
        assert api_data["campaign_count"] == 1
        assert api_data["correlated_sessions_count"] == 2
        assert len(api_data["campaigns"]) == 1
        assert api_data["campaigns"][0]["fingerprint"] == shared_fp
        assert set(api_data["campaigns"][0]["session_keys"]) == {"sim-sess-a", "sim-sess-b"}

        # 3. UI agreement verification
        ui_resp = corr_client.get("/admin")
        assert ui_resp.status_code == 200
        ui_html = ui_resp.get_data(as_text=True)
        assert "1 ACTIVE CAMPAIGN (2 SESSIONS)" in ui_html
        assert shared_fp[:16] in ui_html
        assert "data-session-key=\"sim-sess-a\"" in ui_html
        assert "data-session-key=\"sim-sess-b\"" in ui_html
        assert "data-session-key=\"sim-sess-c\"" not in ui_html.split("campaign-sessions")[1].split("</section>")[0]

    def test_correlation_idempotency_and_no_duplicate_records(self, corr_app, corr_client):
        """Re-evaluating campaigns or repeating the query does not create duplicate campaign rows or mutate DB."""
        now = iso_time()
        shared_fp = "sim-fingerprint-shared-01"

        with connect_database(corr_app.db_path) as conn:
            for s in ("sess-1", "sess-2"):
                conn.execute("INSERT INTO sessions (session_key, created_at, updated_at) VALUES (?, ?, ?)", (s, now, now))
                conn.execute(
                    "INSERT INTO events (session_key, event_at, event_type, username_fingerprint) VALUES (?, ?, 'login_failed', ?)",
                    (s, now, shared_fp)
                )
            conn.commit()

            c1 = get_correlated_campaigns(conn)
            c2 = get_correlated_campaigns(conn)
            assert c1 == c2
            assert len(c1) == 1

            # Count of events in database is strictly preserved
            ev_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            assert ev_count == 2

    def test_empty_database_produces_empty_state(self, corr_app, corr_client):
        """When no sessions or events exist, the API and UI render an explicit clean zero state."""
        with connect_database(corr_app.db_path) as conn:
            campaigns = get_correlated_campaigns(conn)
            assert campaigns == []

        api_resp = corr_client.get("/api/campaigns")
        assert api_resp.status_code == 200
        data = api_resp.get_json()
        assert data["campaign_count"] == 0
        assert data["correlated_sessions_count"] == 0
        assert data["campaigns"] == []

        ui_resp = corr_client.get("/admin")
        assert ui_resp.status_code == 200
        html = ui_resp.get_data(as_text=True)
        assert "0 CORRELATED" in html
        assert "No multi-session campaigns detected" in html

    def test_credential_sweep_scenario_generates_correlated_campaign(self, corr_app, corr_client):
        """
        Executing the credential_sweep scenario generates coordinated attack sessions targeting shared
        principals (admin@internal.corp, service@internal.corp), successfully creating a correlated campaign.
        """
        with corr_app.app_context():
            res = corr_app.run_demo_scenario("credential_sweep", isolate=False)
            assert res is not None
            assert res["risk_score"] == 50
            assert res["decoy_active"] == 1

        with connect_database(corr_app.db_path) as conn:
            campaigns = get_correlated_campaigns(conn, include_isolated=False)
            assert len(campaigns) >= 1, "Credential sweep must produce correlated campaign across coordinated sessions"
            # At least one campaign must have >= 2 sessions
            assert any(c["session_count"] >= 2 for c in campaigns)

        # Check API reflects the detected campaign
        api_resp = corr_client.get("/api/campaigns")
        assert api_resp.status_code == 200
        data = api_resp.get_json()
        assert data["campaign_count"] >= 1
        assert data["correlated_sessions_count"] >= 2

        # Check UI displays active campaigns badge
        ui_resp = corr_client.get("/admin")
        assert ui_resp.status_code == 200
        html = ui_resp.get_data(as_text=True)
        assert "ACTIVE CAMPAIGN" in html
        assert "0 CORRELATED" not in html
