"""
Unit and integration tests for Scenario Lab, Deterministic Benchmark, and What-If Analyzer (Prompt 06).
"""
import json
import sqlite3
import pytest
from app import create_app, SCENARIO_DEFINITIONS


@pytest.fixture
def lab_client(tmp_path):
    """Provides an isolated Flask test client with a clean temporary SQLite database."""
    db_file = tmp_path / "test_scenario_lab.sqlite3"
    app = create_app({
        "TESTING": True,
        "DATABASE": str(db_file),
        "SECRET_KEY": "test-scenario-lab-secret-2026",
        "HIGH_RISK_THRESHOLD": 50,
        "DEMO_MODE": True,
    })
    with app.test_client() as client:
        yield client


class TestScenarioLabDeterministicExecution:
    """Validates deterministic execution of all 6 canonical scenarios."""

    def test_normal_user_scenario(self, lab_client):
        """Normal user: single successful login, score 0, no decoy."""
        resp = lab_client.post("/lab/simulate/normal_user", data={"add_to_demo_activity": "0"}, follow_redirects=True)
        assert resp.status_code == 200
        html = resp.data.decode("utf-8")
        assert "Normal Successful User" in html
        assert "NOT ACTIVATED" in html

        # Verify in database
        app = lab_client.application
        from app import connect_database
        with connect_database(app.config["DATABASE"]) as conn:
            row = conn.execute("SELECT * FROM sessions WHERE scenario = 'normal_user'").fetchone()
            assert row is not None
            assert row["risk_score"] == 0
            assert row["risk_band"] == "LOW"
            assert row["decoy_active"] == 0
            assert row["is_simulated"] == 1
            assert row["is_isolated"] == 1

            events = conn.execute("SELECT * FROM events WHERE session_key = ?", (row["session_key"],)).fetchall()
            assert len(events) == 1
            assert events[0]["event_type"] == "login_success"
            assert events[0]["is_isolated"] == 1

    def test_forgetful_user_scenario(self, lab_client):
        """Forgetful user: 1 typo, 20s pause, valid login -> score 0 (LOW), no decoy."""
        resp = lab_client.post("/lab/simulate/forgetful_user", data={"add_to_demo_activity": "0"}, follow_redirects=True)
        assert resp.status_code == 200

        app = lab_client.application
        from app import connect_database
        with connect_database(app.config["DATABASE"]) as conn:
            row = conn.execute("SELECT * FROM sessions WHERE scenario = 'forgetful_user'").fetchone()
            assert row is not None
            assert row["risk_score"] == 0
            assert row["risk_band"] == "LOW"
            assert row["decoy_active"] == 0
            assert row["is_simulated"] == 1

            events = conn.execute("SELECT event_type FROM events WHERE session_key = ? ORDER BY id ASC", (row["session_key"],)).fetchall()
            types = [e["event_type"] for e in events]
            assert types == ["login_failed", "login_success"]

    def test_rapid_failures_scenario(self, lab_client):
        """Rapid failures: 3 rapid attempts against single principal -> Score 50 (HIGH), decoy activated."""
        resp = lab_client.post("/lab/simulate/rapid_failures", data={"add_to_demo_activity": "0"}, follow_redirects=True)
        assert resp.status_code == 200
        html = resp.data.decode("utf-8")
        assert "ACTIVATED" in html

        app = lab_client.application
        from app import connect_database
        with connect_database(app.config["DATABASE"]) as conn:
            row = conn.execute("SELECT * FROM sessions WHERE scenario = 'rapid_failures'").fetchone()
            assert row is not None
            assert row["risk_score"] == 50
            assert row["risk_band"] == "HIGH"
            assert row["decoy_active"] == 1
            assert row["is_simulated"] == 1

            # Synthetic decoy actions recorded
            decoy_events = conn.execute("SELECT * FROM events WHERE session_key = ? AND event_type LIKE 'decoy_%'", (row["session_key"],)).fetchall()
            assert len(decoy_events) >= 1

    def test_regular_cadence_scenario(self, lab_client):
        """Regular cadence: 4 periodic attempts at 2.0s -> Score 85 (HIGH), decoy activated."""
        resp = lab_client.post("/lab/simulate/regular_cadence", data={"add_to_demo_activity": "0"}, follow_redirects=True)
        assert resp.status_code == 200

        app = lab_client.application
        from app import connect_database
        with connect_database(app.config["DATABASE"]) as conn:
            row = conn.execute("SELECT * FROM sessions WHERE scenario = 'regular_cadence'").fetchone()
            assert row is not None
            assert row["risk_score"] == 85
            assert row["risk_band"] == "HIGH"
            assert row["decoy_active"] == 1

    def test_credential_sweep_scenario(self, lab_client):
        """Credential sweep: 4 distinct accounts -> Score 50 (HIGH), decoy activated."""
        resp = lab_client.post("/lab/simulate/credential_sweep", data={"add_to_demo_activity": "0"}, follow_redirects=True)
        assert resp.status_code == 200

        app = lab_client.application
        from app import connect_database
        with connect_database(app.config["DATABASE"]) as conn:
            row = conn.execute("SELECT * FROM sessions WHERE scenario = 'credential_sweep'").fetchone()
            assert row is not None
            assert row["risk_score"] == 50
            assert row["risk_band"] == "HIGH"
            assert row["decoy_active"] == 1

    def test_boundary_scenarios_below_at_and_above(self, lab_client):
        """Boundary test: 2 attempts (score 0), 3 attempts (score 50 = threshold), 4 attempts (score 65 > threshold)."""
        app = lab_client.application
        from app import connect_database

        # 1. Immediately below threshold: 2 attempts
        lab_client.post("/lab/simulate/boundary_below", data={"add_to_demo_activity": "0"})
        with connect_database(app.config["DATABASE"]) as conn:
            row_below = conn.execute("SELECT * FROM sessions WHERE scenario = 'boundary_below'").fetchone()
            assert row_below["risk_score"] == 0
            assert row_below["decoy_active"] == 0

        # 2. Exactly at threshold: 3 attempts
        lab_client.post("/lab/simulate/boundary_at", data={"add_to_demo_activity": "0"})
        with connect_database(app.config["DATABASE"]) as conn:
            row_at = conn.execute("SELECT * FROM sessions WHERE scenario = 'boundary_at'").fetchone()
            assert row_at["risk_score"] == 50
            assert row_at["decoy_active"] == 1

        # 3. Immediately above threshold: 4 attempts
        lab_client.post("/lab/simulate/boundary_above", data={"add_to_demo_activity": "0"})
        with connect_database(app.config["DATABASE"]) as conn:
            row_above = conn.execute("SELECT * FROM sessions WHERE scenario = 'boundary_above'").fetchone()
            assert row_above["risk_score"] == 65
            assert row_above["decoy_active"] == 1


class TestScenarioLabIsolationAndSafety:
    """Validates lab isolation prevents contamination of live judge activity."""

    def test_isolated_run_does_not_contaminate_control_room(self, lab_client):
        """An isolated scenario run does not show up in the main admin dashboard or metrics."""
        # Clean state check
        resp_admin_before = lab_client.get("/admin")
        assert b"Total sessions" in resp_admin_before.data

        # Run isolated scenario
        lab_client.post("/lab/simulate/rapid_failures", data={"add_to_demo_activity": "0"})

        # Control Room query should not display the isolated session
        resp_admin = lab_client.get("/admin")
        assert b"iso-rapid_fail" not in resp_admin.data

        # Metrics API should show 0 sessions for live control room
        resp_metrics = lab_client.get("/api/metrics")
        data_metrics = json.loads(resp_metrics.data.decode("utf-8"))
        assert data_metrics["summary"]["sessions"] == 0
        assert data_metrics["summary"]["failed_attempts"] == 0

    def test_add_to_demo_activity_option_reflects_in_control_room(self, lab_client):
        """When explicit 'Add to Control Room activity' is checked, it appears in Control Room with SIMULATED badge."""
        lab_client.post("/lab/simulate/rapid_failures", data={"add_to_demo_activity": "1"})

        # Appears in Control Room
        resp_admin = lab_client.get("/admin")
        assert b"sim-rapid_fail" in resp_admin.data
        assert b"SIMULATED" in resp_admin.data

        # Metrics count increments
        resp_metrics = lab_client.get("/api/metrics")
        data_metrics = json.loads(resp_metrics.data.decode("utf-8"))
        assert data_metrics["summary"]["sessions"] == 1
        assert data_metrics["summary"]["failed_attempts"] == 3

    def test_reset_lab_clears_isolated_runs_only(self, lab_client):
        """Reset lab runs clears only is_isolated=1 sessions, preserving demo activity."""
        # 1. Add demo session
        lab_client.post("/lab/simulate/normal_user", data={"add_to_demo_activity": "1"})
        # 2. Add isolated lab session
        lab_client.post("/lab/simulate/rapid_failures", data={"add_to_demo_activity": "0"})

        app = lab_client.application
        from app import connect_database
        with connect_database(app.config["DATABASE"]) as conn:
            assert conn.execute("SELECT COUNT(*) FROM sessions WHERE is_isolated = 0").fetchone()[0] == 1
            assert conn.execute("SELECT COUNT(*) FROM sessions WHERE is_isolated = 1").fetchone()[0] == 1

        # 3. Call reset_lab
        r_reset = lab_client.post("/lab/reset", follow_redirects=True)
        assert r_reset.status_code == 200

        with connect_database(app.config["DATABASE"]) as conn:
            # Isolated sessions deleted
            assert conn.execute("SELECT COUNT(*) FROM sessions WHERE is_isolated = 1").fetchone()[0] == 0
            # Demo session preserved!
            assert conn.execute("SELECT COUNT(*) FROM sessions WHERE is_isolated = 0").fetchone()[0] == 1


class TestDeterministicBenchmarkSuite:
    """Validates the benchmark evaluation calculations and honest metrics reporting."""

    def test_benchmark_suite_computes_exact_confusion_counts(self, lab_client):
        """Running the full benchmark suite evaluates all 8 cases and produces honest TP/TN/FP/FN."""
        resp = lab_client.post("/lab/benchmark", follow_redirects=True)
        assert resp.status_code == 200
        html = resp.data.decode("utf-8")

        assert "Sample Size (N)" in html
        assert "True Positives (TP)" in html
        assert "True Negatives (TN)" in html
        assert "Containment Rate (TPR)" in html
        assert "False Positive Rate (FPR)" in html
        assert "Benchmark Methodology &amp; Evaluation Transparency" in html

        # Verify all 8 test cases evaluated
        for sc_name in ["normal_user", "forgetful_user", "boundary_below", "boundary_at", "boundary_above", "rapid_failures", "regular_cadence", "credential_sweep"]:
            assert sc_name in html

    def test_benchmark_accuracy_and_definitions(self, lab_client):
        """Directly call run_scenario_benchmark_suite to verify mathematical formula correctness."""
        from app import run_demo_scenario
        app = lab_client.application
        with app.app_context():
            # Run benchmark under active threshold 50
            suite = app.view_functions["run_benchmark"]
            # Or run directly via client
            resp = lab_client.post("/lab/benchmark")
            assert resp.status_code == 302

            with lab_client.session_transaction() as sess:
                bm = sess.get("latest_benchmark")
                assert bm is not None
                assert bm["total_cases"] == 8
                assert bm["true_positives"] == 5
                assert bm["true_negatives"] == 3
                assert bm["false_positives"] == 0
                assert bm["false_negatives"] == 0
                assert bm["containment_rate"] == 100.0
                assert bm["false_positive_rate"] == 0.0
                assert bm["all_passed"] is True


class TestWhatIfPolicyThresholdAnalyzer:
    """Validates that What-If analysis evaluates a copy without mutating state."""

    def test_whatif_analysis_evaluates_copy_without_database_mutation(self, lab_client):
        """What-If threshold adjustment re-scores evidence on a copy without altering database or active config."""
        # 1. Create a rapid failures session (score 50, contained at threshold 50)
        lab_client.post("/lab/simulate/rapid_failures", data={"add_to_demo_activity": "0"})

        app = lab_client.application
        from app import connect_database
        with connect_database(app.config["DATABASE"]) as conn:
            sess_row = conn.execute("SELECT * FROM sessions WHERE scenario = 'rapid_failures'").fetchone()
            sid = sess_row["session_key"]
            orig_score = sess_row["risk_score"]
            orig_band = sess_row["risk_band"]
            orig_decoy = sess_row["decoy_active"]
            assert orig_score == 50
            assert orig_decoy == 1

        # 2. Test candidate threshold of 70 (higher than 50)
        # Under threshold 70, score 50 is ELEVATED, not HIGH -> verdict changed to ALLOW
        resp_70 = lab_client.post("/api/lab/whatif", json={"session_key": sid, "threshold": 70})
        assert resp_70.status_code == 200
        data_70 = resp_70.json

        assert data_70["active_threshold"] == 50
        assert data_70["active_decision"] == "CONTAIN"
        assert data_70["whatif_threshold"] == 70
        assert data_70["whatif_decision"] == "ALLOW"
        assert data_70["verdict_changed"] is True
        assert data_70["is_copy_evaluation"] is True
        assert data_70["database_mutated"] is False
        assert "would NOT have been contained" in data_70["impact_analysis"]

        # 3. Verify SQLite database row was completely unmutated
        with connect_database(app.config["DATABASE"]) as conn:
            after_row = conn.execute("SELECT * FROM sessions WHERE session_key = ?", (sid,)).fetchone()
            assert after_row["risk_score"] == orig_score
            assert after_row["risk_band"] == orig_band
            assert after_row["decoy_active"] == orig_decoy
            assert app.config["HIGH_RISK_THRESHOLD"] == 50

    def test_whatif_analysis_on_benign_session_with_low_threshold(self, lab_client):
        """Testing a lower candidate threshold (35) on a single typo session confirms score 0 remains ALLOW."""
        lab_client.post("/lab/simulate/forgetful_user", data={"add_to_demo_activity": "0"})
        app = lab_client.application
        from app import connect_database
        with connect_database(app.config["DATABASE"]) as conn:
            sess_row = conn.execute("SELECT * FROM sessions WHERE scenario = 'forgetful_user'").fetchone()
            sid = sess_row["session_key"]

        resp_35 = lab_client.post("/api/lab/whatif", json={"session_key": sid, "threshold": 35})
        assert resp_35.status_code == 200
        data_35 = resp_35.json
        assert data_35["whatif_score"] == 0
        assert data_35["whatif_decision"] == "ALLOW"
        assert data_35["database_mutated"] is False

    def test_whatif_threshold_boundaries_and_consistency(self, lab_client):
        """Validates that candidate threshold = active threshold preserves score and decision,
        and tests below, equal, and above score boundary semantics."""
        lab_client.post("/lab/simulate/regular_cadence", data={"add_to_demo_activity": "0"})
        app = lab_client.application
        from app import connect_database
        with connect_database(app.config["DATABASE"]) as conn:
            sess_row = conn.execute("SELECT * FROM sessions WHERE scenario = 'regular_cadence'").fetchone()
            sid = sess_row["session_key"]
            score = sess_row["risk_score"]
            assert score >= 70

        # Boundary 1: Candidate threshold EQUAL to active threshold (50)
        # MUST preserve score and CONTAIN decision - cannot drop score to 0 or flip to ALLOW!
        resp_equal_active = lab_client.post("/api/lab/whatif", json={"session_key": sid, "threshold": 50})
        assert resp_equal_active.status_code == 200
        d_eq_active = resp_equal_active.json
        assert d_eq_active["active_score"] == score
        assert d_eq_active["active_decision"] == "CONTAIN"
        assert d_eq_active["whatif_score"] == score
        assert d_eq_active["whatif_decision"] == "CONTAIN"
        assert d_eq_active["whatif_band"] == "HIGH"
        assert d_eq_active["verdict_changed"] is False

        # Boundary 2: Candidate threshold BELOW score (40) -> CONTAIN
        resp_below = lab_client.post("/api/lab/whatif", json={"session_key": sid, "threshold": 40})
        assert resp_below.status_code == 200
        d_below = resp_below.json
        assert d_below["whatif_score"] == score
        assert d_below["whatif_decision"] == "CONTAIN"
        assert d_below["whatif_band"] == "HIGH"

        # Boundary 3: Candidate threshold EQUAL to score -> CONTAIN
        resp_equal_score = lab_client.post("/api/lab/whatif", json={"session_key": sid, "threshold": score})
        assert resp_equal_score.status_code == 200
        d_equal = resp_equal_score.json
        assert d_equal["whatif_score"] == score
        assert d_equal["whatif_decision"] == "CONTAIN"
        assert d_equal["whatif_band"] == "HIGH"

        # Boundary 4: Candidate threshold ABOVE score (score + 10) -> ALLOW
        thresh_above = min(100, score + 10)
        resp_above = lab_client.post("/api/lab/whatif", json={"session_key": sid, "threshold": thresh_above})
        assert resp_above.status_code == 200
        d_above = resp_above.json
        assert d_above["whatif_score"] == score
        assert d_above["whatif_decision"] == "ALLOW"
        assert d_above["whatif_band"] == "ELEVATED"
        assert d_above["verdict_changed"] is True


class TestScenarioLabSecurityControls:
    """Validates simulator routes security and demo mode restrictions."""

    def test_simulator_disabled_outside_demo_mode(self, tmp_path):
        """Outside demo mode (DEMO_MODE=False), all simulator routes return 403."""
        db_file = tmp_path / "test_no_demo.sqlite3"
        app = create_app({
            "TESTING": True,
            "DATABASE": str(db_file),
            "SECRET_KEY": "test-sec-secret",
            "DEMO_MODE": False,
        })
        with app.test_client() as client:
            r_lab = client.get("/lab")
            assert r_lab.status_code == 403

            r_sim = client.post("/lab/simulate/rapid_failures")
            assert r_sim.status_code == 403

            r_bench = client.post("/lab/benchmark")
            assert r_bench.status_code == 403

            r_whatif = client.post("/api/lab/whatif", json={"threshold": 60})
            assert r_whatif.status_code == 403
