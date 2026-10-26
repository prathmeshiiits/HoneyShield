"""Property-based and boundary test suite using Hypothesis and Pytest."""
from __future__ import annotations

import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from app import DEMO_PASSWORD, DEMO_USERNAME, create_app
from risk_engine import DEFAULT_HIGH_RISK_THRESHOLD, band_from_score, score_from_failures


# ---------------------------------------------------------------------------
# 1. Exact Boundary Tests
# ---------------------------------------------------------------------------
class TestRiskBoundaries:
    """Test risk values at exact boundaries: 0, 34, 35, 64, 65, 100, and outside range."""

    @pytest.mark.parametrize(
        "score,threshold,expected_band",
        [
            # Boundary tests at default threshold (50)
            (0, 50, "LOW"),
            (34, 50, "LOW"),
            (35, 50, "ELEVATED"),
            (49, 50, "ELEVATED"),
            (50, 50, "HIGH"),
            (64, 50, "HIGH"),
            (65, 50, "HIGH"),
            (100, 50, "HIGH"),
            # Boundary tests at high threshold (65)
            (0, 65, "LOW"),
            (34, 65, "LOW"),
            (35, 65, "ELEVATED"),
            (64, 65, "ELEVATED"),
            (65, 65, "HIGH"),
            (100, 65, "HIGH"),
            # Boundary tests at threshold = 35
            (34, 35, "LOW"),
            (35, 35, "HIGH"),
            # Boundary tests at threshold = 0
            (0, 0, "HIGH"),
            # Boundary tests at threshold = 100
            (99, 100, "ELEVATED"),
            (100, 100, "HIGH"),
            # Values outside supported range (clamped internally)
            (-1, 50, "LOW"),
            (-100, 50, "LOW"),
            (101, 50, "HIGH"),
            (999, 50, "HIGH"),
        ],
    )
    def test_risk_values_at_boundaries(self, score: int, threshold: int, expected_band: str):
        band = band_from_score(score, threshold=threshold)
        assert band == expected_band, f"Score {score} with threshold {threshold} gave {band}, expected {expected_band}"

    def test_invalid_types_handled_gracefully(self):
        assert band_from_score(None, 50) == "LOW"  # type: ignore
        assert band_from_score("invalid", 50) == "LOW"  # type: ignore
        assert band_from_score(50, None) == "HIGH"  # type: ignore


# ---------------------------------------------------------------------------
# 2. Hypothesis Property-Based Tests: Invariants & Scoring
# ---------------------------------------------------------------------------
event_strategy = st.fixed_dictionaries(
    {
        "event_at": st.one_of(
            st.datetimes(
                min_value=datetime(2026, 1, 1),
                max_value=datetime(2026, 12, 31),
                timezones=st.just(timezone.utc),
            ).map(lambda dt: dt.isoformat(timespec="milliseconds")),
            st.text(min_size=0, max_size=30),  # Potential malformed timestamps
        ),
        "username_fingerprint": st.one_of(
            st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=64),
            st.none(),
        ),
    }
)


class TestHypothesisRiskEngine:
    """Hypothesis property-based tests for risk engine robustness."""

    @given(
        failures=st.lists(event_strategy, max_size=25),
        threshold=st.integers(min_value=-50, max_value=150),
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_score_and_band_invariants(self, failures: list[dict[str, Any]], threshold: int):
        """Invariant: score is always within [0, 100] and band strictly matches score and threshold."""
        score, band, reasons = score_from_failures(failures, threshold=threshold)

        assert 0 <= score <= 100, f"Score {score} outside [0, 100] for input {failures}"
        assert band in {"LOW", "ELEVATED", "HIGH"}, f"Unexpected band {band}"
        assert isinstance(reasons, list)
        assert len(reasons) >= 1
        assert all(isinstance(r, str) for r in reasons)

        # Verify band matches score
        clamped_threshold = max(0, min(100, threshold))
        if score >= clamped_threshold:
            assert band == "HIGH", f"Score {score} >= threshold {threshold} but band was {band}"
        elif score >= 35:
            assert band == "ELEVATED", f"Score {score} >= 35 but band was {band}"
        else:
            assert band == "LOW", f"Score {score} < 35 but band was {band}"

    @given(
        principal=st.text(min_size=1, max_size=32),
        interval=st.floats(min_value=0.1, max_value=15.0),
    )
    @settings(max_examples=50)
    def test_repeated_failures_against_same_principal(self, principal: str, interval: float):
        """Repeated failures on the same principal within 60s should trigger rapid_failures + repeated_principal."""
        base = datetime(2026, 10, 26, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            {
                "event_at": (base + timedelta(seconds=i * interval)).isoformat(timespec="milliseconds"),
                "username_fingerprint": principal,
            }
            for i in range(3)
        ]
        score, band, reasons = score_from_failures(events, threshold=50)
        assert score >= 50
        assert band == "HIGH"
        assert any("Multiple failed logins" in r for r in reasons)
        assert any("Repeated failures against one username fingerprint" in r for r in reasons)

    @given(
        principals=st.sets(st.text(min_size=1, max_size=20), min_size=3, max_size=5),
        interval=st.floats(min_value=0.1, max_value=12.0),
    )
    @settings(max_examples=50)
    def test_credential_stuffing_diversity(self, principals: set[str], interval: float):
        """Distinct principals within 60s should trigger rapid_failures + username_diversity."""
        base = datetime(2026, 10, 26, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            {
                "event_at": (base + timedelta(seconds=i * interval)).isoformat(timespec="milliseconds"),
                "username_fingerprint": p,
            }
            for i, p in enumerate(principals)
        ]
        score, band, reasons = score_from_failures(events, threshold=50)
        assert score >= 50
        assert band == "HIGH"
        assert any("Many distinct username fingerprints" in r for r in reasons)

    @given(
        count=st.integers(min_value=1, max_value=10),
        fingerprint=st.text(max_size=30),
    )
    @settings(max_examples=30)
    def test_duplicate_submissions_identical_timestamps(self, count: int, fingerprint: str):
        """Simultaneous submissions (interval = 0) must not cause ZeroDivisionError or crash."""
        base_str = datetime(2026, 10, 26, 12, 0, 0, tzinfo=timezone.utc).isoformat()
        events = [{"event_at": base_str, "username_fingerprint": fingerprint} for _ in range(count)]
        score, band, _ = score_from_failures(events, threshold=50)
        assert 0 <= score <= 100
        assert band in {"LOW", "ELEVATED", "HIGH"}

    @given(
        offsets=st.lists(st.floats(min_value=0.0, max_value=300.0), min_size=3, max_size=8),
    )
    @settings(max_examples=40)
    def test_out_of_order_timestamps(self, offsets: list[float]):
        """Unordered timestamps should be sorted chronologically without producing negative intervals."""
        base = datetime(2026, 10, 26, 12, 0, 0, tzinfo=timezone.utc)
        # Reverse offsets to create out-of-order sequence
        events = [
            {
                "event_at": (base + timedelta(seconds=off)).isoformat(timespec="milliseconds"),
                "username_fingerprint": f"user-{idx}",
            }
            for idx, off in enumerate(reversed(offsets))
        ]
        score, band, _ = score_from_failures(events, threshold=50)
        assert 0 <= score <= 100
        assert band in {"LOW", "ELEVATED", "HIGH"}

    def test_rolling_window_boundary_exact_60s(self):
        """Span of exactly 60.0s triggers rapid_failures; span of 60.1s does not."""
        base = datetime(2026, 10, 26, 12, 0, 0, tzinfo=timezone.utc)
        # Exactly 60s
        events_60 = [
            {"event_at": base.isoformat(), "username_fingerprint": "a"},
            {"event_at": (base + timedelta(seconds=30)).isoformat(), "username_fingerprint": "b"},
            {"event_at": (base + timedelta(seconds=60)).isoformat(), "username_fingerprint": "c"},
        ]
        score_60, _, reasons_60 = score_from_failures(events_60)
        assert any("Multiple failed logins" in r for r in reasons_60)

        # 60.5s (outside 60s window)
        events_61 = [
            {"event_at": base.isoformat(), "username_fingerprint": "a"},
            {"event_at": (base + timedelta(seconds=30)).isoformat(), "username_fingerprint": "b"},
            {"event_at": (base + timedelta(seconds=60.5)).isoformat(), "username_fingerprint": "c"},
        ]
        score_61, _, reasons_61 = score_from_failures(events_61)
        assert not any("Multiple failed logins" in r for r in reasons_61)


# ---------------------------------------------------------------------------
# 3. Hypothesis Property-Based Tests: HTTP Input Validation & Reset
# ---------------------------------------------------------------------------
class TestHypothesisInputValidation:
    """Hypothesis tests for Flask routes against unexpected, empty, oversized, Unicode inputs."""

    @classmethod
    def setup_class(cls):
        import gc
        cls.temp_dir = tempfile.TemporaryDirectory(prefix="hs-fuzz-")
        cls.db_path = Path(cls.temp_dir.name) / "fuzz.sqlite3"
        cls.app = create_app({"TESTING": True, "DATABASE": str(cls.db_path), "SECRET_KEY": "fuzz-key"})

    @classmethod
    def teardown_class(cls):
        import gc
        gc.collect()
        try:
            cls.temp_dir.cleanup()
        except (PermissionError, OSError):
            pass

    @given(
        username=st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=200),
        password=st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=300),
    )
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_login_input_fuzzing(self, username: str, password: str):
        """Login route handles arbitrary input without 500 error or database corruption."""
        with self.app.test_client() as client:
            resp = client.post("/login", data={"username": username, "password": password})
            # Must either reject with 400 (validation), redirect with 302 (accepted/decoy), or return 200 (re-render)
            assert resp.status_code in {200, 302, 400}, f"Unexpected status {resp.status_code} for input"

            # Check validation boundaries
            cleaned = username.strip()
            if not cleaned or len(cleaned) > 64 or len(password) > 128:
                assert resp.status_code == 400

            # Verify database remains operational
            conn = sqlite3.connect(str(self.db_path))
            try:
                row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
                assert row[0] >= 1  # Demo user intact
            finally:
                conn.close()

    def test_reset_behavior_and_isolation(self):
        """Verify reset clears all events and sessions while preserving demo user idempotently."""
        with tempfile.TemporaryDirectory(prefix="hs-reset-") as tmp:
            db_path = Path(tmp) / "reset.sqlite3"
            test_app = create_app({"TESTING": True, "DATABASE": str(db_path), "SECRET_KEY": "reset-key"})
            with test_app.test_client() as client:
                # 1. Trigger normal and suspicious simulations
                client.post("/admin/simulate/suspicious")
                client.post("/admin/simulate/normal")

                conn = sqlite3.connect(str(db_path))
                try:
                    sess_count = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
                    ev_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                    assert sess_count >= 2
                    assert ev_count >= 5
                finally:
                    conn.close()

                # 2. Reset demo
                reset_resp = client.post("/admin/reset")
                assert reset_resp.status_code == 302

                # 3. Assert zero sessions and events, but demo user preserved
                conn = sqlite3.connect(str(db_path))
                try:
                    assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
                    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
                    assert conn.execute("SELECT COUNT(*) FROM users WHERE username = ?", (DEMO_USERNAME,)).fetchone()[0] == 1
                finally:
                    conn.close()

                # 4. Immediate login after reset works cleanly
                login_resp = client.post("/login", data={"username": DEMO_USERNAME, "password": DEMO_PASSWORD})
                assert login_resp.status_code == 302
                assert login_resp.headers["Location"].endswith("/dashboard")
