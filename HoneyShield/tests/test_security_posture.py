"""Security posture and OWASP defensive verification suite."""
from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path

import pytest
from werkzeug.security import check_password_hash

from app import DEMO_PASSWORD, DEMO_USERNAME, create_app


@pytest.fixture
def sec_app():
    """Create isolated test application with temporary database."""
    with tempfile.TemporaryDirectory(prefix="hs-sec-") as tmp:
        db_path = Path(tmp) / "sec.sqlite3"
        app = create_app({
            "TESTING": True,
            "DATABASE": str(db_path),
            "SECRET_KEY": "security-audit-secret-key-2026",
            "HIGH_RISK_THRESHOLD": 50,
        })
        app.db_path = str(db_path)  # type: ignore
        yield app


class TestSecurityPosture:
    """Automated security posture checks aligned with OWASP ZAP controls."""

    def test_security_headers_present_on_all_responses(self, sec_app):
        """Verify presence of key security headers on all endpoints."""
        with sec_app.test_client() as client:
            for path in ["/", "/login", "/admin", "/healthz"]:
                resp = client.get(path)
                headers = resp.headers

                # Anti-MIME sniffing
                assert headers.get("X-Content-Type-Options") == "nosniff", f"Missing nosniff on {path}"
                # Anti-Clickjacking
                assert headers.get("X-Frame-Options") == "SAMEORIGIN", f"Missing X-Frame-Options on {path}"
                # Referrer privacy
                assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin", f"Missing Referrer-Policy on {path}"
                # Content Security Policy
                assert "Content-Security-Policy" in headers, f"Missing CSP on {path}"
                assert "default-src 'self'" in headers["Content-Security-Policy"]

    def test_session_cookie_security_flags(self, sec_app):
        """Verify session cookie includes HttpOnly and SameSite attributes."""
        with sec_app.test_client() as client:
            resp = client.get("/login")
            set_cookie = resp.headers.get("Set-Cookie", "")
            # Flask sets session cookie upon creating current_sid()
            if set_cookie:
                assert "HttpOnly" in set_cookie, "Session cookie missing HttpOnly flag"
                assert "SameSite=Lax" in set_cookie or "SameSite=Strict" in set_cookie, "Session cookie missing SameSite flag"

    def test_passwords_never_stored_in_database_or_events(self, sec_app):
        """Verify plain passwords are never persisted in users, sessions, or events tables."""
        sensitive_password = "SecretSuperConfidentialPassword!999"
        with sec_app.test_client() as client:
            # Attempt login with sensitive password
            client.post("/login", data={"username": "demo", "password": sensitive_password})

            conn = sqlite3.connect(sec_app.db_path)
            conn.row_factory = sqlite3.Row
            try:
                # 1. Users table must have salted scrypt hash, not plaintext
                user_row = conn.execute("SELECT password_hash FROM users WHERE username = ?", (DEMO_USERNAME,)).fetchone()
                assert user_row is not None
                stored_hash = user_row["password_hash"]
                assert stored_hash.startswith("scrypt:"), "Password hash not using modern scrypt algorithm"
                assert sensitive_password not in stored_hash
                assert DEMO_PASSWORD not in stored_hash
                assert check_password_hash(stored_hash, DEMO_PASSWORD)

                # 2. Events table must not contain sensitive_password anywhere
                event_rows = conn.execute("SELECT * FROM events").fetchall()
                for row in event_rows:
                    row_dict = dict(row)
                    for key, val in row_dict.items():
                        assert sensitive_password not in str(val), f"Password leaked in column {key}: {val}"

                # 3. Sessions table must not contain sensitive_password anywhere
                session_rows = conn.execute("SELECT * FROM sessions").fetchall()
                for row in session_rows:
                    row_dict = dict(row)
                    for key, val in row_dict.items():
                        assert sensitive_password not in str(val), f"Password leaked in sessions.{key}"
            finally:
                conn.close()

    def test_username_privacy_via_per_session_hmac(self, sec_app):
        """Verify targeted usernames are fingerprinted with HMAC and not stored in plain text."""
        target_username = "victim_admin_executive@internal.domain"
        with sec_app.test_client() as client:
            client.post("/login", data={"username": target_username, "password": "BadPassword123"})

            conn = sqlite3.connect(sec_app.db_path)
            conn.row_factory = sqlite3.Row
            try:
                events = conn.execute("SELECT event_type, username_fingerprint, details_json FROM events").fetchall()
                assert len(events) >= 1
                for ev in events:
                    assert target_username not in ev["details_json"], "Plain username found in details_json"
                    if ev["username_fingerprint"]:
                        assert target_username not in ev["username_fingerprint"]
                        assert len(ev["username_fingerprint"]) == 24, "Fingerprint not 24-char truncated HMAC"
            finally:
                conn.close()

    def test_output_escaping_prevents_stored_and_reflected_xss(self, sec_app):
        """Malicious script tags in username or filters must be HTML-escaped by Jinja2."""
        xss_payload = '<script>alert("XSS")</script>'
        with sec_app.test_client() as client:
            resp = client.post("/login", data={"username": xss_payload, "password": "bad"})
            body = resp.get_data(as_text=True)
            # The literal unescaped tag must NOT appear in HTML
            assert "<script>alert" not in body

            # Admin filter reflection
            resp_admin = client.get(f"/admin?session={xss_payload}")
            admin_body = resp_admin.get_data(as_text=True)
            assert "<script>alert" not in admin_body

    def test_sql_injection_defense_on_all_filters(self, sec_app):
        """SQL injection payloads in queries must be safely handled via parameterized SQL."""
        sqli_payloads = [
            "' OR '1'='1",
            "admin'; DROP TABLE sessions; --",
            "1 UNION SELECT 1, 2, 3, 4, 5, 6, 7, 8, 9",
        ]
        with sec_app.test_client() as client:
            for payload in sqli_payloads:
                resp = client.get(f"/admin?band={payload}&session={payload}")
                assert resp.status_code == 200

            # Ensure schema and tables are completely intact
            conn = sqlite3.connect(sec_app.db_path)
            try:
                tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
                assert {"users", "sessions", "events"}.issubset(tables)
            finally:
                conn.close()

    def test_session_invalidation_and_access_revocation_on_logout(self, sec_app):
        """Logging out sets authenticated=0 in database and clears session cookie."""
        with sec_app.test_client() as client:
            # 1. Login successfully
            client.post("/login", data={"username": DEMO_USERNAME, "password": DEMO_PASSWORD})
            dash_resp = client.get("/dashboard")
            assert dash_resp.status_code == 200

            # 2. Check authenticated in DB
            conn = sqlite3.connect(sec_app.db_path)
            try:
                row = conn.execute("SELECT authenticated FROM sessions LIMIT 1").fetchone()
                assert row[0] == 1
            finally:
                conn.close()

            # 3. Logout
            client.get("/logout")

            # 4. Check authenticated reset in DB
            conn = sqlite3.connect(sec_app.db_path)
            try:
                row = conn.execute("SELECT authenticated FROM sessions LIMIT 1").fetchone()
                assert row[0] == 0
            finally:
                conn.close()

            # 5. Accessing dashboard is immediately blocked
            dash_after = client.get("/dashboard")
            assert dash_after.status_code == 302
            assert dash_after.headers["Location"].endswith(("/login", "/"))
