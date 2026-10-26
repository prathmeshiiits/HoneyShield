"""Comprehensive validation of judges' real browser inputs and edge cases against the backend."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app import DEMO_PASSWORD, DEMO_USERNAME, create_app


class LiveJudgeInputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
        self.tmp.close()
        self.db_path = self.tmp.name
        self.app = create_app({"DATABASE": self.db_path, "TESTING": True})
        self.client = self.app.test_client()

    def tearDown(self):
        try:
            Path(self.db_path).unlink(missing_ok=True)
        except OSError:
            pass

    def test_judge_normal_login_and_logout_journey(self):
        """Judge types correct credentials: logs in smoothly, accesses dashboard, and logs out."""
        resp = self.client.post(
            "/login",
            data={"username": DEMO_USERNAME, "password": DEMO_PASSWORD},
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Normal session experience", resp.data)

        # Confirm dashboard is directly accessible while authenticated
        dash = self.client.get("/dashboard")
        self.assertEqual(dash.status_code, 200)
        self.assertIn(b"Welcome back", dash.data)

        # Logout revokes authentication
        logout = self.client.get("/logout", follow_redirects=True)
        self.assertEqual(logout.status_code, 200)
        self.assertIn(b"left the demo workspace", logout.data)

        # Subsequent dashboard visit redirects to login
        dash_after = self.client.get("/dashboard", follow_redirects=False)
        self.assertEqual(dash_after.status_code, 302)
        self.assertIn(dash_after.headers["Location"], {"/", "/login"})

    def test_judge_single_typo_does_not_activate_decoy(self):
        """Judge mistypes password once: error message displayed, session remains LOW risk (0)."""
        resp = self.client.post(
            "/login",
            data={"username": DEMO_USERNAME, "password": "WrongPassword123!"},
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Sign-in was not successful", resp.data)

        # Recovery on second attempt works
        recovery = self.client.post(
            "/login",
            data={"username": DEMO_USERNAME, "password": DEMO_PASSWORD},
            follow_redirects=True,
        )
        self.assertEqual(recovery.status_code, 200)
        self.assertIn(b"Normal session experience", recovery.data)

    def test_judge_three_failed_attempts_divert_to_decoy_and_trap(self):
        """Judge tests brute force: 3 consecutive wrong passwords divert session to decoy sandbox."""
        for idx in range(1, 3):
            r = self.client.post("/login", data={"username": "demo", "password": f"BadPass{idx}!"}, follow_redirects=False)
            self.assertEqual(r.status_code, 200)
            self.assertIn(b"Sign-in was not successful", r.data)

        # Attempt 3 crosses threshold
        r3 = self.client.post("/login", data={"username": "demo", "password": "BadPass3!"}, follow_redirects=False)
        self.assertEqual(r3.status_code, 302)
        self.assertIn("/decoy", r3.headers["Location"])

        # Decoy environment renders
        decoy_page = self.client.get("/decoy")
        self.assertEqual(decoy_page.status_code, 200)
        self.assertIn(b"Controlled decoy environment", decoy_page.data)

        # Trapped: cannot access real /dashboard
        dash = self.client.get("/dashboard", follow_redirects=False)
        self.assertEqual(dash.status_code, 302)
        self.assertIn("/decoy", dash.headers["Location"])

        # Trapped: cannot bypass even by submitting valid password now
        bypass = self.client.post("/login", data={"username": DEMO_USERNAME, "password": DEMO_PASSWORD}, follow_redirects=False)
        self.assertEqual(bypass.status_code, 302)
        self.assertIn("/decoy", bypass.headers["Location"])

    def test_judge_canary_and_decoy_interactions(self):
        """Judge interacts with decoy records, backup canary, and API key canary."""
        for idx in range(3):
            self.client.post("/login", data={"username": "demo", "password": f"Wrong{idx}"})

        # Test each decoy action
        for action in ("open_record", "open_report", "admin_resource", "export_report", "download_backup", "view_api_key"):
            resp = self.client.post("/decoy/action", data={"action": action}, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"Synthetic interaction recorded", resp.data)

    def test_judge_credential_spraying_different_usernames(self):
        """Judge tests credential spraying by entering 3 different usernames in rapid succession."""
        for name in ("judge_admin", "judge_root"):
            r = self.client.post("/login", data={"username": name, "password": "BadPassword123!"}, follow_redirects=False)
            self.assertEqual(r.status_code, 200)

        r3 = self.client.post("/login", data={"username": "judge_service", "password": "BadPassword123!"}, follow_redirects=False)
        self.assertEqual(r3.status_code, 302)
        self.assertIn("/decoy", r3.headers["Location"])

    def test_judge_input_validation_and_hostile_payloads(self):
        """Judge enters empty, whitespace, oversized, SQLi, and XSS inputs."""
        # Empty inputs
        r_empty = self.client.post("/login", data={"username": "", "password": ""}, follow_redirects=False)
        self.assertEqual(r_empty.status_code, 400)

        # Whitespace-only username
        r_white = self.client.post("/login", data={"username": "    ", "password": "validPassword"}, follow_redirects=False)
        self.assertEqual(r_white.status_code, 400)

        # Oversized username (>64 chars)
        r_over = self.client.post("/login", data={"username": "U" * 65, "password": "validPassword"}, follow_redirects=False)
        self.assertEqual(r_over.status_code, 400)

        # SQL Injection in username
        c_sqli = self.app.test_client()
        r_sqli = c_sqli.post("/login", data={"username": "' OR '1'='1' --", "password": "foo"}, follow_redirects=False)
        self.assertEqual(r_sqli.status_code, 200)
        self.assertIn(b"Sign-in was not successful", r_sqli.data)

        # XSS in username
        c_xss = self.app.test_client()
        r_xss = c_xss.post("/login", data={"username": "<script>alert(1)</script>", "password": "foo"}, follow_redirects=True)
        self.assertEqual(r_xss.status_code, 200)
        self.assertNotIn(b"<script>alert(1)</script>", r_xss.data)

        # Unicode username
        c_uni = self.app.test_client()
        r_uni = c_uni.post("/login", data={"username": "тест_юзер", "password": "тест_пароль_2026!"}, follow_redirects=False)
        self.assertEqual(r_uni.status_code, 200)
        self.assertIn(b"Sign-in was not successful", r_uni.data)

        # Password with complex symbols
        c_sym = self.app.test_client()
        r_sym = c_sym.post("/login", data={"username": "demo", "password": "!@#$%^&*()_+-=[]{}|;:,.<>?/"}, follow_redirects=False)
        self.assertEqual(r_sym.status_code, 200)
        self.assertIn(b"Sign-in was not successful", r_sym.data)

    def test_judge_session_isolation_independent_browsers(self):
        """Two independent judges/browsers: attacker session does not pollute normal user session."""
        c_attacker = self.app.test_client()
        c_normal = self.app.test_client()

        # Attacker fails 3 times and is diverted to decoy
        for idx in range(3):
            c_attacker.post("/login", data={"username": "demo", "password": f"Attack{idx}"})
        r_decoy = c_attacker.get("/decoy")
        self.assertEqual(r_decoy.status_code, 200)

        # Normal user enters correct credentials in their own session
        r_normal = c_normal.post(
            "/login",
            data={"username": DEMO_USERNAME, "password": DEMO_PASSWORD},
            follow_redirects=True,
        )
        self.assertEqual(r_normal.status_code, 200)
        self.assertIn(b"Normal session experience", r_normal.data)
        # Normal user goes to real dashboard, NOT decoy
        self.assertEqual(c_normal.get("/dashboard").status_code, 200)

    def test_judge_threshold_65_boundary_below_at_and_above(self):
        """When configured with threshold 65: test below (50), at (65), and above (80) without score inflation."""
        tmp = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
        tmp.close()
        app65 = create_app({
            "DATABASE": tmp.name,
            "TESTING": True,
            "HIGH_RISK_THRESHOLD": 65,
            "REPEATED_FAILURES_POLICY_LIMIT": 0,  # Pure risk engine evaluation
        })
        client = app65.test_client()

        # Attempts 1 and 2: Low risk (score 0 < 65)
        for i in range(2):
            r = client.post("/login", data={"username": "demo", "password": f"Bad{i}"}, follow_redirects=False)
            self.assertEqual(r.status_code, 200)

        # Attempt 3: Rapid + Repeated principal = 50 (below 65). Stays on login page.
        r3 = client.post("/login", data={"username": "demo", "password": "Bad2"}, follow_redirects=False)
        self.assertEqual(r3.status_code, 200)
        self.assertIn(b"Sign-in was not successful", r3.data)

        # Attempt 4: Sustained failures (+15) reaches 65 (AT threshold 65). Diverts to decoy!
        r4 = client.post("/login", data={"username": "demo", "password": "Bad3"}, follow_redirects=False)
        self.assertEqual(r4.status_code, 302)
        self.assertIn("/decoy", r4.headers["Location"])

        # Attempt 5: Persistent volume (+15) reaches 80 (ABOVE threshold 65). Stays diverted!
        r5 = client.post("/login", data={"username": "demo", "password": "Bad4"}, follow_redirects=False)
        self.assertEqual(r5.status_code, 302)
        self.assertIn("/decoy", r5.headers["Location"])

        import gc
        gc.collect()
        try:
            Path(tmp.name).unlink(missing_ok=True)
        except OSError:
            pass

    def test_judge_direct_decoy_access_without_activation_redirects_to_login(self):
        """Direct access to /decoy without authorized decoy activation must redirect to /login."""
        fresh_client = self.app.test_client()
        r = fresh_client.get("/decoy", follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn(r.headers["Location"], {"/", "/login"})

        # Decoy action also rejected with 403 Forbidden
        r_act = fresh_client.post("/decoy/action", data={"action": "open_record"})
        self.assertEqual(r_act.status_code, 403)

    def test_judge_assessment_engine_contract(self):
        """Validate authoritative assess_risk logic and output dictionary contract."""
        from risk_engine import assess_risk
        # Empty failures
        res_empty = assess_risk([])
        self.assertEqual(res_empty["score"], 0)
        self.assertEqual(res_empty["band"], "LOW")
        self.assertEqual(res_empty["decision"], "normal")
        self.assertFalse(res_empty["activate_decoy"])
        self.assertEqual(res_empty["engine_version"], "2.0.0")

        # 3 failures against same principal
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        three_failures = [
            {"event_at": now, "username_fingerprint": "abc123456789"},
            {"event_at": now, "username_fingerprint": "abc123456789"},
            {"event_at": now, "username_fingerprint": "abc123456789"},
        ]
        res_three = assess_risk(three_failures, threshold=50)
        self.assertEqual(res_three["score"], 50)
        self.assertEqual(res_three["band"], "HIGH")
        self.assertEqual(res_three["decision"], "decoy")
        self.assertTrue(res_three["activate_decoy"])

        # Under threshold 65, 3 failures is elevated
        res_three_65 = assess_risk(three_failures, threshold=65)
        self.assertEqual(res_three_65["score"], 50)
        self.assertEqual(res_three_65["band"], "ELEVATED")
        self.assertEqual(res_three_65["decision"], "recovery")
        self.assertFalse(res_three_65["activate_decoy"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

