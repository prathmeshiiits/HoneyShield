"""Audit and verification of the master workflow requirements with a fresh isolated database."""
from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from app import DEMO_PASSWORD, DEMO_USERNAME, create_app


class MasterWorkflowAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
        self.tmp.close()
        self.db_path = self.tmp.name
        self.app = create_app({"DATABASE": self.db_path, "TESTING": True, "HIGH_RISK_THRESHOLD": 50})
        self.client = self.app.test_client()

    def tearDown(self):
        import gc
        gc.collect()
        try:
            Path(self.db_path).unlink(missing_ok=True)
        except OSError:
            pass

    def test_p0_real_user_path_normal_login_and_logout(self):
        """P0 Gate 1: Real user path with clean DB: initial page, valid login, dashboard, logout."""
        # 1. Initial page
        r_init = self.client.get("/")
        self.assertEqual(r_init.status_code, 200)
        self.assertIn(b"Adaptive deception layer", r_init.data)

        # 2. Valid login
        r_login = self.client.post("/login", data={"username": DEMO_USERNAME, "password": DEMO_PASSWORD}, follow_redirects=False)
        self.assertEqual(r_login.status_code, 302)
        self.assertIn("/dashboard", r_login.headers["Location"])

        # 3. User dashboard
        r_dash = self.client.get("/dashboard")
        self.assertEqual(r_dash.status_code, 200)
        self.assertIn(b"Welcome back, <span>demo</span>", r_dash.data)

        # 4. Logout
        r_logout = self.client.get("/logout", follow_redirects=True)
        self.assertEqual(r_logout.status_code, 200)

        # 5. Access revoked
        r_dash_revoked = self.client.get("/dashboard", follow_redirects=False)
        self.assertEqual(r_dash_revoked.status_code, 302)
        self.assertIn(r_dash_revoked.headers["Location"], {"/", "/login"})

    def test_p0_attacker_flow_three_failures_decoy_divert_and_lockdown(self):
        """P0 Gate 2: Attacker fails 3 times, score crosses threshold, session diverted to decoy and locked down."""
        c_att = self.app.test_client()

        # 2 failed attempts
        for i in range(2):
            r = c_att.post("/login", data={"username": "demo", "password": f"GuessPass{i}!"}, follow_redirects=False)
            self.assertEqual(r.status_code, 200)
            self.assertIn(b"Sign-in was not successful", r.data)

        # 3rd failed attempt crosses threshold of 50
        r3 = c_att.post("/login", data={"username": "demo", "password": "GuessPass2!"}, follow_redirects=False)
        self.assertEqual(r3.status_code, 302)
        self.assertIn("/decoy", r3.headers["Location"])

        # Decoy environment renders
        r_decoy = c_att.get("/decoy")
        self.assertEqual(r_decoy.status_code, 200)
        self.assertIn(b"Controlled decoy environment", r_decoy.data)

        # Route lockdown: cannot access /dashboard
        r_dash = c_att.get("/dashboard", follow_redirects=False)
        self.assertEqual(r_dash.status_code, 302)
        self.assertIn("/decoy", r_dash.headers["Location"])

        # Route lockdown: submitting valid credentials diverts to /decoy
        r_sub = c_att.post("/login", data={"username": DEMO_USERNAME, "password": DEMO_PASSWORD}, follow_redirects=False)
        self.assertEqual(r_sub.status_code, 302)
        self.assertIn("/decoy", r_sub.headers["Location"])

    def test_p0_decoy_canaries_and_admin_event_feed(self):
        """P0 Gate 3: Decoy canary object interactions persist to SQLite and appear in admin feed."""
        c_att = self.app.test_client()
        for i in range(3):
            c_att.post("/login", data={"username": "demo", "password": f"Wrong{i}"})

        # Interact with standard decoy records and canaries
        for act in ("open_record", "download_backup", "view_api_key"):
            r_act = c_att.post("/decoy/action", data={"action": act}, follow_redirects=True)
            self.assertEqual(r_act.status_code, 200)

        # Inspect SQLite database directly
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        events = [dict(r) for r in conn.execute("SELECT event_type FROM events").fetchall()]
        types = {r["event_type"] for r in events}
        self.assertIn("decoy_activated", types)
        self.assertIn("decoy_record_opened", types)
        self.assertIn("decoy_canary_backup_downloaded", types)
        self.assertIn("decoy_canary_token_accessed", types)
        conn.close()

        # Check admin control room renders these events
        r_adm = self.client.get("/admin")
        self.assertEqual(r_adm.status_code, 200)
        self.assertIn(b"Decoy active", r_adm.data)
        self.assertIn(b"STORED", r_adm.data)

    def test_p0_session_isolation_independent_browsers(self):
        """P0 Gate 4: Independent sessions remain isolated; attacker risk does not affect normal user."""
        c_att = self.app.test_client()
        c_norm = self.app.test_client()

        # Attacker fails 3 times
        for i in range(3):
            c_att.post("/login", data={"username": "demo", "password": f"Bad{i}"})
        self.assertEqual(c_att.get("/decoy").status_code, 200)

        # Normal user logs in
        r_norm = c_norm.post("/login", data={"username": DEMO_USERNAME, "password": DEMO_PASSWORD}, follow_redirects=False)
        self.assertEqual(r_norm.status_code, 302)
        self.assertIn("/dashboard", r_norm.headers["Location"])

        # Normal user enters legitimate dashboard
        self.assertEqual(c_norm.get("/dashboard").status_code, 200)

    def test_p0_admin_reset_idempotency_and_preservation(self):
        """P0 Gate 5: Reset cleans demo history, does not delete demo user, allows immediate reuse."""
        c_att = self.app.test_client()
        for i in range(3):
            c_att.post("/login", data={"username": "demo", "password": f"Bad{i}"})

        # Reset
        r_rst = self.client.post("/admin/reset", follow_redirects=True)
        self.assertEqual(r_rst.status_code, 200)
        self.assertIn(b"Demo sessions and event history were reset", r_rst.data)

        # Verify DB directly
        conn = sqlite3.connect(self.db_path)
        events_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        sessions_count = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        users_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        self.assertEqual(events_count, 0)
        self.assertEqual(sessions_count, 0)
        self.assertEqual(users_count, 1)
        conn.close()

        # Immediate login succeeds
        r_fresh = self.client.post("/login", data={"username": DEMO_USERNAME, "password": DEMO_PASSWORD}, follow_redirects=True)
        self.assertEqual(r_fresh.status_code, 200)
        self.assertIn(b"Welcome back, <span>demo</span>", r_fresh.data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
