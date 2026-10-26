import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

try:
    from app import DEMO_PASSWORD, DEMO_USERNAME, create_app
except ModuleNotFoundError as import_error:
    if import_error.name == "flask":
        raise unittest.SkipTest("Flask integration tests require installing requirements.txt; Flask is unavailable in this offline validation environment.")
    raise


class HoneyShieldAppTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="honeyshield-test-")
        self.db_path = Path(self.temp_dir.name) / "test.sqlite3"
        self.app = create_app({"TESTING": True, "DATABASE": str(self.db_path), "SECRET_KEY": "test-only-key"})
        self.client = self.app.test_client()

    def tearDown(self):
        import gc
        gc.collect()
        try:
            self.temp_dir.cleanup()
        except (PermissionError, OSError):
            pass

    def rows(self, sql, args=()):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            return conn.execute(sql, args).fetchall()
        finally:
            conn.close()

    def test_health_and_local_assets(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ok")
        for path, content_type in (
            ("/static/css/style.css", "text/css"),
            ("/static/js/app.js", "javascript"),
        ):
            asset = self.client.get(path)
            self.assertEqual(asset.status_code, 200)
            self.assertIn(content_type, asset.content_type)
            self.assertGreater(len(asset.data), 100)

    def test_normal_login_and_workspace(self):
        response = self.client.post(
            "/login", data={"username": DEMO_USERNAME, "password": DEMO_PASSWORD}, follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Normal session experience", response.data)
        self.assertIn(b"Recent workspace activity", response.data)
        events = self.rows("SELECT event_type, details_json FROM events")
        self.assertTrue(any(row["event_type"] == "login_success" for row in events))
        self.assertEqual(self.rows("SELECT authenticated FROM sessions")[0]["authenticated"], 1)
        user = self.rows("SELECT password_hash FROM users WHERE username = ?", (DEMO_USERNAME,))[0]
        self.assertNotEqual(user["password_hash"], DEMO_PASSWORD)
        self.assertTrue(user["password_hash"].startswith("scrypt:"))

    def test_three_failed_attempts_activate_decoy_and_redirect(self):
        # 1st failure: low risk
        resp1 = self.client.post("/login", data={"username": "demo", "password": "BadPassword1!"}, follow_redirects=False)
        self.assertEqual(resp1.status_code, 200)
        self.assertIn(b"Sign-in was not successful", resp1.data)
        state1 = self.rows("SELECT risk_score, risk_band, decoy_active FROM sessions")[0]
        self.assertEqual(state1["risk_score"], 0)
        self.assertEqual(state1["decoy_active"], 0)

        # 2nd failure: still low risk
        resp2 = self.client.post("/login", data={"username": "demo", "password": "BadPassword2!"}, follow_redirects=False)
        self.assertEqual(resp2.status_code, 200)
        self.assertIn(b"Sign-in was not successful", resp2.data)
        state2 = self.rows("SELECT risk_score, risk_band, decoy_active FROM sessions")[0]
        self.assertEqual(state2["risk_score"], 0)
        self.assertEqual(state2["decoy_active"], 0)

        # 3rd failure: crosses threshold of 50, flags decoy_active and redirects to /decoy
        resp3 = self.client.post("/login", data={"username": "demo", "password": "BadPassword3!"}, follow_redirects=False)
        self.assertEqual(resp3.status_code, 302)
        self.assertIn("/decoy", resp3.headers["Location"])

        state3 = self.rows("SELECT risk_score, risk_band, decoy_active FROM sessions")[0]
        self.assertGreaterEqual(state3["risk_score"], 50)
        self.assertEqual(state3["risk_band"], "HIGH")
        self.assertEqual(state3["decoy_active"], 1)

        # Verify /decoy shows synthetic sandbox
        decoy_page = self.client.get("/decoy")
        self.assertEqual(decoy_page.status_code, 200)
        self.assertIn(b"Controlled decoy environment", decoy_page.data)

        # Perform decoy action and verify recorded
        action_resp = self.client.post("/decoy/action", data={"action": "open_record"}, follow_redirects=True)
        self.assertEqual(action_resp.status_code, 200)

        # Verify admin reflects decoy active
        admin_resp = self.client.get("/admin")
        self.assertIn(b"Decoy active", admin_resp.data)

        # Verify reset and subsequent legitimate login
        self.client.post("/admin/reset")
        fresh = self.client.post("/login", data={"username": DEMO_USERNAME, "password": DEMO_PASSWORD}, follow_redirects=True)
        self.assertEqual(fresh.status_code, 200)
        self.assertIn(b"Normal session experience", fresh.data)

    def test_three_diverse_failed_attempts_activate_decoy_and_redirect(self):
        for idx in range(2):
            resp = self.client.post("/login", data={"username": f"attacker-{idx}", "password": "bad"}, follow_redirects=False)
            self.assertEqual(resp.status_code, 200)

        resp3 = self.client.post("/login", data={"username": "attacker-2", "password": "bad"}, follow_redirects=False)
        self.assertEqual(resp3.status_code, 302)
        self.assertIn("/decoy", resp3.headers["Location"])

        state = self.rows("SELECT risk_score, risk_band, decoy_active FROM sessions")[0]
        self.assertGreaterEqual(state["risk_score"], 50)
        self.assertEqual(state["risk_band"], "HIGH")
        self.assertEqual(state["decoy_active"], 1)

    def test_real_login_failures_escalate_and_route_to_decoy(self):
        for index in range(5):
            response = self.client.post(
                "/login",
                data={"username": f"guess-user-{index}", "password": "NeverStoreThisPassword!"},
                follow_redirects=False,
            )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/decoy", response.headers["Location"])
        decoy_page = self.client.get("/decoy")
        self.assertEqual(decoy_page.status_code, 200)
        self.assertIn(b"Controlled decoy environment", decoy_page.data)
        state = self.rows("SELECT risk_score, risk_band, decoy_active FROM sessions")[0]
        self.assertGreaterEqual(state["risk_score"], 50)
        self.assertEqual(state["risk_band"], "HIGH")
        self.assertEqual(state["decoy_active"], 1)
        self.assertEqual(self.rows("SELECT authenticated FROM sessions")[0]["authenticated"], 0)

    def test_password_and_attempted_usernames_are_not_persisted_in_event_log(self):
        sensitive_password = "NeverStoreThisPassword!"
        private_username = "not-a-real-person-username"
        self.client.post("/login", data={"username": private_username, "password": sensitive_password})
        event_rows = self.rows("SELECT event_type, username_fingerprint, details_json FROM events")
        serialized = json.dumps([dict(row) for row in event_rows])
        self.assertNotIn(sensitive_password, serialized)
        self.assertNotIn(private_username, serialized)
        self.assertTrue(any(row["username_fingerprint"] for row in event_rows))

    def test_suspicious_simulator_crosses_threshold_and_logs_decoy_actions(self):
        response = self.client.post("/admin/simulate/suspicious", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Suspicious scenario stored", response.data)
        state = self.rows("SELECT session_key, risk_score, risk_band, decoy_active FROM sessions WHERE scenario = 'suspicious'")[0]
        self.assertGreaterEqual(state["risk_score"], 65)
        self.assertEqual(state["risk_band"], "HIGH")
        self.assertEqual(state["decoy_active"], 1)
        events = self.rows("SELECT event_type FROM events WHERE session_key = ?", (state["session_key"],))
        kinds = [row["event_type"] for row in events]
        self.assertIn("decoy_activated", kinds)
        self.assertIn("decoy_record_opened", kinds)
        self.assertIn("decoy_report_opened", kinds)
        self.assertIn("decoy_admin_resource_attempted", kinds)
        detail = self.client.get(f"/admin/decoy/{state['session_key']}")
        self.assertEqual(detail.status_code, 200)
        self.assertIn(b"HS-2048", detail.data)

    def test_decoy_interaction_from_ui_is_logged(self):
        self.client.post("/admin/simulate/suspicious")
        state = self.rows("SELECT session_key FROM sessions WHERE scenario = 'suspicious'")[0]
        response = self.client.post(
            f"/admin/decoy/{state['session_key']}/action", data={"action": "open_record"}, follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Synthetic interaction recorded", response.data)
        count = self.rows(
            "SELECT COUNT(*) AS n FROM events WHERE session_key = ? AND event_type = 'decoy_record_opened'",
            (state["session_key"],),
        )[0]["n"]
        self.assertGreaterEqual(count, 2)

    def test_normal_simulator_stays_low_and_does_not_activate_decoy(self):
        response = self.client.post("/admin/simulate/normal", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        state = self.rows("SELECT risk_score, risk_band, decoy_active FROM sessions WHERE scenario = 'normal'")[0]
        self.assertEqual(state["risk_score"], 0)
        self.assertEqual(state["risk_band"], "LOW")
        self.assertEqual(state["decoy_active"], 0)

    def test_reset_clears_sessions_and_events_but_preserves_demo_account(self):
        self.client.post("/admin/simulate/suspicious")
        response = self.client.post("/admin/reset", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"were reset", response.data)
        self.assertEqual(self.rows("SELECT COUNT(*) AS n FROM sessions")[0]["n"], 0)
        self.assertEqual(self.rows("SELECT COUNT(*) AS n FROM events")[0]["n"], 0)
        self.assertEqual(self.rows("SELECT COUNT(*) AS n FROM users WHERE username = ?", (DEMO_USERNAME,))[0]["n"], 1)

    def test_referenced_pages_render(self):
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(self.client.get("/login").status_code, 200)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)
        self.assertEqual(self.client.get("/admin").status_code, 200)
        self.client.post("/login", data={"username": DEMO_USERNAME, "password": DEMO_PASSWORD})
        self.assertEqual(self.client.get("/dashboard").status_code, 200)

    def test_invalid_login_shows_helpful_error_and_preserves_privacy(self):
        response = self.client.post(
            "/login",
            data={"username": "demo", "password": "WrongPassword123!"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Sign-in was not successful", response.data)
        event_rows = self.rows("SELECT details_json FROM events")
        self.assertFalse(any("WrongPassword123!" in row["details_json"] for row in event_rows))

    def test_logout_revokes_access_to_dashboard(self):
        self.client.post("/login", data={"username": DEMO_USERNAME, "password": DEMO_PASSWORD})
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        logout_resp = self.client.get("/logout", follow_redirects=True)
        self.assertEqual(logout_resp.status_code, 200)
        self.assertIn(b"left the demo workspace", logout_resp.data)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    def test_unauthorized_decoy_access_is_prevented(self):
        resp = self.client.get("/decoy")
        self.assertEqual(resp.status_code, 302)
        self.assertIn(resp.headers["Location"], {"/", "/login"})
        action_resp = self.client.post("/decoy/action", data={"action": "open_record"})
        self.assertEqual(action_resp.status_code, 403)

    def test_multiple_resets_are_idempotent_and_usable_immediately(self):
        self.client.post("/admin/simulate/suspicious")
        resp1 = self.client.post("/admin/reset", follow_redirects=True)
        self.assertEqual(resp1.status_code, 200)
        resp2 = self.client.post("/admin/reset", follow_redirects=True)
        self.assertEqual(resp2.status_code, 200)
        login_resp = self.client.post(
            "/login",
            data={"username": DEMO_USERNAME, "password": DEMO_PASSWORD},
            follow_redirects=True,
        )
        self.assertEqual(login_resp.status_code, 200)
        self.assertIn(b"Welcome back", login_resp.data)

    def test_all_decoy_actions_persist_events(self):
        self.client.post("/admin/simulate/suspicious")
        state = self.rows("SELECT session_key FROM sessions WHERE scenario = 'suspicious'")[0]
        sid = state["session_key"]
        for action in ("open_record", "open_report", "admin_resource", "export_report", "download_backup", "view_api_key"):
            resp = self.client.post(f"/admin/decoy/{sid}/action", data={"action": action}, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
        events = self.rows("SELECT event_type FROM events WHERE session_key = ?", (sid,))
        types = [r["event_type"] for r in events]
        self.assertIn("decoy_record_opened", types)
        self.assertIn("decoy_report_opened", types)
        self.assertIn("decoy_admin_resource_attempted", types)
        self.assertIn("decoy_report_export_requested", types)
        self.assertIn("decoy_canary_backup_downloaded", types)
        self.assertIn("decoy_canary_token_accessed", types)

    def test_active_decoy_session_entering_correct_password_diverts_to_decoy(self):
        # Trigger 3 failed logins to activate decoy
        for idx in range(3):
            self.client.post("/login", data={"username": "demo", "password": f"wrong-{idx}"})
        state = self.rows("SELECT decoy_active, authenticated FROM sessions")[0]
        self.assertEqual(state["decoy_active"], 1)
        self.assertEqual(state["authenticated"], 0)

        # Now submit the correct credentials from this suspicious session
        resp = self.client.post(
            "/login",
            data={"username": DEMO_USERNAME, "password": DEMO_PASSWORD},
            follow_redirects=False,
        )
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/decoy", resp.headers["Location"])

        # Verify session is NOT authenticated to normal dashboard
        state_after = self.rows("SELECT decoy_active, authenticated FROM sessions")[0]
        self.assertEqual(state_after["decoy_active"], 1)
        self.assertEqual(state_after["authenticated"], 0)

        # Accessing /dashboard must redirect to /decoy
        dash_resp = self.client.get("/dashboard", follow_redirects=False)
        self.assertEqual(dash_resp.status_code, 302)
        self.assertIn("/decoy", dash_resp.headers["Location"])

    def test_fresh_database_initialisation(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            fresh_db_path = Path(tmp_dir) / "fresh.sqlite3"
            test_app = create_app({"DATABASE": str(fresh_db_path), "TESTING": True})
            with test_app.app_context():
                conn = sqlite3.connect(str(fresh_db_path))
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = {row[0] for row in cursor.fetchall()}
                self.assertIn("users", tables)
                self.assertIn("sessions", tables)
                self.assertIn("events", tables)
                cursor.execute("SELECT username, password_hash FROM users WHERE username = ?", (DEMO_USERNAME,))
                user = cursor.fetchone()
                self.assertIsNotNone(user)
                self.assertTrue(user[1].startswith("scrypt:"))
                conn.close()



if __name__ == "__main__":
    unittest.main(verbosity=2)
