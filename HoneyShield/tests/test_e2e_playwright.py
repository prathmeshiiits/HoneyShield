"""End-to-End browser tests using Playwright Chromium."""
from __future__ import annotations

import gc
import re
import socket
import tempfile
import threading
import time
from pathlib import Path
from typing import Generator

import pytest
from werkzeug.serving import make_server

from app import DEMO_PASSWORD, DEMO_USERNAME, create_app

try:
    from playwright.sync_api import Browser, BrowserContext, Page, sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

LOGIN_URL_RE = re.compile(r"/(login)?$")


def find_free_port() -> int:
    """Find an available port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def live_server() -> Generator[str, None, None]:
    """Start an isolated background HTTP server on a random port with an isolated SQLite db."""
    if not PLAYWRIGHT_AVAILABLE:
        pytest.skip("Playwright is not installed in this environment.")

    temp_dir = tempfile.TemporaryDirectory(prefix="hs-playwright-")
    db_path = Path(temp_dir.name) / "e2e.sqlite3"
    port = find_free_port()
    base_url = f"http://127.0.0.1:{port}"

    app = create_app({
        "TESTING": True,
        "DATABASE": str(db_path),
        "SECRET_KEY": "playwright-e2e-secret-key-2026",
        "HIGH_RISK_THRESHOLD": 50,
        "RISK_WINDOW_SECONDS": 180,
    })

    server = make_server("127.0.0.1", port, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    # Wait for server readiness
    import urllib.request
    ready = False
    for _ in range(30):
        try:
            with urllib.request.urlopen(f"{base_url}/healthz", timeout=1) as resp:
                if resp.status == 200:
                    ready = True
                    break
        except Exception:
            time.sleep(0.1)

    if not ready:
        server.shutdown()
        pytest.fail("Live server failed to start within timeout.")

    try:
        yield base_url
    finally:
        server.shutdown()
        gc.collect()
        try:
            temp_dir.cleanup()
        except (PermissionError, OSError):
            pass


@pytest.fixture(scope="module")
def browser() -> Generator[Browser, None, None]:
    """Launch headless Chromium browser."""
    if not PLAYWRIGHT_AVAILABLE:
        pytest.skip("Playwright is not installed.")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            yield browser
        finally:
            browser.close()


def create_page(context: BrowserContext) -> Page:
    """Create a page configured with auto-accepted dialogs and pre-seeded disclosure acknowledgement."""
    page = context.new_page()
    page.set_default_timeout(7000)
    page.on("dialog", lambda dialog: dialog.accept())
    page.add_init_script("try { window.sessionStorage.setItem('honeyshield-demo-disclosure-seen', '1'); } catch(e){}")
    return page


def dismiss_disclosure_if_visible(page: Page) -> None:
    try:
        btn = page.locator("#demoDisclosureContinue")
        if btn.is_visible(timeout=250):
            btn.click()
    except Exception:
        pass


@pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="Playwright is required for browser tests")
class TestHoneyShieldE2E:
    """E2E browser tests verifying complete user and attacker flows."""

    def test_valid_login_normal_dashboard_and_logout(self, live_server: str, browser: Browser):
        """User logs in with valid credentials, sees user dashboard, and logs out."""
        context = browser.new_context()
        page = create_page(context)

        # 1. Navigate to login
        page.goto(f"{live_server}/login")
        dismiss_disclosure_if_visible(page)
        assert "HoneyShield" in page.title()
        assert page.locator("#username").is_visible()

        # 2. Fill demo credentials and submit
        page.fill("#username", DEMO_USERNAME)
        page.fill("#password", DEMO_PASSWORD)
        page.click("button[type='submit']")

        # 3. Verify user dashboard
        page.wait_for_url(f"{live_server}/dashboard")
        assert "Protected Workspace" in page.content() or "USER WORKSPACE" in page.content()
        assert DEMO_USERNAME in page.content()

        # 4. Log out
        page.click("text=Sign out")
        page.wait_for_url(LOGIN_URL_RE)
        assert "You have left the demo workspace." in page.content()

        # 5. Access control after logout: navigating back to /dashboard redirects to login
        page.goto(f"{live_server}/dashboard")
        page.wait_for_url(LOGIN_URL_RE)

        context.close()

    def test_invalid_login_shows_error(self, live_server: str, browser: Browser):
        """Invalid password displays error message without activating decoy on attempt #1."""
        context = browser.new_context()
        page = create_page(context)

        page.goto(f"{live_server}/login")
        dismiss_disclosure_if_visible(page)
        page.fill("#username", DEMO_USERNAME)
        page.fill("#password", "WrongPassword!123")
        page.click("button[type='submit']")

        assert page.url.endswith("/login") or page.url == f"{live_server}/"
        assert "Sign-in was not successful" in page.content()

        context.close()

    def test_three_failed_attempts_activate_decoy_and_telemetry(self, live_server: str, browser: Browser):
        """Entering incorrect password 3 times escalates risk to 50 (HIGH) and routes into decoy."""
        context = browser.new_context()
        page = create_page(context)

        # Attempt 1
        page.goto(f"{live_server}/login")
        dismiss_disclosure_if_visible(page)
        page.fill("#username", DEMO_USERNAME)
        page.fill("#password", "BadPass1")
        page.click("button[type='submit']")
        page.wait_for_selector("text=Sign-in was not successful")

        # Attempt 2
        page.fill("#username", DEMO_USERNAME)
        page.fill("#password", "BadPass2")
        page.click("button[type='submit']")
        page.wait_for_selector("text=Sign-in was not successful")

        # Attempt 3 -> triggers HIGH risk (50/100) and redirect to /decoy
        page.fill("#username", DEMO_USERNAME)
        page.fill("#password", "BadPass3")
        page.click("button[type='submit']")

        page.wait_for_url(f"{live_server}/decoy")
        assert "Operations" in page.content()
        assert "HS-2048" in page.content()

        # Telemetry: interact with decoy actions
        # Action 1: Open synthetic customer record
        page.click("button:has-text('Open ↗')")
        page.wait_for_url(f"{live_server}/decoy")
        assert "Synthetic interaction recorded" in page.content()

        # Action 2: Inspect admin resource
        page.click("button:has-text('Inspect ↗')")
        page.wait_for_url(f"{live_server}/decoy")
        assert "Synthetic interaction recorded" in page.content()

        # Action 3: Export synthetic report
        page.click("button:has-text('Export ↗')")
        page.wait_for_url(f"{live_server}/decoy")
        assert "Synthetic interaction recorded" in page.content()

        context.close()

    def test_session_isolation_normal_user_not_affected_by_attacker(self, live_server: str, browser: Browser):
        """Attacker triggering decoy in Context A does not contaminate Context B (clean user)."""
        attacker_context = browser.new_context()
        normal_context = browser.new_context()

        attacker_page = create_page(attacker_context)
        normal_page = create_page(normal_context)

        # Attacker fails 3 times
        for i in range(3):
            attacker_page.goto(f"{live_server}/login")
            dismiss_disclosure_if_visible(attacker_page)
            attacker_page.fill("#username", f"attacker-{i}")
            attacker_page.fill("#password", "wrong")
            attacker_page.click("button[type='submit']")

        attacker_page.wait_for_url(f"{live_server}/decoy")
        assert "/decoy" in attacker_page.url

        # Normal user logs in simultaneously in separate session
        normal_page.goto(f"{live_server}/login")
        dismiss_disclosure_if_visible(normal_page)
        normal_page.fill("#username", DEMO_USERNAME)
        normal_page.fill("#password", DEMO_PASSWORD)
        normal_page.click("button[type='submit']")

        normal_page.wait_for_url(f"{live_server}/dashboard")
        assert "Protected Workspace" in normal_page.content() or "USER WORKSPACE" in normal_page.content()
        assert "/decoy" not in normal_page.url

        attacker_context.close()
        normal_context.close()

    def test_browser_navigation_and_access_controls(self, live_server: str, browser: Browser):
        """Refreshes, direct navigation, and browser Back button cannot bypass controls."""
        context = browser.new_context()
        page = create_page(context)

        # 1. Unauthenticated direct access to /decoy must redirect to login
        page.goto(f"{live_server}/decoy")
        page.wait_for_url(LOGIN_URL_RE)

        # 2. Unauthenticated direct access to /dashboard must redirect to login
        page.goto(f"{live_server}/dashboard")
        page.wait_for_url(LOGIN_URL_RE)

        # 3. Log in normally
        dismiss_disclosure_if_visible(page)
        page.fill("#username", DEMO_USERNAME)
        page.fill("#password", DEMO_PASSWORD)
        page.click("button[type='submit']")
        page.wait_for_url(f"{live_server}/dashboard")

        # 4. Refreshing dashboard keeps user authenticated
        page.reload()
        assert "Protected Workspace" in page.content() or "USER WORKSPACE" in page.content()

        # 5. Log out
        page.click("text=Sign out")
        page.wait_for_url(LOGIN_URL_RE)

        # 6. Click browser back button after logout -> should NOT grant access to private dashboard
        page.go_back()
        page.reload()
        page.wait_for_url(LOGIN_URL_RE)

        context.close()

    def test_admin_investigation_and_reset(self, live_server: str, browser: Browser):
        """Admin views session telemetry and executes reset successfully."""
        context = browser.new_context()
        page = create_page(context)

        # 1. Navigate to admin dashboard
        page.goto(f"{live_server}/admin")
        assert "HoneyShield" in page.content()

        # 2. Trigger suspicious simulation
        page.click("form[action*='suspicious'] button")
        page.wait_for_url(f"{live_server}/admin")
        assert "Suspicious scenario stored" in page.content()

        # 3. Trigger reset demo (dialog is auto-accepted)
        page.click("form[action*='/admin/reset'] button")
        page.wait_for_url(f"{live_server}/admin")
        assert "Demo sessions and event history were reset" in page.content()

        # 4. Verify sessions table has zero rows
        assert "No sessions match those filters" in page.content()

        context.close()
