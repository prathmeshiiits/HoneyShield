"""E2E Verification of Authentication Navigation Journeys (Tests 1 - 6)."""
from __future__ import annotations
import sys
import os
from pathlib import Path
from playwright.sync_api import sync_playwright, Page, BrowserContext

BASE_URL = "http://127.0.0.1:5000"
DEMO_USER = "demo"
DEMO_PASS = "ShieldDemo!2026"

if sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

def setup_page(ctx: BrowserContext, errors_list: list[str]) -> Page:
    page = ctx.new_page()
    page.set_default_timeout(8000)
    page.on("console", lambda msg: errors_list.append(f"CONSOLE {msg.type}: {msg.text}") if msg.type == "error" else None)
    return page

def dismiss_disclosure(page: Page) -> None:
    try:
        btn = page.locator("#demoDisclosureContinue")
        if btn.is_visible(timeout=500):
            btn.click()
    except Exception:
        pass

def run_e2e_verification():
    results = {}
    console_errors = []

    # Ensure artifacts directory exists for screenshots
    Path("artifacts").mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        
        # --- TEST 1: Landing to login ---
        print("[TEST 1] Starting Landing to Login...")
        ctx1 = browser.new_context(viewport={"width": 1280, "height": 800})
        p1 = setup_page(ctx1, console_errors)
        
        p1.goto(f"{BASE_URL}/")
        p1.wait_for_load_state("networkidle")
        dismiss_disclosure(p1)
        
        # Check logged-out navbar links
        nav_text = p1.locator(".header-nav").inner_text()
        print("Logged-out navbar text:", nav_text.replace("\n", " | "))
        assert "Sign In" in nav_text or "Sign in" in nav_text, "Navbar must contain Sign In when logged out"
        assert "My Workspace" not in nav_text, "Navbar must NOT contain My Workspace when logged out"
        assert "Sign Out" not in nav_text, "Navbar must NOT contain Sign Out when logged out"
        
        # Click Sign In in navbar
        p1.click(".header-nav a:has-text('Sign In'), .header-nav a:has-text('Sign in')")
        p1.wait_for_url(f"{BASE_URL}/login")
        dismiss_disclosure(p1)
        assert p1.locator("#username").is_visible(), "Username field must be visible on /login"
        assert p1.locator("#password").is_visible(), "Password field must be visible on /login"
        print("Navbar Sign In opens /login with form fields successfully.")
        
        # Return home and click hero CTA button
        p1.goto(f"{BASE_URL}/")
        p1.wait_for_load_state("networkidle")
        dismiss_disclosure(p1)
        hero_btn = p1.locator("#heroSignInBtn")
        assert hero_btn.is_visible(), "Hero Sign In to Workspace button must be visible"
        hero_helper = p1.locator("#heroSignInHelper")
        assert hero_helper.is_visible(), "Hero Sign In helper line must be visible"
        assert "Sign in to access your normal workspace" in hero_helper.inner_text()
        
        hero_btn.click()
        p1.wait_for_url(f"{BASE_URL}/login")
        dismiss_disclosure(p1)
        assert p1.locator("#username").is_visible(), "Hero CTA must open real /login form"
        print("[TEST 1] PASS: Landing to login verified.")
        results["Test 1 — Landing to login"] = "PASS"
        ctx1.close()

        # --- TEST 2: Successful login ---
        print("\n[TEST 2] Starting Successful Login...")
        ctx2 = browser.new_context(viewport={"width": 1280, "height": 800})
        p2 = setup_page(ctx2, console_errors)
        
        p2.goto(f"{BASE_URL}/login")
        p2.wait_for_load_state("networkidle")
        dismiss_disclosure(p2)
        
        p2.fill("#username", DEMO_USER)
        p2.fill("#password", DEMO_PASS)
        p2.click("button[type='submit']")
        
        p2.wait_for_url(f"{BASE_URL}/dashboard")
        p2.wait_for_load_state("networkidle")
        dismiss_disclosure(p2)
        
        dashboard_content = p2.content()
        assert "Welcome back," in dashboard_content and DEMO_USER in dashboard_content, "Dashboard must show welcome message"
        
        auth_nav_text = p2.locator(".header-nav").inner_text()
        print("Authenticated navbar text:", auth_nav_text.replace("\n", " | "))
        assert "My Workspace" in auth_nav_text, "Navbar must contain My Workspace when authenticated"
        assert "Sign Out" in auth_nav_text, "Navbar must contain Sign Out when authenticated"
        assert "Sign In" not in auth_nav_text and "Sign in" not in auth_nav_text, "Navbar must NOT contain Sign In when authenticated"
        
        # Refresh and check persistence
        p2.reload()
        p2.wait_for_load_state("networkidle")
        dismiss_disclosure(p2)
        assert p2.url == f"{BASE_URL}/dashboard"
        assert "My Workspace" in p2.locator(".header-nav").inner_text()
        print("[TEST 2] PASS: Successful login and navbar state verified.")
        results["Test 2 — Successful login"] = "PASS"

        # --- TEST 3: Failed login ---
        print("\n[TEST 3] Starting Failed Login...")
        ctx3 = browser.new_context(viewport={"width": 1280, "height": 800})
        p3 = setup_page(ctx3, console_errors)
        
        p3.goto(f"{BASE_URL}/login")
        p3.wait_for_load_state("networkidle")
        dismiss_disclosure(p3)
        
        p3.fill("#username", DEMO_USER)
        p3.fill("#password", "WrongPassword!999")
        p3.click("button[type='submit']")
        
        p3.wait_for_load_state("networkidle")
        dismiss_disclosure(p3)
        assert p3.url == f"{BASE_URL}/login", f"Failed login must remain on /login, got {p3.url}"
        flash_text = p3.locator(".flash-error, .flash").inner_text()
        print("Failed login flash message:", flash_text)
        assert "Sign-in was not successful" in flash_text, "Error message must be shown"
        assert "Welcome back" not in p3.content(), "Workspace content must not appear on failed login"
        print("[TEST 3] PASS: Failed login error handling verified.")
        results["Test 3 — Failed login"] = "PASS"
        ctx3.close()

        # --- TEST 4: Workspace navigation ---
        print("\n[TEST 4] Starting Workspace Navigation...")
        # Use existing authenticated page p2
        p2.click(".header-nav a:has-text('My Workspace')")
        p2.wait_for_url(f"{BASE_URL}/dashboard")
        assert "Welcome back" in p2.content()
        
        # Navigate to Control Room
        p2.click(".header-nav a:has-text('Control Room')")
        p2.wait_for_url(f"{BASE_URL}/admin")
        dismiss_disclosure(p2)
        assert "Security Overview" in p2.content() or "Control Room" in p2.content() or "OPERATIONAL" in p2.content()
        
        # Navigate to Scenario Lab
        p2.click(".header-nav a:has-text('Scenario Lab')")
        p2.wait_for_url(f"{BASE_URL}/lab")
        dismiss_disclosure(p2)
        assert "Scenario Lab" in p2.content()
        
        # Navigate back to workspace
        p2.click(".header-nav a:has-text('My Workspace')")
        p2.wait_for_url(f"{BASE_URL}/dashboard")
        assert "Welcome back" in p2.content()
        print("[TEST 4] PASS: Workspace navigation verified.")
        results["Test 4 — Workspace navigation"] = "PASS"

        # --- TEST 5: Sign out ---
        print("\n[TEST 5] Starting Sign Out...")
        p2.click(".header-nav a:has-text('Sign Out')")
        p2.wait_for_url(f"{BASE_URL}/")
        p2.wait_for_load_state("networkidle")
        dismiss_disclosure(p2)
        
        landing_content = p2.content()
        assert "You have signed out successfully" in landing_content, "Landing page must display sign-out confirmation"
        
        logged_out_nav = p2.locator(".header-nav").inner_text()
        print("Logged-out navbar after signout:", logged_out_nav.replace("\n", " | "))
        assert "Sign In" in logged_out_nav, "Navbar must revert to Sign In"
        assert "My Workspace" not in logged_out_nav, "Navbar must not show My Workspace"
        assert "Sign Out" not in logged_out_nav, "Navbar must not show Sign Out"
        
        # Try direct access to /dashboard
        p2.goto(f"{BASE_URL}/dashboard")
        p2.wait_for_url(f"{BASE_URL}/login")
        dismiss_disclosure(p2)
        print("Direct access to /dashboard redirected to /login.")
        
        # Test browser back button
        p2.go_back()
        p2.wait_for_load_state("networkidle")
        # Should be on /login or / and NOT seeing private workspace data
        assert "Welcome back, demo" not in p2.content(), "Protected content must not be accessible via Back button"
        print("[TEST 5] PASS: Sign out and session revocation verified.")
        results["Test 5 — Sign out"] = "PASS"
        ctx2.close()

        # --- TEST 6: Visual verification ---
        print("\n[TEST 6] Starting Visual Verification...")
        ctx6 = browser.new_context(viewport={"width": 1280, "height": 800})
        p6 = setup_page(ctx6, console_errors)
        
        # 1. Desktop landing
        p6.goto(f"{BASE_URL}/")
        p6.wait_for_load_state("networkidle")
        dismiss_disclosure(p6)
        p6.screenshot(path="artifacts/landing_desktop.png")
        
        # Check hero button visual styles
        btn_box = p6.locator("#heroSignInBtn").bounding_box()
        assert btn_box is not None, "Hero Sign In button must be rendered with bounding box"
        assert btn_box["width"] > 150, "Hero Sign In button must have prominent width"
        
        # 2. Desktop login
        p6.goto(f"{BASE_URL}/login")
        p6.wait_for_load_state("networkidle")
        dismiss_disclosure(p6)
        p6.screenshot(path="artifacts/login_desktop.png")
        
        # 3. Authenticate and check navbar row alignment
        p6.fill("#username", DEMO_USER)
        p6.fill("#password", DEMO_PASS)
        p6.click("button[type='submit']")
        p6.wait_for_url(f"{BASE_URL}/dashboard")
        p6.wait_for_load_state("networkidle")
        dismiss_disclosure(p6)
        p6.screenshot(path="artifacts/workspace_desktop.png")
        
        # Verify Sign Out and My Workspace are on the same horizontal navbar row (same or close y-coordinate)
        ws_box = p6.locator(".header-nav a:has-text('My Workspace')").bounding_box()
        so_box = p6.locator(".header-nav a:has-text('Sign Out')").bounding_box()
        assert ws_box is not None and so_box is not None
        y_diff = abs(ws_box["y"] - so_box["y"])
        print(f"Navbar vertical delta between My Workspace and Sign Out: {y_diff}px")
        assert y_diff < 15, "Sign Out and My Workspace must be on the same horizontal navbar row"
        
        # 4. Narrow screen viewport (375x667)
        ctx_mobile = browser.new_context(viewport={"width": 375, "height": 667})
        p_mobile = setup_page(ctx_mobile, console_errors)
        p_mobile.goto(f"{BASE_URL}/")
        p_mobile.wait_for_load_state("networkidle")
        dismiss_disclosure(p_mobile)
        # Check menu toggle button is visible
        menu_toggle = p_mobile.locator("#menuToggle")
        assert menu_toggle.is_visible(), "Menu toggle button must be visible on narrow screens"
        menu_toggle.click()
        p_mobile.wait_for_selector("#navDrawer:not([hidden])")
        drawer_text = p_mobile.locator("#navDrawer").inner_text()
        print("Mobile drawer text:", drawer_text.replace("\n", " | "))
        assert "Sign In" in drawer_text, "Mobile drawer must show Sign In when logged out"
        p_mobile.screenshot(path="artifacts/mobile_nav_drawer.png")
        ctx_mobile.close()
        
        print("[TEST 6] PASS: Visual verification completed with screenshots saved.")
        results["Test 6 — Visual verification"] = "PASS"
        ctx6.close()
        
        browser.close()

    print("\n================== VERIFICATION SUMMARY ==================")
    for test, status in results.items():
        print(f"  [{status}] {test}")
    print(f"Console errors: {len(console_errors)}")
    if console_errors:
        for err in console_errors:
            print("  ", err)
    print("==========================================================")
    
    if any(s != "PASS" for s in results.values()):
        sys.exit(1)

if __name__ == "__main__":
    run_e2e_verification()
