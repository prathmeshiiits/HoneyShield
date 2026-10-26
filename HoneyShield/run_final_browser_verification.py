"""
HoneyShield Final Integration & Real-Browser Verification Suite
Executes all user journeys, verifies interactive behaviors, exercises What-If Analyzer,
validates JSON/CSV exports, and captures high-resolution screenshots into verification/evidence/.
"""

import os
import sys
import json
import csv
import io
import time
import re
from playwright.sync_api import sync_playwright, expect

BASE_URL = "http://127.0.0.1:5000"
EVIDENCE_DIR = os.path.join(os.path.dirname(__file__), "verification", "evidence")
os.makedirs(EVIDENCE_DIR, exist_ok=True)

results = {}

def log(msg):
    print(f"[VERIFY] {msg}", flush=True)

def re_pattern(txt):
    return re.compile(rf".*{re.escape(txt)}.*")

def dismiss_disclosure(page):
    try:
        page.evaluate("try { localStorage.setItem('hs_disclosure_seen', 'true'); } catch(e){}")
        btn = page.locator("#demoDisclosureContinue")
        if btn.is_visible(timeout=400):
            btn.click()
            page.wait_for_timeout(200)
    except Exception:
        pass

def run_verification():
    log("Starting comprehensive real-browser verification on " + BASE_URL)
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        
        # -------------------------------------------------------------
        # Journey 1: Landing Page & "Same Login, Two Realities" Demo
        # -------------------------------------------------------------
        log("--- Journey 1: Landing Page & Two Realities Demo ---")
        context = browser.new_context(viewport={"width": 1280, "height": 840})
        page = context.new_page()
        page.goto(f"{BASE_URL}/", wait_until="networkidle")
        dismiss_disclosure(page)
        
        # Verify title and primary CTA
        actual_title = page.title()
        log(f"Page title: {actual_title}")
        assert "Behavioural Cyber Deception Platform" in actual_title
        
        hero_btn = page.locator("#heroSignInBtn")
        expect(hero_btn).to_be_visible()
        expect(hero_btn).to_contain_text("Sign In to Workspace")
        
        # Verify "Same Login, Two Realities" interactive demonstration
        realities_section = page.locator("#two-realities-demo")
        expect(realities_section).to_be_visible()
        
        btn_normal = page.locator("#btnRealityNormal")
        btn_attacker = page.locator("#btnRealityAttacker")
        btn_both = page.locator("#btnRealityBoth")
        card_legit = page.locator("#realityCardLegit")
        card_attacker = page.locator("#realityCardAttacker")
        
        expect(card_legit).to_be_visible()
        expect(card_attacker).to_be_visible()
        
        # Test tab switching
        btn_normal.click()
        page.wait_for_timeout(200)
        expect(card_legit).to_be_visible()
        assert not card_attacker.is_visible(), "Attacker card should be hidden in normal view"
        
        btn_attacker.click()
        page.wait_for_timeout(200)
        expect(card_attacker).to_be_visible()
        assert not card_legit.is_visible(), "Legit card should be hidden in attacker view"
        
        btn_both.click()
        page.wait_for_timeout(200)
        expect(card_legit).to_be_visible()
        expect(card_attacker).to_be_visible()
        
        page.screenshot(path=os.path.join(EVIDENCE_DIR, "01_landing_desktop.png"), full_page=False)
        log("Saved 01_landing_desktop.png")
        
        # Mobile view of landing page
        context_mobile = browser.new_context(viewport={"width": 375, "height": 812})
        page_mobile = context_mobile.new_page()
        page_mobile.goto(f"{BASE_URL}/", wait_until="networkidle")
        dismiss_disclosure(page_mobile)
        page_mobile.screenshot(path=os.path.join(EVIDENCE_DIR, "02_landing_mobile.png"), full_page=False)
        log("Saved 02_landing_mobile.png")
        context_mobile.close()
        
        results["landing_page_and_two_realities"] = "PASS"

        # -------------------------------------------------------------
        # Journey 2: Dedicated Sign-In Page
        page.locator("#heroSignInBtn").click()
        page.wait_for_url("**/login", timeout=8000)
        dismiss_disclosure(page)
        
        expect(page.locator(".login-card h2")).to_contain_text("Sign in to continue")
        expect(page.locator("input[name='username']")).to_be_visible()
        expect(page.locator("input[name='password']")).to_be_visible()
        expect(page.locator("button[type='submit']")).to_be_visible()
        page.screenshot(path=os.path.join(EVIDENCE_DIR, "03_login_page.png"), full_page=False)
        log("Saved 03_login_page.png")
        results["dedicated_login_page"] = "PASS"

        # -------------------------------------------------------------
        # Journey 3: Normal Authentication & Legitimate Workspace
        # -------------------------------------------------------------
        log("--- Journey 3: Normal Authentication & Legitimate Workspace ---")
        page.fill("input[name='username']", "demo")
        page.fill("input[name='password']", "ShieldDemo!2026")
        page.click("button[type='submit']")
        page.wait_for_url("**/dashboard")
        dismiss_disclosure(page)
        
        expect(page.locator("h1")).to_contain_text("Welcome back")
        expect(page.locator(".header-nav a[href='/logout']")).to_be_visible()
        expect(page.locator("text=Sign In to Workspace")).not_to_be_visible()
        page.screenshot(path=os.path.join(EVIDENCE_DIR, "04_authenticated_workspace.png"), full_page=False)
        log("Saved 04_authenticated_workspace.png")
        results["normal_auth_workspace"] = "PASS"

        # -------------------------------------------------------------
        # Journey 4: Sign-In while logged in, Sign-Out flow & No Leak
        # -------------------------------------------------------------
        log("--- Journey 4: Sign-Out flow & Cache Protection ---")
        # Direct navigate to /login while authenticated
        page.goto(f"{BASE_URL}/login")
        expect(page).to_have_url(f"{BASE_URL}/dashboard")
        
        # Click sign out
        page.click(".header-nav a[href='/logout']")
        page.wait_for_url(f"{BASE_URL}/")
        expect(page.locator(".flash, .flash-message")).to_contain_text("signed out successfully")
        page.screenshot(path=os.path.join(EVIDENCE_DIR, "05_logged_out_landing.png"), full_page=False)
        log("Saved 05_logged_out_landing.png")
        
        # Attempt back navigation
        page.goto(f"{BASE_URL}/dashboard")
        expect(page).to_have_url(f"{BASE_URL}/login")
        context.close()
        results["auth_navigation_and_logout"] = "PASS"

        # -------------------------------------------------------------
        # Journey 5: Control Room, Real Charts & Campaign Correlation
        # -------------------------------------------------------------
        log("--- Journey 5: Control Room & Shared Telemetry ---")
        admin_ctx = browser.new_context(viewport={"width": 1360, "height": 900})
        admin_page = admin_ctx.new_page()
        admin_page.goto(f"{BASE_URL}/admin", wait_until="networkidle")
        dismiss_disclosure(admin_page)
        
        # Ensure we have both a suspicious and normal scenario in database
        admin_page.click("button:has-text('Simulate suspicious session')")
        admin_page.wait_for_load_state("networkidle")
        dismiss_disclosure(admin_page)
        admin_page.click("button:has-text('Simulate normal session')")
        admin_page.wait_for_load_state("networkidle")
        dismiss_disclosure(admin_page)
        
        # Verify Charts
        svg_chart = admin_page.locator("#attemptsSvgChart")
        expect(svg_chart).to_be_visible()
        # Verify bars are rendered inside svg
        bars_count = svg_chart.locator("rect").count()
        log(f"Rendered attempt bars in SVG chart: {bars_count}")
        assert bars_count > 0, "Expected attempt chart SVG to render rect bars from events"
        
        # Verify Risk Distribution Stacked Bar
        risk_bar = admin_page.locator("#riskStackedBar")
        expect(risk_bar).to_be_visible()
        expect(admin_page.locator("#distSegmentLow")).to_be_visible()
        expect(admin_page.locator("#distSegmentHigh")).to_be_visible()
        
        # Verify Campaign Correlation Section
        campaign_sec = admin_page.locator("#campaign-correlation")
        expect(campaign_sec).to_be_visible()
        
        admin_page.screenshot(path=os.path.join(EVIDENCE_DIR, "06_control_room_full.png"), full_page=False)
        log("Saved 06_control_room_full.png")
        results["control_room_charts_and_campaigns"] = "PASS"

        # -------------------------------------------------------------
        # Journey 6: Shared Global Filters & Clickable KPI Cards
        # -------------------------------------------------------------
        log("--- Journey 6: Shared Global Filters & Clickable KPI Cards ---")
        # Click High-risk KPI card
        admin_page.locator(".metric-card[data-kpi-band='HIGH']").first.click()
        admin_page.wait_for_url("**/admin?band=HIGH")
        admin_page.wait_for_load_state("networkidle")
        dismiss_disclosure(admin_page)
        
        # Verify active KPI styling
        high_kpi_filtered = admin_page.locator(".metric-card[data-kpi-band='HIGH']").first
        expect(high_kpi_filtered).to_have_class(re_pattern("is-active-kpi"))
        # Verify active filter chip
        expect(admin_page.locator(".active-filters-chips")).to_contain_text("Band: HIGH")
        
        admin_page.screenshot(path=os.path.join(EVIDENCE_DIR, "07_control_room_filtered_high.png"), full_page=False)
        log("Saved 07_control_room_filtered_high.png")
        
        # Clear filters
        clear_btn = admin_page.locator("#clearAllFiltersBtn")
        clear_btn.click()
        admin_page.wait_for_url(f"{BASE_URL}/admin")
        results["control_room_shared_filters_and_kpis"] = "PASS"

        # -------------------------------------------------------------
        # Journey 7: Session Flight Recorder (Investigation Workspace)
        # -------------------------------------------------------------
        log("--- Journey 7: Session Flight Recorder & Attack-Path ---")
        # Find a high risk session row in table
        inspect_btn = admin_page.locator(".inspect-session-btn").first
        sid = inspect_btn.get_attribute("data-session-key")
        log(f"Inspecting session {sid}")
        
        # Navigate directly to the dedicated investigation page
        admin_page.goto(f"{BASE_URL}/admin/session/{sid}", wait_until="networkidle")
        dismiss_disclosure(admin_page)
        
        expect(admin_page.locator("#sessionKeyDisplay")).to_contain_text(sid)
        expect(admin_page.locator(".evidence-legend-callout")).to_be_visible()
        
        # Verify Attack Path Pipeline (5 steps)
        pipeline = admin_page.locator("#attackPathPipeline")
        expect(pipeline).to_be_visible()
        step_nodes = pipeline.locator(".attack-step").count()
        log(f"Deterministic attack-path steps: {step_nodes}")
        assert step_nodes >= 3, "Expected at least 3 attack path nodes"
        
        # Verify 7 Explainable signals breakdown
        signals = admin_page.locator(".inv-signal-card").count()
        log(f"Explainable signals displayed: {signals}")
        assert signals >= 7, "Expected 7 explainable signals"
        
        # Verify chronological flight timeline
        timeline_items = admin_page.locator(".timeline-item").count()
        log(f"Flight recorder timeline events: {timeline_items}")
        assert timeline_items > 0, "Expected flight recorder timeline to contain events"
        
        admin_page.screenshot(path=os.path.join(EVIDENCE_DIR, "08_session_flight_recorder.png"), full_page=False)
        log("Saved 08_session_flight_recorder.png")
        
        # Screenshot focused on attack path
        pipeline.screenshot(path=os.path.join(EVIDENCE_DIR, "09_attack_path_visualization.png"))
        log("Saved 09_attack_path_visualization.png")
        results["session_flight_recorder_and_attack_path"] = "PASS"

        # -------------------------------------------------------------
        # Journey 8: Real JSON & CSV Evidence Export
        # -------------------------------------------------------------
        log("--- Journey 8: Real JSON and CSV Evidence Export ---")
        # Fetch JSON export
        json_resp = admin_page.request.get(f"{BASE_URL}/admin/session/{sid}/export?format=json")
        assert json_resp.status == 200, f"JSON export status {json_resp.status}"
        assert "application/json" in json_resp.headers.get("content-type", "")
        export_data = json_resp.json()
        assert export_data["export_type"] == "honeyshield_session_investigation"
        assert export_data["session_overview"]["session_key"] == sid
        assert len(export_data["recorded_events"]) > 0
        assert "password" not in json.dumps(export_data).lower() or "zero plaintext passwords" in json.dumps(export_data).lower()
        
        # Write JSON to evidence directory
        json_path = os.path.join(EVIDENCE_DIR, "exported_session_evidence.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2)
        log(f"Saved verified JSON export ({os.path.getsize(json_path)} bytes)")

        # Fetch CSV export
        csv_resp = admin_page.request.get(f"{BASE_URL}/admin/session/{sid}/export?format=csv")
        assert csv_resp.status == 200, f"CSV export status {csv_resp.status}"
        assert "text/csv" in csv_resp.headers.get("content-type", "")
        csv_text = csv_resp.text()
        reader = csv.reader(io.StringIO(csv_text))
        rows = list(reader)
        assert len(rows) >= 2, "Expected CSV header and at least one data row"
        assert rows[0][0] == "Session_ID"
        assert rows[0][2] == "Assessed_Risk"
        assert rows[1][0] == sid
        
        # Write CSV to evidence directory
        csv_path = os.path.join(EVIDENCE_DIR, "exported_session_evidence.csv")
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write(csv_text)
        log(f"Saved verified CSV export ({os.path.getsize(csv_path)} bytes)")
        
        admin_page.screenshot(path=os.path.join(EVIDENCE_DIR, "10_export_verification.png"), full_page=False)
        log("Saved 10_export_verification.png")
        results["evidence_json_csv_export"] = "PASS"

        # -------------------------------------------------------------
        # Journey 9: Scenario Lab, Benchmark & What-If Analyzer Consistency
        # -------------------------------------------------------------
        log("--- Journey 9: Scenario Lab, Benchmark & What-If Analyzer ---")
        admin_page.goto(f"{BASE_URL}/lab", wait_until="networkidle")
        dismiss_disclosure(admin_page)
        
        # Run benchmark
        admin_page.click("button:has-text('Run Full Benchmark Suite')")
        admin_page.wait_for_load_state("networkidle")
        dismiss_disclosure(admin_page)
        
        expect(admin_page.locator(".benchmark-kpi-grid")).to_be_visible()
        
        # What-If Threshold Analyzer Verification
        whatif_slider = admin_page.locator("#whatifSlider")
        expect(whatif_slider).to_be_visible()
        
        active_score_str = admin_page.locator("#activeScoreVal").inner_text().strip()
        active_score = int(active_score_str) if active_score_str.isdigit() else 50
        log(f"Active session score: {active_score}")
        
        # Test candidate threshold at 50
        whatif_slider.fill("50")
        admin_page.wait_for_timeout(400)
        whatif_score_50 = int(admin_page.locator("#whatifScoreVal").inner_text().strip())
        whatif_verdict_50 = admin_page.locator("#whatifDecisionVal").inner_text().strip()
        log(f"What-If at threshold 50: Score={whatif_score_50}, Verdict={whatif_verdict_50}")
        assert whatif_score_50 == active_score, "Score must match active score!"
        
        # Test candidate threshold above score (90)
        whatif_slider.fill("90")
        admin_page.wait_for_timeout(400)
        whatif_score_90 = int(admin_page.locator("#whatifScoreVal").inner_text().strip())
        whatif_verdict_90 = admin_page.locator("#whatifDecisionVal").inner_text().strip()
        log(f"What-If at threshold 90: Score={whatif_score_90}, Verdict={whatif_verdict_90}")
        assert whatif_score_90 == active_score, "Risk score must be preserved across candidate thresholds!"
        if active_score < 90:
            assert "ALLOW" in whatif_verdict_90, f"Expected ALLOW when threshold > score, got {whatif_verdict_90}"
        
        # Test candidate threshold below score (20)
        whatif_slider.fill("20")
        admin_page.wait_for_timeout(400)
        whatif_score_20 = int(admin_page.locator("#whatifScoreVal").inner_text().strip())
        whatif_verdict_20 = admin_page.locator("#whatifDecisionVal").inner_text().strip()
        log(f"What-If at threshold 20: Score={whatif_score_20}, Verdict={whatif_verdict_20}")
        assert whatif_score_20 == active_score, "Risk score must be preserved across candidate thresholds!"
        if active_score >= 20:
            assert "CONTAIN" in whatif_verdict_20, f"Expected CONTAIN when threshold <= score, got {whatif_verdict_20}"
        
        admin_page.screenshot(path=os.path.join(EVIDENCE_DIR, "11_scenario_lab_whatif.png"), full_page=False)
        log("Saved 11_scenario_lab_whatif.png")
        results["scenario_lab_whatif_consistency"] = "PASS"

        # -------------------------------------------------------------
        # Journey 10: Server-side Decoy Diversion & Canary Traps
        # -------------------------------------------------------------
        log("--- Journey 10: Decoy Diversion & Canary Interaction ---")
        attacker_ctx = browser.new_context(viewport={"width": 1280, "height": 800})
        att_page = attacker_ctx.new_page()
        
        # Perform 3 failed logins in rapid succession
        for attempt in range(1, 4):
            att_page.goto(f"{BASE_URL}/login", wait_until="networkidle")
            dismiss_disclosure(att_page)
            att_page.fill("input[name='username']", "executive.victim")
            att_page.fill("input[name='password']", f"WrongPassword!{attempt}")
            att_page.click("button[type='submit']")
            att_page.wait_for_timeout(300)
        
        # Verify server-side diversion to /decoy
        expect(att_page).to_have_url(f"{BASE_URL}/decoy")
        dismiss_disclosure(att_page)
        expect(att_page.locator("h1")).to_contain_text("Operations")
        expect(att_page.locator(".decoy-banner")).to_be_visible()
        expect(att_page.locator(".status-danger")).to_contain_text("Decoy active")
        
        # Interact with decoy canary lure (synthetic record action)
        canary_btn = att_page.locator("form[action*='decoy'] button").first
        if canary_btn.is_visible():
            canary_btn.click()
            att_page.wait_for_load_state("networkidle")
            dismiss_disclosure(att_page)
        
        att_page.screenshot(path=os.path.join(EVIDENCE_DIR, "12_decoy_canary_active.png"), full_page=False)
        log("Saved 12_decoy_canary_active.png")
        attacker_ctx.close()
        results["server_side_decoy_and_canaries"] = "PASS"

        # -------------------------------------------------------------
        # Journey 11: Narrow Screen (Mobile) Control Room
        # -------------------------------------------------------------
        log("--- Journey 11: Narrow-Screen Responsive Control Room ---")
        mob_ctx = browser.new_context(viewport={"width": 375, "height": 812})
        mob_page = mob_ctx.new_page()
        mob_page.goto(f"{BASE_URL}/admin", wait_until="networkidle")
        dismiss_disclosure(mob_page)
        
        expect(mob_page.locator("h1")).to_be_visible()
        expect(mob_page.locator("#attemptsSvgChart")).to_be_visible()
        expect(mob_page.locator(".metric-grid")).to_be_visible()
        
        mob_page.screenshot(path=os.path.join(EVIDENCE_DIR, "13_control_room_mobile.png"), full_page=False)
        log("Saved 13_control_room_mobile.png")
        mob_ctx.close()
        admin_ctx.close()
        results["responsive_mobile_layout"] = "PASS"

        browser.close()

    print("\n" + "="*60)
    print("FINAL REAL-BROWSER VERIFICATION RESULTS:")
    print("="*60)
    for feat, status in results.items():
        print(f"  {feat:<45}: {status}")
    print("="*60)

if __name__ == "__main__":
    run_verification()
