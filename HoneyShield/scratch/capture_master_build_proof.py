"""
Captures visual proof and export samples for HoneyShield Master Build:
- landing_page.png
- desktop_control_room.png
- session_investigation.png
- mobile_view.png
- sample_export.json & sample_export.csv
"""
import json
import urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright

BASE_URL = "http://127.0.0.1:5000"
ARTIFACTS_DIR = Path("artifacts/master_build")
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        # 1. Landing Page (1440x900)
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.goto(f"{BASE_URL}/", wait_until="networkidle")
        page.wait_for_timeout(500)
        page.screenshot(path=str(ARTIFACTS_DIR / "landing_page.png"), full_page=False)
        print("Captured landing_page.png")

        # 2. Control Room Desktop View (1440x900)
        # Ensure at least one suspicious scenario has been run so the dashboard is rich with data
        req = urllib.request.Request(f"{BASE_URL}/admin/simulate/suspicious", method="POST")
        try:
            urllib.request.urlopen(req)
        except Exception as e:
            print("Simulation trigger notice:", e)

        page.goto(f"{BASE_URL}/admin", wait_until="networkidle")
        page.wait_for_selector(".distribution-bar")
        page.wait_for_selector("#attemptsChartCard")
        page.wait_for_timeout(1000)
        page.screenshot(path=str(ARTIFACTS_DIR / "desktop_control_room.png"), full_page=False)
        print("Captured desktop_control_room.png")

        # 3. Session Investigation Page (1440x900)
        resp = urllib.request.urlopen(f"{BASE_URL}/api/events?limit=1")
        data = json.loads(resp.read().decode("utf-8"))
        sid = data["events"][0]["session_key"] if data.get("events") else None
        if not sid:
            resp2 = urllib.request.urlopen(f"{BASE_URL}/api/metrics")
            m_data = json.loads(resp2.read().decode("utf-8"))
            sid = "demo-session-inspect"

        page.goto(f"{BASE_URL}/admin/session/{sid}", wait_until="networkidle")
        page.wait_for_selector(".attack-path-pipeline, .flight-recorder-panel")
        page.wait_for_timeout(800)
        page.screenshot(path=str(ARTIFACTS_DIR / "session_investigation.png"), full_page=False)
        print("Captured session_investigation.png")

        # 4. Mobile View (390x844)
        mobile_page = browser.new_page(viewport={"width": 390, "height": 844})
        mobile_page.goto(f"{BASE_URL}/admin", wait_until="networkidle")
        mobile_page.wait_for_timeout(800)
        mobile_page.screenshot(path=str(ARTIFACTS_DIR / "mobile_view.png"), full_page=False)
        print("Captured mobile_view.png")

        # 5. Download Export Samples
        json_req = urllib.request.urlopen(f"{BASE_URL}/admin/session/{sid}/export?format=json")
        json_content = json_req.read().decode("utf-8")
        (ARTIFACTS_DIR / "sample_export.json").write_text(json_content, encoding="utf-8")

        csv_req = urllib.request.urlopen(f"{BASE_URL}/admin/session/{sid}/export?format=csv")
        csv_content = csv_req.read().decode("utf-8")
        (ARTIFACTS_DIR / "sample_export.csv").write_text(csv_content, encoding="utf-8")
        print("Generated sample_export.json and sample_export.csv")

        browser.close()


if __name__ == "__main__":
    main()
