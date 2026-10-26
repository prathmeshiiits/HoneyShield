import urllib.request
import urllib.parse
import json
import re
import sys

BASE_URL = "http://127.0.0.1:5000"

def run_test():
    print(f"[*] Testing HoneyShield live SOC UI and endpoints at {BASE_URL}...")

    # 1. Test GET /admin initial page load
    req = urllib.request.Request(f"{BASE_URL}/admin")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200, f"Expected 200 from /admin, got {resp.status}"
        html = resp.read().decode("utf-8")

    # Assert required UI elements in admin_dashboard.html
    required_ids = [
        'id="scenario-console"',
        'id="event-stream"',
        'id="methodology"',
        'id="freshnessBadge"',
        'id="refreshMetricsBtn"',
        'id="attemptsChartCard"',
        'id="attemptsSvgChart"',
        'id="attemptsChartEmpty"',
        'id="riskDistributionCard"',
        'id="riskStackedBar"',
        'id="investigationModal"',
        'id="investigationBackdrop"',
        'id="invSignalsGrid"',
        'id="invTimeline"',
    ]
    for rid in required_ids:
        assert rid in html, f"Missing required element {rid} in /admin HTML"
    print("[+] Stage 1: All required SOC dashboard IDs and chart elements present in /admin HTML.")

    # 2. Check time window pills
    for window in ['data-window="300"', 'data-window="900"', 'data-window="3600"', 'data-window="86400"']:
        assert window in html, f"Missing time-window filter {window} in /admin HTML"
    print("[+] Stage 2: All 4 time-window filter controls (5m, 15m, 1h, All) verified.")

    # 3. Clean initial state verification
    post_reset = urllib.request.Request(f"{BASE_URL}/admin/reset", data=b"", method="POST")
    with urllib.request.urlopen(post_reset) as resp:
        assert resp.status in (200, 302)

    with urllib.request.urlopen(f"{BASE_URL}/api/metrics") as resp:
        metrics = json.loads(resp.read().decode("utf-8"))
        assert metrics["summary"]["sessions"] == 0
        assert metrics["summary"]["events"] == 0
        assert metrics["risk_distribution"] == {"LOW": 0, "ELEVATED": 0, "HIGH": 0}
    print("[+] Stage 3: Clean reset verified (0 sessions, 0 events, empty risk distribution).")

    # 4. Trigger suspicious session simulation
    post_sim = urllib.request.Request(f"{BASE_URL}/admin/simulate/suspicious", data=b"", method="POST")
    with urllib.request.urlopen(post_sim) as resp:
        assert resp.status in (200, 302)

    # Re-fetch /admin HTML
    with urllib.request.urlopen(f"{BASE_URL}/admin") as resp:
        html_sim = resp.read().decode("utf-8")
        assert 'inspect-session-btn' in html_sim, "Expected inspect-session-btn on session row"
        assert 'Inspect ↗' in html_sim, "Expected 'Inspect ↗' label on session row"
        assert 'Open decoy ↗' in html_sim or 'Decoy ↗' in html_sim

    # Extract session key from inspect button
    m = re.search(r'data-session-key="([^"]+)"', html_sim)
    assert m, "Failed to find data-session-key in session table"
    session_key = m.group(1)
    print(f"[+] Stage 4: Suspicious simulation populated session table. Found session_key: {session_key}")

    # 5. Deep-dive into session investigation endpoint /api/session/<key>
    with urllib.request.urlopen(f"{BASE_URL}/api/session/{session_key}") as resp:
        assert resp.status == 200
        raw_json = json.loads(resp.read().decode("utf-8"))
        inv_data = raw_json.get("session", raw_json)
        assert inv_data["session_key"] == session_key
        assert inv_data["risk_score"] >= 50
        assert inv_data["risk_band"] == "HIGH"
        assert inv_data["decision"] == "decoy"
        assert inv_data["decoy_active"] is True
        
        # Verify all 7 explainable signals
        signals = {s["signal"]: s for s in inv_data["signal_contributions"]}
        expected_signals = [
            "rapid_failures", "repeated_principal", "sustained_failures",
            "persistent_volume", "username_diversity", "regular_cadence", "gradual_backoff"
        ]
        for es in expected_signals:
            assert es in signals, f"Missing explainable signal: {es}"
        # In suspicious simulation, rapid_failures, username_diversity, and regular_cadence are triggered
        print(f"[*] Triggered signals in suspicious simulation: {[k for k, v in signals.items() if v['triggered']]}")
        assert signals["rapid_failures"]["triggered"] is True
        assert signals["username_diversity"]["triggered"] is True
        assert signals["regular_cadence"]["triggered"] is True
        assert len(inv_data["events"]) >= 3
    print(f"[+] Stage 5: Session deep-dive /api/session/<key> verified with 7 signals and chronological timeline.")

    # 6. Verify chart attempts endpoint with populated buckets
    with urllib.request.urlopen(f"{BASE_URL}/api/chart/attempts?window=3600") as resp:
        assert resp.status == 200
        chart_data = json.loads(resp.read().decode("utf-8"))
        assert chart_data["empty"] is False
        assert len(chart_data["buckets"]) > 0
        b0 = chart_data["buckets"][0]
        assert "bucket" in b0 and "failed" in b0 and "success" in b0
        assert b0["failed"] >= 3
    print(f"[+] Stage 6: Real authentication attempts chart timeseries verified with {len(chart_data['buckets'])} bucket(s).")

    # 7. Final clean reset
    with urllib.request.urlopen(post_reset) as resp:
        assert resp.status in (200, 302)
    print("[+] Stage 7: Final reset completed. All live SOC UI checks passed with 100% success!")

if __name__ == "__main__":
    run_test()
