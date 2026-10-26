# HoneyShield Chart Failure Investigation & Concrete Evidence Report

## 1. Executive Summary
An evidence-based investigation was conducted on the running HoneyShield application at `http://127.0.0.1:5000` using direct SQLite database inspection, live HTTP endpoint probing, and headless Playwright Chromium browser diagnostics.

Two primary defects were identified:
1. **Completely Blank "Authentication attempts over time" Chart**: The browser console revealed an uncaught parsing exception: `Uncaught SyntaxError: Unexpected token 'catch'` at `static/js/app.js:719`. This was caused by an unclosed `if (!resp.ok) {` statement at line 583 that omitted its closing curly brace `}`. Because the syntax error halted JavaScript evaluation during file parsing, the `DOMContentLoaded` listener was never registered, `loadAttemptsChart()` was never called, and the `<svg id="attemptsSvgChart">` element remained completely empty (0 child nodes). Furthermore, Content Security Policy (`style-src 'self'`) blocked inline SVG and element style declarations.
2. **Risk-Distribution Right-Hand Panel Clipping**: At viewport widths between 1024px and 1150px (typical laptop resolutions or snapped windows), `.soc-charts-grid` retained a two-column layout (`minmax(0, 1.4fr) minmax(360px, 0.86fr)`). In conjunction with `.panel { overflow: hidden }` and fixed-column child grids (`.distribution-legend { grid-template-columns: repeat(3, 1fr) }` and `.heuristic-chip-grid { grid-template-columns: 1fr 1fr }`), the right card (`#riskDistributionCard`) suffered internal content overflow (`scrollWidth = 387px` vs `clientWidth = 371px`), visibly clipping the right edge of the heuristic chips and legend tags.

---

## 2. Phase 2 Concrete Evidence

### A. Database Evidence
- **Database File**: `data/honeyshield.sqlite3` (57,344 bytes).
- **Stored Sessions**: 10 total sessions in SQLite:
  - 3 non-isolated sessions (`is_isolated = 0`):
    - `47a1b20b96df487bbcfab0e59819ca76`: `risk_score = 0`, `risk_band = LOW`, `is_simulated = 0`
    - `71d72f176e3a4aa9a073c974309ab100`: `risk_score = 30`, `risk_band = LOW`, `is_simulated = 0`
    - `sim-suspicious-989775d148de`: `risk_score = 70`, `risk_band = HIGH`, `is_simulated = 1`
  - 7 isolated scenario lab sessions (`is_isolated = 1`).
- **Stored Events**:
  - Non-isolated events (`is_isolated = 0`): 12 authentication attempts.
    - `login_failed`: 9 attempts (4 organic browser + 5 simulated demo).
    - `login_success`: 3 attempts (all organic browser).
- **Timestamps**:
  - ISO-8601 UTC with timezone offset format: `YYYY-MM-DDTHH:MM:SS.mmm+00:00` (e.g., `2026-10-26T20:16:25.045+00:00`).
  - Stored timestamps are consistent UTC across all rows.

### B. Backend API Evidence
- **Endpoint**: `GET /api/chart/attempts?window=3600`
- **HTTP Status**: `200 OK`
- **Response Payload**:
  ```json
  {
    "status": "ok",
    "window_seconds": 3600,
    "empty": false,
    "total_attempts": 12,
    "total_failed": 9,
    "total_success": 3,
    "buckets": [
      {
        "bucket": "2026-10-26T20:12:00Z",
        "browser_failed": 1,
        "browser_success": 1,
        "simulated_failed": 5,
        "simulated_success": 0,
        "failed": 6,
        "success": 1,
        "total": 7
      },
      {
        "bucket": "2026-10-26T20:16:00Z",
        "browser_failed": 2,
        "browser_success": 0,
        "simulated_failed": 0,
        "simulated_success": 0,
        "failed": 2,
        "success": 0,
        "total": 2
      },
      {
        "bucket": "2026-10-26T20:17:00Z",
        "browser_failed": 1,
        "browser_success": 2,
        "simulated_failed": 0,
        "simulated_success": 0,
        "failed": 1,
        "success": 2,
        "total": 3
      }
    ]
  }
  ```
- **Finding**: The backend route and query are functioning accurately and return valid chronological bucket data. However, the frontend never processed this payload due to the JavaScript parse error.

### C. Browser Evidence (Playwright Headless Chromium)
- **Uncaught Page Error**:
  ```
  [pageerror] Unexpected token 'catch' (static/js/app.js:719)
  ```
- **Console Security Violations**:
  ```
  [error] Applying inline style violates the following Content Security Policy directive 'style-src 'self''.
  ```
- **Network Trace**:
  - `GET /static/css/style.css` -> `200`
  - `GET /static/js/app.js` -> `200`
  - Notice `/api/chart/attempts` was **never requested** by the browser.
- **DOM Inspection of `#attemptsSvgChart`**:
  - `visible`: `true`
  - `bounding_box`: `{'width': 766.47, 'height': 190.0}`
  - `children.length`: `0` (completely empty SVG element, showing only fallback comment `<!-- Dynamically populated or rendered via JS -->`)
- **Visual Inspection of `#riskDistributionCard`**:
  - At 1060px viewport: Card `clientWidth` is 371px, but `scrollWidth` is 387px. Because `.panel` defines `overflow: hidden`, 16px of horizontal content on the right side is clipped.

---

## 3. Root Cause Conclusion
1. **Chart Failure**: Unclosed brace on line 583 of `static/js/app.js` broke JS parsing. Because the SVG is only rendered client-side, the chart remained blank. In addition, lack of `'unsafe-inline'` in `style-src` prevented dynamic tooltip/bar styling.
2. **Clipping**: Rigid `repeat(3, 1fr)` and `1fr 1fr` subgrids inside `#riskDistributionCard` coupled with an overly low responsive breakpoint (1024px) for `.soc-charts-grid` caused clipping on viewports between 1024px and 1150px.
