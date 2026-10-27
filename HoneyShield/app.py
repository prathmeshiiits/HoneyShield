"""HoneyShield: a local-only, behavioural honeypot demonstration."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import sqlite3
import sys
import uuid
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    Response,
    abort,
    flash,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from risk_engine import (
    DEFAULT_HIGH_RISK_THRESHOLD,
    assess_risk,
    band_from_score,
    get_signal_contributions,
    score_from_failures,
)

ROOT_DIR = Path(__file__).resolve().parent
DEMO_USERNAME = "demo"
DEMO_PASSWORD = "ShieldDemo!2026"

SCENARIO_DEFINITIONS: dict[str, dict[str, Any]] = {
    "normal_user": {
        "title": "Normal Successful User",
        "category": "BENIGN",
        "ground_truth": "ALLOW",
        "description": "Legitimate enterprise user entering valid credentials on first attempt without anomalous delays or retries.",
        "expected_score_band": "0 / LOW",
        "expected_decoy": False,
        "signals_expected": ["clean_session (0)"],
    },
    "forgetful_user": {
        "title": "Forgetful User (Typo & Pause Recovery)",
        "category": "BENIGN",
        "ground_truth": "ALLOW",
        "description": "Plausible human typo on attempt 1, followed by a 20-second pause to recall password, then successful authentication.",
        "expected_score_band": "0 / LOW",
        "expected_decoy": False,
        "signals_expected": ["human_recovery_pause"],
    },
    "rapid_failures": {
        "title": "Rapid Repeated Failures (Brute Force)",
        "category": "MALICIOUS",
        "ground_truth": "CONTAIN",
        "description": "High-velocity automated brute-force attack submitting 3 rapid failed attempts against the same targeted account within 5 seconds.",
        "expected_score_band": "50 / HIGH",
        "expected_decoy": True,
        "signals_expected": ["rapid_failures (+30)", "repeated_principal (+20)"],
    },
    "regular_cadence": {
        "title": "Regular-Cadence Scripted Attempts",
        "category": "MALICIOUS",
        "ground_truth": "CONTAIN",
        "description": "Programmed script firing 4 failed attempts at mathematically periodic 2.0-second cadence (CV <= 0.05, mean <= 5s).",
        "expected_score_band": "85 / HIGH",
        "expected_decoy": True,
        "signals_expected": ["rapid_failures (+30)", "repeated_principal (+20)", "regular_cadence (+20)", "sustained_failures (+15)"],
    },
    "credential_sweep": {
        "title": "Username Sweep (Credential Spraying)",
        "category": "MALICIOUS",
        "ground_truth": "CONTAIN",
        "description": "Spraying attempts rotating through 4 distinct corporate account names within 60 seconds to evade per-account lockouts.",
        "expected_score_band": "50 / HIGH",
        "expected_decoy": True,
        "signals_expected": ["rapid_failures (+30)", "username_diversity (+20)"],
    },
    "boundary_below": {
        "title": "Policy Boundary: Immediately Below Threshold (2 Failures)",
        "category": "BOUNDARY_BENIGN",
        "ground_truth": "ALLOW",
        "description": "2 rapid failures against a single username. Below the 3-failure policy trigger limit; score remains 0.",
        "expected_score_band": "0 / LOW",
        "expected_decoy": False,
        "signals_expected": ["sub_threshold_volume"],
    },
    "boundary_at": {
        "title": "Policy Boundary: Exactly At Threshold (3 Failures)",
        "category": "BOUNDARY_MALICIOUS",
        "ground_truth": "CONTAIN",
        "description": "Exactly 3 rapid failures against a targeted username. Evaluated risk reaches 50 (HIGH threshold); decoy triggers.",
        "expected_score_band": "50 / HIGH",
        "expected_decoy": True,
        "signals_expected": ["rapid_failures (+30)", "repeated_principal (+20)"],
    },
    "boundary_above": {
        "title": "Policy Boundary: Immediately Above Threshold (4 Failures)",
        "category": "BOUNDARY_MALICIOUS",
        "ground_truth": "CONTAIN",
        "description": "4 sustained failures against a targeted username. Score reaches 65 (HIGH threshold); decoy triggers.",
        "expected_score_band": "65 / HIGH",
        "expected_decoy": True,
        "signals_expected": ["rapid_failures (+30)", "repeated_principal (+20)", "sustained_failures (+15)"],
    },
}


# Runtime paths are anchored to this file so the project can be moved as a folder.
def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_time(value: datetime | None = None) -> str:
    return (value or utc_now()).astimezone(timezone.utc).isoformat(timespec="milliseconds")


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def connect_database(path: str | Path) -> sqlite3.Connection:
    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_database(app: Flask) -> None:
    """Create schema and seed the demo account idempotently."""
    with closing(connect_database(app.config["DATABASE"])) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                session_key TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                risk_score INTEGER NOT NULL DEFAULT 0,
                risk_band TEXT NOT NULL DEFAULT 'LOW',
                decoy_active INTEGER NOT NULL DEFAULT 0,
                is_simulated INTEGER NOT NULL DEFAULT 0,
                authenticated INTEGER NOT NULL DEFAULT 0,
                scenario TEXT NOT NULL DEFAULT 'browser',
                risk_reasons TEXT NOT NULL DEFAULT '[]',
                is_isolated INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_key TEXT NOT NULL,
                event_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                interval_seconds REAL,
                username_fingerprint TEXT,
                details_json TEXT NOT NULL DEFAULT '{}',
                is_isolated INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(session_key) REFERENCES sessions(session_key) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_events_session_time
                ON events(session_key, event_at);
            CREATE INDEX IF NOT EXISTS idx_events_type_time
                ON events(event_type, event_at);
            """
        )
        # Idempotent migration for older local demo databases.
        session_columns = {row["name"] for row in conn.execute("PRAGMA table_info(sessions)").fetchall()}
        if "authenticated" not in session_columns:
            conn.execute("ALTER TABLE sessions ADD COLUMN authenticated INTEGER NOT NULL DEFAULT 0")
        if "is_isolated" not in session_columns:
            conn.execute("ALTER TABLE sessions ADD COLUMN is_isolated INTEGER NOT NULL DEFAULT 0")

        event_columns = {row["name"] for row in conn.execute("PRAGMA table_info(events)").fetchall()}
        if "is_isolated" not in event_columns:
            conn.execute("ALTER TABLE events ADD COLUMN is_isolated INTEGER NOT NULL DEFAULT 0")

        # The application stores a salted password hash; the demo password is never stored.
        conn.execute(
            "INSERT OR IGNORE INTO users(username, password_hash, created_at) VALUES (?, ?, ?)",
            (DEMO_USERNAME, generate_password_hash(DEMO_PASSWORD, method="scrypt"), iso_time()),
        )
        conn.commit()

        # Fallback auto-seed: If running in production (not testing) and sessions table is empty,
        # restore historical baseline data so the Control Room always remembers full history on Render.
        if not app.config.get("TESTING", False):
            try:
                sessions_count = conn.execute("SELECT COUNT(*) FROM sessions WHERE is_isolated = 0").fetchone()[0]
                if sessions_count == 0:
                    seed_file = ROOT_DIR / "data" / "baseline_seed.sqlite3"
                    if seed_file.exists():
                        with sqlite3.connect(str(seed_file)) as seed_conn:
                            seed_conn.row_factory = sqlite3.Row
                            seed_sessions = seed_conn.execute("SELECT * FROM sessions WHERE is_isolated = 0").fetchall()
                            seed_events = seed_conn.execute("SELECT * FROM events WHERE is_isolated = 0").fetchall()
                            for s in seed_sessions:
                                conn.execute(
                                    """INSERT OR IGNORE INTO sessions
                                       (session_key, created_at, updated_at, risk_score, risk_band, decoy_active,
                                        is_simulated, authenticated, scenario, risk_reasons, is_isolated)
                                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                                    (
                                        s["session_key"], s["created_at"], s["updated_at"], s["risk_score"], s["risk_band"],
                                        s["decoy_active"], s["is_simulated"], s["authenticated"], s["scenario"],
                                        s["risk_reasons"], s["is_isolated"]
                                    ),
                                )
                            for e in seed_events:
                                conn.execute(
                                    """INSERT INTO events
                                       (session_key, event_at, event_type, interval_seconds,
                                        username_fingerprint, details_json, is_isolated)
                                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                                    (
                                        e["session_key"], e["event_at"], e["event_type"], e["interval_seconds"],
                                        e["username_fingerprint"], e["details_json"], e["is_isolated"]
                                    ),
                                )
                            conn.commit()
            except Exception:
                pass


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get(
            "HONEYSHIELD_SECRET_KEY", "development-only-change-before-deployment"
        ),
        DATABASE=str(ROOT_DIR / "data" / "honeyshield.sqlite3"),
        HIGH_RISK_THRESHOLD=int(os.environ.get("HONEYSHIELD_HIGH_RISK_THRESHOLD", DEFAULT_HIGH_RISK_THRESHOLD)),
        REPEATED_FAILURES_POLICY_LIMIT=int(os.environ.get("HONEYSHIELD_REPEATED_FAILURES_LIMIT", 3)),
        RISK_WINDOW_SECONDS=180,
        DEMO_MODE=True,
        TESTING=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    if test_config:
        app.config.update(test_config)

    if not 1 <= int(app.config["HIGH_RISK_THRESHOLD"]) <= 100:
        raise ValueError("HIGH_RISK_THRESHOLD must be between 1 and 100")
    init_database(app)

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'sha256-AvTVHBcNofa3IlokSYvtLncC8olGf+LRM+Eh8Ctnwr4='; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'self';"
        )
        return response

    @app.context_processor
    def inject_shared_context() -> dict[str, bool]:
        sid = session.get("hs_sid")
        state = get_db().execute(
            "SELECT authenticated FROM sessions WHERE session_key = ?", (sid,)
        ).fetchone() if sid else None
        return {"is_authenticated": bool(state and state["authenticated"])}

    @app.teardown_appcontext
    def close_db(_error: BaseException | None = None) -> None:
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def get_db() -> sqlite3.Connection:
        if "db" not in g:
            g.db = connect_database(app.config["DATABASE"])
        return g.db

    def current_sid() -> str:
        sid = session.get("hs_sid")
        if not sid:
            sid = uuid.uuid4().hex
            session["hs_sid"] = sid
        return str(sid)

    def fingerprint_username(sid: str, username: str) -> str:
        # Per-session keyed fingerprint: username is never stored in the event stream.
        key = (str(app.config["SECRET_KEY"]) + ":" + sid).encode("utf-8")
        message = username.strip().casefold().encode("utf-8", errors="replace")
        return hmac.new(key, message, hashlib.sha256).hexdigest()[:24]

    def ensure_session(
        conn: sqlite3.Connection,
        sid: str,
        is_simulated: bool = False,
        scenario: str = "browser",
        is_isolated: bool = False,
    ) -> None:
        now = iso_time()
        conn.execute(
            """INSERT OR IGNORE INTO sessions
               (session_key, created_at, updated_at, risk_score, risk_band, decoy_active,
                is_simulated, scenario, risk_reasons, is_isolated)
               VALUES (?, ?, ?, 0, 'LOW', 0, ?, ?, '[]', ?)""",
            (sid, now, now, int(is_simulated), scenario, int(is_isolated)),
        )

    def load_recent_failures(conn: sqlite3.Connection, sid: str) -> list[sqlite3.Row]:
        cutoff = iso_time(utc_now() - timedelta(seconds=int(app.config["RISK_WINDOW_SECONDS"])))
        return conn.execute(
            """SELECT event_at, interval_seconds, username_fingerprint
               FROM events WHERE session_key = ? AND event_type = 'login_failed'
               AND event_at >= ? ORDER BY event_at ASC, id ASC""",
            (sid, cutoff),
        ).fetchall()

    def calculate_risk(conn: sqlite3.Connection, sid: str) -> tuple[int, str, list[str]]:
        failures = [dict(row) for row in load_recent_failures(conn, sid)]
        return score_from_failures(failures, threshold=int(app.config["HIGH_RISK_THRESHOLD"]))

    def append_event_raw(
        conn: sqlite3.Connection,
        sid: str,
        event_type: str,
        details: dict[str, Any] | None = None,
        event_at: datetime | None = None,
        interval_seconds: float | None = None,
        username_fingerprint: str | None = None,
        is_isolated: int = 0,
    ) -> None:
        safe_details = details or {}
        conn.execute(
            """INSERT INTO events(session_key, event_at, event_type, interval_seconds,
                                 username_fingerprint, details_json, is_isolated)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                sid,
                iso_time(event_at),
                event_type,
                interval_seconds,
                username_fingerprint,
                json.dumps(safe_details, separators=(",", ":"), ensure_ascii=True),
                int(is_isolated),
            ),
        )

    def record_event(
        sid: str,
        event_type: str,
        *,
        details: dict[str, Any] | None = None,
        username_fingerprint: str | None = None,
        event_at: datetime | None = None,
        is_simulated: bool = False,
        scenario: str = "browser",
        is_isolated: bool = False,
    ) -> dict[str, Any]:
        conn = get_db()
        ensure_session(conn, sid, is_simulated=is_simulated, scenario=scenario, is_isolated=is_isolated)
        timestamp = event_at or utc_now()
        interval: float | None = None
        if event_type == "login_failed":
            previous = conn.execute(
                "SELECT event_at FROM events WHERE session_key = ? AND event_type = 'login_failed' ORDER BY event_at DESC, id DESC LIMIT 1",
                (sid,),
            ).fetchone()
            if previous:
                interval = max(0.0, (timestamp - parse_time(previous["event_at"])).total_seconds())
        append_event_raw(
            conn,
            sid,
            event_type,
            details=details,
            event_at=timestamp,
            interval_seconds=interval,
            username_fingerprint=username_fingerprint,
            is_isolated=int(is_isolated),
        )
        recent_failures = [dict(row) for row in load_recent_failures(conn, sid)]
        policy_limit = int(app.config.get("REPEATED_FAILURES_POLICY_LIMIT", 3))
        assessment = assess_risk(
            recent_failures,
            threshold=int(app.config["HIGH_RISK_THRESHOLD"]),
            policy_limit=policy_limit,
        )
        score = assessment["score"]
        band = assessment["band"]
        reasons = assessment["reasons"]
        policy_triggered = assessment["policy_triggered"]

        row = conn.execute("SELECT decoy_active FROM sessions WHERE session_key = ?", (sid,)).fetchone()
        activate_now = bool(assessment["activate_decoy"] and row and not row["decoy_active"])
        conn.execute(
            """UPDATE sessions SET updated_at = ?, risk_score = ?, risk_band = ?,
               risk_reasons = ?, decoy_active = CASE WHEN ? THEN 1 ELSE decoy_active END,
               authenticated = CASE WHEN ? THEN 0 ELSE authenticated END
               WHERE session_key = ?""",
            (iso_time(timestamp), score, band, json.dumps(reasons), int(activate_now), int(activate_now), sid),
        )
        if activate_now:
            reason_text = (
                "Security policy triggered containment"
                if policy_triggered and score < int(app.config["HIGH_RISK_THRESHOLD"])
                else "Behavioural score reached the configured high-risk threshold"
            )
            append_event_raw(
                conn,
                sid,
                "decoy_activated",
                details={"reason": reason_text, "score": score},
                event_at=timestamp,
                is_isolated=int(is_isolated),
            )
        conn.commit()
        updated = conn.execute("SELECT * FROM sessions WHERE session_key = ?", (sid,)).fetchone()
        return dict(updated)

    def get_session(sid: str) -> dict[str, Any] | None:
        row = get_db().execute("SELECT * FROM sessions WHERE session_key = ?", (sid,)).fetchone()
        return dict(row) if row else None

    def session_events(sid: str, limit: int = 100) -> list[dict[str, Any]]:
        rows = get_db().execute(
            "SELECT * FROM events WHERE session_key = ? ORDER BY event_at DESC, id DESC LIMIT ?",
            (sid, limit),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            try:
                item["details"] = json.loads(item.pop("details_json"))
            except (ValueError, TypeError):
                item["details"] = {}
            result.append(item)
        return result

    def record_decoy_action(sid: str, action: str, simulated: bool = False, is_isolated: bool = False) -> None:
        allowed = {
            "open_record": ("decoy_record_opened", "Opened synthetic customer record"),
            "open_report": ("decoy_report_opened", "Opened synthetic activity report"),
            "admin_resource": ("decoy_admin_resource_attempted", "Attempted a synthetic admin resource"),
            "export_report": ("decoy_report_export_requested", "Requested a synthetic report export"),
            "download_backup": ("decoy_canary_backup_downloaded", "Canary object accessed: fake backup.sql download"),
            "view_api_key": ("decoy_canary_token_accessed", "Canary token accessed: fake AWS production key"),
            "backup_manifest": ("decoy_canary_backup_downloaded", "Canary downloaded: Backup Manifest"),
            "api_inventory": ("decoy_canary_token_accessed", "Canary token accessed: Synthetic API Inventory"),
            "privilege_report": ("decoy_canary_privilege_report_viewed", "Canary viewed: Quarterly Privilege Report"),
        }
        if action not in allowed:
            abort(400, description="Unsupported demo action")
        event_type, label = allowed[action]
        state = get_session(sid) or {}
        scenario = state.get("scenario", "suspicious" if simulated else "browser")
        effective_isolated = bool(state.get("is_isolated", is_isolated))
        record_event(
            sid,
            event_type,
            details={"action": action, "label": label, "source": "simulator" if simulated else "decoy-ui"},
            is_simulated=simulated,
            scenario=scenario,
            is_isolated=effective_isolated,
        )

    def run_demo_scenario(scenario: str, isolate: bool = False, run_id: str | None = None) -> dict[str, Any]:
        valid_scenarios = {
            "suspicious", "normal", "normal_user", "forgetful_user",
            "rapid_failures", "regular_cadence", "credential_sweep",
            "threshold_boundary", "boundary_below", "boundary_at", "boundary_above",
        }
        if scenario not in valid_scenarios:
            raise ValueError("Unknown demo scenario")

        suffix = run_id or uuid.uuid4().hex[:12]
        prefix = "iso-" if isolate else "sim-"
        sid = f"{prefix}{scenario[:10]}-{suffix}"

        conn = get_db()
        ensure_session(conn, sid, is_simulated=True, scenario=scenario, is_isolated=isolate)
        conn.commit()

        if scenario == "suspicious":
            # Exact original implementation preserved for baseline tests
            intervals = [0.80, 0.82, 0.79, 0.81, 0.80]
            base = utc_now() - timedelta(seconds=sum(intervals))
            current = base
            for index, interval in enumerate(intervals):
                if index:
                    current += timedelta(seconds=interval)
                principal = f"synthetic-user-{index + 1}@example.invalid"
                record_event(
                    sid,
                    "login_failed",
                    details={"source": "simulator", "attempt": index + 1},
                    username_fingerprint=fingerprint_username(sid, principal),
                    event_at=current,
                    is_simulated=True,
                    scenario=scenario,
                    is_isolated=isolate,
                )
            state = get_session(sid) or {}
            if state.get("decoy_active"):
                for action in ("open_record", "open_report", "admin_resource"):
                    record_decoy_action(sid, action, simulated=True, is_isolated=isolate)

        elif scenario in ("normal", "normal_user"):
            base = utc_now() - timedelta(seconds=2)
            record_event(
                sid,
                "login_success",
                details={"source": "simulator", "note": "Valid credentials on first attempt"},
                event_at=base,
                is_simulated=True,
                scenario=scenario,
                is_isolated=isolate,
            )

        elif scenario == "forgetful_user":
            base = utc_now() - timedelta(seconds=22)
            record_event(
                sid,
                "login_failed",
                details={"source": "simulator", "note": "one plausible typo"},
                username_fingerprint=fingerprint_username(sid, "demo"),
                event_at=base,
                is_simulated=True,
                scenario=scenario,
                is_isolated=isolate,
            )
            record_event(
                sid,
                "login_success",
                details={"source": "simulator", "note": "successful retry after pause"},
                event_at=base + timedelta(seconds=20),
                is_simulated=True,
                scenario=scenario,
                is_isolated=isolate,
            )

        elif scenario == "rapid_failures":
            intervals = [1.2, 1.4, 1.1]
            base = utc_now() - timedelta(seconds=sum(intervals))
            current = base
            for index, interval in enumerate(intervals):
                if index:
                    current += timedelta(seconds=interval)
                record_event(
                    sid,
                    "login_failed",
                    details={"source": "simulator", "attempt": index + 1, "pattern": "rapid_burst"},
                    username_fingerprint=fingerprint_username(sid, "demo"),
                    event_at=current,
                    is_simulated=True,
                    scenario=scenario,
                    is_isolated=isolate,
                )
            state = get_session(sid) or {}
            if state.get("decoy_active"):
                for action in ("open_record", "open_report", "admin_resource"):
                    record_decoy_action(sid, action, simulated=True, is_isolated=isolate)

        elif scenario == "regular_cadence":
            intervals = [2.00, 2.00, 2.01, 2.00]
            base = utc_now() - timedelta(seconds=sum(intervals))
            current = base
            for index, interval in enumerate(intervals):
                if index:
                    current += timedelta(seconds=interval)
                record_event(
                    sid,
                    "login_failed",
                    details={"source": "simulator", "attempt": index + 1, "pattern": "robotic_cadence"},
                    username_fingerprint=fingerprint_username(sid, "demo"),
                    event_at=current,
                    is_simulated=True,
                    scenario=scenario,
                    is_isolated=isolate,
                )
            state = get_session(sid) or {}
            if state.get("decoy_active"):
                for action in ("open_record", "open_report", "admin_resource"):
                    record_decoy_action(sid, action, simulated=True, is_isolated=isolate)

        elif scenario == "credential_sweep":
            principals = ["admin@internal.corp", "service@internal.corp", "devops@internal.corp", "secops@internal.corp"]
            intervals = [1.1, 2.9, 1.3]
            base = utc_now() - timedelta(seconds=6)
            current = base
            for index, principal in enumerate(principals):
                if index:
                    current += timedelta(seconds=intervals[index - 1])
                record_event(
                    sid,
                    "login_failed",
                    details={"source": "simulator", "attempt": index + 1, "pattern": "credential_sweep", "target": principal.split('@')[0]},
                    username_fingerprint=fingerprint_username(sid, principal),
                    event_at=current,
                    is_simulated=True,
                    scenario=scenario,
                    is_isolated=isolate,
                )
            state = get_session(sid) or {}
            if state.get("decoy_active"):
                for action in ("open_record", "open_report", "admin_resource"):
                    record_decoy_action(sid, action, simulated=True, is_isolated=isolate)

        elif scenario == "boundary_below":
            base = utc_now() - timedelta(seconds=3)
            record_event(
                sid,
                "login_failed",
                details={"source": "simulator", "attempt": 1, "note": "boundary sub-limit 1"},
                username_fingerprint=fingerprint_username(sid, "demo"),
                event_at=base,
                is_simulated=True,
                scenario=scenario,
                is_isolated=isolate,
            )
            record_event(
                sid,
                "login_failed",
                details={"source": "simulator", "attempt": 2, "note": "boundary sub-limit 2"},
                username_fingerprint=fingerprint_username(sid, "demo"),
                event_at=base + timedelta(seconds=1.2),
                is_simulated=True,
                scenario=scenario,
                is_isolated=isolate,
            )

        elif scenario in ("boundary_at", "threshold_boundary"):
            base = utc_now() - timedelta(seconds=4)
            record_event(
                sid,
                "login_failed",
                details={"source": "simulator", "attempt": 1, "note": "boundary attempt 1"},
                username_fingerprint=fingerprint_username(sid, "demo"),
                event_at=base,
                is_simulated=True,
                scenario=scenario,
                is_isolated=isolate,
            )
            record_event(
                sid,
                "login_failed",
                details={"source": "simulator", "attempt": 2, "note": "boundary attempt 2"},
                username_fingerprint=fingerprint_username(sid, "demo"),
                event_at=base + timedelta(seconds=1.2),
                is_simulated=True,
                scenario=scenario,
                is_isolated=isolate,
            )
            record_event(
                sid,
                "login_failed",
                details={"source": "simulator", "attempt": 3, "note": "boundary threshold trigger"},
                username_fingerprint=fingerprint_username(sid, "demo"),
                event_at=base + timedelta(seconds=2.4),
                is_simulated=True,
                scenario=scenario,
                is_isolated=isolate,
            )
            state = get_session(sid) or {}
            if state.get("decoy_active"):
                record_decoy_action(sid, "open_record", simulated=True, is_isolated=isolate)

        elif scenario == "boundary_above":
            base = utc_now() - timedelta(seconds=6)
            offsets = [0.0, 1.0, 3.8, 5.0]
            for i in range(4):
                record_event(
                    sid,
                    "login_failed",
                    details={"source": "simulator", "attempt": i + 1, "note": f"boundary escalation {i + 1}"},
                    username_fingerprint=fingerprint_username(sid, "demo"),
                    event_at=base + timedelta(seconds=offsets[i]),
                    is_simulated=True,
                    scenario=scenario,
                    is_isolated=isolate,
                )
            state = get_session(sid) or {}
            if state.get("decoy_active"):
                record_decoy_action(sid, "open_record", simulated=True, is_isolated=isolate)

        return {"session_key": sid, **(get_session(sid) or {}), "events": len(session_events(sid))}

    def run_scenario_benchmark_suite(threshold: int, isolate: bool = True) -> dict[str, Any]:
        test_cases = [
            "normal_user",
            "forgetful_user",
            "boundary_below",
            "boundary_at",
            "boundary_above",
            "rapid_failures",
            "regular_cadence",
            "credential_sweep",
        ]
        benchmark_run_id = uuid.uuid4().hex[:8]
        per_case_results = []
        tp = 0
        tn = 0
        fp = 0
        fn = 0

        for case_name in test_cases:
            res = run_demo_scenario(case_name, isolate=isolate, run_id=benchmark_run_id)
            meta = SCENARIO_DEFINITIONS.get(case_name, {})
            ground_truth = meta.get("ground_truth", "ALLOW")
            actual_decoy = bool(res.get("decoy_active"))
            actual_verdict = "CONTAIN" if actual_decoy else "ALLOW"
            matched = (actual_verdict == ground_truth)

            if ground_truth == "CONTAIN":
                if actual_decoy:
                    tp += 1
                    classification = "TP"
                else:
                    fn += 1
                    classification = "FN"
            else:
                if not actual_decoy:
                    tn += 1
                    classification = "TN"
                else:
                    fp += 1
                    classification = "FP"

            per_case_results.append({
                "scenario": case_name,
                "title": meta.get("title", case_name),
                "category": meta.get("category", "BENIGN"),
                "ground_truth": ground_truth,
                "session_key": res["session_key"],
                "score": res.get("risk_score", 0),
                "band": res.get("risk_band", "LOW"),
                "decoy_active": actual_decoy,
                "actual_verdict": actual_verdict,
                "classification": classification,
                "passed": matched,
                "events_count": res.get("events", 0),
                "description": meta.get("description", ""),
            })

        total_cases = len(test_cases)
        containment_rate = round((tp / (tp + fn)) * 100, 1) if (tp + fn) > 0 else 0.0
        false_positive_rate = round((fp / (fp + tn)) * 100, 1) if (fp + tn) > 0 else 0.0

        return {
            "run_id": benchmark_run_id,
            "evaluated_at": iso_time(),
            "threshold": threshold,
            "total_cases": total_cases,
            "true_positives": tp,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "containment_rate": containment_rate,
            "false_positive_rate": false_positive_rate,
            "all_passed": (fn == 0 and fp == 0),
            "results": per_case_results,
        }

    @app.route("/", methods=["GET", "POST"], endpoint="landing")
    def landing():
        sid = current_sid()
        active = get_session(sid)
        if active and active.get("decoy_active"):
            return redirect(url_for("decoy"))
        if request.method == "POST":
            return login()
        return render_template("landing.html", risk=active)

    @app.route("/login", methods=["GET", "POST"], endpoint="login")
    def login():
        sid = current_sid()
        active = get_session(sid)
        if active and active["decoy_active"]:
            return redirect(url_for("decoy"))
        if active and active.get("authenticated"):
            return redirect(url_for("user_dashboard"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if not username or not password or len(username) > 64 or len(password) > 128:
                flash("Enter a username and password within the allowed length.", "error")
                return render_template("login.html", risk=active), 400

            conn = get_db()
            user = conn.execute("SELECT password_hash FROM users WHERE username = ?", (username,)).fetchone()
            authenticated = bool(user and check_password_hash(user["password_hash"], password))
            if authenticated:
                # Do not let an active decoy session bypass the decoy by eventually guessing correctly.
                latest = get_session(sid)
                if latest and latest.get("decoy_active"):
                    record_event(sid, "login_diverted_to_decoy", details={"reason": "Active decoy session entered valid credentials"})
                    flash("The requested workspace is ready.", "info")
                    return redirect(url_for("decoy"))

                record_event(sid, "login_success", details={"outcome": "accepted"})
                conn.execute(
                    "UPDATE sessions SET authenticated = 1, updated_at = ? WHERE session_key = ?",
                    (iso_time(), sid),
                )
                conn.commit()
                return redirect(url_for("user_dashboard"))

            record_event(
                sid,
                "login_failed",
                details={"outcome": "rejected"},
                username_fingerprint=fingerprint_username(sid, username),
            )
            active = get_session(sid)
            if active and active["decoy_active"]:
                flash("The requested workspace is ready.", "info")
                return redirect(url_for("decoy"))
            flash("Sign-in was not successful. Check the local demo credentials and try again.", "error")
        return render_template("login.html", risk=get_session(sid))

    @app.get("/dashboard")
    def user_dashboard():
        sid = session.get("hs_sid")
        state = get_session(str(sid)) if sid else None
        if state and state["decoy_active"]:
            return redirect(url_for("decoy"))
        if not state or not state.get("authenticated"):
            return redirect(url_for("login"))
        resp = make_response(render_template("user_dashboard.html", demo_username=DEMO_USERNAME))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    @app.get("/logout")
    def logout():
        sid = session.get("hs_sid")
        if sid:
            conn = get_db()
            conn.execute(
                "UPDATE sessions SET authenticated = 0, decoy_active = 0, updated_at = ? WHERE session_key = ?",
                (iso_time(), str(sid)),
            )
            conn.commit()
            record_event(str(sid), "user_logged_out", details={"outcome": "session_terminated", "source": "browser"})
        session.pop("hs_sid", None)
        flash("You have signed out successfully. You have left the demo workspace.", "success")
        return redirect(url_for("landing"))

    @app.get("/decoy")
    def decoy():
        sid = current_sid()
        state = get_session(sid)
        if not state or not state["decoy_active"]:
            return redirect(url_for("login"))
        # Views are evidence too; timestamps and session association go into SQLite.
        record_event(sid, "decoy_dashboard_opened", details={"source": "browser"})
        return render_template(
            "decoy_dashboard.html",
            decoy_sid=sid,
            is_admin_view=False,
            events=session_events(sid),
        )

    @app.post("/decoy/action")
    def decoy_action():
        sid = current_sid()
        state = get_session(sid)
        if not state or not state["decoy_active"]:
            abort(403)
        record_decoy_action(sid, request.form.get("action", ""))
        flash("Synthetic interaction recorded for this session.", "success")
        return redirect(url_for("decoy"))

    def get_risk_distribution(
        conn: sqlite3.Connection,
        source: str = "",
        window_seconds: int = 0,
        session_filter: str = "",
        include_isolated: bool = False,
    ) -> dict[str, int]:
        where = "WHERE is_isolated = 0" if not include_isolated else "WHERE 1=1"
        params: list[Any] = []
        if session_filter:
            where += " AND session_key LIKE ?"
            params.append(f"%{session_filter[:32]}%")
        if source == "browser":
            where += " AND is_simulated = 0"
        elif source == "simulation":
            where += " AND is_simulated = 1"
        if window_seconds > 0:
            cutoff = iso_time(utc_now() - timedelta(seconds=window_seconds))
            where += " AND updated_at >= ?"
            params.append(cutoff)

        rows = conn.execute(
            f"SELECT risk_band, COUNT(*) as count FROM sessions {where} GROUP BY risk_band",
            params,
        ).fetchall()
        dist = {"LOW": 0, "ELEVATED": 0, "HIGH": 0}
        for row in rows:
            band = str(row["risk_band"]).upper()
            if band in dist:
                dist[band] = int(row["count"])
        return dist

    def get_metrics_summary(
        conn: sqlite3.Connection,
        band: str = "",
        source: str = "",
        window_seconds: int = 0,
        session_filter: str = "",
        include_isolated: bool = False,
    ) -> dict[str, Any]:
        s_where = "WHERE is_isolated = 0" if not include_isolated else "WHERE 1=1"
        s_params: list[Any] = []
        if band in {"LOW", "ELEVATED", "HIGH"}:
            s_where += " AND risk_band = ?"
            s_params.append(band)
        if session_filter:
            s_where += " AND session_key LIKE ?"
            s_params.append(f"%{session_filter[:32]}%")
        if source == "browser":
            s_where += " AND is_simulated = 0"
        elif source == "simulation":
            s_where += " AND is_simulated = 1"
        if window_seconds > 0:
            cutoff = iso_time(utc_now() - timedelta(seconds=window_seconds))
            s_where += " AND updated_at >= ?"
            s_params.append(cutoff)

        total_sessions = conn.execute(f"SELECT COUNT(*) FROM sessions {s_where}", s_params).fetchone()[0]
        suspicious_sessions = conn.execute(f"SELECT COUNT(*) FROM sessions {s_where} AND risk_score >= 35", s_params).fetchone()[0]
        decoy_sessions = conn.execute(f"SELECT COUNT(*) FROM sessions {s_where} AND decoy_active = 1", s_params).fetchone()[0]

        e_where = """
            FROM events e
            LEFT JOIN sessions s ON e.session_key = s.session_key
            WHERE e.is_isolated = 0
        """ if not include_isolated else """
            FROM events e
            LEFT JOIN sessions s ON e.session_key = s.session_key
            WHERE 1=1
        """
        e_params: list[Any] = []
        if band in {"LOW", "ELEVATED", "HIGH"}:
            e_where += " AND s.risk_band = ?"
            e_params.append(band)
        if session_filter:
            e_where += " AND e.session_key LIKE ?"
            e_params.append(f"%{session_filter[:32]}%")
        if source == "browser":
            e_where += " AND COALESCE(s.is_simulated, 0) = 0"
        elif source == "simulation":
            e_where += " AND COALESCE(s.is_simulated, 0) = 1"
        if window_seconds > 0:
            cutoff = iso_time(utc_now() - timedelta(seconds=window_seconds))
            e_where += " AND e.event_at >= ?"
            e_params.append(cutoff)

        total_events = conn.execute(f"SELECT COUNT(*) {e_where}", e_params).fetchone()[0]
        failed_attempts = conn.execute(f"SELECT COUNT(*) {e_where} AND e.event_type = 'login_failed'", e_params).fetchone()[0]
        successful_attempts = conn.execute(f"SELECT COUNT(*) {e_where} AND e.event_type = 'login_success'", e_params).fetchone()[0]
        canary_interactions = conn.execute(
            f"SELECT COUNT(*) {e_where} AND e.event_type LIKE 'decoy_%' AND e.event_type != 'decoy_activated'", e_params
        ).fetchone()[0]

        # Calculate risk distribution scoped to source/window/session
        dist = get_risk_distribution(
            conn,
            source=source,
            window_seconds=window_seconds,
            session_filter=session_filter,
            include_isolated=include_isolated,
        )
        if band in {"LOW", "ELEVATED", "HIGH"}:
            dist = {k: (dist[k] if k == band else 0) for k in dist}

        return {
            "sessions": total_sessions,
            "events": total_events,
            "failed_attempts": failed_attempts,
            "successful_attempts": successful_attempts,
            "total_attempts": failed_attempts + successful_attempts,
            "suspicious": suspicious_sessions,
            "low_sessions": dist["LOW"],
            "elevated_sessions": dist["ELEVATED"],
            "high_sessions": dist["HIGH"],
            "decoys": decoy_sessions,
            "interactions": canary_interactions,
            "time_window_seconds": int(app.config.get("RISK_WINDOW_SECONDS", 180)),
            "threshold": int(app.config.get("HIGH_RISK_THRESHOLD", 50)),
            "policy_limit": int(app.config.get("REPEATED_FAILURES_POLICY_LIMIT", 3)),
            "policy_version": "2.0.0",
        }


    def get_attempts_over_time(conn: sqlite3.Connection, window_seconds: int = 3600, include_isolated: bool = False, source: str = "") -> list[dict[str, Any]]:
        and_iso = "" if include_isolated else "AND e.is_isolated = 0"
        source_cond = ""
        if source == "browser":
            source_cond = "AND COALESCE(s.is_simulated, 0) = 0"
        elif source == "simulation":
            source_cond = "AND COALESCE(s.is_simulated, 0) = 1"

        if window_seconds <= 0 or window_seconds >= 604800:
            rows = conn.execute(
                f"""SELECT e.event_at, e.event_type, COALESCE(s.is_simulated, 0) as is_simulated
                   FROM events e
                   LEFT JOIN sessions s ON e.session_key = s.session_key
                   WHERE e.event_type IN ('login_failed', 'login_success') {and_iso} {source_cond}
                   ORDER BY e.event_at ASC, e.id ASC""",
            ).fetchall()
        else:
            cutoff = iso_time(utc_now() - timedelta(seconds=window_seconds))
            rows = conn.execute(
                f"""SELECT e.event_at, e.event_type, COALESCE(s.is_simulated, 0) as is_simulated
                   FROM events e
                   LEFT JOIN sessions s ON e.session_key = s.session_key
                   WHERE e.event_type IN ('login_failed', 'login_success') AND e.event_at >= ? {and_iso} {source_cond}
                   ORDER BY e.event_at ASC, e.id ASC""",
                (cutoff,),
            ).fetchall()
        if not rows:
            return []
        buckets: dict[str, dict[str, int]] = {}
        for row in rows:
            try:
                dt = parse_time(row["event_at"])
                bucket_key = dt.strftime("%Y-%m-%dT%H:%M:00Z")
            except Exception:
                bucket_key = str(row["event_at"])[:16] + ":00Z"
            if bucket_key not in buckets:
                buckets[bucket_key] = {
                    "failed": 0,
                    "success": 0,
                    "browser_failed": 0,
                    "browser_success": 0,
                    "simulated_failed": 0,
                    "simulated_success": 0,
                }
            is_sim = bool(row["is_simulated"])
            if row["event_type"] == "login_failed":
                buckets[bucket_key]["failed"] += 1
                if is_sim:
                    buckets[bucket_key]["simulated_failed"] += 1
                else:
                    buckets[bucket_key]["browser_failed"] += 1
            elif row["event_type"] == "login_success":
                buckets[bucket_key]["success"] += 1
                if is_sim:
                    buckets[bucket_key]["simulated_success"] += 1
                else:
                    buckets[bucket_key]["browser_success"] += 1

        return [
            {
                "bucket": k,
                "failed": v["failed"],
                "success": v["success"],
                "browser_failed": v["browser_failed"],
                "browser_success": v["browser_success"],
                "simulated_failed": v["simulated_failed"],
                "simulated_success": v["simulated_success"],
                "total": v["failed"] + v["success"],
            }
            for k, v in sorted(buckets.items())
        ]

    def get_filtered_events(
        conn: sqlite3.Connection,
        band: str = "",
        session_filter: str = "",
        event_type: str = "",
        is_simulated: int | None = None,
        limit: int = 60,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        base_query = """
            FROM events e
            LEFT JOIN sessions s ON e.session_key = s.session_key
            WHERE e.is_isolated = 0
        """
        params: list[Any] = []
        if band in {"LOW", "ELEVATED", "HIGH"}:
            base_query += " AND s.risk_band = ?"
            params.append(band)
        if session_filter:
            base_query += " AND e.session_key LIKE ?"
            params.append(f"%{session_filter[:32]}%")
        if event_type:
            base_query += " AND e.event_type = ?"
            params.append(event_type[:64])
        if is_simulated is not None:
            base_query += " AND s.is_simulated = ?"
            params.append(int(bool(is_simulated)))

        count_sql = "SELECT COUNT(*) " + base_query
        total = conn.execute(count_sql, params).fetchone()[0]

        safe_limit = max(1, min(200, int(limit)))
        safe_offset = max(0, int(offset))
        data_sql = f"""
            SELECT 
                e.id, e.session_key, e.event_at, e.event_type, e.interval_seconds,
                e.username_fingerprint, e.details_json,
                s.risk_score, s.risk_band, s.is_simulated
            {base_query}
            ORDER BY e.event_at DESC, e.id DESC
            LIMIT ? OFFSET ?
        """
        data_params = params + [safe_limit, safe_offset]
        rows = conn.execute(data_sql, data_params).fetchall()
        events = []
        for row in rows:
            item = dict(row)
            try:
                item["details"] = json.loads(item.pop("details_json", "{}"))
            except (ValueError, TypeError):
                item["details"] = {}
            safe_result = item["details"].get("outcome", item["details"].get("action", item["event_type"]))
            item["safe_result"] = safe_result
            item["reason"] = item["details"].get("label", item["details"].get("reason", item["details"].get("note", "")))
            item["is_simulated"] = bool(item.get("is_simulated"))
            events.append(item)
        return events, total

    def get_session_investigation(conn: sqlite3.Connection, sid: str) -> dict[str, Any] | None:
        session_row = conn.execute("SELECT * FROM sessions WHERE session_key = ?", (sid,)).fetchone()
        if not session_row:
            return None
        sess = dict(session_row)
        try:
            sess["reasons"] = json.loads(sess.pop("risk_reasons", "[]"))
        except (ValueError, TypeError):
            sess["reasons"] = []

        event_rows = conn.execute(
            """SELECT id, event_at, event_type, interval_seconds, username_fingerprint, details_json
               FROM events WHERE session_key = ? ORDER BY event_at ASC, id ASC""",
            (sid,),
        ).fetchall()
        events = []
        for r in event_rows:
            item = dict(r)
            try:
                item["details"] = json.loads(item.pop("details_json", "{}"))
            except (ValueError, TypeError):
                item["details"] = {}
            events.append(item)

        failures = [e for e in events if e.get("event_type") == "login_failed"]
        contributions = get_signal_contributions(failures)

        # Construct deterministic attack path from session evidence
        attack_path = []
        first_event = events[0] if events else None
        if first_event:
            attack_path.append({
                "step": 1,
                "title": "Initial Sign-In Attempt",
                "status": "info",
                "badge": "INGRESS",
                "timestamp": first_event["event_at"],
                "description": f"Session established from {'simulation generator' if sess['is_simulated'] else 'browser client'}.",
                "event_id": first_event.get("id"),
            })
        else:
            attack_path.append({
                "step": 1,
                "title": "Initial Session Registration",
                "status": "neutral",
                "badge": "REGISTERED",
                "timestamp": sess["created_at"],
                "description": "Session established in database.",
                "event_id": None,
            })

        failures = [e for e in events if e.get("event_type") == "login_failed"]
        successes = [e for e in events if e.get("event_type") == "login_success"]
        if failures:
            intervals = [e["interval_seconds"] for e in failures if e.get("interval_seconds") is not None]
            min_interval = min(intervals) if intervals else 0
            attack_path.append({
                "step": 2,
                "title": f"Authentication Pattern ({len(failures)} failure{'s' if len(failures) > 1 else ''})",
                "status": "danger" if len(failures) >= 3 else ("warning" if len(failures) >= 2 else "neutral"),
                "badge": "RETRY BURST" if len(failures) >= 3 else "RETRY PATTERN",
                "timestamp": failures[-1]["event_at"],
                "description": f"{len(failures)} failed sign-in attempt{'s' if len(failures) > 1 else ''} recorded with shortest interval {round(min_interval, 2)}s.",
                "event_id": failures[-1].get("id"),
            })
        elif successes:
            attack_path.append({
                "step": 2,
                "title": "Legitimate Authentication",
                "status": "safe",
                "badge": "ACCEPTED",
                "timestamp": successes[0]["event_at"],
                "description": "Successful sign-in with verified credentials on first attempt without anomalous delays.",
                "event_id": successes[0].get("id"),
            })

        score = sess["risk_score"]
        band = sess["risk_band"]
        thresh = int(app.config["HIGH_RISK_THRESHOLD"])
        active_sigs = [s["name"] for s in contributions if s.get("triggered")]
        sig_str = f"Triggered signals: {', '.join(active_sigs)}" if active_sigs else "No anomalous risk signals triggered"
        attack_path.append({
            "step": 3,
            "title": f"Risk Engine Evaluation ({score}/100 · {band})",
            "status": "danger" if score >= thresh else ("warning" if score >= 35 else "safe"),
            "badge": f"{band} RISK",
            "timestamp": sess["updated_at"],
            "description": f"Score {score}/100 assessed against policy threshold {thresh}. {sig_str}.",
            "event_id": None,
        })

        decoy_events = [e for e in events if "decoy" in e.get("event_type", "") or e.get("event_type") == "login_diverted_to_decoy"]
        if sess["decoy_active"] or decoy_events:
            first_decoy = decoy_events[0] if decoy_events else None
            attack_path.append({
                "step": 4,
                "title": "Decoy Sandbox Diversion",
                "status": "danger",
                "badge": "CONTAINED",
                "timestamp": first_decoy["event_at"] if first_decoy else sess["updated_at"],
                "description": "Policy threshold exceeded. Session silently isolated into monitored synthetic decoy environment.",
                "event_id": first_decoy.get("id") if first_decoy else None,
            })
        elif sess["authenticated"]:
            attack_path.append({
                "step": 4,
                "title": "Normal Workspace Granted",
                "status": "safe",
                "badge": "ALLOWED",
                "timestamp": successes[0]["event_at"] if successes else sess["updated_at"],
                "description": "Risk score within acceptable tolerance. Legitimate workspace session authorized.",
                "event_id": successes[0].get("id") if successes else None,
            })
        else:
            attack_path.append({
                "step": 4,
                "title": "Awaiting Valid Credentials",
                "status": "neutral",
                "badge": "UNAUTHENTICATED",
                "timestamp": sess["updated_at"],
                "description": "Session has not yet successfully authenticated or crossed containment threshold.",
                "event_id": None,
            })

        canary_events = [e for e in events if "canary" in e.get("event_type", "") or "download" in e.get("event_type", "")]
        if canary_events:
            attack_path.append({
                "step": 5,
                "title": f"Canary Traps Triggered ({len(canary_events)} interaction{'s' if len(canary_events) > 1 else ''})",
                "status": "danger",
                "badge": "CANARY ALERT",
                "timestamp": canary_events[-1]["event_at"],
                "description": f"Adversary accessed monitored canary assets ({', '.join(sorted(set([e['event_type'] for e in canary_events])))}), confirming hostile intent.",
                "event_id": canary_events[-1].get("id"),
            })
        elif sess["decoy_active"]:
            attack_path.append({
                "step": 5,
                "title": "Decoy Telemetry Monitoring",
                "status": "warning",
                "badge": "ACTIVE TRAP",
                "timestamp": sess["updated_at"],
                "description": "Decoy environment active. Awaiting adversary interaction with bait files.",
                "event_id": None,
            })
        elif sess["authenticated"]:
            attack_path.append({
                "step": 5,
                "title": "Normal Session Activity",
                "status": "safe",
                "badge": "CLEAN",
                "timestamp": sess["updated_at"],
                "description": "Legitimate enterprise user operating within normal parameters without policy alerts.",
                "event_id": None,
            })

        return {
            "session_key": sid,
            "created_at": sess["created_at"],
            "updated_at": sess["updated_at"],
            "risk_score": sess["risk_score"],
            "risk_band": sess["risk_band"],
            "threshold": int(app.config["HIGH_RISK_THRESHOLD"]),
            "policy_version": "2.0.0",
            "decision": "decoy" if sess["decoy_active"] else ("recovery" if sess["risk_score"] >= 35 else "normal"),
            "decoy_active": bool(sess["decoy_active"]),
            "authenticated": bool(sess["authenticated"]),
            "is_simulated": bool(sess["is_simulated"]),
            "scenario": sess["scenario"],
            "reasons": sess["reasons"],
            "signal_contributions": contributions,
            "attack_path": attack_path,
            "events_count": len(events),
            "events": events,
        }

    @app.get("/admin")
    def admin_dashboard():
        conn = get_db()
        band_filter = request.args.get("band", "").upper().strip()
        session_filter = request.args.get("session", request.args.get("q", "")).strip()
        source_filter = request.args.get("source", "").lower().strip()
        time_filter = request.args.get("time", request.args.get("window", "all")).lower().strip()

        # Window mapping: 5m, 15m, 1h, 24h, all
        window_map = {"5m": 300, "15m": 900, "1h": 3600, "24h": 86400, "all": 0}
        window_seconds = window_map.get(time_filter, 0)
        if time_filter.isdigit():
            window_seconds = int(time_filter)

        sessions_query = "SELECT * FROM sessions WHERE is_isolated = 0"
        params: list[Any] = []
        if band_filter in {"LOW", "ELEVATED", "HIGH"}:
            sessions_query += " AND risk_band = ?"
            params.append(band_filter)
        if session_filter:
            sessions_query += " AND session_key LIKE ?"
            params.append(f"%{session_filter[:32]}%")
        if source_filter == "browser":
            sessions_query += " AND is_simulated = 0"
        elif source_filter == "simulation":
            sessions_query += " AND is_simulated = 1"

        if window_seconds > 0:
            cutoff = iso_time(utc_now() - timedelta(seconds=window_seconds))
            sessions_query += " AND updated_at >= ?"
            params.append(cutoff)

        sessions_query += " ORDER BY updated_at DESC LIMIT 30"
        sessions = [dict(row) for row in conn.execute(sessions_query, params).fetchall()]
        for item in sessions:
            try:
                item["reasons"] = json.loads(item.pop("risk_reasons"))
            except (ValueError, TypeError):
                item["reasons"] = []

        is_sim_filter = 1 if source_filter == "simulation" else (0 if source_filter == "browser" else None)
        events, total_events_count = get_filtered_events(
            conn,
            band=band_filter,
            session_filter=session_filter,
            is_simulated=is_sim_filter,
            limit=60,
        )

        def get_correlated_campaigns(conn_c: sqlite3.Connection) -> list[dict[str, Any]]:
            """Identify multi-session attack campaigns sharing targeted principals or attack patterns."""
            try:
                rows_c = conn_c.execute("""
                    SELECT username_fingerprint, COUNT(DISTINCT session_key) as session_count,
                           GROUP_CONCAT(DISTINCT session_key) as session_keys,
                           MIN(event_at) as first_seen, MAX(event_at) as last_seen,
                           COUNT(*) as total_attempts
                    FROM events
                    WHERE is_isolated = 0 AND username_fingerprint IS NOT NULL AND username_fingerprint != ''
                    GROUP BY username_fingerprint
                    HAVING session_count >= 2
                    ORDER BY session_count DESC, total_attempts DESC
                    LIMIT 5
                """).fetchall()
                campaign_list = []
                for rc in rows_c:
                    s_keys = [k.strip() for k in rc["session_keys"].split(",") if k.strip()]
                    campaign_list.append({
                        "fingerprint": rc["username_fingerprint"],
                        "session_count": rc["session_count"],
                        "session_keys": s_keys,
                        "first_seen": rc["first_seen"],
                        "last_seen": rc["last_seen"],
                        "total_attempts": rc["total_attempts"],
                        "confidence": "HIGH (Identical HMAC target fingerprint across sessions)",
                    })
                return campaign_list
            except Exception:
                return []

        summary = get_metrics_summary(
            conn,
            band=band_filter,
            source=source_filter,
            window_seconds=window_seconds,
            session_filter=session_filter,
        )
        risk_dist = get_risk_distribution(
            conn,
            source=source_filter,
            window_seconds=window_seconds,
            session_filter=session_filter,
        )
        if band_filter in {"LOW", "ELEVATED", "HIGH"}:
            risk_dist = {k: (risk_dist[k] if k == band_filter else 0) for k in risk_dist}

        attempts = get_attempts_over_time(conn, window_seconds=window_seconds, source=source_filter)
        campaigns = get_correlated_campaigns(conn)
        return render_template(
            "admin_dashboard.html",
            sessions=sessions,
            events=events,
            summary=summary,
            risk_dist=risk_dist,
            attempts=attempts,
            campaigns=campaigns,
            band_filter=band_filter,
            session_filter=session_filter,
            source_filter=source_filter,
            time_filter=time_filter,
            threshold=int(app.config["HIGH_RISK_THRESHOLD"]),
        )

    @app.post("/admin/simulate/<scenario>")
    def simulate(scenario: str):
        try:
            result = run_demo_scenario(scenario)
        except ValueError:
            abort(404)
        if scenario == "suspicious":
            flash(
                f"Suspicious scenario stored: risk {result['risk_score']}/100 ({result['risk_band']}); decoy {'activated' if result['decoy_active'] else 'not activated'}.",
                "success" if result["decoy_active"] else "error",
            )
        else:
            flash(
                f"Normal scenario stored: risk {result['risk_score']}/100 ({result['risk_band']}); no decoy activation.",
                "success",
            )
        return redirect(url_for("admin_dashboard"))

    @app.post("/admin/reset")
    def reset_demo():
        conn = get_db()
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM sessions")
        conn.commit()
        session.pop("hs_sid", None)
        flash("Demo sessions and event history were reset. The demo account was preserved.", "success")
        return redirect(url_for("admin_dashboard"))

    @app.get("/lab")
    def scenario_lab():
        if not app.config.get("DEMO_MODE", True):
            abort(403, description="Scenario Lab disabled outside demo mode")
        conn = get_db()
        threshold = int(app.config["HIGH_RISK_THRESHOLD"])
        recent_sessions = [
            dict(r) for r in conn.execute(
                "SELECT * FROM sessions WHERE is_simulated = 1 ORDER BY updated_at DESC, rowid DESC LIMIT 15"
            ).fetchall()
        ]
        selected_sid = request.args.get("session", "").strip()
        selected_session = None
        if selected_sid:
            selected_session = get_session(selected_sid)
        if not selected_session and recent_sessions:
            selected_session = recent_sessions[0]

        benchmark_data = session.get("latest_benchmark")
        return render_template(
            "scenario_lab.html",
            scenarios=SCENARIO_DEFINITIONS,
            recent_sessions=recent_sessions,
            selected_session=selected_session,
            benchmark=benchmark_data,
            threshold=threshold,
        )

    @app.post("/lab/simulate/<scenario>")
    def simulate_lab(scenario: str):
        if not app.config.get("DEMO_MODE", True):
            abort(403, description="Simulator routes disabled outside demo mode")
        add_to_demo = (request.form.get("add_to_demo_activity") == "1")
        try:
            result = run_demo_scenario(scenario, isolate=(not add_to_demo))
        except ValueError:
            abort(404, description="Unknown scenario")

        meta = SCENARIO_DEFINITIONS.get(scenario, {})
        title = meta.get("title", scenario)
        state_mode = "Added to Control Room activity" if add_to_demo else "Isolated in Lab"
        decoy_status = "ACTIVATED" if result.get("decoy_active") else "NOT ACTIVATED"
        flash(
            f"Scenario '{title}' generated ({state_mode}): Risk score {result['risk_score']}/100 ({result['risk_band']}); Decoy {decoy_status}.",
            "success" if (result.get("decoy_active") == (meta.get("ground_truth") == "CONTAIN")) else "info",
        )
        return redirect(url_for("scenario_lab", session=result["session_key"]))

    @app.post("/lab/benchmark")
    def run_benchmark():
        if not app.config.get("DEMO_MODE", True):
            abort(403, description="Simulator routes disabled outside demo mode")
        threshold = int(app.config["HIGH_RISK_THRESHOLD"])
        suite = run_scenario_benchmark_suite(threshold=threshold, isolate=True)
        session["latest_benchmark"] = suite
        flash(
            f"Deterministic benchmark suite finished: {suite['total_cases']} cases evaluated under active threshold {suite['threshold']}. "
            f"Containment Rate: {suite['containment_rate']}% (TP={suite['true_positives']}, FN={suite['false_negatives']}); "
            f"False Positive Rate: {suite['false_positive_rate']}% (FP={suite['false_positives']}, TN={suite['true_negatives']}).",
            "success",
        )
        return redirect(url_for("scenario_lab"))

    @app.post("/lab/reset")
    def reset_lab():
        conn = get_db()
        conn.execute("DELETE FROM events WHERE is_isolated = 1")
        conn.execute("DELETE FROM sessions WHERE is_isolated = 1")
        conn.commit()
        session.pop("latest_benchmark", None)
        flash("Lab-isolated scenario runs and benchmark history were reset. Live demo activity was preserved.", "success")
        return redirect(url_for("scenario_lab"))

    @app.post("/api/lab/whatif")
    def api_lab_whatif():
        if not app.config.get("DEMO_MODE", True):
            abort(403, description="Simulator endpoints disabled outside demo mode")
        data = request.get_json(silent=True) or {}
        session_key = str(data.get("session_key", "")).strip()
        conn = get_db()
        if not session_key:
            latest = conn.execute("SELECT session_key FROM sessions ORDER BY updated_at DESC LIMIT 1").fetchone()
            if not latest:
                return jsonify({"error": "No sessions available for what-if evaluation"}), 404
            session_key = latest["session_key"]

        session_row = conn.execute("SELECT * FROM sessions WHERE session_key = ?", (session_key,)).fetchone()
        if not session_row:
            return jsonify({"error": "Session not found"}), 404
        sess = dict(session_row)

        try:
            whatif_threshold = int(data.get("threshold", 50))
        except (ValueError, TypeError):
            whatif_threshold = 50
        whatif_threshold = max(20, min(100, whatif_threshold))

        # Retrieve the session's immutable failure evidence without wall-clock cutoff
        session_failures = conn.execute(
            """SELECT event_at, interval_seconds, username_fingerprint
               FROM events WHERE session_key = ? AND event_type = 'login_failed'
               ORDER BY event_at ASC, id ASC""",
            (session_key,),
        ).fetchall()
        failures = [dict(r) for r in session_failures]
        policy_limit = int(app.config.get("REPEATED_FAILURES_POLICY_LIMIT", 3))

        active_threshold = int(app.config["HIGH_RISK_THRESHOLD"])

        # Determine evidence-derived risk score from the immutable failure evidence
        if failures:
            evidence_score, _, reasons = score_from_failures(failures, threshold=active_threshold)
            if sess["risk_score"] > 0:
                evidence_score = max(int(sess["risk_score"]), evidence_score)
        else:
            evidence_score = int(sess["risk_score"])
            reasons = json.loads(sess.get("risk_reasons") or "[]")

        active_score = evidence_score
        active_band = band_from_score(active_score, threshold=active_threshold)
        active_decision = "CONTAIN" if (active_score >= active_threshold or sess.get("decoy_active")) else "ALLOW"

        # Candidate hypothetical policy evaluation: preserves the evidence-derived score
        whatif_score = evidence_score
        whatif_band = band_from_score(whatif_score, threshold=whatif_threshold)
        whatif_decision = "CONTAIN" if whatif_score >= whatif_threshold else "ALLOW"
        verdict_changed = (whatif_decision != active_decision)

        if not verdict_changed:
            impact_text = f"Policy verdict remains identical ({whatif_decision}) under candidate threshold {whatif_threshold} (score: {whatif_score})."
        elif active_decision == "CONTAIN" and whatif_decision == "ALLOW":
            impact_text = (
                f"Under higher threshold {whatif_threshold}, this session (score {whatif_score}) would NOT have been contained, "
                "allowing the actor to continue attempts without decoy diversion."
            )
        else:
            impact_text = (
                f"Under lower threshold {whatif_threshold}, this session (score {whatif_score}) would have triggered earlier containment into the decoy."
            )

        current_active_threshold = int(app.config["HIGH_RISK_THRESHOLD"])
        current_sess_db = conn.execute("SELECT risk_score, risk_band, decoy_active FROM sessions WHERE session_key = ?", (session_key,)).fetchone()
        db_unmutated = (
            current_active_threshold == active_threshold
            and current_sess_db["risk_score"] == sess["risk_score"]
            and current_sess_db["risk_band"] == sess["risk_band"]
            and current_sess_db["decoy_active"] == sess["decoy_active"]
        )

        return jsonify({
            "status": "ok",
            "session_key": session_key,
            "active_threshold": active_threshold,
            "active_score": active_score,
            "active_band": active_band,
            "active_decision": active_decision,
            "whatif_threshold": whatif_threshold,
            "whatif_score": whatif_score,
            "whatif_band": whatif_band,
            "whatif_decision": whatif_decision,
            "verdict_changed": verdict_changed,
            "impact_analysis": impact_text,
            "is_copy_evaluation": True,
            "database_mutated": not db_unmutated,
            "failures_count": len(failures),
        })

    @app.get("/admin/decoy/<session_key>")
    def admin_decoy(session_key: str):
        state = get_session(session_key)
        if not state or not state["decoy_active"]:
            abort(404)
        return render_template(
            "decoy_dashboard.html",
            decoy_sid=session_key,
            is_admin_view=True,
            events=session_events(session_key),
        )

    @app.post("/admin/decoy/<session_key>/action")
    def admin_decoy_action(session_key: str):
        state = get_session(session_key)
        if not state or not state["decoy_active"]:
            abort(404)
        record_decoy_action(session_key, request.form.get("action", ""), simulated=bool(state["is_simulated"]))
        flash("Synthetic interaction recorded for the selected session.", "success")
        return redirect(url_for("admin_decoy", session_key=session_key))

    def generate_canary_download(sid: str, object_id: str, is_admin: bool = False) -> Response:
        allowed_canary_downloads = {
            "backup_manifest": {
                "filename": "backup_manifest.json",
                "mimetype": "application/json",
                "event_type": "decoy_canary_backup_downloaded",
                "label": "Canary downloaded: Backup Manifest",
                "content": json.dumps({
                    "canary_notice": "THIS IS A SYNTHETIC DECOY ARTIFACT GENERATED LOCALLY BY HONEYSHIELD.",
                    "environment": "LOCAL DEMO SANDBOX - NON-FUNCTIONAL",
                    "canary_id": "HS-CANARY-BAK-2026",
                    "timestamp": iso_time(),
                    "session_reference": sid,
                    "manifest": {
                        "version": "2026.4.1",
                        "components": ["auth_store_hashes_only", "policy_rules", "synthetic_canaries"],
                        "checksum": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        "note": "No plaintext passwords, session cookies, or production secrets exist in this file."
                    }
                }, indent=2)
            },
            "privilege_report": {
                "filename": "quarterly_privilege_report.json",
                "mimetype": "application/json",
                "event_type": "decoy_canary_privilege_report_viewed",
                "label": "Canary downloaded: Quarterly Privilege Report",
                "content": json.dumps({
                    "canary_notice": "THIS IS A SYNTHETIC DECOY ARTIFACT GENERATED LOCALLY BY HONEYSHIELD.",
                    "environment": "LOCAL DEMO SANDBOX - NON-FUNCTIONAL",
                    "canary_id": "HS-CANARY-PRIV-2026",
                    "timestamp": iso_time(),
                    "session_reference": sid,
                    "report": {
                        "audit_period": "Q4 2026",
                        "scope": "Local Sandbox Administrator Privileges",
                        "assignments": [
                            {"principal": "synthetic-admin@example.invalid", "tier": "TIER-0-SANDBOX", "status": "Synthetic"},
                            {"principal": "synthetic-auditor@example.invalid", "tier": "TIER-1-OBSERVER", "status": "Synthetic"}
                        ],
                        "note": "Fabricated role assignments for local demonstration."
                    }
                }, indent=2)
            }
        }
        if object_id not in allowed_canary_downloads:
            abort(400, description="Invalid or unsupported canary object ID")

        item = allowed_canary_downloads[object_id]
        record_event(
            sid,
            item["event_type"],
            details={"object_id": object_id, "action": "download", "label": item["label"], "source": "admin-inspection" if is_admin else "browser"}
        )
        resp = Response(item["content"], mimetype=item["mimetype"])
        resp.headers["Content-Disposition"] = f'attachment; filename="{item["filename"]}"'
        resp.headers["X-HoneyShield-Synthetic"] = "Canary-Object"
        return resp

    def get_canary_object_detail(sid: str, object_id: str, is_admin: bool = False) -> Any:
        allowed_canaries = {
            "api_inventory": {
                "object_id": "api_inventory",
                "title": "Synthetic API Inventory",
                "canary_token": "hs_canary_sec_prod_99a8b7c6d5e4_nonfunctional",
                "classification": "NON-FUNCTIONAL SYNTHETIC CANARY TOKEN",
                "warning": "This token is synthetic, local, and intentionally non-functional. All access is logged to HoneyShield SOC.",
                "event_type": "decoy_canary_token_accessed",
                "label": "Canary token accessed: Synthetic API Inventory",
                "attributes": {
                    "synthetic_scope": "read:decoy-data",
                    "issued_at": "2026-10-01T00:00:00Z",
                    "expiration": "2026-12-31T23:59:59Z",
                    "status": "Monitored Lure"
                }
            },
            "privilege_report": {
                "object_id": "privilege_report",
                "title": "Quarterly Privilege Report",
                "classification": "SYNTHETIC DECOY ROLE MANIFEST",
                "warning": "Fabricated role assignments for local demonstration.",
                "event_type": "decoy_canary_privilege_report_viewed",
                "label": "Canary viewed: Quarterly Privilege Report",
                "attributes": {
                    "audit_period": "Q4 2026",
                    "reviewed_by": "Compliance Lead (Synthetic)",
                    "tier_0_accounts": 2,
                    "status": "Archived (Synthetic)"
                }
            },
            "backup_manifest": {
                "object_id": "backup_manifest",
                "title": "Backup Manifest Summary",
                "classification": "SYNTHETIC BACKUP CATALOG",
                "warning": "Synthetic manifest catalog. Contains no live database connection or secrets.",
                "event_type": "decoy_canary_backup_downloaded",
                "label": "Canary viewed: Backup Manifest Summary",
                "attributes": {
                    "archive_id": "HS-BAK-2026-09A",
                    "storage": "Local Sandbox WAL",
                    "checksum": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                }
            }
        }
        if object_id not in allowed_canaries:
            abort(400, description="Invalid or unknown canary object ID")

        item = allowed_canaries[object_id]
        record_event(
            sid,
            item["event_type"],
            details={"object_id": object_id, "action": "view", "label": item["label"], "source": "admin-inspection" if is_admin else "browser"}
        )
        return jsonify({"status": "ok", "canary": item})

    @app.get("/decoy/download/<object_id>")
    def decoy_download_canary(object_id: str):
        sid = current_sid()
        state = get_session(sid)
        if not state or not state["decoy_active"]:
            abort(403)
        return generate_canary_download(sid, object_id)

    @app.get("/decoy/canary/<object_id>")
    def decoy_view_canary(object_id: str):
        sid = current_sid()
        state = get_session(sid)
        if not state or not state["decoy_active"]:
            abort(403)
        return get_canary_object_detail(sid, object_id)

    @app.get("/admin/decoy/<session_key>/download/<object_id>")
    def admin_decoy_download(session_key: str, object_id: str):
        state = get_session(session_key)
        if not state or not state["decoy_active"]:
            abort(404)
        return generate_canary_download(session_key, object_id, is_admin=True)

    @app.get("/admin/decoy/<session_key>/canary/<object_id>")
    def admin_decoy_view_canary(session_key: str, object_id: str):
        state = get_session(session_key)
        if not state or not state["decoy_active"]:
            abort(404)
        return get_canary_object_detail(session_key, object_id, is_admin=True)

    @app.get("/admin/session/<session_key>", endpoint="session_flight_recorder")
    @app.get("/admin/session/<session_key>", endpoint="admin_session_investigation")
    def session_flight_recorder(session_key: str):
        conn = get_db()
        sess = get_session_investigation(conn, session_key)
        if not sess:
            abort(404)
        return render_template(
            "session_flight_recorder.html",
            session=sess,
            threshold=int(app.config["HIGH_RISK_THRESHOLD"]),
        )

    def admin_session_investigation(session_key: str):
        return session_flight_recorder(session_key)

    @app.get("/admin/session/<session_key>/export", endpoint="admin_session_export")
    @app.get("/api/session/<session_key>/export", endpoint="api_session_export")
    def export_session_investigation(session_key: str):
        conn = get_db()
        detail = get_session_investigation(conn, session_key)
        if not detail:
            abort(404)

        fmt = request.args.get("format", "json").lower().strip()
        timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_sid = "".join(c for c in session_key if c.isalnum() or c in "-_")[:24]

        if fmt == "csv":
            import csv
            import io
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "Session_ID", "Source_Type", "Assessed_Risk", "Risk_Band",
                "Policy_Threshold", "Policy_Verdict", "Decoy_Active", "Authenticated",
                "Event_ID", "Timestamp_UTC", "Event_Type", "Interval_Seconds",
                "HMAC_Fingerprint", "Safe_Details", "Triggered_Signals"
            ])
            sig_list = "; ".join([s["name"] for s in detail.get("signal_contributions", []) if s.get("triggered")]) or "None"
            source_type = "Simulation" if detail.get("is_simulated") else "Browser"

            if not detail.get("events"):
                writer.writerow([
                    detail["session_key"], source_type, detail["risk_score"], detail["risk_band"],
                    detail["threshold"], detail["decision"].upper(), detail["decoy_active"], detail["authenticated"],
                    "", "", "NO_EVENTS_RECORDED", "", "", "", sig_list
                ])
            else:
                for ev in detail["events"]:
                    clean_details = {k: v for k, v in ev.get("details", {}).items() if "password" not in k.lower() and "secret" not in k.lower()}
                    writer.writerow([
                        detail["session_key"],
                        source_type,
                        detail["risk_score"],
                        detail["risk_band"],
                        detail["threshold"],
                        detail["decision"].upper(),
                        detail["decoy_active"],
                        detail["authenticated"],
                        ev.get("id", ""),
                        ev.get("event_at", ""),
                        ev.get("event_type", ""),
                        ev.get("interval_seconds", ""),
                        ev.get("username_fingerprint", ""),
                        json.dumps(clean_details),
                        sig_list
                    ])
            return Response(
                output.getvalue(),
                mimetype="text/csv; charset=utf-8",
                headers={
                    "Content-Disposition": f'attachment; filename="honeyshield-investigation-{safe_sid}-{timestamp_slug}.csv"',
                    "X-Content-Type-Options": "nosniff",
                }
            )

        # JSON format
        clean_events = []
        for ev in detail.get("events", []):
            clean_ev = dict(ev)
            clean_ev["details"] = {k: v for k, v in ev.get("details", {}).items() if "password" not in k.lower() and "secret" not in k.lower()}
            clean_events.append(clean_ev)

        payload = {
            "export_version": "1.0.0",
            "exported_at": iso_time(),
            "export_type": "honeyshield_session_investigation",
            "classification": "CONFIDENTIAL / SOC INVESTIGATION EVIDENCE",
            "privacy_notice": "Zero plaintext passwords or authentication secrets stored or exported. Usernames pseudonymized via per-session HMAC.",
            "derived_vs_recorded": {
                "recorded_evidence": "Immutable event timestamps, interval seconds, HMAC fingerprints, and event types from SQLite audit store.",
                "calculated_interpretation": "Assessed risk score, risk band, policy threshold comparison, and containment decision.",
            },
            "session_overview": {
                "session_key": detail["session_key"],
                "source_type": "Simulation" if detail.get("is_simulated") else "Browser",
                "created_at": detail["created_at"],
                "updated_at": detail["updated_at"],
                "risk_score": detail["risk_score"],
                "risk_band": detail["risk_band"],
                "policy_threshold": detail["threshold"],
                "decision": detail["decision"],
                "decoy_active": detail["decoy_active"],
                "authenticated": detail["authenticated"],
                "scenario": detail["scenario"],
            },
            "explainable_signals": detail.get("signal_contributions", []),
            "attack_path": detail.get("attack_path", []),
            "events_count": len(clean_events),
            "recorded_events": clean_events,
        }
        return Response(
            json.dumps(payload, indent=2),
            mimetype="application/json; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="honeyshield-investigation-{safe_sid}-{timestamp_slug}.json"',
                "X-Content-Type-Options": "nosniff",
            }
        )

    def admin_session_export(session_key: str):
        return export_session_investigation(session_key)

    def api_session_export(session_key: str):
        return export_session_investigation(session_key)

    @app.get("/healthz")
    def healthz():
        # Lightweight readiness check; does not expose paths, secrets, or credentials.
        get_db().execute("SELECT 1").fetchone()
        return jsonify({"status": "ok", "service": "HoneyShield", "storage": "sqlite"})

    @app.get("/api/metrics")
    def api_metrics():
        conn = get_db()
        summary = get_metrics_summary(conn)
        risk_dist = get_risk_distribution(conn)
        attempts = get_attempts_over_time(conn)
        return jsonify({
            "status": "ok",
            "summary": summary,
            "risk_distribution": risk_dist,
            "attempts_over_time": attempts,
            "threshold": int(app.config["HIGH_RISK_THRESHOLD"]),
            "policy_version": "2.0.0",
        })

    @app.get("/api/events")
    def api_events():
        conn = get_db()
        band = request.args.get("band", "").upper()
        session_filter = request.args.get("session", "").strip()
        event_type = request.args.get("type", "").strip()
        sim_param = request.args.get("simulated")
        is_simulated = None
        if sim_param in ("1", "true", "True"):
            is_simulated = 1
        elif sim_param in ("0", "false", "False"):
            is_simulated = 0

        try:
            limit = int(request.args.get("limit", 60))
        except (ValueError, TypeError):
            limit = 60

        try:
            offset = int(request.args.get("offset", 0))
        except (ValueError, TypeError):
            offset = 0

        events, total = get_filtered_events(
            conn,
            band=band,
            session_filter=session_filter,
            event_type=event_type,
            is_simulated=is_simulated,
            limit=limit,
            offset=offset,
        )
        return jsonify({
            "status": "ok",
            "total": total,
            "limit": max(1, min(200, limit)),
            "offset": max(0, offset),
            "events": events,
        })

    @app.get("/api/session/<session_key>")
    def api_session_detail(session_key: str):
        conn = get_db()
        detail = get_session_investigation(conn, session_key)
        if not detail:
            return jsonify({"status": "error", "message": "Session not found"}), 404
        return jsonify({"status": "ok", "session": detail})

    @app.get("/api/chart/attempts")
    def api_chart_attempts():
        conn = get_db()
        raw_win = str(request.args.get("window", "3600")).lower().strip()
        if raw_win in ("all", "none"):
            clamped_window = 0
        else:
            try:
                w_val = int(raw_win)
                clamped_window = max(60, min(86400, w_val))
            except (ValueError, TypeError):
                clamped_window = 3600
        source_param = request.args.get("source", "").lower().strip()
        buckets = get_attempts_over_time(conn, window_seconds=clamped_window, source=source_param)
        return jsonify({
            "status": "ok",
            "window_seconds": clamped_window,
            "buckets": buckets,
            "empty": len(buckets) == 0,
            "total_attempts": sum(b.get("total", b.get("failed", 0) + b.get("success", 0)) for b in buckets),
            "total_failed": sum(b.get("failed", 0) for b in buckets),
            "total_success": sum(b.get("success", 0) for b in buckets),
        })

    app.run_demo_scenario = run_demo_scenario
    app.run_scenario_benchmark_suite = run_scenario_benchmark_suite
    return app


def run_demo_scenario(scenario: str, isolate: bool = False, run_id: str | None = None) -> dict[str, Any]:
    """Module-level scenario runner delegate invoking scenario logic in app context."""
    from flask import current_app, has_app_context
    if has_app_context() and hasattr(current_app, "run_demo_scenario"):
        return current_app.run_demo_scenario(scenario, isolate=isolate, run_id=run_id)
    app = create_app()
    with app.app_context():
        return app.run_demo_scenario(scenario, isolate=isolate, run_id=run_id)


def main() -> int:
    is_cloud = "PORT" in os.environ or "RENDER" in os.environ or "RAILWAY_ENVIRONMENT" in os.environ
    raw_port = os.environ.get("PORT") or os.environ.get("HONEYSHIELD_PORT") or "5000"
    try:
        port = int(raw_port)
    except ValueError:
        print("Port must be a valid integer (for example, 5000).", file=sys.stderr)
        return 2
    default_host = "0.0.0.0" if is_cloud else "127.0.0.1"
    host = os.environ.get("HONEYSHIELD_HOST", default_host)
    if not 1 <= port <= 65535:
        print("Port must be between 1 and 65535.", file=sys.stderr)
        return 2
    if host not in {"127.0.0.1", "localhost", "::1", "0.0.0.0"}:
        print("HoneyShield host must be 127.0.0.1, localhost, ::1, or 0.0.0.0.", file=sys.stderr)
        return 2
    app = create_app()
    probe_host = "127.0.0.1" if host == "localhost" else host
    try:
        with socket.socket(socket.AF_INET6 if probe_host == "::1" else socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((probe_host, port))
    except OSError as exc:
        if exc.errno in {98, 48, 10048, 10013}:
            print(
                f"Port {port} is unavailable. Close the other server or set PORT to another port, e.g. 5001.",
                file=sys.stderr,
            )
            return 1
        print(f"Could not bind to {probe_host}:{port}: {exc}", file=sys.stderr)
        return 1
    url_host = "[::1]" if probe_host == "::1" else ("0.0.0.0" if probe_host == "0.0.0.0" else "127.0.0.1")
    print("\nHoneyShield server")
    print(f"Listening on: http://{url_host}:{port}")
    print("Press Ctrl+C to stop.\n", flush=True)
    try:
        app.run(host=probe_host, port=port, debug=False, use_reloader=False)
    except OSError as exc:
        print(f"Server could not start on port {port}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
