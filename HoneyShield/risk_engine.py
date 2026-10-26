"""Pure, interpretable risk scoring logic used by both login and demo scenarios."""
from __future__ import annotations

import math
import statistics
from datetime import datetime, timezone
from typing import Any

RISK_WEIGHTS = {
    "rapid_failures": 30,
    "username_diversity": 20,
    "regular_cadence": 20,
    "gradual_backoff": 10,
    "repeated_principal": 20,
    "sustained_failures": 15,
}
LOW_MAX = 34
ELEVATED_MAX = 49
DEFAULT_HIGH_RISK_THRESHOLD = 50


def _parse_utc(value: Any) -> datetime | None:
    """Safely parse an ISO-8601 string or datetime into a UTC datetime, or return None."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip())
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None


def band_from_score(score: int | float, threshold: int = DEFAULT_HIGH_RISK_THRESHOLD) -> str:
    """Determine the risk band ('LOW', 'ELEVATED', or 'HIGH') strictly based on score and threshold."""
    try:
        s = int(score)
    except (ValueError, TypeError):
        s = 0
    s = max(0, min(100, s))

    try:
        t = int(threshold)
    except (ValueError, TypeError):
        t = DEFAULT_HIGH_RISK_THRESHOLD

    if s >= t:
        return "HIGH"
    if s >= 35:
        return "ELEVATED"
    return "LOW"


def score_from_failures(
    failures: list[dict[str, Any]] | None, threshold: int = DEFAULT_HIGH_RISK_THRESHOLD
) -> tuple[int, str, list[str]]:
    """Return (score, band, reasons) from recent login-failure event mappings.

    Each event mapping needs `event_at` and may include `username_fingerprint`. The caller
    supplies the rolling-window events, making this function deterministic and easy to test.
    Handles empty, oversized, malformed, out-of-order, and Unicode inputs gracefully.
    """
    if not failures or not isinstance(failures, list):
        return 0, band_from_score(0, threshold), ["No strong suspicious pattern in the current rolling window"]

    score = 0
    reasons: list[str] = []

    # Filter and sort valid timestamped events chronologically to be resilient to out-of-order inputs
    valid_events: list[tuple[datetime, dict[str, Any]]] = []
    for item in failures:
        if isinstance(item, dict):
            parsed_dt = _parse_utc(item.get("event_at"))
            if parsed_dt is not None:
                valid_events.append((parsed_dt, item))

    valid_events.sort(key=lambda pair: pair[0])

    if len(valid_events) >= 3:
        span = (valid_events[-1][0] - valid_events[0][0]).total_seconds()
        if 0 <= span <= 60:
            score += RISK_WEIGHTS["rapid_failures"]
            reasons.append("Multiple failed logins in a short interval")

    fingerprints = [
        str(row.get("username_fingerprint"))
        for _, row in valid_events
        if row.get("username_fingerprint") is not None and str(row.get("username_fingerprint")) != ""
    ]
    if len(set(fingerprints)) >= 3:
        score += RISK_WEIGHTS["username_diversity"]
        reasons.append("Many distinct username fingerprints in this session")

    times = [item[0] for item in valid_events]
    gaps = [(times[index] - times[index - 1]).total_seconds() for index in range(1, len(times))]
    if len(gaps) >= 3 and all(gap > 0 for gap in gaps):
        mean_gap = statistics.mean(gaps)
        coefficient_of_variation = statistics.pstdev(gaps) / mean_gap if mean_gap > 0 else math.inf
        if mean_gap <= 5 and coefficient_of_variation <= 0.22:
            score += RISK_WEIGHTS["regular_cadence"]
            reasons.append("Highly regular request cadence consistent with automation-like behaviour")
        if all(gaps[index + 1] >= gaps[index] * 1.25 for index in range(len(gaps) - 1)):
            score += RISK_WEIGHTS["gradual_backoff"]
            reasons.append("Retry intervals show a repeated gradual-backoff pattern")

    if len(fingerprints) >= 3 and len(set(fingerprints)) == 1:
        score += RISK_WEIGHTS["repeated_principal"]
        reasons.append("Repeated failures against one username fingerprint")
        if len(valid_events) >= 4:
            score += RISK_WEIGHTS["sustained_failures"]
            reasons.append("Sustained authentication attempts against targeted username")
        if len(valid_events) >= 5:
            score += 15
            reasons.append("Exhaustive password guessing pattern")

    score = max(0, min(100, score))
    band = band_from_score(score, threshold=threshold)

    if not reasons:
        reasons = ["No strong suspicious pattern in the current rolling window"]
    return score, band, reasons


def assess_risk(
    failures: list[dict[str, Any]] | None,
    threshold: int = DEFAULT_HIGH_RISK_THRESHOLD,
    policy_limit: int = 0,
) -> dict[str, Any]:
    """Authoritative risk assessment returning score, band, threshold, decision, and explainable evidence."""
    score, band, reasons = score_from_failures(failures, threshold=threshold)
    valid_failures = [f for f in (failures or []) if isinstance(f, dict)]
    failure_count = len(valid_failures)
    fingerprints = [
        str(r.get("username_fingerprint"))
        for r in valid_failures
        if r.get("username_fingerprint") is not None and str(r.get("username_fingerprint")) != ""
    ]
    policy_triggered = bool(
        policy_limit > 0 and failure_count >= policy_limit and len(set(fingerprints)) == 1
    )
    if policy_triggered:
        policy_reason = f"Security policy triggered: {failure_count} consecutive attempts against targeted principal"
        if policy_reason not in reasons:
            reasons.append(policy_reason)

    activate_decoy = bool(score >= threshold or policy_triggered)
    decision = "decoy" if activate_decoy else ("recovery" if score >= 35 else "normal")

    return {
        "score": score,
        "band": band,
        "threshold": threshold,
        "decision": decision,
        "activate_decoy": activate_decoy,
        "policy_triggered": policy_triggered,
        "reasons": reasons,
        "failure_count": failure_count,
        "engine_version": "2.0.0",
    }


def get_signal_contributions(failures: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Return explicit breakdown of each behavioural risk signal and its contribution."""
    valid_events: list[tuple[datetime, dict[str, Any]]] = []
    for item in (failures or []):
        if isinstance(item, dict):
            parsed_dt = _parse_utc(item.get("event_at"))
            if parsed_dt is not None:
                valid_events.append((parsed_dt, item))
    valid_events.sort(key=lambda pair: pair[0])

    # 1. rapid failures
    rapid_active = False
    if len(valid_events) >= 3:
        span = (valid_events[-1][0] - valid_events[0][0]).total_seconds()
        if 0 <= span <= 60:
            rapid_active = True

    # 2. username diversity
    fingerprints = [
        str(row.get("username_fingerprint"))
        for _, row in valid_events
        if row.get("username_fingerprint") is not None and str(row.get("username_fingerprint")) != ""
    ]
    diversity_active = len(set(fingerprints)) >= 3

    # 3. regular cadence and backoff
    times = [item[0] for item in valid_events]
    gaps = [(times[index] - times[index - 1]).total_seconds() for index in range(1, len(times))]
    cadence_active = False
    backoff_active = False
    if len(gaps) >= 3 and all(gap > 0 for gap in gaps):
        mean_gap = statistics.mean(gaps)
        cv = statistics.pstdev(gaps) / mean_gap if mean_gap > 0 else math.inf
        if mean_gap <= 5 and cv <= 0.22:
            cadence_active = True
        if all(gaps[index + 1] >= gaps[index] * 1.25 for index in range(len(gaps) - 1)):
            backoff_active = True

    # 4. repeated principal and sustained
    repeated_active = len(fingerprints) >= 3 and len(set(fingerprints)) == 1
    sustained_active = repeated_active and len(valid_events) >= 4
    persistent_active = repeated_active and len(valid_events) >= 5

    return [
        {
            "signal": "rapid_failures",
            "name": "Rapid Failures",
            "weight": RISK_WEIGHTS["rapid_failures"],
            "triggered": rapid_active,
            "description": "3+ failed logins within a 60-second window",
        },
        {
            "signal": "repeated_principal",
            "name": "Targeted Principal",
            "weight": RISK_WEIGHTS["repeated_principal"],
            "triggered": repeated_active,
            "description": "3+ failed attempts targeted at the same username",
        },
        {
            "signal": "sustained_failures",
            "name": "Sustained Failures",
            "weight": RISK_WEIGHTS["sustained_failures"],
            "triggered": sustained_active,
            "description": "4+ sustained failed attempts against targeted principal",
        },
        {
            "signal": "persistent_volume",
            "name": "Exhaustive Guessing",
            "weight": 15,
            "triggered": persistent_active,
            "description": "5+ persistent authentication failures against target",
        },
        {
            "signal": "username_diversity",
            "name": "Username Diversity",
            "weight": RISK_WEIGHTS["username_diversity"],
            "triggered": diversity_active,
            "description": "3+ distinct username fingerprints (credential spraying)",
        },
        {
            "signal": "regular_cadence",
            "name": "Automation Cadence",
            "weight": RISK_WEIGHTS["regular_cadence"],
            "triggered": cadence_active,
            "description": "Near-identical request intervals consistent with scripted bot",
        },
        {
            "signal": "gradual_backoff",
            "name": "Gradual Backoff",
            "weight": RISK_WEIGHTS["gradual_backoff"],
            "triggered": backoff_active,
            "description": "Exponential retry backoff pattern attempting stealth evasion",
        },
    ]


