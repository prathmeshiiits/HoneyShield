# HoneyShield — Master Project Workflow & Acceptance Gates
**Version 2.0 · 26 October 2026**

## Goal

Deliver a credible hackathon prototype for **“The Honeypot That Learns Who’s Lying”**: infer suspicious behaviour from session evidence, adapt the user experience cautiously, direct sufficiently suspicious sessions to a session-isolated synthetic decoy, and give defenders explainable, replayable evidence. Judges must be able to enter their own inputs and see the real backend process them; the Scenario Lab is optional, not the only way the app works.

## Source synthesis

- **Claude/MIRAGE plan:** behavioural signals, deception ladder, normal-human recovery, canary objects, attacker dossier, replay, scenario lab, evaluation, and a strong Antigravity verification protocol.
- **HoneyShield research/implementation blueprint:** preserve the existing Flask/SQLite app if it is what the audit confirms; state machine; event schema; privacy-aware timing signals; acceptance gates; local automated tests; professional SOC layout.
- **External design/technical inspiration:** T-Pot and Elastic/Kibana for operational dashboard conventions; Cowrie for structured event recording and replay; OpenCanary/Canarytokens for instrumented decoy interactions; OWASP WSTG/ZAP for local security verification; Playwright for browser journeys; Hypothesis for useful generated edge cases if compatible.

These are inspiration/reference projects, not assets to copy or dependencies to install wholesale. Use original HoneyShield branding. Do not copy a proprietary site pixel-perfectly or imply HoneyShield equals these mature platforms.

## Workflow rule: audit, don't assume

The two initial prompts have already been started/queued. Let them finish. Then inspect the actual source tree, source diffs, running routes, database, test suite and browser output. Each phase below is **gap-driven**: if a feature already exists and passes its acceptance tests, do not rebuild it. Record `PASS`, `PARTIAL`, `FAIL`, or `NOT TESTED` in `IMPLEMENTATION_NOTES.md` with file/test evidence.

## P0: non-negotiable product behavior

1. **Real input path:** a judge can open the actual login flow and try their own usernames/passwords or arbitrary invalid values. Backend validation and policy code—not frontend constants or demo buttons—determine outcomes.
2. **Honest risk engine:** one authoritative backend implementation computes score, band, evidence contributions and recommended decision. The UI reads the same score/policy. A failed login count alone is not presented as proof of an attacker.
3. **Policy/redirect consistency:** one documented threshold/policy controls server-side decision. Backend session state and protected-route access agree; frontend redirect is not the security boundary.
4. **Human recovery:** uncertain/forgetful behavior is not automatically branded malicious. There is a cautious recovery path when compatible with the existing design.
5. **Decoy isolation:** high-risk sessions receive only synthetic decoy data; ordinary sessions keep the normal experience; another session cannot access a decoy merely by guessing a URL or ID.
6. **Evidence persistence:** login attempts, signal evidence, decisions and canary actions are persisted and correlated by opaque session reference. Never store passwords, password contents, raw keystrokes or secret session cookies in events.
7. **Useful SOC UI:** metrics, charts, filters and event rows are all derived from real stored backend data; simulator data is visibly labelled as simulated. Empty state means zero/no data, not invented sample counts.
8. **Reliability:** fresh temporary DB startup, reset, logout and session boundaries are tested. Demo reset must not destroy schema or the configured demo account.

## Suggested data flow (adapt to actual architecture)

`Request / timing-only metadata` → `validated event` → `session feature aggregate` → `risk assessment + evidence reasons` → `policy decision` → `normal / recovery / decoy response` → `persisted structured events` → `JSON API / server-rendered view` → `SOC widgets/charts`.

Keep the current stack and routes if they can satisfy this. Avoid framework migrations, cloud dependencies, a heavy event stack, or installing all of T-Pot just to imitate its dashboard. Polling is acceptable if WebSockets would destabilise the build.

## Risk signals and privacy

Use the minimum signals that can be implemented and tested: failures over time, distinct username count where relevant, request cadence regularity, retries/recovery patterns, and decoy-object interactions. Browser telemetry is optional and spoofable. Never record characters typed or password strings. Timing data can disadvantage users with disabilities, slow networks, mobile devices or assistive technology; it must be supporting evidence only and documented. Keep score bounded to the declared range and avoid double-counting the same event.

## Professional UI direction

Use a unified, original HoneyShield SOC theme:
- Ink/navy background `#0B1020`, surface `#121A2B`, raised surface `#172338`.
- Cyan/teal highlight around `#43D9D0`; clear neutral text and secondary text.
- Low risk = green, elevated = amber, high = restrained red. Do not rely on colour alone; include text/icon/labels.
- Clear grid, concise headings, consistent spacing, compact data density, subtle borders, restrained shadows, accessible focus and contrast, reduced-motion support.
- Take layout inspiration from operational security dashboards: KPI strip, time-series, risk distribution, filterable event feed, investigation panel. Cowrie-inspired timeline/replay and Canarytokens-inspired synthetic canary alerts are high-value.
- Do not add fake maps, fake live badges, invented alerts, or placeholder chart values. No animation at the expense of legibility.
- Reuse a library already installed. If none exists, add one lightweight compatible chart library only if install/build/testing works; otherwise use accessible SVG or simple server-generated chart data.
- Make loading, empty, error, and populated states explicit. Apply theme consistently to login, user dashboard, decoy, SOC, lab and results pages.

## Pages / story (preserve existing URLs where possible)

1. Existing login/landing route.
2. Existing normal user dashboard.
3. Existing admin/SOC route, commonly `/admin` if confirmed.
4. Existing decoy route, commonly `/decoy` if confirmed.
5. Optional local-only `/lab` scenario run and `/results` evaluation, only if core workflow passes.
6. Optional session detail page or panel reachable from real event rows.

Do not create duplicate routes just because this document lists a logical page.

## Ordered phases after the two existing prompts

| Phase | Prompt | Main purpose | Gate before moving on |
|---|---|---|---|
| 1 | `PROMPT_01_AUDIT_AFTER_CURRENT_PROMPTS.md` | inspect actual work and prevent duplication | evidence-backed status matrix; current app starts |
| 2 | `PROMPT_02_REPAIR_REAL_INPUT_CORE_FLOW.md` | fill P0 gaps only | judge-input login→risk→policy→normal/recovery/decoy passes |
| 3 | `PROMPT_03_REAL_DATA_CONTRACTS_AND_API.md` | backend-backed dashboard data | data contract/API is stable and tested |
| 4 | `PROMPT_04_PROFESSIONAL_SOC_UI_AND_CHARTS.md` | polished visual SOC interface | every visual widget uses real backend data and works in browser |
| 5 | `PROMPT_05_TIMELINE_DECOY_CANARIES.md` | investigation + instrumented decoy | actions persist and appear in session timeline |
| 6 | `PROMPT_06_SCENARIO_LAB_AND_EVALUATION.md` | deterministic judge-friendly demo | scenarios use actual engine and honest measured outcomes |
| 7 | `PROMPT_07_TEST_MATRIX_AND_BROWSER_REGRESSION.md` | edge-case + browser testing | critical tests pass or blocker is documented and fixed |
| 8 | `PROMPT_08_SECURITY_PRIVACY_AND_RELEASE_FREEZE.md` | security review, responsive QA, README, final demo | repeatable clean start, demo script and limitations verified |

The `PROMPT_00` universal contract must precede every phase prompt. Prompts are not a command to implement every item blindly; each phase must audit existing behavior and work only on genuine gaps.

## Five-hour allocation AFTER the two already-running prompts (flexible)

- 15 min: audit and run current build.
- 45 min: fix any remaining P0 flow/session failures.
- 25 min: stable backend metrics/events contract.
- 60 min: data-driven SOC UI/charts.
- 35 min: session timeline and canary event wiring.
- 30 min: small deterministic Scenario Lab (skip if core took longer).
- 45 min: backend/browser regression and repair.
- 25 min: security/privacy and responsive check.
- 20 min: clean startup and judging rehearsal.

If core repair runs late, skip the Scenario Lab or P2 extras before compromising security/tests.

## Feature done definition

A feature is **DONE** only if all applicable checks pass:
1. Agent identifies files/routes and edits or verifies the actual implementation.
2. Button/control is reachable and has a real action, loading/error feedback and understandable state.
3. Real backend action is wired to it; no hardcoded counts, scores, chart data or simulated success.
4. Persisted data and session identity agree after refresh.
5. Automated test covers the behavior; browser/manual verification confirms it appears in the UI.
6. Any simulation is explicitly labelled and isolated from live activity.
7. The agent reports exact changed files, commands, counts/results, screenshots or browser evidence where available, and unverified items.

## Final 90-second judging path

1. Open a normal login in one browser context; enter ordinary/incorrect inputs, recover, and show it remains on the legitimate path when policy evidence is low.
2. Use a separate session to perform repeated/regular suspicious attempts; show the score, supporting evidence and policy threshold changing from real events.
3. When server policy activates deception, follow the redirect and interact with a fictional canary record.
4. Switch to SOC; open that same opaque session reference and show its timeline, contribution breakdown and canary alert.
5. Run one labelled Scenario Lab comparison only if that page has been tested.

Do not claim real-world detection accuracy. Describe the risk engine as an explainable heuristic unless a genuine model has training data, evaluation and reproducible metrics.

## Reference links

- T-Pot: https://github.com/telekom-security/tpotce
- Cowrie: https://github.com/cowrie/cowrie
- OpenCanary: https://github.com/thinkst/opencanary
- Canarytokens: https://github.com/thinkst/canarytokens
- SNARE/Tanner: https://github.com/mushorg/snare and https://github.com/mushorg/tanner
- Playwright: https://playwright.dev/python/docs/intro
- Hypothesis: https://github.com/HypothesisWorks/hypothesis
- OWASP Web Security Testing Guide: https://owasp.org/projects/web-security-testing-guide
- OWASP ZAP: https://www.zaproxy.org/

References show patterns and testing options; they do not establish that HoneyShield already implements those capabilities.
