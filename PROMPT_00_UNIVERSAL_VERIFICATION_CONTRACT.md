# Prompt 00 — Universal verification contract

You are modifying the **existing HoneyShield repository**, not generating a second app. Read `MASTER_WORKFLOW.md` and `HONEYPOT_WINNING_PLAN.md` first. Preserve the current language/framework, working routes, login credentials setup, schema and existing UI unless inspection reveals a concrete defect.

## Required behavior for this prompt

1. Inspect relevant files before editing; identify the exact existing code path.
2. Create or update `IMPLEMENTATION_NOTES.md` with truthful status (`PASS`, `PARTIAL`, `FAIL`, `NOT TESTED`), evidence and remaining gaps.
3. Implement actual edits, save files, then reopen the changed files and inspect `git diff --stat` if Git exists.
4. Run the narrow relevant tests first, then broader tests and the actual local startup command where time permits. Never claim a test ran if it did not.
5. Use the existing test framework. Add a dependency only if compatible and useful; do not turn a five-hour demo into a toolchain migration.
6. Do not hardcode live metrics, risk scores, chart points, event rows, fake alerts or success states into the frontend. Use backend data. Simulations must have a `simulated` marker and visible UI label.
7. No button may be decorative: it must invoke a real action, provide loading/error handling, and visibly update the resulting state, or be removed/disabled with an explanation.
8. Never log/store submitted passwords, typed characters, session cookies or real secrets. Decoy content is synthetic, local and nonfunctional.
9. Do not use real external targets, scan the internet, or expose local simulator endpoints outside demo/test mode.
10. Do not loosen tests merely to get green. Fix causes, explain unavoidable failures and mark unverified behavior explicitly.

## Definition of phase completion

Report: (a) files changed, (b) why each change was needed, (c) exact commands run, (d) actual test results, (e) browser-visible checks and screenshot paths if the tool can capture them, (f) known gaps. If a feature already passes its acceptance criteria with evidence, leave it alone. If no meaningful change was needed, report the verification evidence rather than inventing edits.

## No-change/failure recovery

If nothing changes or a feature is not visible: stop repeating the plan; inspect its route/template/JS/backend/API/console/network/test path; reproduce the issue; implement the smallest fix; rerun the specific failing check; report evidence. Do not restart or duplicate other work to mask the failure.
