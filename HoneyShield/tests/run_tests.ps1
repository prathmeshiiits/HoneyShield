# HoneyShield Automated Test Suite Runner
# Executes Unittest, Pytest + Hypothesis, Playwright E2E, Schemathesis API contracts, and Security Posture tests.

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
Set-Location -LiteralPath $ProjectRoot

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "             HoneyShield Defensive Test Runner                   " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

$venvPython = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
$venvPytest = Join-Path $ProjectRoot '.venv\Scripts\pytest.exe'

if (-not (Test-Path -LiteralPath $venvPython)) {
    Write-Host "[!] Virtual environment not found at .venv. Run run.ps1 or test.ps1 first." -ForegroundColor Yellow
    exit 1
}

# Ensure dev dependencies are installed
Write-Host "[*] Checking testing dependencies (requirements-dev.txt)..." -ForegroundColor Gray
& $venvPython -m pip install --disable-pip-version-check -q -r (Join-Path $ProjectRoot 'requirements-dev.txt')

Write-Host "[*] Running complete test suite via pytest..." -ForegroundColor Cyan
Write-Host ""

$sw = [System.Diagnostics.Stopwatch]::StartNew()
& $venvPytest tests -v --tb=short
$exitCode = $LASTEXITCODE
$sw.Stop()

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "                     Test Execution Summary                      " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " Total Duration: $([math]::Round($sw.Elapsed.TotalSeconds, 2)) seconds" -ForegroundColor Gray

if ($exitCode -eq 0) {
    Write-Host " Result: ALL TEST SUITES PASSED (Exit Code: 0)" -ForegroundColor Green
    Write-Host ""
    Write-Host " Verified Modules:" -ForegroundColor White
    Write-Host "   [PASS] 1. Unittest Integration & Static Integrity (test_app.py, test_static_integrity.py)" -ForegroundColor Green
    Write-Host "   [PASS] 2. Hypothesis Property-Based & Boundary Tests (test_hypothesis_risk.py)" -ForegroundColor Green
    Write-Host "   [PASS] 3. Playwright Headless Chromium E2E Journeys (test_e2e_playwright.py)" -ForegroundColor Green
    Write-Host "   [PASS] 4. API Contract & Schemathesis Tests (test_api_contracts.py)" -ForegroundColor Green
    Write-Host "   [PASS] 5. OWASP Security Posture & Privacy Audits (test_security_posture.py)" -ForegroundColor Green
    Write-Host "   [PASS] 6. Live Judge Input Journeys & Hostile Payload Tests (test_live_judge_inputs.py)" -ForegroundColor Green
} else {
    Write-Host " Result: TEST SUITE REPORTED FAILURES (Exit Code: $exitCode)" -ForegroundColor Red
}
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

exit $exitCode
