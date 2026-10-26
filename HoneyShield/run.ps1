$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$venvPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $venvPython)) {
    $pythonCommand = $null
    $pythonArgs = @()
    if (Get-Command py -ErrorAction SilentlyContinue) {
        foreach ($version in @('3.13', '3.12', '3.11')) {
            try {
                $verOut = & py ("-" + $version) --version 2>$null
                if ($LASTEXITCODE -eq 0) {
                    $pythonCommand = 'py'
                    $pythonArgs = @("-" + $version)
                    break
                }
            } catch {}
        }
        if (-not $pythonCommand) {
            try {
                $verOut = & py --version 2>$null
                if ($LASTEXITCODE -eq 0) { $pythonCommand = 'py' }
            } catch {}
        }
    }
    if (-not $pythonCommand -and (Get-Command python -ErrorAction SilentlyContinue)) {
        $pythonCommand = 'python'
    }
    if (-not $pythonCommand) {
        Write-Error 'Python was not found. Install Python 3.11, 3.12, or 3.13 from python.org, then reopen PowerShell.'
        exit 1
    }

    Write-Host 'Creating a project-local virtual environment...'
    & $pythonCommand @pythonArgs -m venv (Join-Path $PSScriptRoot '.venv')
    if ($LASTEXITCODE -ne 0) { throw 'Could not create .venv. Check that Python includes the venv module.' }
}

Write-Host 'Installing/checking the small dependency set...'
& $venvPython -m pip install --disable-pip-version-check -r (Join-Path $PSScriptRoot 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed. Check your internet connection or pip configuration and retry.' }

$port = if ($env:HONEYSHIELD_PORT) { $env:HONEYSHIELD_PORT } else { '5000' }
Write-Host "Starting HoneyShield. The server prints the exact URL; default: http://127.0.0.1:$port"
Write-Host 'No virtual-environment activation is required. Press Ctrl+C to stop.'
& $venvPython (Join-Path $PSScriptRoot 'app.py')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
