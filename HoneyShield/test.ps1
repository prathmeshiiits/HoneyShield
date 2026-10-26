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
                if ($LASTEXITCODE -eq 0) { $pythonCommand = 'py'; $pythonArgs = @("-" + $version); break }
            } catch {}
        }
        if (-not $pythonCommand) {
            try {
                $verOut = & py --version 2>$null
                if ($LASTEXITCODE -eq 0) { $pythonCommand = 'py' }
            } catch {}
        }
    }
    if (-not $pythonCommand -and (Get-Command python -ErrorAction SilentlyContinue)) { $pythonCommand = 'python' }
    if (-not $pythonCommand) { Write-Error 'Python was not found. Install Python 3.11, 3.12, or 3.13 first.'; exit 1 }
    Write-Host 'Creating .venv for the test run...'
    & $pythonCommand @pythonArgs -m venv (Join-Path $PSScriptRoot '.venv')
    if ($LASTEXITCODE -ne 0) { throw 'Could not create .venv.' }
}
& $venvPython -m pip install --disable-pip-version-check -r (Join-Path $PSScriptRoot 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
& $venvPython -m unittest discover -s tests -v
exit $LASTEXITCODE
