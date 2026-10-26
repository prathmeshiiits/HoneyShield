@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  py -3.12 -m venv .venv 2>nul
  if errorlevel 1 py -3.11 -m venv .venv 2>nul
  if errorlevel 1 py -m venv .venv 2>nul
  if errorlevel 1 python -m venv .venv
  if errorlevel 1 goto :venv_error
)
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 goto :install_error
echo Starting HoneyShield. Default URL: http://127.0.0.1:5000
".venv\Scripts\python.exe" app.py
goto :end
:venv_error
echo Could not create the virtual environment. Please install Python 3.11 or 3.12.
exit /b 1
:install_error
echo Dependency installation failed. Check pip/network settings and retry.
exit /b 1
:end
endlocal
