# Validation notes for this release

Validation was repeated against a fresh extraction of `HoneyShield.zip` on 2026-10-26 using Python 3.13.5 in the available Linux environment. The package-index was unreachable (DNS/network failure) and Flask was not preinstalled, so the Flask integration module was skipped by its explicit environment guard. Windows PowerShell and a browser screenshot runtime were not available.

## Checks that passed

- `unzip -t HoneyShield.zip`: archive integrity passed with no ZIP errors.
- Fresh extraction check: required top-level `HoneyShield/` structure present; no `.venv`, `__pycache__`, `.pyc`, SQLite database, or test runtime database included.
- `python -m compileall -q app.py risk_engine.py tests`: passed.
- `python -m unittest discover -s tests -v`: 13 tests discovered, 12 passed and 1 module skipped because Flask could not be installed in this offline environment. The passing tests cover risk escalation, normal retry scoring, threshold configuration, score cap, required-file integrity, Python AST parsing, Jinja template parsing, route/template endpoint references, local-only assets, navigation/modal references, and the event-recorder call signature.
- `node --check static/js/app.js`: passed.
- Static inspection confirms requirements are pinned and the runtime templates, CSS, JavaScript, tests, PowerShell scripts, and documentation are included in the archive.

## Not verified here

- Installing Flask/Werkzeug/Jinja2 into a clean virtual environment; package-index DNS/network access failed.
- Flask server startup, HTTP `/healthz`, actual HTTP login/decoy flows, SQLite integration behaviour, and the Flask integration tests end-to-end.
- Running `run.ps1`, `test.ps1`, or `run.bat` on Windows 11; PowerShell/Windows is unavailable in this environment.
- Interactive Chromium rendering, keyboard interactions, and screenshot inspection; a browser-render attempt was unavailable/timed out.

No successful Flask startup or end-to-end browser test is claimed. On Windows, extract the ZIP, open PowerShell in the `HoneyShield` folder, run ` .\run.ps1 `, then in a second terminal run ` .\test.ps1 ` after the dependencies have installed. If dependency installation fails, check network access and retry. The application does not require external network access once its declared Python dependencies are installed.
