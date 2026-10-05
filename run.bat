@echo off
cd /d "%~dp0"
where python >nul 2>nul || (echo Python 3.10 or newer is required. Install it from python.org and tick "Add to PATH". & pause & exit /b 1)
if not exist .venv (
  echo Creating virtual environment...
  python -m venv .venv
)
call .venv\Scripts\activate.bat
python -m pip install --quiet --disable-pip-version-check -r requirements.txt
python app.py
pause
