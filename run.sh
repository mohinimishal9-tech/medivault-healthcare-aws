#!/usr/bin/env bash
cd "$(dirname "$0")"
command -v python3 >/dev/null || { echo "Python 3.10+ is required."; exit 1; }
[ -d .venv ] || { echo "Creating virtual environment..."; python3 -m venv .venv; }
source .venv/bin/activate
python -m pip install --quiet --disable-pip-version-check -r requirements.txt
python app.py
