#!/bin/bash
# Build a Linux executable: dist/LandullTriage/LandullTriage
cd "$(dirname "$0")" || exit 1
set -e
[ -d .venv ] || python3 -m venv .venv
.venv/bin/python -m pip install -q --upgrade pip
.venv/bin/python -m pip install -q -r requirements.txt
.venv/bin/python fetch_tools.py
VOLDIR=$(.venv/bin/python -c "import os, volatility3; print(os.path.dirname(volatility3.__file__))")
.venv/bin/pyinstaller --noconfirm --clean --log-level WARN --windowed --name LandullTriage \
  --icon assets/icon.png --add-data "assets:assets" --add-data "$VOLDIR:volatility3" \
  --collect-submodules volatility3 --collect-submodules triage --hidden-import pefile --paths . \
  landull_triage.py
rm -rf build LandullTriage.spec
echo "BUILD OK -> dist/LandullTriage/LandullTriage"
