#!/bin/bash
# Double-click to build LandullTriage.app (first run downloads Qt and Volatility, ~3-5 minutes).
cd "$(dirname "$0")" || exit 1
exec > >(tee build.log) 2>&1
echo "== LandullTriage: macOS build =="
PY=""
for c in python3.13 python3.12 python3.11 python3.10 python3; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)'; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then echo "Python 3.9+ is required: https://www.python.org/downloads/"; read -r -p "Press Enter to close"; exit 1; fi
echo "Using $($PY --version) at $(command -v $PY)"
[ -d .venv ] || "$PY" -m venv .venv || exit 1
.venv/bin/python -m pip install -q --upgrade pip
.venv/bin/python -m pip install -q -r requirements.txt || { echo "pip install failed"; read -r -p "Press Enter"; exit 1; }
VOLDIR=$(.venv/bin/python -c "import os, volatility3; print(os.path.dirname(volatility3.__file__))")
.venv/bin/pyinstaller --noconfirm --clean --log-level WARN --windowed \
  --name LandullTriage --icon assets/icon.icns --osx-bundle-identifier com.landull.triage \
  --add-data "assets:assets" --add-data "$VOLDIR:volatility3" \
  --collect-submodules volatility3 --collect-submodules triage --hidden-import pefile --paths . \
  landull_triage.py || { echo "BUILD FAILED"; read -r -p "Press Enter to close"; exit 1; }
rm -rf build LandullTriage.spec
echo
echo "BUILD OK -> $(pwd)/dist/LandullTriage.app"
echo "Drag it into your Applications folder to install."
open -R "dist/LandullTriage.app"
