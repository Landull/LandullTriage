@echo off
rem Double-click to build dist\LandullTriage\LandullTriage.exe
cd /d "%~dp0"
if not exist .venv ( py -3 -m venv .venv || python -m venv .venv )
.venv\Scripts\python -m pip install -q --upgrade pip
.venv\Scripts\python -m pip install -q -r requirements.txt || goto :fail
.venv\Scripts\python fetch_tools.py || goto :fail
for /f "delims=" %%v in ('.venv\Scripts\python -c "import os, volatility3; print(os.path.dirname(volatility3.__file__))"') do set VOLDIR=%%v
.venv\Scripts\pyinstaller --noconfirm --clean --log-level WARN --windowed --name LandullTriage ^
  --icon assets\icon.ico --add-data "assets;assets" --add-data "%VOLDIR%;volatility3" ^
  --collect-submodules volatility3 --collect-submodules triage --hidden-import pefile --paths . ^
  landull_triage.py || goto :fail
rmdir /s /q build & del LandullTriage.spec
echo BUILD OK -^> dist\LandullTriage\LandullTriage.exe
pause
exit /b 0
:fail
echo BUILD FAILED
pause
exit /b 1
