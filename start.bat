@echo off
setlocal
cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" set "PYTHON_CMD=.venv\Scripts\python.exe"
if not defined PYTHON_CMD (
    where py >nul 2>nul
    if not errorlevel 1 set "PYTHON_CMD=py -3"
)
if not defined PYTHON_CMD (
    where python >nul 2>nul
    if not errorlevel 1 set "PYTHON_CMD=python"
)
if not defined PYTHON_CMD (
    echo GhostFrame could not find Python.
    echo Install Python 3.10 or newer from https://www.python.org/downloads/
    pause
    exit /b 1
)

%PYTHON_CMD% -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)"
if not %errorlevel%==0 (
    echo GhostFrame requires Python 3.10 or newer. Please update Python and try again.
    pause
    exit /b 1
)

%PYTHON_CMD% -c "import streamlit, PIL, pikepdf" >nul 2>nul
if not %errorlevel%==0 (
    echo GhostFrame dependencies are missing.
    echo Install them with: %PYTHON_CMD% -m pip install -r requirements.txt
    pause
    exit /b 1
)

echo Starting GhostFrame at http://localhost:8501
%PYTHON_CMD% -m streamlit run app.py --server.address localhost --server.port 8501 --server.headless false
if not %errorlevel%==0 pause
