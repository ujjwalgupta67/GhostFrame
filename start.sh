#!/bin/sh

set -eu
cd "$(dirname "$0")"

if [ -x ".venv/bin/python" ]; then
    PYTHON_CMD=.venv/bin/python
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD=python3
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD=python
else
    echo "GhostFrame could not find Python. Install Python 3.10 or newer from https://www.python.org/downloads/"
    exit 1
fi

if ! "$PYTHON_CMD" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)"; then
    echo "GhostFrame requires Python 3.10 or newer. Please update Python and try again."
    exit 1
fi

if ! "$PYTHON_CMD" -c "import streamlit, PIL, pikepdf" >/dev/null 2>&1; then
    echo "GhostFrame dependencies are missing."
    echo "Install them with: $PYTHON_CMD -m pip install -r requirements.txt"
    exit 1
fi

echo "Starting GhostFrame at http://localhost:8501"
exec "$PYTHON_CMD" -m streamlit run app.py --server.address localhost --server.port 8501 --server.headless false
