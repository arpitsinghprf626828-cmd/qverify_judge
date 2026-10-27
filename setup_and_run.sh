#!/usr/bin/env bash
# macOS / Linux: creates a virtual environment, installs everything, builds the demo data and starts the app.
set -e
[ -d .venv ] || { command -v python3.12 >/dev/null && python3.12 -m venv .venv || python3 -m venv .venv; }
source .venv/bin/activate
pip install -r requirements.txt
[ -f samples/batch/ground_truth.json ] || python generate_samples.py
streamlit run app.py
