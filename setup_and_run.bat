@echo off
REM Windows: creates a virtual environment (Python 3.12 or 3.11), installs everything, builds the demo data and starts the app.
if exist .venv goto have_venv
py -3.12 -m venv .venv 2>nul
if exist .venv goto have_venv
py -3.11 -m venv .venv 2>nul
if exist .venv goto have_venv
echo Python 3.11 or 3.12 was not found. Install one from python.org (tick "Add Python to PATH") and run this again.
exit /b 1
:have_venv
call .venv\Scripts\activate
pip install -r requirements.txt
if not exist samples\batch\ground_truth.json ( python generate_samples.py )
streamlit run app.py
