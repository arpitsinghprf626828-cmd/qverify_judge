#!/bin/sh
# All state (keys, vault, models, case database, audit log, users) lives in /data so it survives container restarts.
set -e
mkdir -p /data && cd /data
[ -f rules.json ] || cp /app/rules.json .
[ -d .streamlit ] || cp -r /app/.streamlit .
if [ "${QV_SEED_DEMO:-1}" = "1" ] && [ ! -f samples/batch/ground_truth.json ]; then python /app/generate_samples.py; fi
exec streamlit run /app/app.py --server.port "${PORT:-8501}" --server.address 0.0.0.0
