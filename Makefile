run:        ; streamlit run app.py
test:       ; python -m pytest -q
docker:     ; docker compose up -d --build
prod:       ; docker compose -f docker-compose.prod.yml up -d --build
logs:       ; docker compose logs -f qverify
backup:     ; ./scripts/backup.sh
