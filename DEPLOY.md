# Deploying Q-Verify (complete guide)

Everything needed is in this folder: `Dockerfile`, `docker-compose.yml` (simple), `docker-compose.prod.yml` (HTTPS), `Caddyfile`,
`render.yaml`, `fly.toml`, `.github/workflows/ci.yml`, `scripts/backup.sh`, `scripts/restore.sh`, `.env.example`, `Makefile`.

## 1. Configure (all options)
`cp .env.example .env` and edit. Key settings:
| Variable | Meaning |
|---|---|
| `QV_DEMO=0` | Hide demo accounts and never use the known demo passwords |
| `QV_PW_ADMIN1`, `QV_PW_REVIEWER1`, `QV_PW_AUDITOR1`, `QV_PW_APPLICANT1` | Your own passwords (if unset in demo-off mode, random ones are printed once in the logs) |
| `QV_KEY_PASSPHRASE` | Encrypts every private key at rest (AES-256-GCM, scrypt). Keep it safe: without it the keys cannot be read |
| `QV_SEED_DEMO=1` | Build synthetic demo data on first start (0 = empty system) |
| `QV_IDLE_MINUTES=30` | Automatic sign-out after inactivity |
| `DOMAIN`, `ACME_EMAIL` | Public hostname and e-mail for the automatic HTTPS certificate |

Built-in protections: login lockout (5 failures in 10 minutes), scrypt-hashed passwords, idle timeout, encrypted keys, ML-KEM sealed uploads, signed audit log.

## 2. Run
- **Local / quick server:** `docker compose up -d --build` then http://localhost:8501
- **Public HTTPS on your own server (recommended):** point a DNS A record for `DOMAIN` at the server, open ports 80 and 443, then
  `docker compose -f docker-compose.prod.yml up -d --build`. Caddy obtains and renews the certificate automatically.
- **Render:** New > Blueprint from the repo (uses `render.yaml`, persistent disk at /data, random key passphrase generated; set the four passwords).
- **Fly.io:** `fly launch --no-deploy`, `fly volumes create qv_data --size 1`, `fly secrets set QV_KEY_PASSPHRASE=... QV_PW_ADMIN1=...`, `fly deploy` (uses `fly.toml`).
- **Streamlit Community Cloud (demo only):** push to GitHub, create the app from `app.py`; `packages.txt` installs Tesseract. Data is ephemeral there.
- **No Docker:** `setup_and_run.bat` / `./setup_and_run.sh`.

## Public evaluator access (SIH)
Set `QV_JUDGE_PASSWORD` (Fly: `fly secrets set QV_JUDGE_PASSWORD=...`; compose: add to `.env`). The login page then shows a "Judge access" box with user `judge1` and that password, and the demo accounts stay hidden. The judge role cannot revoke keys or edit rules. Remove the variable after the evaluation and `judge1` is deleted on the next login attempt.

## Fly.io (recommended for months-long hosting)
Edit `app` in `fly.toml` to a unique name, then follow the commands at the top of that file. The 2 GB memory setting and the 180 s health-check grace period are required: the first start builds the demo data. Keep `QV_KEY_PASSPHRASE` in a password manager.

## 3. Operate
- Logs: `make logs` (first-start random passwords appear here if you did not set them).
- Backup: `make backup` writes `backups/qverify-DATE.tar.gz` (contains encrypted keys, case database, audit log). Restore: `docker compose down && scripts/restore.sh backups/FILE && docker compose up -d`.
- Update: `git pull && docker compose up -d --build` (state is in the `qv_data` volume and survives).
- CI: the GitHub Action runs the test suite and a Docker build on every push.
- Key passphrase: it cannot be changed after keys exist (there is no re-encryption under a new passphrase yet). Choose it before first start, store it in a password manager, and include it in your disaster-recovery notes. `keystore.rotate_all()` only encrypts keys that were created while no passphrase was set.

## 4. What was and was not verified
Verified in this build: the judge-account and file-name logic in isolation; earlier builds passed 19 automated tests (not re-run after the latest patch, run `python -m pytest -q` yourself); the container entrypoint run in production mode (health check, demo accounts hidden, env passwords, login lockout, validation, signing, encrypted keys including the ML-KEM vault key); a fresh start from an empty folder.
NOT verified here: the Docker image build and the Caddy/Render/Fly configs, because the build environment could not pull images from Docker Hub. They follow standard patterns, but run `docker compose up --build` once on your machine and watch the logs before going live.

## 5. Honest limits for a real regulator deployment
- ML-DSA/ML-KEM come from pure-Python libraries that are not side-channel hardened; switch to liboqs and keep keys in an HSM/KMS for production.
- Issuers, AICTE records and certificates are simulated; integrate authorised sources before relying on results.
- Login is application-level; for production put SSO (OIDC) in front of it. Findings are indicators for human review, never decisions.
