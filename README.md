# 🔏 Q-Verify AICTE (SIH26261)
**AI finds the issue. Trusted checks verify the claim. Post-quantum cryptography protects the evidence. Humans decide.**

Decision-support for AICTE reviewers: it reads institution documents, flags suspicious or inconsistent ones with evidence, checks issuer-signed credentials offline, and produces reports that carry a post-quantum signature. Findings are **indicators for human review, never automatic decisions**. All data is synthetic and all issuers are simulated.

| For evaluators | Link |
|---|---|
| 🌐 Live demo | **LIVE_LINK_HERE** |
| 🎥 Demo video | **VIDEO_LINK_HERE** |
| 🔑 Judge login (on the live demo login page) | user `judge1`, password shown on the page |

## 1. See it in 3 minutes (live demo, nothing to install)
1. Open the live link and sign in as **judge1**. (First load can take up to a minute if the server was idle.)
2. **Validate** → choose **Problem sample** → **Run validation**. Open **Findings**: 21 findings, each linked to evidence (edited PDF metadata, a date in a different font, QR mismatch, an ML-DSA credential that contradicts the printed date, reused or distant photos).
3. **Signed Report** → *Generate & sign report* → the gold seal says VALID. Click **Tamper with one finding** → the seal turns red: INVALID.
4. **Verify a Report** (also on the login page, no sign-in needed): upload the downloaded `signed_report.json`, change one character, upload again.
5. Look at **PQC Trust Center**, **Quantum Vault**, **ML & Metrics** and **Audit** (hash-chained log with signed checkpoints).

The judge account can run everything except revoking keys and editing rules, so one evaluator cannot change results for the next. The admin role (local runs) can do both.

## 2. Run it yourself
**Easiest (Docker, no setup):**
```
docker compose -f docker-compose.demo.yml up --build
```
Open http://localhost:8501. Demo accounts are shown on the login page.

**Python 3.11 or 3.12:**
```
python -m venv .venv
.venv\Scripts\activate          (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt
streamlit run app.py
```
Open http://localhost:8501. On first start the app builds its own synthetic demo data (about 30 seconds). Windows users can double-click `setup_and_run.bat` instead, which picks Python 3.12 or 3.11 automatically.
Tesseract OCR is optional (only for scanned files and photos): Windows installer from the UB Mannheim page, Ubuntu `sudo apt install tesseract-ocr`, macOS `brew install tesseract`.

Local demo accounts (shown on the login page when `QV_DEMO` is not 0):
| User | Password | Role |
|---|---|---|
| applicant1 | Applicant@123 | upload, see findings, vault |
| reviewer1 | Reviewer@123 | decisions, signing, dashboard, batch |
| auditor1 | Auditor@123 | read-only, audit trail |
| admin1 | Admin@123 | everything: keys, rules, audit |

Run the tests: `python -m pytest -q` (19 tests). Deployment guide: `DEPLOY.md`.

## 3. What makes it different
- **Post-quantum cryptography is part of the workflow, not a badge:** issuer credentials (ML-DSA) embedded in certificates and verified offline, a root-signed key registry with revoke/reinstate, signed reports with a classical+post-quantum hybrid, an ML-KEM-sealed evidence vault, and a hash-chained audit log with signed Merkle checkpoints.
- **Explainable AI, advisory only:** keyword-first document classifier with a TF-IDF/logistic-regression helper, and an IsolationForest anomaly score. Neither decides anything.
- **Evidence, not black-box scores:** 19 configurable rules, each finding highlights the exact spot on the page.
- **Applicant-friendly:** a 0 to 100 submission-readiness gauge so applicants can fix problems before filing.

## 4. Five-minute demo script (log in as admin1 locally)
1. **Dashboard** → validate the clean and problem samples and the 24-application labelled batch (about 25 s).
2. **Validate** → Problem sample → **Findings** (21).
3. **PQC Trust Center**: registry (root-signed), **Forgery lab** (change a date → INVALID), **Revoke** the NBA key, re-run validation (its certificates are rejected), then **Reinstate**. Note: revocation changes results for everyone until reinstated, which is why the judge role cannot do it.
4. **Signed Report** → sign → VALID → Tamper → INVALID. **Verify a Report**: upload the JSON.
5. **Quantum Vault**, **ML & Metrics**, **Rules**, **Benchmark**, **Audit**. Then run the **Clean sample**: zero findings.

## 5. What is in each file
| File | Purpose |
|---|---|
| `app.py`, `ui.py` | Streamlit app (login, dashboard, findings with evidence viewer, trust center, vault, ML tab, rule editor, audit) and its design system |
| `engine.py` | Reading, 19 configurable rules, issuer verification, scoring, report |
| `rules.json` | Rules, severities, handbook references and thresholds (editable in the app) |
| `ocr.py` | Text cascade: digital text first, Tesseract OCR for scans/images, word confidence |
| `forensics.py` | PDF metadata/fonts/incremental saves, QR decode, perceptual hash, EXIF GPS, blur, hash store, evidence highlighter |
| `ml.py` | Explainable ML: document classifier (TF-IDF + logistic regression) and IsolationForest anomaly score (advisory) |
| `pqc/registry.py` | Root-signed trusted key registry (ML-DSA-65), revoke / reinstate |
| `pqc/credentials.py` | Issuer-signed ML-DSA credentials embedded in certificates, verified offline |
| `pqc/signing.py` | Signed verification reports (ML-DSA-44 + Ed25519 hybrid), QR, benchmark |
| `pqc/vault.py` | ML-KEM-768 + AES-256-GCM sealed storage |
| `pqc/audit.py` | Hash-chained audit log + ML-DSA-signed Merkle checkpoints |
| `auth.py`, `store.py`, `reporting.py` | Roles (scrypt-hashed passwords), case database + alerts, PDF report |
| `generate_samples.py` | Builds clean/problem samples, photos, the 24-app labelled batch + ground truth, mock registry, demo PKI |
| `metrics.py` | Extraction accuracy and per-rule precision/recall on the batch (`python metrics.py`) |
| `tests/` | 19 automated tests (`python -m pytest -q`) |

## 6. Honest limits (say these to judges)
- ML-DSA / ML-KEM come from pure-Python educational libraries (`dilithium-py`, `kyber-py`): correct but not side-channel hardened. Production would use liboqs or a vendor library with an HSM/KMS.
- A valid signature proves a record is unchanged since a trusted key signed it. It does not prove the underlying claims are true.
- Issuer registries, AICTE records and certificates are synthetic simulations. Real integration needs authorised access.
- Metrics are measured on synthetic data with injected faults: they show the rules work, not real-world accuracy. Quote the sample size (24 applications, 433 fields).
- The ML models train on synthetic text; the anomaly score is advisory and never decides anything. All findings are indicators for human review.
- Never describe the system as "quantum computing" or "quantum-proof": it uses post-quantum cryptography on ordinary computers.

## 7. Reset / troubleshooting
- Reset everything: delete `keys/ vault/ models/ samples/ cases.db users.json audit*.jsonl hashes.db registry.json` then `python generate_samples.py`.
- "Run python generate_samples.py first": sample data missing. Run it.
- OCR rows say method `none`: Tesseract is not installed or not on PATH.
- Port busy: `streamlit run app.py --server.port 8600`.
- First start trains the ML models (a few seconds).
