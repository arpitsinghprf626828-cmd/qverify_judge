import json, copy, os
from pathlib import Path
import pandas as pd, streamlit as st
import engine, ui, auth, store, reporting, metrics, ml
import forensics as fx
from pqc import registry, signing, credentials, vault
from pqc.audit import AuditLog

st.set_page_config(page_title="Q-Verify AICTE", page_icon="🔏", layout="wide")
def _prod_guard():
    """Deployment mode (QV_DEMO=0) must not start with raw keys or placeholder secrets."""
    if os.environ.get("QV_DEMO", "1") != "0": return
    probs = []
    if not os.environ.get("QV_KEY_PASSPHRASE"): probs.append("QV_KEY_PASSPHRASE is not set (private keys would be stored unencrypted)")
    probs += [f"{k} still has a placeholder value" for k, x in os.environ.items() if k.startswith("QV_") and "change-me" in x.lower()]
    if probs:
        st.error("Server is not configured safely, so it refused to start:\n\n" + "\n".join("- " + p for p in probs)); st.stop()
_prod_guard()
ui.inject(); registry.ensure_pki(); auth.ensure_users()
if os.environ.get("QV_SEED_DEMO", "1") != "0" and not Path("samples/batch/ground_truth.json").exists():
    import subprocess, sys
    with st.spinner("First start: building synthetic demo data (about 30 seconds)..."):
        subprocess.run([sys.executable, str(Path(__file__).resolve().parent / "generate_samples.py")], check=False)
audit = AuditLog(); SS = st.session_state
@st.cache_resource
def get_hs(): return fx.HashStore()
@st.cache_resource
def get_cases(): return store.CaseStore()
HS, CASES = get_hs(), get_cases()
REG = json.load(open("registry.json")) if Path("registry.json").exists() else {"institutions": {}, "issuers": {}}
SEV = {"High": "🔴", "Medium": "🟠", "Low": "🟡"}
TAGS = ["ML-DSA (FIPS 204)", "ML-KEM (FIPS 203)", "Offline credential verification", "Hash-chained + signed audit", "Explainable ML", "Human final decision", "Synthetic data · simulated issuers"]
SS.setdefault("user", None)
SHOW_DEMO = os.environ.get("QV_DEMO", "1") != "0"

def verify_widget(key):
    st.write("Check any signed report: upload `signed_report.json`. Edit one character in a text editor first to watch it fail.")
    up = st.file_uploader("signed_report.json", type=["json"], key=key)
    if up:
        try:
            env = json.load(up); vv = signing.verify_envelope(env)
            ui.seal_banner(vv["valid"], "Authentic and unchanged" if vv["valid"] else "Verification failed",
                           f"{env.get('alg')} · key {env.get('key_id')} · signed {env.get('signed_at')}" if vv["valid"] else f"Reason: {vv.get('reason')}. The report was altered or signed by an untrusted key.")
            st.caption(f"Technical detail: {vv}")
        except Exception as e: st.error(f"Not a valid envelope: {e}")

# ================= LOGIN =================
if not SS.user:
    ui.hero("Q-Verify AICTE", "AI finds the issue • Trusted checks verify the claim • <b>Post-quantum cryptography protects the evidence</b>", TAGS)
    a, b = st.columns([1, 1], gap="large")
    with a:
        with st.form("login"):
            st.subheader("Sign in"); u = st.text_input("Username"); pw = st.text_input("Password", type="password")
            if st.form_submit_button("Sign in", type="primary"):
                wait = auth.locked_for(u)
                user = None if wait else auth.login(u, pw)
                if wait: st.error(f"Too many failed attempts. Try again in {wait // 60 + 1} minute(s).")
                elif user: SS.user = user; audit.add(u, "login", user["role"]); st.rerun()
                else: audit.add(u or "?", "login_failed", ""); st.error("Invalid username or password")
        with st.expander("🔏 Verify a signed report (no sign-in needed)"): verify_widget("pub_login")
    with b:
        if SHOW_DEMO:
            st.subheader("Demo accounts")
            st.dataframe(pd.DataFrame([[k, v[0], v[1]] for k, v in auth.DEMO.items()], columns=["Username", "Role", "Password"]), hide_index=True)
            st.caption("Applicant: upload & see own findings. Reviewer: decisions & signing. Auditor: read-only + audit. Admin: keys, rules, everything.")
        elif os.environ.get("QV_JUDGE_PASSWORD"):
            st.subheader("Judge access")
            st.info(f"Username **judge1**  ·  Password **{os.environ['QV_JUDGE_PASSWORD']}**\n\nSynthetic data only. Suggested path: Validate → Problem sample → Run validation → Findings → Signed Report → Tamper.")
        else:
            st.subheader("How it works"); st.write("Applicants upload evidence and get an instant readiness check. Reviewers see evidence-linked findings and decide. Every report is signed with post-quantum cryptography and can be verified by anyone.")
    st.stop()

import time
IDLE = int(os.environ.get("QV_IDLE_MINUTES", "30")) * 60
if time.time() - SS.get("last_seen", time.time()) > IDLE:
    audit.add(SS.user["name"], "session_timeout", ""); SS.user = None; SS.pop("result", None); st.warning("Signed out after inactivity."); st.rerun()
SS.last_seen = time.time()
U = SS.user; P = lambda perm: auth.can(U, perm)
with st.sidebar:
    st.markdown(f"**👤 {U['name']}**  \n{ui.pill(U['role'], 'pq')}", unsafe_allow_html=True)
    if st.button("Sign out"): audit.add(U["name"], "logout", ""); SS.user = None; SS.pop("result", None); st.rerun()
    st.caption("Everything here uses synthetic data. Issuers and AICTE records are SIMULATED.")
ui.hero("Q-Verify AICTE", "AI finds the issue • Trusted checks verify the claim • <b>Post-quantum cryptography protects the evidence</b>", TAGS)

names = ["🏠 Overview"]
if P("view_all"): names.append("📋 Dashboard")
if P("upload"): names.append("📥 Validate")
if P("upload") or P("view_all"): names.append("🔎 Findings")
if P("view_trust"): names.append("🔐 PQC Trust Center")
names.append("✅ Verify a Report")
if P("sign"): names.append("📝 Signed Report")
if P("view_vault"): names.append("🗄️ Quantum Vault")
if P("view_all"): names.append("🧠 ML & Metrics")
if P("edit_rules"): names.append("⚙️ Rules")
if P("view_trust"): names.append("📊 Benchmark & Readiness")
if P("view_audit"): names.append("🧾 Audit")
T = dict(zip(names, st.tabs(names)))
def samples(folder):
    f = Path("samples") / folder
    return ([(p.name, p.read_bytes()) for p in sorted(f.iterdir()) if p.suffix.lower() in (".pdf", ".jpg", ".jpeg", ".png")], json.load(open(f / "form.json"))) if f.exists() else ([], None)

# ================= OVERVIEW =================
with T["🏠 Overview"]:
    st.subheader("Why post-quantum?")
    st.write("Approval evidence must stay verifiable for years. Signatures based on RSA/ECC are expected to be breakable by a large future quantum computer, so records that look authentic could one day be forged. "
             "Q-Verify uses NIST-standardised post-quantum algorithms for everything that must stay trustworthy.")
    c = st.columns(4)
    ui.card(c[0], "Issuer-signed credentials", "Certificates carry an ML-DSA signature from the issuer. Verified <b>offline</b>; edited dates or fields fail instantly.", "🏛️")
    ui.card(c[1], "Signed reports", "Each verification report is signed (ML-DSA, optional Ed25519 hybrid). One changed character = INVALID.", "📝")
    ui.card(c[2], "Quantum-safe vault", "Uploads sealed with ML-KEM-768 key exchange + AES-256-GCM, bound to the case id.", "🗄️")
    ui.card(c[3], "Tamper-evident audit", "Hash chain plus ML-DSA-signed Merkle checkpoints: even a full history rewrite is caught.", "🧾")
    st.write(""); c = st.columns(4)
    ui.card(c[0], "AI document reading", "Text extraction with OCR fallback (Tesseract), explainable ML classifier, fields with page + snippet evidence.", "🤖")
    ui.card(c[1], "19 configurable rules", "Handbook-aligned checks stored in rules.json and editable in the app, each with a clause reference.", "📏")
    ui.card(c[2], "Forensics", "Metadata, mixed fonts, incremental saves, QR vs printed reference, photo reuse (perceptual hash), GPS and blur.", "🔬")
    ui.card(c[3], "Human in control", "Findings are indicators with evidence. Reviewers accept, reject, request clarification or escalate, with a reason.", "🧑‍⚖️")
    st.info("A valid signature proves a record is unchanged since the trusted key signed it. It does not prove the underlying claims are true; that needs issuer verification and human review.")

# ================= DASHBOARD =================
if "📋 Dashboard" in T:
    with T["📋 Dashboard"]:
        rows = CASES.rows(); df = pd.DataFrame(rows)
        k = st.columns(4)
        ui.kpi(k[0], len(rows), "Cases"); ui.kpi(k[1], sum(r["status"] == "Needs review" for r in rows), "Needs review", "#b7791f")
        ui.kpi(k[2], sum(r["status"] == "Escalated" for r in rows), "Escalated", "#b42318"); ui.kpi(k[3], sum(r["high"] for r in rows), "High findings (all cases)", "#0b7a6b")
        st.write("")
        if P("run_batch") and st.button("▶ Validate clean + problem samples and the 24-application labelled batch"):
            prog = st.progress(0.0, "Running..."); jobs = [("clean", "samples/clean"), ("problem", "samples/problem")] + [(a.name, str(a)) for a in sorted(Path("samples/batch").glob("app_*"))]
            for i, (nm, path) in enumerate(jobs):
                fo = Path(path); docs = [(p.name, p.read_bytes()) for p in sorted(fo.iterdir()) if p.suffix.lower() in (".pdf", ".jpg", ".png")]; form = json.load(open(fo / "form.json"))
                res = engine.validate(docs, form, REG, hash_store=HS); CASES.add(U["name"], form, res); prog.progress((i + 1) / len(jobs), f"{nm}")
            audit.add(U["name"], "batch_run", f"{len(jobs)} applications"); st.rerun()
        if df.empty: st.info("No cases yet. Run a validation or the batch.")
        else:
            f1, f2 = st.columns(2); stt = f1.multiselect("Status", sorted(df.status.unique()), default=list(df.status.unique())); q = f2.text_input("Institution contains")
            v = df[df.status.isin(stt) & df.inst_name.str.contains(q, case=False)]
            st.dataframe(v[["id", "ts", "inst_name", "inst_id", "status", "score", "high", "n", "user"]], hide_index=True, width="stretch")
            st.subheader("Priority queue (highest explainable score first)")
            st.dataframe(df[df.status.isin(["Needs review", "Escalated"])].sort_values("score", ascending=False).head(8)[["id", "inst_name", "score", "high", "status"]], hide_index=True, width="stretch")
            if P("decide"):
                c1, c2, c3 = st.columns([1, 1, 1]); cid = c1.selectbox("Case id", list(df.id)); ns = c2.selectbox("Set status", ["Needs review", "Escalated", "Resolved"])
                if c3.button("Update status"): CASES.set_status(cid, ns); audit.add(U["name"], "case_status", f"case {cid} -> {ns}"); st.rerun()
        st.subheader("Alerts")
        al = CASES.alerts()
        if al:
            st.dataframe(pd.DataFrame(al), hide_index=True, width="stretch")
            if P("decide") and st.button("📧 Send alerts (simulated e-mail to outbox/alerts.log)"):
                p = store.send_alert("\n".join(f"Case {a['case']} {a['institution']}: {a['type']} - {a['detail']}" for a in al[:30])); audit.add(U["name"], "alerts_sent", str(p)); st.success(f"Written to {p}")
        else: st.success("No open alerts.")

# ================= VALIDATE =================
if "📥 Validate" in T:
    with T["📥 Validate"]:
        src = st.radio("Application source", ["Clean sample", "Problem sample", "Upload my own"], horizontal=True)
        as_of = st.date_input("Validation date", value=pd.Timestamp.today().date())
        if src != "Upload my own":
            docs, form = samples("clean" if src == "Clean sample" else "problem")
            if not docs: st.warning("Run `python generate_samples.py` first.")
        else:
            a, b, c = st.columns(3)
            form = {"category": "Extension of Approval (EoA)", "institution_id": a.text_input("Institution ID", "AICTE-1-100234"), "institution_name": b.text_input("Institution name", "Narmada Institute of Technology (Demo)"),
                    "claimed_intake": int(c.number_input("Claimed intake", value=360))}
            la, lo = st.columns(2); lat = la.text_input("Campus latitude (optional)"); lon = lo.text_input("Campus longitude (optional)")
            if lat and lon: form.update(campus_lat=float(lat), campus_lon=float(lon))
            docs = [(x.name, x.read()) for x in (st.file_uploader("Upload PDFs or photos (jpg/png)", type=["pdf", "jpg", "jpeg", "png"], accept_multiple_files=True) or [])]
        if form: st.json(form, expanded=False)
        st.write(f"**{len(docs)} file(s)**: " + ", ".join(n for n, _ in docs))
        if st.button("▶ Run validation", type="primary", disabled=not docs):
            with st.spinner("Sealing files, reading, checking rules, verifying credentials..."):
                res = engine.validate(docs, form, REG, as_of, hash_store=HS); SS.update(result=res, form=form, env=None, docs=docs)
                for n, bts in docs: vault.store(n, bts, form["institution_id"])
                SS.case_id = CASES.add(U["name"], form, res)
                audit.add(U["name"], "validation_run", f"{form['institution_id']} | {len(docs)} files | score {res['score']} | {engine.RULES_VERSION[:20]}")
                for p in res["parsed"]:
                    if p.get("issuer"): audit.add("system", "issuer_check", f"{p['name']} -> {p['issuer']['status']} (pqc={p['issuer']['pqc']})")
            st.success("Done. Open the Findings tab.")

# ================= FINDINGS =================
if "🔎 Findings" in T:
    with T["🔎 Findings"]:
        r = SS.get("result")
        if not r: st.info("Run a validation first.")
        else:
            F = r["findings"]; k = st.columns(4); bytes_of = dict(SS.get("docs", []))
            ui.kpi(k[0], len(r["parsed"]), "Files"); ui.kpi(k[1], len(F), "Findings", "#b7791f"); ui.kpi(k[2], sum(f["severity"] == "High" for f in F), "High severity", "#b42318"); ui.kpi(k[3], r["score"], "Priority score", "#0b7a6b")
            st.write(""); ui.readiness(F); st.write("")
            with st.expander("Why this priority score? (explainable)"): st.table(pd.DataFrame(r["breakdown"], columns=["Finding", "Rule", "Points"]))
            st.subheader("Checklist and verification status"); have = {p["doc_type"]: p for p in r["parsed"]}
            for q in engine.load_rules()["category_checklists"][SS.form["category"]]:
                p = have.get(q); c1, c2, c3 = st.columns([2, 3, 4]); c1.write(f"**{ {'noc': 'NOC', 'fire_safety': 'Fire safety'}.get(q, q.replace('_', ' ').capitalize()) }**"); c2.write(("✅ " + p["name"]) if p else "❌ MISSING")
                iss = (p or {}).get("issuer")
                c3.markdown((ui.status_pill(iss["status"]) + (" " + ui.pill("PQC offline", "pq") if iss["pqc"] else "")) if iss else ui.pill("n/a"), unsafe_allow_html=True)
            photos = [p for p in r["parsed"] if p["kind"] == "photo"]
            if photos:
                st.subheader("Infrastructure photos"); cols = st.columns(len(photos))
                for c, p in zip(cols, photos):
                    c.image(bytes_of.get(p["name"]), caption=f"{p['name']} | sharpness {p['image']['blur']} | GPS {p['image']['gps'] and tuple(round(x, 3) for x in p['image']['gps'])}" if p["image"] else p["name"])
            st.subheader("Evidence-linked findings")
            if not F: st.success("No findings. Clean application.")
            for f in F:
                with st.expander(f"{SEV[f['severity']]} {f['id']} · {f['rule']} · {f['document']} — {f['message']}"):
                    st.write(f"**Rule applied:** {f['rule']} — {f['rule_text']}"); st.write(f"**Handbook reference:** {f['handbook_ref']}"); st.write(f"**Evidence:** {f['evidence'] or '-'}")
                    raw = bytes_of.get(f["document"])
                    if raw and f.get("needle") and f["document"].lower().endswith(".pdf"):
                        png = fx.highlight_png(raw, f["page"] or 1, f["needle"])
                        if png: st.image(png, caption="Evidence highlighted on the document page", width=380)
                    st.caption("Preliminary indicator requiring human verification, not proof of misconduct.")
                    if P("decide"):
                        c1, c2 = st.columns([1, 2]); act = c1.selectbox("Reviewer action", ["—", "Accept", "Reject", "Request clarification", "Escalate"], key="a" + f["id"]); why = c2.text_input("Reason", key="w" + f["id"])
                        if st.button("Record decision", key="b" + f["id"]) and act != "—" and why:
                            auth.need(U, "decide", audit); audit.add(U["name"], f"finding_{act.lower().replace(' ', '_')}", f"{f['id']} {f['rule']}: {why}")
                            if act == "Escalate" and SS.get("case_id"): CASES.set_status(SS.case_id, "Escalated")
                            st.success("Recorded in audit trail")
                    else: st.caption("Read-only for your role.")

# ================= PQC TRUST CENTER =================
if "🔐 PQC Trust Center" in T:
    with T["🔐 PQC Trust Center"]:
        st.subheader("Trusted key registry"); reg, ok = registry.load()
        st.markdown(ui.pill("Registry signature valid (root ML-DSA-65)", "ok") if ok else ui.pill("REGISTRY TAMPERED", "bad"), unsafe_allow_html=True)
        st.dataframe(pd.DataFrame([{"Issuer": e["issuer_id"], "Owner": e["owner"], "Algorithm": e["alg"], "Key ID": e["key_id"], "Valid to": e["valid_to"], "Status": e["status"]} for e in reg.values()]), hide_index=True, width="stretch")
        if P("manage_keys"):
            c1, c2, c3 = st.columns([2, 1, 1]); who = c1.selectbox("Issuer key", [e["issuer_id"] for e in reg.values() if e["issuer_id"] != "PLATFORM"])
            if c2.button("🚫 Revoke key"): auth.need(U, "manage_keys", audit); registry.revoke(who); audit.add(U["name"], "key_revoked", who); st.rerun()
            if c3.button("♻ Reinstate"): auth.need(U, "manage_keys", audit); registry.reinstate(who); audit.add(U["name"], "key_reinstated", who); st.rerun()
            st.caption("Revoke an issuer key and re-run validation: every credential from that issuer is rejected.")
        else: st.caption("Key revocation is limited to the admin role.")
        r = SS.get("result"); st.subheader("Document credentials (verified offline)")
        if not r: st.info("Run a validation first.")
        else:
            rows, envs = [], {}
            for p in r["parsed"]:
                s = p["meta"].get("cred") if p["meta"] else None
                if s:
                    env = credentials.decode(s); v = credentials.verify(env); envs[p["name"]] = env
                    rows.append({"Document": p["name"], "Issuer": v["issuer"], "Key ID": v["key_id"], "Signature": "VALID" if v["ok"] else f"INVALID ({v['reason']})", "Signature size (B)": len(registry.unb64(env["sig"])), "Document check": (p.get("issuer") or {}).get("status")})
                elif p["kind"] != "photo": rows.append({"Document": p["name"], "Issuer": "-", "Key ID": "-", "Signature": "no credential", "Signature size (B)": 0, "Document check": (p.get("issuer") or {}).get("status", "n/a")})
            st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
            if envs:
                st.subheader("🧪 Forgery lab"); pick = st.selectbox("Credential", list(envs)); env = copy.deepcopy(envs[pick]); st.json(env["payload"])
                newv = st.text_input("Change valid_until to", str(env["payload"].get("valid_until") or ""))
                if st.button("Verify edited credential"):
                    env["payload"]["valid_until"] = newv; v = credentials.verify(env)
                    (st.success if v["ok"] else st.error)("Unchanged - VALID" if v["ok"] else f"INVALID - {v['reason']} (an attacker cannot re-sign without the issuer's private key)"); audit.add(U["name"], "forgery_lab", f"{pick}: ok={v['ok']}")

# ================= VERIFY A REPORT (all roles) =================
with T["✅ Verify a Report"]:
    verify_widget("pub")

# ================= SIGNED REPORT =================
if "📝 Signed Report" in T:
    with T["📝 Signed Report"]:
        r = SS.get("result")
        if not r: st.info("Run a validation first.")
        else:
            hybrid = st.checkbox("Hybrid mode (ML-DSA + Ed25519; both must verify)", value=True)
            if st.button("🔏 Generate & sign report", type="primary"):
                auth.need(U, "sign", audit); SS.env = signing.sign_report(engine.build_report(SS.form, r), hybrid); audit.add(U["name"], "report_signed", f"{SS.env['alg']} key {SS.env['key_id']} sha256 {SS.env['report_sha256'][:16]}")
            env = SS.get("env")
            if env:
                c1, c2 = st.columns([2, 1])
                with c1:
                    v = signing.verify_envelope(env); ui.seal_banner(v["valid"], "Signature VALID" if v["valid"] else "Signature INVALID", f"{env['alg']} · key {env['key_id']}" if v["valid"] else f"Reason: {v.get('reason')}"); st.caption(f"Technical detail: {v}")
                    if st.button("😈 Tamper with one finding, then verify"):
                        t = copy.deepcopy(env)
                        if t["report"]["findings"]: t["report"]["findings"][0]["severity"] = "Low"
                        else: t["report"]["priority_score"] += 1
                        vt = signing.verify_envelope(t); ui.seal_banner(vt["valid"], "Still valid?!" if vt["valid"] else "Tampering detected: signature INVALID", "One finding was edited after signing, so verification fails." if not vt["valid"] else "Unexpected: investigate."); st.caption(f"Technical detail: {vt}"); audit.add("demo", "tamper_test", f"valid={vt['valid']}")
                    d1, d2 = st.columns(2); d1.download_button("⬇ Signed report (JSON)", json.dumps(env, indent=2), "signed_report.json"); d2.download_button("⬇ Report (PDF)", reporting.report_pdf(env), "verification_report.pdf")
                    st.caption(f"{env['alg']} · key {env['key_id']} · {env['signed_at']}")
                c2.image(signing.qr_png(env), caption="QR: algorithm, key id, report hash")

# ================= VAULT =================
if "🗄️ Quantum Vault" in T:
    with T["🗄️ Quantum Vault"]:
        st.write("Uploaded files are sealed with **ML-KEM-768** (key encapsulation) + **AES-256-GCM**. The key exchange does not rely on RSA/ECC.")
        docs = SS.get("docs")
        if not docs: st.info("Run a validation first to seal files.")
        else:
            n = st.selectbox("File", [x for x, _ in docs]); raw = dict(docs)[n]; case = SS.form["institution_id"]; blob = vault.seal(raw, case); i = vault.info(blob)
            a, b, c = st.columns(3); ui.kpi(a, f"{len(raw):,} B", "Original"); ui.kpi(b, f"{len(blob):,} B", "Sealed blob", "#5b3fd6"); ui.kpi(c, f"{i['kem_ciphertext_bytes']} B", "KEM ciphertext")
            st.markdown(f'<div class="sig">sealed (first 96 bytes): {blob[:96].hex()}...</div>', unsafe_allow_html=True)
            if st.button("Open sealed file"): st.success(f"Decrypted OK: {vault.open_sealed(blob, case) == raw}")
            if st.button("Try opening under a different case id"):
                try: vault.open_sealed(blob, "OTHER-CASE"); st.error("Unexpected success")
                except Exception: st.success("Rejected: the case id is bound as associated data, so files cannot be swapped between cases.")

# ================= ML & METRICS =================
if "🧠 ML & Metrics" in T:
    with T["🧠 ML & Metrics"]:
        st.write("**Explainable ML.** A TF-IDF + logistic-regression classifier names the document type and shows the terms behind its decision. An IsolationForest scores unusual file characteristics (advisory only). Both train on SYNTHETIC data and retrain automatically.")
        mp = Path("models/metrics.json")
        if mp.exists(): st.json(json.loads(mp.read_text()), expanded=False)
        r = SS.get("result")
        if r: st.dataframe(pd.DataFrame([{"File": p["name"], "Kind": p["kind"], "Type used": p["doc_type"], "ML type": (p["ml"] or {}).get("type"), "ML confidence": round((p["ml"] or {}).get("confidence", 0), 3),
                                          "Why (top terms)": ", ".join((p["ml"] or {}).get("top_terms", [])), "Extraction": p["method"], "Anomaly score": (p["anomaly"] or {}).get("score")} for p in r["parsed"]]), hide_index=True, width="stretch")
        c1, c2 = st.columns(2)
        if c1.button("▶ Evaluate on the 24-application labelled batch"):
            with st.spinner("Evaluating..."): SS.eval = metrics.run()
        if c2.button("♻ Retrain models") and P("edit_rules"): ml.train_classifier(); ml.train_anomaly(); st.success("Retrained")
        e = SS.get("eval") or (json.load(open("models/eval.json")) if Path("models/eval.json").exists() else None)
        if e:
            k = st.columns(4); ui.kpi(k[0], e["applications"], "Applications"); ui.kpi(k[1], f"{e['extraction_accuracy']:.1%}", f"Extraction ({e['fields_checked']} fields)", "#0b7a6b")
            ui.kpi(k[2], f"{e['micro_precision']:.2f} / {e['micro_recall']:.2f}", "Precision / recall", "#5b3fd6"); ui.kpi(k[3], f"{e['avg_seconds_per_case']}s", "Avg time per case")
            st.dataframe(pd.DataFrame(e["per_rule"]), hide_index=True, width="stretch")
            st.caption("Measured on synthetic applications with injected faults, so it shows rule correctness, not real-world accuracy. Report the sample size whenever you quote these numbers.")

# ================= RULES =================
if "⚙️ Rules" in T:
    with T["⚙️ Rules"]:
        cfg = engine.load_rules(); st.write("Rules and thresholds live in `rules.json`. Changes apply to the next validation and are written to the audit trail.")
        S = cfg["settings"]; cols = st.columns(4)
        for i, (k, v) in enumerate(S.items()):
            S[k] = type(v)(cols[i % 4].text_input(k, str(v), key="s_" + k)) if not isinstance(v, str) else cols[i % 4].text_input(k, v, key="s_" + k)
        for rid, rule in cfg["rules"].items():
            c1, c2, c3, c4 = st.columns([1, 1, 3, 3]); rule["enabled"] = c1.toggle(rid, rule["enabled"], key="e" + rid)
            rule["severity"] = c2.selectbox("Severity", ["High", "Medium", "Low"], ["High", "Medium", "Low"].index(rule["severity"]), key="v" + rid, label_visibility="collapsed")
            c3.caption(rule["text"]); rule["handbook_ref"] = c4.text_input("Handbook ref", rule["handbook_ref"], key="h" + rid, label_visibility="collapsed")
        if st.button("💾 Save rules", type="primary"):
            auth.need(U, "edit_rules", audit); engine.save_rules(cfg); audit.add(U["name"], "rules_changed", f"enabled={sum(r['enabled'] for r in cfg['rules'].values())}/{len(cfg['rules'])}"); st.success("Saved")

# ================= BENCHMARK =================
if "📊 Benchmark & Readiness" in T:
    with T["📊 Benchmark & Readiness"]:
        n = st.slider("Runs to average", 3, 30, 10)
        if st.button("Run benchmark"): SS.bench = signing.benchmark(n)
        if SS.get("bench"): st.dataframe(pd.DataFrame(SS.bench), hide_index=True, width="stretch"); st.caption("Measured on this machine with a pure-Python ML-DSA; production uses an optimised library.")
        st.subheader("Cryptographic inventory")
        st.dataframe(pd.DataFrame([["Issuer credentials", "ML-DSA-44 (FIPS 204)", "Yes"], ["Verification reports", "ML-DSA-44 + Ed25519 hybrid", "Yes (hybrid)"], ["Key registry signature", "ML-DSA-65 (FIPS 204)", "Yes"], ["Audit checkpoints", "ML-DSA-44 over Merkle root", "Yes"],
                                   ["Upload key exchange", "ML-KEM-768 (FIPS 203)", "Yes"], ["File encryption", "AES-256-GCM", "Yes (symmetric)"], ["Hashing", "SHA-256", "Yes"]], columns=["Purpose", "Algorithm", "Quantum-safe"]), hide_index=True, width="stretch")
        st.caption("Symmetric cryptography and SHA-256 remain acceptable against quantum attack at these sizes; the Ed25519 hybrid leg is classical by design during migration.")

# ================= AUDIT =================
if "🧾 Audit" in T:
    with T["🧾 Audit"]:
        ok, bad = audit.verify_chain(); (st.success if ok else st.error)("Hash chain intact ✅" if ok else f"Chain broken at entry {bad} ❌")
        if st.button("📌 Create signed checkpoint"): audit.checkpoint()
        cps = audit.verify_checkpoints()
        if cps: st.dataframe(pd.DataFrame(cps), hide_index=True, width="stretch")
        es = audit.entries()
        if es: st.dataframe(pd.DataFrame(es)[["ts", "actor", "action", "detail", "hash"]].iloc[::-1], hide_index=True, width="stretch")
