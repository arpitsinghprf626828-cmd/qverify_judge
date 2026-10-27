"""Builds ALL synthetic test data: clean + problem applications, photos, a 12-application labelled batch, mock AICTE registry,
demo PKI (keys/), and the cross-institution hash store. Everything is synthetic; issuers/AICTE records are SIMULATED."""
import json, io, random, shutil, datetime as dt
from pathlib import Path
import numpy as np, qrcode, piexif
from PIL import Image, ImageDraw, ImageFilter, ImageEnhance
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
from pypdf import PdfReader, PdfWriter
import pymupdf
from pqc import registry, credentials
import forensics as fx

registry.ensure_pki()
T = dt.date.today(); d = lambda n: (T + dt.timedelta(days=n)).isoformat()
pdfd = lambda day: "D:" + day.replace("-", "") + "120000"
TITLES = {"affidavit": "AFFIDAVIT AND UNDERTAKING", "noc": "STATE NO OBJECTION CERTIFICATE (NOC)", "accreditation": "NBA ACCREDITATION CERTIFICATE",
          "fire_safety": "FIRE SAFETY CERTIFICATE", "building": "BUILDING STABILITY CERTIFICATE"}
ISSUER = {"noc": "STATE_NOC", "accreditation": "NBA", "fire_safety": "FIRE", "building": "BUILDING"}
Path("hashes.db").unlink(missing_ok=True); store = fx.HashStore()

def make_pdf(path, dtype, inst_id, inst_name, ref, issue, valid, intake=None, created=None, modified=None, producer="Institution DMS",
             cred=None, qr_text=None, alt_font=False, incremental=False):
    buf = io.BytesIO(); c = canvas.Canvas(buf, pagesize=A4); y = 800
    lines = [TITLES[dtype], "(SYNTHETIC DEMO DOCUMENT - NOT REAL)", "", f"Institution Name: {inst_name}", f"Institution ID: {inst_id}"]
    if ref: lines.append(f"Reference No: {ref}")
    lines.append(f"Issue Date: {issue}")
    if valid: lines.append(f"Valid Until: {valid}")
    if intake: lines.append(f"Approved Intake: {intake}")
    for ln in lines:
        c.setFont("Courier-Bold" if (alt_font and ln.startswith("Valid Until")) else "Helvetica", 11); c.drawString(60, y, ln); y -= 22
    if ref:
        q = qrcode.make(qr_text or f"QV|{ref}").convert("RGB"); c.drawImage(ImageReader(q), 400, 640, 110, 110)
        c.setFont("Helvetica", 7); c.drawString(400, 630, "Scan to verify")
    c.save(); buf.seek(0)
    w = PdfWriter(); w.append(PdfReader(buf))
    md = {"/Producer": producer, "/CreationDate": pdfd(created or issue), "/ModDate": pdfd(modified or created or issue)}
    if cred: md["/QVerifyCred"] = credentials.encode(cred)
    w.add_metadata(md)
    with open(path, "wb") as f: w.write(f)
    if incremental:
        doc = pymupdf.open(str(path)); doc[0].add_text_annot((10, 10), "edited"); doc.saveIncr(); doc.close()

def make_photo(path, seed, gps=None, blur=False, size=(1200, 800)):
    rng = np.random.default_rng(seed); img = Image.new("RGB", size, tuple(int(v) for v in rng.integers(60, 200, 3))); dr = ImageDraw.Draw(img)
    for _ in range(40):
        x, y = int(rng.integers(0, size[0] - 120)), int(rng.integers(0, size[1] - 90)); w, h = int(rng.integers(40, 200)), int(rng.integers(30, 140))
        dr.rectangle([x, y, x + w, y + h], fill=tuple(int(v) for v in rng.integers(0, 255, 3)), outline=(20, 20, 20), width=2)
    a = np.asarray(img).astype(np.int16) + rng.integers(-18, 18, (size[1], size[0], 1)); img = Image.fromarray(np.clip(a, 0, 255).astype(np.uint8))
    if blur: img = img.filter(ImageFilter.GaussianBlur(8))
    save_photo(path, img, gps); return img

def save_photo(path, img, gps=None, quality=92):
    kw = {"exif": piexif.dump(fx.gps_exif_bytes(*gps))} if gps else {}
    img.save(path, "JPEG", quality=quality, **kw)

reg = {"institutions": {}, "issuers": {}}
def build(folder, inst_id, name, form_intake, doc_intake, docs, inst_rec, campus=None, root="samples"):
    out = Path(root) / folder
    if out.exists(): shutil.rmtree(out)
    out.mkdir(parents=True); reg["institutions"][inst_id] = inst_rec
    for dtype, kw in docs.items():
        ref = kw.pop("ref", None); fname = kw.pop("file", f"{dtype}.pdf"); reg_valid = kw.pop("reg_valid", kw.get("valid")); online = kw.pop("online", True)
        copies = kw.pop("copies", []); mode = kw.pop("cred", "ok"); true_valid = kw.pop("true_valid", kw.get("valid")); true_issue = kw.pop("true_issue", kw["issue"])
        cred = None
        if dtype in ISSUER and mode != "none":
            shipped = {"doc_type": dtype, "ref_no": ref, "institution_id": inst_id, "valid_until": kw.get("valid"), "issue_date": kw["issue"]}
            signed = {**shipped, "valid_until": true_valid, "issue_date": true_issue}
            cred = (credentials.issue(ISSUER[dtype], shipped) if mode == "ok" else credentials.issue(ISSUER[dtype], signed) if mode == "forged_text"
                    else credentials.issue(ISSUER[dtype], shipped, sign_payload=signed))
        make_pdf(out / fname, dtype, inst_id, name, ref, intake=doc_intake if dtype == "affidavit" else None, cred=cred, **kw)
        for cp in copies: shutil.copy(out / fname, out / cp)
        if ref: reg["issuers"][ref] = {"institution_id": inst_id, "doc_type": dtype, "valid_until": reg_valid, "issuer": f"{dtype.upper()} ISSUER (MOCK)", "online": online}
    form = {"category": "Extension of Approval (EoA)", "institution_id": inst_id, "institution_name": name, "claimed_intake": form_intake}
    if campus: form.update(campus_lat=campus[0], campus_lon=campus[1])
    (out / "form.json").write_text(json.dumps(form, indent=2))
    return out

# ---------------- clean ----------------
INDORE, DELHI, BHOPAL = (22.7196, 75.8577), (28.6139, 77.2090), (23.2599, 77.4126)
o = build("clean", "AICTE-1-100234", "Narmada Institute of Technology (Demo)", 360, 360, {
    "affidavit": dict(ref=None, issue=d(-100), valid=None), "noc": dict(ref="NOC/MP/2025/0451", issue=d(-300), valid=d(400)),
    "accreditation": dict(ref="NBA/2025/7781", issue=d(-200), valid=d(600)), "fire_safety": dict(ref="FIRE/IND/2026/118", issue=d(-90), valid=d(270)),
    "building": dict(ref="BSC/2025/3390", issue=d(-250), valid=d(500))},
    {"name": "Narmada Institute of Technology (Demo)", "approved_intake": 360, "eoa_status": "Approved", "ter_paid": True, "open_deficiency": False}, campus=INDORE)
lab = make_photo(o / "lab_photo.jpg", seed=1, gps=(INDORE[0] + 0.001, INDORE[1] + 0.001))
store.add("AICTE-1-100234", "lab_photo.jpg", fx.phash(lab))             # registered earlier submission

# ---------------- problem ----------------
o = build("problem", "AICTE-1-200777", "Vindhya College of Engineering (Demo)", 420, 360, {
    "affidavit": dict(ref=None, issue=d(-80), valid=None),
    "noc": dict(ref="NOC/MP/2024/0099", issue=d(-900), valid=d(700), true_valid=d(-200), cred="forged_text", reg_valid=d(-200), created=d(-900), modified=d(-2),
                producer="Adobe Photoshop 25.0", qr_text="QV|NOC/MP/2019/0001", alt_font=True, incremental=True),
    "accreditation": dict(ref="NBA/2024/5120", issue=d(-400), valid=d(-30), online=False, file="NBA_cert.pdf", copies=["NBA_cert_copy.pdf"]),
    "fire_safety": dict(ref="FIRE/IND/2025/044", issue=d(-400), valid=d(300), true_valid=d(-30), cred="tampered", reg_valid=d(-30))},
    {"name": "Vindhya College of Engineering (Demo)", "approved_intake": 360, "eoa_status": "Approved", "ter_paid": False, "open_deficiency": True}, campus=BHOPAL)
reused = lab.resize((1000, 667)); reused = ImageEnhance.Brightness(reused).enhance(1.05)
save_photo(o / "lab_photo.jpg", reused, gps=DELHI, quality=78)               # photo reused from another institution, wrong GPS
make_photo(o / "classroom_blur.jpg", seed=2, gps=(BHOPAL[0] + 0.001, BHOPAL[1]), blur=True)

# ---------------- labelled batch (ground truth) ----------------
NAMES = ["Malwa", "Satpura", "Holkar", "Chambal", "Betwa", "Kshipra", "Vindhya", "Narmada", "Tapti", "Sanchi", "Pachmarhi", "Orchha"]
PFX = {"noc": "NOC/MP", "accreditation": "NBA", "fire_safety": "FIRE/IND", "building": "BSC"}
FAULTS = ["missing:affidavit", "missing:noc", "missing:accreditation", "missing:fire_safety", "missing:building", "expired:noc", "expired:accreditation", "expired:fire_safety",
          "expired:building", "intake", "duplicate", "forged_text:accreditation", "forged_text:building", "tampered:noc", "tampered:fire_safety", "photoshop:accreditation",
          "photoshop:building", "unpaid_ter", "qr_mismatch:fire_safety", "font_edit:noc"]
def touched(f):
    k = f.split(":")[-1]; return {"intake": "affidavit", "duplicate": "noc", "unpaid_ter": "record"}.get(f, k)
rng = random.Random(42); truth = {}
for i in range(1, 25):
    inst = f"AICTE-1-3{i:05d}"; name = f"{NAMES[(i-1) % len(NAMES)]} {i} Institute of Technology (Demo)"
    docs = {"affidavit": dict(ref=None, issue=d(-rng.randint(60, 200)), valid=None)}
    for t in ISSUER: docs[t] = dict(ref=f"{PFX[t]}/{inst[-5:]}/{i}", issue=d(-rng.randint(100, 500)), valid=d(rng.randint(150, 700)))
    form_intake, doc_intake = 360, 360; rec = {"name": name, "approved_intake": 360, "eoa_status": "Approved", "ter_paid": True, "open_deficiency": False}
    chosen, used = [], set()
    pool = rng.sample(FAULTS, len(FAULTS))
    if i <= len(FAULTS): pool = [FAULTS[i - 1]] + [f for f in pool if f != FAULTS[i - 1]]   # every fault type appears at least once
    want = 0 if i > len(FAULTS) + 0 and i > 20 else (1 + (rng.random() < 0.5) if i <= len(FAULTS) else 0)
    for f in pool:
        if len(chosen) >= want: break
        if touched(f) not in used and not (f == "duplicate" and "noc" in used) and not (f.startswith("missing:affidavit") and "affidavit" in used): chosen.append(f); used.add(touched(f))
    exp = set()
    for f in chosen:
        kind, _, t = f.partition(":"); fn = f"{t}.pdf"
        if kind == "missing": docs.pop(t); exp.add(("R01", "-"))
        elif kind == "expired": docs[t]["issue"] = d(-rng.randint(400, 600)); docs[t]["valid"] = d(-rng.randint(20, 200)); docs[t]["reg_valid"] = docs[t]["valid"]; exp |= {("R03", fn), ("R11", fn)}
        elif f == "intake": form_intake = 420; exp |= {("R07", "affidavit.pdf"), ("R08", "form")}
        elif f == "duplicate": docs["noc"]["copies"] = ["noc_copy.pdf"]; exp.add(("R09", "noc_copy.pdf"))
        elif kind == "forged_text": docs[t].update(cred="forged_text", true_valid=d(rng.randint(150, 300)), valid=d(rng.randint(400, 800))); exp.add(("R11", fn))
        elif kind == "tampered": docs[t].update(cred="tampered", true_valid=d(rng.randint(10, 100)), valid=d(rng.randint(400, 800))); exp.add(("R11", fn))
        elif kind == "photoshop": docs[t].update(created=d(-300), modified=d(-3), producer="Adobe Photoshop 25.0"); exp.add(("R10", fn))
        elif f == "unpaid_ter": rec["ter_paid"] = False; exp.add(("R12", "AICTE record"))
        elif kind == "qr_mismatch": docs[t]["qr_text"] = "QV|FAKE/0000"; exp.add(("R17", fn))
        elif kind == "font_edit": docs[t]["alt_font"] = True; exp.add(("R18", fn))
    # the 'missing' doc was popped AFTER faults touching other docs were set, so recompute truth fields from what was written
    out = build(f"app_{i:02d}", inst, name, form_intake, doc_intake, {k: dict(v) for k, v in docs.items()}, rec, root="samples/batch")
    fields = {}
    for t, kw in docs.items():
        fields[f"{t}.pdf"] = {"institution_id": inst, "issue_date": kw["issue"]}
        if kw.get("valid"): fields[f"{t}.pdf"]["valid_until"] = kw["valid"]
        if kw.get("ref"): fields[f"{t}.pdf"]["ref_no"] = kw["ref"]
    if "affidavit" in docs: fields["affidavit.pdf"]["intake"] = str(doc_intake)
    truth[f"app_{i:02d}"] = {"faults": chosen, "expected": sorted(exp), "fields": fields}
Path("samples/batch/ground_truth.json").write_text(json.dumps(truth, indent=2))
Path("registry.json").write_text(json.dumps(reg, indent=2))
print("Done: samples/clean, samples/problem, samples/batch (24 labelled apps), registry.json, keys/, hashes.db")
