"""Printable PDF of the signed verification report (summary, documents, findings, signature block, QR)."""
import io
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from pqc import signing, registry
def report_pdf(env):
    r = env["report"]; ss = getSampleStyleSheet(); B = ParagraphStyle("b", parent=ss["BodyText"], fontSize=8.5, leading=11)
    C = lambda t: Paragraph(str(t), B); buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=14 * mm, bottomMargin=14 * mm, title="Q-Verify signed verification report")
    s = [Paragraph("Q-Verify AICTE - Verification Report", ss["Title"]),
         Paragraph(f"{r['application']['institution_name']} | {r['application']['institution_id']} | {r['application']['category']}", ss["Heading3"]),
         Paragraph(f"Validation date {r['as_of']} | Priority score {r['priority_score']} | {r['rules_version']}", B), Spacer(1, 6)]
    def tbl(rows, widths, head=True):
        t = Table([[C(c) for c in row] for row in rows], colWidths=[w * mm for w in widths], repeatRows=1 if head else 0)
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), .3, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dbe7f3")), ("VALIGN", (0, 0), (-1, -1), "TOP")])); return t
    s += [Paragraph("Documents", ss["Heading3"]), tbl([["File", "Type", "Extraction", "Issuer status", "PQC verified"]] + [[x["name"], x["type"], x["extraction"], x["issuer_status"], "yes" if x["pqc_verified"] else "no"] for x in r["documents"]], [55, 30, 25, 45, 25]), Spacer(1, 6)]
    s += [Paragraph(f"Findings ({len(r['findings'])})", ss["Heading3"])]
    s += [tbl([["ID", "Rule", "Severity", "Document", "Message"]] + [[f["id"], f["rule"], f["severity"], f["document"], f["message"]] for f in r["findings"]], [12, 14, 20, 38, 96])] if r["findings"] else [Paragraph("No findings.", B)]
    v = signing.verify_envelope(env)
    s += [Spacer(1, 8), Paragraph("Cryptographic signature", ss["Heading3"]),
          tbl([["Algorithm", env["alg"]], ["Key ID", env["key_id"]], ["Signed at", env["signed_at"]], ["Report SHA-256", env["report_sha256"]],
               ["ML-DSA signature size", f"{len(registry.unb64(env['sig_mldsa']))} bytes"], ["Status when generated", "VALID" if v["valid"] else "INVALID"]], [45, 135], head=False),
          Spacer(1, 6), Image(io.BytesIO(signing.qr_png(env)), 28 * mm, 28 * mm), Spacer(1, 4), Paragraph(r["notice"], B),
          Paragraph("A valid signature proves the report is unchanged since signing by the holder of a trusted key. It does not prove the underlying documents are genuine.", B)]
    doc.build(s); return buf.getvalue()
