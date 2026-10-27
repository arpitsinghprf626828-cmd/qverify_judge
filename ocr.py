"""Text extraction cascade: digital text first, OCR (Tesseract) only where a page has no text or the file is an image."""
import io, os, shutil
from pypdf import PdfReader
from PIL import Image, ImageOps
for _c in (r"C:\Program Files\Tesseract-OCR\tesseract.exe", r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe"):   # common Windows install paths
    if not shutil.which("tesseract") and os.path.exists(_c): os.environ["PATH"] += os.pathsep + os.path.dirname(_c)
IMG_EXT = (".jpg", ".jpeg", ".png", ".tif", ".tiff", ".bmp", ".webp")
def tesseract_available(): return shutil.which("tesseract") is not None

def ocr_image(img, lang="eng"):
    """-> (text, average word confidence 0-100). Raises if Tesseract is missing."""
    import pytesseract
    from pytesseract import Output
    g = ImageOps.autocontrast(img.convert("L"))
    if g.width < 1500: g = g.resize((g.width * 2, g.height * 2))
    d = pytesseract.image_to_data(g, lang=lang, config="--psm 6", output_type=Output.DICT)
    lines, confs = {}, []
    for i, w in enumerate(d["text"]):
        if not w.strip() or float(d["conf"][i]) < 0: continue
        lines.setdefault((d["block_num"][i], d["par_num"][i], d["line_num"][i]), []).append(w); confs.append(float(d["conf"][i]))
    return "\n".join(" ".join(ws) for _, ws in sorted(lines.items())), (sum(confs) / len(confs) if confs else 0.0)

def extract_pages(raw, name, lang="eng"):
    """-> (pages: list[str], method: 'text'|'ocr'|'mixed'|'none', confidence: float|None)"""
    low = name.lower()
    if low.endswith(IMG_EXT):
        if not tesseract_available(): return [""], "none", None
        try:
            t, c = ocr_image(Image.open(io.BytesIO(raw)), lang); return [t], "ocr", c
        except Exception: return [""], "none", None
    try: pages = [(pg.extract_text() or "") for pg in PdfReader(io.BytesIO(raw)).pages]
    except Exception: return [""], "none", None
    used, confs = False, []
    for i, t in enumerate(pages):
        if len(t.strip()) < 20 and tesseract_available():
            try:
                import pymupdf
                doc = pymupdf.open(stream=raw, filetype="pdf"); pix = doc[i].get_pixmap(dpi=300)
                txt, c = ocr_image(Image.open(io.BytesIO(pix.tobytes("png"))), lang); pages[i] = txt; used = True; confs.append(c)
            except Exception: pass
    method = "text" if not used else ("ocr" if all(len(p.strip()) < 20 for p in pages) is False and len(confs) == len(pages) else "mixed")
    return pages, method, (sum(confs) / len(confs) if confs else None)
