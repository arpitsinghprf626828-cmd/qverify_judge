"""Quantum-safe sealed storage: ML-KEM-768 (FIPS 203) encapsulates a fresh 32-byte key per file; AES-256-GCM encrypts the file.
blob = KEM ciphertext (1088 B) || nonce (12 B) || AES-GCM ciphertext+tag. The case id is bound as associated data."""
import os, re
from pathlib import Path
from kyber_py.ml_kem import ML_KEM_768 as KEM
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from . import keystore
KD = Path("keys"); VD = Path("vault"); CT = 1088

def _keys():
    KD.mkdir(exist_ok=True)
    if not (KD / "kem_ek.bin").exists():
        ek, dk = KEM.keygen(); (KD / "kem_ek.bin").write_bytes(ek); keystore.write_secret(KD / "kem_dk.bin", dk)
    return (KD / "kem_ek.bin").read_bytes(), keystore.read_secret(KD / "kem_dk.bin")

def seal(data: bytes, case_id: str) -> bytes:
    ek, _ = _keys(); key, ct = KEM.encaps(ek); nonce = os.urandom(12)
    return ct + nonce + AESGCM(key).encrypt(nonce, data, case_id.encode())

def open_sealed(blob: bytes, case_id: str) -> bytes:
    _, dk = _keys(); key = KEM.decaps(dk, blob[:CT])
    return AESGCM(key).decrypt(blob[CT:CT + 12], blob[CT + 12:], case_id.encode())

def _safe(s): return (re.sub(r"[^A-Za-z0-9._-]", "_", Path(str(s).replace("\\", "/")).name)[:80].lstrip(".") or "file")

def store(name: str, data: bytes, case_id: str) -> Path:
    """File name = <case>__<name>.qv with path characters removed, so uploads cannot escape the vault folder or overwrite another case."""
    VD.mkdir(exist_ok=True); p = VD / f"{_safe(case_id)}__{_safe(name)}.qv"; p.write_bytes(seal(data, case_id)); return p
def info(blob: bytes): return {"kem": "ML-KEM-768", "kem_ciphertext_bytes": CT, "aead": "AES-256-GCM", "total_bytes": len(blob)}
