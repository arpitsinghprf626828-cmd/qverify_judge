"""Private-key storage. If QV_KEY_PASSPHRASE is set, every private key is encrypted at rest with AES-256-GCM under a
scrypt-derived key (file format: b'QVK1' | salt(16) | nonce(12) | ciphertext). Without it, keys are stored raw (demo mode).
Existing raw keys stay readable, so turning the passphrase on later only affects newly written keys (use rotate_all to re-encrypt)."""
import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
MAGIC = b"QVK1"

def _key(salt):
    pw = os.environ.get("QV_KEY_PASSPHRASE")
    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(pw.encode()) if pw else None

def write_secret(path, data: bytes):
    path = Path(path)
    if not os.environ.get("QV_KEY_PASSPHRASE"): path.write_bytes(data)
    else:
        salt, nonce = os.urandom(16), os.urandom(12)
        path.write_bytes(MAGIC + salt + nonce + AESGCM(_key(salt)).encrypt(nonce, data, path.name.encode()))
    try: os.chmod(path, 0o600)
    except OSError: pass

def read_secret(path) -> bytes:
    path = Path(path); b = path.read_bytes()
    if not b.startswith(MAGIC): return b
    if not os.environ.get("QV_KEY_PASSPHRASE"): raise RuntimeError(f"{path.name} is encrypted: set QV_KEY_PASSPHRASE")
    salt, nonce, ct = b[4:20], b[20:32], b[32:]
    return AESGCM(_key(salt)).decrypt(nonce, ct, path.name.encode())

def is_encrypted(path): return Path(path).read_bytes()[:4] == MAGIC

def rotate_all(keydir="keys"):
    """Re-encrypt every private key with the current passphrase. Returns the number of files rewritten."""
    n = 0
    for p in Path(keydir).iterdir():
        if p.suffix == ".sk" or p.name == "kem_dk.bin": write_secret(p, read_secret(p)); n += 1
    return n
