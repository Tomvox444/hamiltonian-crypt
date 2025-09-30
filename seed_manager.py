#!/usr/bin/env python3
"""
seed_manager.py
- Génère une seed 256-bit (32 octets)
- Chiffre la seed avec une passphrase (scrypt -> AES-GCM)
- Déchiffre et dérive une permutation deterministe (Fisher-Yates)
Dépendances: cryptography
"""

import os, struct, json, hmac
from hashlib import sha256
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# -----------------------
# Paramètres
# -----------------------
SEED_SIZE = 32         # 32 bytes = 256 bits
SALT_SIZE = 16
NONCE_SIZE = 12        # AES-GCM nonce
SALT_FILE_SUFFIX = ".salt"
ENC_FILE_SUFFIX  = ".enc"
META_FILE_SUFFIX = ".meta.json"

# -----------------------
# Utils
# -----------------------
def gen_seed() -> bytes:
    return os.urandom(SEED_SIZE)

def derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    # scrypt params: (N, r, p) tuned for interactive use; augmenter si tu veux plus de work.
    kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)  # N=131072 (work factor)
    return kdf.derive(passphrase.encode('utf-8'))

def encrypt_seed(seed: bytes, passphrase: str, outpath: str) -> None:
    salt = os.urandom(SALT_SIZE)
    key = derive_key_from_passphrase(passphrase, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ct = aesgcm.encrypt(nonce, seed, None)
    # write files: outpath.enc, outpath.salt, outpath.meta.json
    with open(outpath + ENC_FILE_SUFFIX, "wb") as f:
        f.write(nonce + ct)
    with open(outpath + SALT_FILE_SUFFIX, "wb") as f:
        f.write(salt)
    meta = {"scheme":"scrypt+AESGCM","salt_size":SALT_SIZE,"nonce_size":NONCE_SIZE,"seed_size":SEED_SIZE}
    with open(outpath + META_FILE_SUFFIX, "w") as f:
        json.dump(meta, f)
    os.chmod(outpath + ENC_FILE_SUFFIX, 0o600)
    os.chmod(outpath + SALT_FILE_SUFFIX, 0o600)
    os.chmod(outpath + META_FILE_SUFFIX, 0o600)

def decrypt_seed(passphrase: str, outpath: str) -> bytes:
    with open(outpath + SALT_FILE_SUFFIX, "rb") as f:
        salt = f.read()
    key = derive_key_from_passphrase(passphrase, salt)
    with open(outpath + ENC_FILE_SUFFIX, "rb") as f:
        data = f.read()
    nonce = data[:NONCE_SIZE]
    ct = data[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    seed = aesgcm.decrypt(nonce, ct, None)
    return seed

# -----------------------
# Deterministic permutation derivation (HKDF-like + HMAC counter DRBG)
# -----------------------
# Simple HKDF-Extract/Expand using HMAC-SHA256 (for the PRNG key)
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, sha256).digest()

def hkdf_expand(prk: bytes, info: bytes, L: int) -> bytes:
    okm = b""
    t = b""
    counter = 1
    while len(okm) < L:
        t = hmac.new(prk, t + info + bytes([counter]), sha256).digest()
        okm += t
        counter += 1
    return okm[:L]

def derive_prng_key(seed_client: bytes, seed_pub: bytes, context: bytes=b"ham-prng") -> bytes:
    prk = hkdf_extract(seed_pub, seed_client)   # salt=seed_pub
    return hkdf_expand(prk, context, 32)        # 256-bit key

class HmacCounterDRBG:
    def __init__(self, key: bytes):
        self.key = key
        self.counter = 0
    def rand_u32(self) -> int:
        c = struct.pack(">Q", self.counter)
        self.counter += 1
        return int.from_bytes(hmac.new(self.key, c, sha256).digest()[:4], "big")
    def randint(self, a: int, b: int) -> int:
        n = b - a + 1
        if n <= 0:
            raise ValueError("bad range")
        # rejection sampling on 32 bits
        t = (1 << 32) - ((1 << 32) % n)
        r = self.rand_u32()
        while r >= t:
            r = self.rand_u32()
        return a + (r % n)

def derive_permutation(n: int, seed_client: bytes, seed_pub: bytes) -> list:
    key = derive_prng_key(seed_client, seed_pub)
    drbg = HmacCounterDRBG(key)
    perm = list(range(n))
    for i in range(n-1, 0, -1):
        j = drbg.randint(0, i)
        perm[i], perm[j] = perm[j], perm[i]
    return perm

# -----------------------
# CLI-like quick demo
# -----------------------
if __name__ == "__main__":
    import argparse, getpass
    p = argparse.ArgumentParser()
    p.add_argument("cmd", choices=["gen","encrypt","decrypt","derive"], help="gen: create seed; encrypt: create encrypted file; decrypt: output seed; derive: derive perm")
    p.add_argument("--out", default="~/.zkp-ham/seed", help="base path (no suffix)")
    p.add_argument("--n", type=int, default=1000, help="n for derive (permutation length)")
    p.add_argument("--seed-pub", default=None, help="hex seed_pub (32 bytes hex) or path to file containing hex")
    args = p.parse_args()

    out = os.path.expanduser(args.out)

    if args.cmd == "gen":
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(out), exist_ok=True)
        
        seed = gen_seed()
        print("Seed (hex):", seed.hex())
        # Store temporarily in a file? Better to encrypt immediately.
        with open(out + ".raw", "wb") as f:
            f.write(seed)
        os.chmod(out + ".raw", 0o600)
        print("Wrote raw seed to", out + ".raw  (prefer encrypt immediately!)")

    elif args.cmd == "encrypt":
        # Generate seed then encrypt (or read existing raw)
        if os.path.exists(out + ".raw"):
            with open(out + ".raw","rb") as f:
                seed = f.read()
        else:
            seed = gen_seed()
        passw = getpass.getpass("Passphrase to encrypt seed: ")
        encrypt_seed(seed, passw, out)
        # optionally shred the raw
        try:
            os.remove(out + ".raw")
        except Exception:
            pass
        print("Encrypted seed written to", out + ENC_FILE_SUFFIX)

    elif args.cmd == "decrypt":
        pw = getpass.getpass("Passphrase to decrypt seed: ")
        s = decrypt_seed(pw, out)
        print("Decrypted seed (hex):", s.hex())

    elif args.cmd == "derive":
        if args.seed_pub is None:
            print("Provide --seed-pub (hex or path)")
            raise SystemExit(1)
        # get seed_client by decrypting
        pw = getpass.getpass("Passphrase to decrypt seed: ")
        seed_client = decrypt_seed(pw, out)
        # load seed_pub
        sp = args.seed_pub
        if os.path.exists(sp):
            with open(sp,"r") as f:
                seed_pub = bytes.fromhex(f.read().strip())
        else:
            seed_pub = bytes.fromhex(sp)
        perm = derive_permutation(args.n, seed_client, seed_pub)
        print("Derived permutation (first 20 indices):", perm[:20])
        # wipe variable references (best-effort)
        seed_client = None

