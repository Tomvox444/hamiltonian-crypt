#!/usr/bin/env python3
"""
zkp_client_mock.py
Client honnête qui effectue une session et répond T_ROUNDS fois.
Pré-requis:
 - seed_manager.py present (decrypt_seed, derive_permutation)
 - matrix_graph.py present (BitMatrix, commit_matrix_rows)
 - graph_adjmatrix.bin et enroll_manifest.json produits lors de l'enrollement
Usage:
    python zkp_client_mock.py --rounds 256
"""
import argparse, json, os, struct, time, hashlib
from getpass import getpass

from seed_manager import decrypt_seed, derive_permutation
from matrix_graph import BitMatrix, commit_matrix_rows

COMMITS_FILE = "commit_package.json"
CHALL_FILE   = "challenge.json"
OPEN_FILE    = "open_package.json"
RESULT_FILE  = "round_result.json"
MANIFEST     = "enroll_manifest.json"
GRAPH_BIN    = "graph_adjmatrix.bin"
SEED_STORE   = "~/.zkp-ham/seed"
SEED_PUB_FILE= "seed_pub.txt"

# T_ROUNDS default (override via CLI)
DEFAULT_T = 256

def atomic_write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

def load_matrix(path):
    with open(path, "rb") as f:
        n = struct.unpack(">I", f.read(4))[0]
        row_bytes = (n + 7)//8
        bm = BitMatrix(n)
        for i in range(n):
            bm.rows[i][:] = f.read(row_bytes)
    return bm

def wait_for_file(path, timeout=30.0):
    t0 = time.time()
    while not os.path.exists(path):
        time.sleep(0.05)
        if time.time() - t0 > timeout:
            return False
    return True

def client_session(t_rounds, seed_store, seed_pub_file):
    # déchiffrer seed_client
    pw = getpass("Passphrase to decrypt seed: ")
    seed_client = decrypt_seed(pw, os.path.expanduser(seed_store))
    # lire seed_pub
    with open(seed_pub_file, "r") as f:
        seed_pub = bytes.fromhex(f.read().strip())

    # charger la matrice
    bm = load_matrix(GRAPH_BIN)
    n = bm.n
    print(f"[client] loaded graph n={n}")

    # préparer session id
    session = f"honest-{int(time.time())}"
    # commits (une fois pour la session) -- on utilise commit_matrix_rows deterministe via seed_session
    seed_session = hashlib.sha256(session.encode()).digest()
    commits, nonces = commit_matrix_rows(bm, seed_session)
    commit_pkg = {"session": session, "commits": [c.hex() for c in commits]}

    # écrire commits de façon atomique (une seule fois)
    atomic_write_json(COMMITS_FILE, commit_pkg)
    print("[client] wrote commit_package.json")

    # dériver sigma (chemin)
    sigma = derive_permutation(n, seed_client, seed_pub)

    # boucle t_rounds
    for rr in range(1, t_rounds + 1):
        # attendre challenge
        if not wait_for_file(CHALL_FILE, timeout=60.0):
            print("[client] timeout waiting challenge -> abort session")
            break
        with open(CHALL_FILE, "r") as f:
            challenge = json.load(f)
        b = challenge.get("b")
        # préparer open_pkg selon b
        open_pkg = {"session": session, "b": b, "opened_rows": [], "context": "row-commit"}
        if b == 1:
            # ouvrir un sous-ensemble du cycle (démo) : on ouvre 200 rows
            to_open = sigma[:min(200, n)]
            for idx in to_open:
                open_pkg["opened_rows"].append({
                    "index": idx,
                    "row_hex": bm.rows[idx].hex(),
                    "nonce_hex": nonces[idx].hex()
                })
            open_pkg["cycle_indices"] = sigma[:min(500, n)]
        else:
            # b == 0 : in maquette, on ouvre toutes les lignes (très lourd)
            for idx in range(n):
                open_pkg["opened_rows"].append({
                    "index": idx,
                    "row_hex": bm.rows[idx].hex(),
                    "nonce_hex": nonces[idx].hex()
                })

        # write atomically
        atomic_write_json(OPEN_FILE, open_pkg)

        # wait a small bit for server to consume (server removes files)
        time.sleep(0.02)
        if rr % 32 == 0 or rr == 1:
            print(f"[client] responded to round {rr}/{t_rounds}")

    # attendre result
    if wait_for_file(RESULT_FILE, timeout=60.0):
        with open(RESULT_FILE, "r") as f:
            res = json.load(f)
        print("[client] session result:", res)
        try: os.remove(RESULT_FILE)
        except: pass
    else:
        print("[client] no final result file (timeout)")

    # cleanup
    try:
        os.remove(COMMITS_FILE)
    except Exception:
        pass
    # wipe seed var
    seed_client = None

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--rounds", type=int, default=DEFAULT_T)
    p.add_argument("--seed", default=SEED_STORE)
    p.add_argument("--seed-pub", default=SEED_PUB_FILE)
    args = p.parse_args()
    client_session(args.rounds, args.seed, args.seed_pub)
