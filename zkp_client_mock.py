#!/usr/bin/env python3
"""
zkp_client_mock.py
Client honnête qui effectue une session et répond T_ROUNDS fois.

Pré-requis:
 - seed_manager.py (decrypt_seed, derive_permutation)
 - matrix_graph.py (BitMatrix, commit_matrix_rows)
 - graph_adjmatrix.bin et enroll_manifest.json produits lors de l'enrôlement

Usage:
    python zkp_client_mock.py --rounds n
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

# T_ROUNDS par défaut (surchargé via CLI)
DEFAULT_T = 128


def atomic_write_json(path, obj):
    """Écriture atomique JSON: .tmp + fsync + replace."""
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def load_matrix(path):
    """Charge graph_adjmatrix.bin -> BitMatrix."""
    with open(path, "rb") as f:
        n = struct.unpack(">I", f.read(4))[0]
        row_bytes = (n + 7)//8
        bm = BitMatrix(n)
        for i in range(n):
            bm.rows[i][:] = f.read(row_bytes)
    return bm


def wait_for_challenge(session_id, round_expected, timeout=120.0, sleep=0.05):
    """
    Attend que challenge.json soit disponible, complètement écrit,
    et qu'il corresponde à la session et au round attendu.
    Renvoie l'objet challenge (dict) ou None en cas de timeout.
    """
    t0 = time.time()
    last_size = -1
    stable = 0

    while True:
        if time.time() - t0 > timeout:
            return None

        if not os.path.exists(CHALL_FILE):
            time.sleep(sleep)
            continue

        # attendre que la taille se stabilise pour éviter JSON partiel
        try:
            size = os.path.getsize(CHALL_FILE)
        except OSError:
            time.sleep(sleep)
            continue

        if size == last_size:
            stable += 1
        else:
            stable = 0
        last_size = size

        if stable < 2 or size == 0:
            time.sleep(sleep)
            continue

        # tenter de parser
        try:
            with open(CHALL_FILE, "r") as f:
                chal = json.load(f)
        except json.JSONDecodeError:
            time.sleep(sleep)
            continue
        except Exception:
            time.sleep(sleep)
            continue

        # valider session et round
        c_sess = chal.get("session")
        c_round = chal.get("round")
        if c_sess == session_id and (c_round == round_expected or c_round >= round_expected):
            return chal

        # Sinon, continuer d'attendre
        time.sleep(sleep)


def wait_for_file(path, timeout=60.0, sleep=0.05):
    """Attendre l'apparition d'un fichier (pour le résultat final)."""
    t0 = time.time()
    while True:
        if os.path.exists(path):
            # petite stabilisation
            last = os.path.getsize(path)
            time.sleep(sleep)
            if os.path.getsize(path) == last:
                return True
        if time.time() - t0 > timeout:
            return False
        time.sleep(sleep)


def client_session(t_rounds, seed_store, seed_pub_file):
    # 1) déchiffrer seed client
    pw = getpass("Passphrase to decrypt seed: ")
    seed_client = decrypt_seed(pw, os.path.expanduser(seed_store))

    # 2) lire seed_pub (hex)
    with open(seed_pub_file, "r") as f:
        seed_pub = bytes.fromhex(f.read().strip())

    # 3) charger la matrice
    bm = load_matrix(GRAPH_BIN)
    n = bm.n
    print(f"[client] loaded graph n={n}")

    # 4) préparer session id
    session = f"honest-{int(time.time())}"
    print(f"[client] session id: {session}")

    # 5) commits (une seule fois par session) — déterministe via seed_session
    seed_session = hashlib.sha256(session.encode()).digest()
    commits, nonces = commit_matrix_rows(bm, seed_session)
    commit_pkg = {"session": session, "commits": [c.hex() for c in commits]}

    # 6) écrire commits (atomique)
    atomic_write_json(COMMITS_FILE, commit_pkg)
    print("[client] wrote commit_package.json")

    # 7) dériver sigma (chemin)
    sigma = derive_permutation(n, seed_client, seed_pub)

    # 8) boucle des rounds
    for rr in range(1, t_rounds + 1):
        print(f"[client] waiting challenge for round {rr} ...")
        challenge = wait_for_challenge(session, rr, timeout=120.0)
        if challenge is None:
            print(f"[client] timeout waiting challenge for round {rr} -> abort session")
            break

        b = challenge.get("b")
        print(f"[client] got challenge for round {rr}: b={b}")

        # préparer open package
        open_pkg = {"session": session, "b": b, "opened_rows": [], "context": "row-commit"}

        if b == 1:
            # ouvrir un sous-ensemble du cycle (démo) : 200 lignes
            to_open = sigma[:min(200, n)]
            for idx in to_open:
                open_pkg["opened_rows"].append({
                    "index": idx,
                    "row_hex": bm.rows[idx].hex(),
                    "nonce_hex": nonces[idx].hex()
                })
            open_pkg["cycle_indices"] = sigma[:min(500, n)]
        else:
            # b == 0 : version maquette -> toutes les lignes (très volumineux)
            for idx in range(n):
                open_pkg["opened_rows"].append({
                    "index": idx,
                    "row_hex": bm.rows[idx].hex(),
                    "nonce_hex": nonces[idx].hex()
                })

        # écrire open (atomique)
        atomic_write_json(OPEN_FILE, open_pkg)

        # petit délai pour laisser le serveur consommer
        time.sleep(0.02)
        if rr % 32 == 0 or rr == 1:
            print(f"[client] responded to round {rr}/{t_rounds}")

    # 9) attendre le résultat final
    print("[client] waiting final result ...")
    if wait_for_file(RESULT_FILE, timeout=300.0):
        with open(RESULT_FILE, "r") as f:
            res = json.load(f)
        print("[client] session result:", res)
        try:
            os.remove(RESULT_FILE)
        except Exception:
            pass
    else:
        print("[client] no final result file (timeout)")

    # 10) cleanup et effacement en mémoire
    try:
        os.remove(COMMITS_FILE)
    except Exception:
        pass
    seed_client = None


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--rounds", type=int, default=DEFAULT_T)
    p.add_argument("--seed", default=SEED_STORE)
    p.add_argument("--seed-pub", default=SEED_PUB_FILE)
    args = p.parse_args()
    client_session(args.rounds, args.seed, args.seed_pub)
