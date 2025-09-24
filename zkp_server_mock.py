#!/usr/bin/env python3
"""
zkp_server_mock.py
Serveur mock pour protocole ZKP-Hamiltonien (session unique, T_ROUNDS consécutifs).
Usage:
    python zkp_server_mock.py --rounds 256
"""
import argparse, json, os, random, time, hashlib

GRAPH_BIN = "graph_adjmatrix.bin"
MANIFEST = "enroll_manifest.json"
COMMITS_FILE = "commit_package.json"
CHALL_FILE  = "challenge.json"
OPEN_FILE   = "open_package.json"
RESULT_FILE = "round_result.json"

# Nombre de rounds consécutifs requis pour accepter la session
T_ROUNDS = 256

# Lecture JSON robuste (attend un JSON complet)
def load_json_when_ready(path, max_wait=30.0, sleep=0.05):
    t0 = time.time()
    while True:
        try:
            with open(path, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            time.sleep(sleep)
        except FileNotFoundError:
            time.sleep(sleep)
        if time.time() - t0 > max_wait:
            raise TimeoutError(f"Timeout reading complete JSON from {path}")

def load_manifest():
    with open(MANIFEST,"r") as f:
        return json.load(f)

def verify_open(commit_list, open_pkg, n_expected):
    """
    Vérifications basiques pour le mock :
      - chaque opened_rows recompute sha256(row||nonce||context) == commit_list[idx]
      - si b==1 : cycle_indices présent, pas de doublons et taille plausible
      - si b==0 : on ne vérifie que les rows ouvertes (mock)
    """
    b = open_pkg.get("b")
    ctx = open_pkg.get("context","").encode()

    for entry in open_pkg.get("opened_rows", []):
        idx = entry.get("index")
        row_hex = entry.get("row_hex","")
        nonce_hex = entry.get("nonce_hex","")
        if idx is None:
            return False, "opened row missing index"
        if idx < 0 or idx >= len(commit_list):
            return False, f"opened row index out of range: {idx}"
        h = hashlib.sha256(bytes.fromhex(row_hex) + bytes.fromhex(nonce_hex) + ctx).hexdigest()
        if h != commit_list[idx]:
            return False, f"row {idx} hash mismatch"

    if b == 1:
        cycle = open_pkg.get("cycle_indices")
        if not cycle:
            return False, "no cycle provided for b=1"
        if len(set(cycle)) != len(cycle):
            return False, "cycle has duplicate vertices"
        if len(cycle) > n_expected:
            return False, "cycle length larger than n"
    # b==0: (mock) we assume permutation/iso checks would be done; accept row/hash checks
    return True, "ok"

def server_loop(t_rounds):
    print("[server] reading enroll_manifest...")
    manifest = load_manifest()
    n = manifest.get("n")
    if n is None:
        raise RuntimeError("enroll_manifest.json must contain 'n'")
    print(f"[server] n={n} commit_count={manifest.get('commit_count')}")

    while True:
        print("[server] waiting for commit_package.json (new session)...")
        # attend commit_package.json
        while not os.path.exists(COMMITS_FILE):
            time.sleep(0.1)
        # lire commit (pas de retry nécessaire : le client écrit de façon atomique)
        with open(COMMITS_FILE, "r") as f:
            commit_pkg = json.load(f)
        commits = commit_pkg.get("commits", [])
        session = commit_pkg.get("session", "sess-unknown")
        print(f"[server] got commits (count={len(commits)}) session={session}")

        session_ok = True
        msg = "ok"
        # boucle t_rounds consécutifs
        for rr in range(1, t_rounds + 1):
            # choisir challenge 1-bit
            b = random.choice([0,1])
            challenge = {"b": b, "session": session, "round": rr}
            # écriture atomique simple (on peut remplacer par atomic file si besoin)
            with open(CHALL_FILE, "w") as f:
                json.dump(challenge, f)
                f.flush()
                os.fsync(f.fileno())
            # attendre open (lecture robuste)
            try:
                open_pkg = load_json_when_ready(OPEN_FILE, max_wait=60.0)
            except TimeoutError:
                session_ok = False
                msg = f"timeout waiting open (round {rr})"
                break

            ok, detail = verify_open(commits, open_pkg, n)
            # supprimer open pour la prochaine itération (le client le réécrira)
            try:
                os.remove(OPEN_FILE)
            except Exception:
                pass

            if not ok:
                session_ok = False
                msg = f"round {rr} failed: {detail}"
                break

            # (optionnel) on peut logger chaque round
            if rr % 32 == 0 or rr == 1:
                print(f"[server] session {session} passed {rr}/{t_rounds} rounds...")

        # résultat final de la session (après boucle)
        result = {"session": session, "ok": session_ok, "msg": msg, "rounds": t_rounds}
        with open(RESULT_FILE, "w") as f:
            json.dump(result, f)
            f.flush()
            os.fsync(f.fileno())
        print(f"[server] session result: ok={session_ok} msg={msg}")

        # cleanup fichiers session (si présents)
        for p in (COMMITS_FILE, CHALL_FILE, OPEN_FILE):
            try: os.remove(p)
            except FileNotFoundError: pass

        # boucler et attendre une nouvelle session
        # si tu veux juste une session, break ici

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--rounds", type=int, default=T_ROUNDS, help="Nombre de rounds par session")
    args = p.parse_args()
    # override T_ROUNDS si demandé en CLI
    T = args.rounds
    server_loop(T)
