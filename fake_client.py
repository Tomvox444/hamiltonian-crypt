#!/usr/bin/env python3
"""
fake_attacker.py
Attacker automatique qui forge des opens pour tester le serveur.
Note: avec T_ROUNDS=256 coté serveur, la probabilité pour un attaquant de réussir
est astronomiquement faible ; ce script servira à vérifier rejet massif.
Usage:
    python fake_attacker.py --trials 20 --mode random
"""
import argparse, json, os, time, random, struct

COMMITS_FILE = "commit_package.json"
CHALL_FILE   = "challenge.json"
OPEN_FILE    = "open_package.json"
RESULT_FILE  = "round_result.json"
MANIFEST     = "enroll_manifest.json"
GRAPH_BIN    = "graph_adjmatrix.bin"

def atomic_write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

def load_manifest():
    with open(MANIFEST,"r") as f:
        return json.load(f)

def ensure_commit_package():
    if os.path.exists(COMMITS_FILE):
        return
    manifest = load_manifest()
    n = manifest.get("n")
    # try to reuse commits_all if present
    if "commits_all" in manifest and isinstance(manifest["commits_all"], list) and len(manifest["commits_all"])==n:
        commits = manifest["commits_all"]
    else:
        commits = ["00"*32]*n
    pkg = {"session":"attacker-session", "commits": commits}
    atomic_write_json(COMMITS_FILE, pkg)

def wait_for_file(path, timeout=30.0):
    t0 = time.time()
    while not os.path.exists(path):
        time.sleep(0.05)
        if time.time() - t0 > timeout:
            return False
    return True

def load_matrix_rows():
    if not os.path.exists(GRAPH_BIN):
        return None
    with open(GRAPH_BIN,"rb") as f:
        n = struct.unpack(">I", f.read(4))[0]
        rb = (n + 7)//8
        rows = []
        for _ in range(n):
            rows.append(f.read(rb))
    return rows

def forge_open_bad_nonce(commit_pkg):
    commits = commit_pkg["commits"]
    n = len(commits)
    rows = load_matrix_rows()
    picks = list(range(min(10, n)))
    opened = []
    for idx in picks:
        row_hex = rows[idx].hex() if rows else ("00" * ((n+7)//8))
        nonce_hex = os.urandom(16).hex()  # wrong nonce
        opened.append({"index": idx, "row_hex": row_hex, "nonce_hex": nonce_hex})
    return {"session": commit_pkg.get("session","attacker-session"), "b":1, "opened_rows": opened, "context":"row-commit"}

def forge_open_tamper_row(commit_pkg):
    commits = commit_pkg["commits"]
    n = len(commits)
    rows = load_matrix_rows()
    picks = list(range(min(10, n)))
    opened = []
    for idx in picks:
        if rows:
            b = bytearray(rows[idx])
            pos = random.randrange(len(b))
            b[pos] ^= 0xFF
            row_hex = bytes(b).hex()
        else:
            row_hex = ("00" * ((n+7)//8))[:-2] + "ff"
        nonce_hex = os.urandom(16).hex()
        opened.append({"index": idx, "row_hex": row_hex, "nonce_hex": nonce_hex})
    return {"session": commit_pkg.get("session","attacker-session"), "b":1, "opened_rows": opened, "context":"row-commit"}

def forge_open_bad_cycle(commit_pkg):
    commits = commit_pkg["commits"]
    n = len(commits)
    rows = load_matrix_rows()
    picks = list(range(min(10,n)))
    opened = []
    for idx in picks:
        row_hex = rows[idx].hex() if rows else ("00" * ((n+7)//8))
        nonce_hex = os.urandom(16).hex()
        opened.append({"index": idx, "row_hex": row_hex, "nonce_hex": nonce_hex})
    bad_cycle = [0,1,2,2,4]
    return {"session": commit_pkg.get("session","attacker-session"), "b":1, "opened_rows": opened, "cycle_indices": bad_cycle, "context":"row-commit"}

def main(trials=20, mode="random", delay=0.1):
    stats = {"total":0, "accepted":0, "rejected":0, "no_result":0}
    for t in range(trials):
        stats["total"] += 1
        print(f"\n[attacker] trial {t+1}/{trials} mode={mode}")
        ensure_commit_package()
        with open(COMMITS_FILE,"r") as f:
            commit_pkg = json.load(f)

        # attendre challenge
        print("[attacker] waiting for challenge.json ...")
        ok = wait_for_file(CHALL_FILE, timeout=30.0)
        if not ok:
            print("[attacker] no challenge (timeout)")
            stats["no_result"] += 1
            try: os.remove(COMMITS_FILE)
            except: pass
            continue
        with open(CHALL_FILE,"r") as f:
            ch = json.load(f)
        b = ch.get("b")
        print(f"[attacker] got challenge b={b}")

        # If server asks b==0 we craft a small wrong open
        if b == 0:
            open_pkg = {"session": commit_pkg.get("session","attacker-session"), "b":0, "perm":[0], "opened_rows": [], "context":"row-commit"}
        else:
            if mode == "bad_nonce":
                open_pkg = forge_open_bad_nonce(commit_pkg)
            elif mode == "tamper_row":
                open_pkg = forge_open_tamper_row(commit_pkg)
            elif mode == "bad_cycle":
                open_pkg = forge_open_bad_cycle(commit_pkg)
            else:
                open_pkg = random.choice([forge_open_bad_nonce(commit_pkg),
                                          forge_open_tamper_row(commit_pkg),
                                          forge_open_bad_cycle(commit_pkg)])
        # write attacker's open atomically
        atomic_write_json(OPEN_FILE, open_pkg)
        print("[attacker] wrote open_package.json (forged)")

        # read result (server writes RESULT_FILE after full session)
        res_ok = wait_for_file(RESULT_FILE, timeout=90.0)
        if not res_ok:
            print("[attacker] no result (timeout)")
            stats["no_result"] += 1
        else:
            with open(RESULT_FILE,"r") as f:
                res = json.load(f)
            if res.get("ok"):
                print("[attacker] SERVER ACCEPTED forged session (unexpected!)")
                stats["accepted"] += 1
            else:
                print("[attacker] server rejected forged session (expected):", res.get("msg"))
                stats["rejected"] += 1
            try: os.remove(RESULT_FILE)
            except: pass

        # cleanup local files for next trial
        for p in (COMMITS_FILE, CHALL_FILE, OPEN_FILE):
            try: os.remove(p)
            except: pass

        time.sleep(delay)

    print("\n[attacker] summary:", stats)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--trials", type=int, default=20)
    p.add_argument("--mode", choices=["random","bad_nonce","tamper_row","bad_cycle"], default="random")
    p.add_argument("--delay", type=float, default=0.1)
    args = p.parse_args()
    main(trials=args.trials, mode=args.mode, delay=args.delay)
