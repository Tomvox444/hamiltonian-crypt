#!/usr/bin/env python3
"""
enroll_client.py  (POC)
- Déchiffre seed client, génère (si besoin) seed_pub, dérive sigma,
  construit graphe avec cycle planté, calcule commits, et écrit:
    - graph_adjmatrix.bin
    - enroll_manifest.json
    - seed_pub.txt (si généré)
Usage:
    python enroll_client.py --seed ~/.zkp-ham/seed --seed-pub seed_pub.txt --n 5000 --davg 4.0
"""
import os, json, struct, argparse
from getpass import getpass
from hashlib import sha256

# adapte ces imports selon tes modules existants
from seed_manager import decrypt_seed, derive_permutation  # doit exister
from matrix_graph import generate_graph_with_planted_cycle, commit_matrix_rows, BitMatrix  # doit exister

def atomic_write(path, obj, mode="json"):
    tmp = path + ".tmp"
    if mode == "json":
        with open(tmp, "w") as f:
            json.dump(obj, f, indent=2)
            f.flush(); os.fsync(f.fileno())
    elif mode == "bin":
        with open(tmp, "wb") as f:
            f.write(obj)
            f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)

def write_graph_bin(path, bm: BitMatrix):
    # format: 4 bytes BE n, then n rows of row_bytes each
    tmp = path + ".tmp"
    with open(tmp,"wb") as f:
        f.write(struct.pack(">I", bm.n))
        for row in bm.rows:
            f.write(row)
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)

def ensure_seed_pub(path):
    """
    If path exists, read and return bytes.
    Otherwise generate 32 random bytes, write to path as hex and return bytes.
    """
    if os.path.exists(path):
        with open(path,"r") as f:
            hx = f.read().strip()
        return bytes.fromhex(hx)
    else:
        b = os.urandom(32)
        with open(path + ".tmp","w") as f:
            f.write(b.hex())
            f.flush(); os.fsync(f.fileno())
        os.replace(path + ".tmp", path)
        print(f"[enroll] generated seed_pub and wrote to {path}")
        return b

def enroll(seed_path, seed_pub_path, n, d_avg, out_graph="graph_adjmatrix.bin", out_manifest="enroll_manifest.json"):
    # 1) decrypt seed client
    pw = getpass("Passphrase to decrypt client seed: ")
    seed_client = decrypt_seed(pw, seed_path)  # doit renvoyer bytes

    # 2) ensure seed_pub exists (generate if needed)
    seed_pub = ensure_seed_pub(seed_pub_path)

    # 3) derive sigma deterministically from (seed_client, seed_pub)
    sigma = derive_permutation(n, seed_client, seed_pub)  # doit renvoyer liste length n

    # 4) generate graph with planted cycle
    bm = generate_graph_with_planted_cycle(n, seed_pub, sigma, d_avg=d_avg)

    # 5) compute commits and nonces (session-independent enrolment commits)
    # use a fixed enrollment session salt (or random once)
    enroll_session = sha256(b"enroll-session-" + os.urandom(8)).digest()
    commits, nonces = commit_matrix_rows(bm, enroll_session)

    # 6) write graph binary
    write_graph_bin(out_graph, bm)
    print(f"[enroll] wrote graph to {out_graph}")

    # 7) create manifest and write atomically
    manifest = {
        "n": n,
        "d_avg": d_avg,
        "seed_pub": seed_pub.hex(),
        "commit_scheme": "sha256(row||nonce||ctx)",
        "commit_count": len(commits),
        "commits_all": [c.hex() for c in commits],   # optionnel ; utile pour POC tests
        "protocol": "hamiltonian-zkp-v1"
    }
    atomic_write(out_manifest, manifest, mode="json")
    print(f"[enroll] wrote manifest to {out_manifest}")

    # wipe sensitive material
    seed_client = None

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--seed", default="~/.zkp-ham/seed", help="path to encrypted client seed")
    p.add_argument("--seed-pub", default="seed_pub.txt", help="path to seed_pub (will be created if absent)")
    p.add_argument("--n", type=int, default=1024, help="number of vertices")
    p.add_argument("--davg", type=float, default=4.0, help="average degree target")
    p.add_argument("--out-graph", default="graph_adjmatrix.bin")
    p.add_argument("--out-manifest", default="enroll_manifest.json")
    args = p.parse_args()

    seed_path = os.path.expanduser(args.seed)
    seed_pub_path = os.path.expanduser(args.seed_pub)
    enroll(seed_path, seed_pub_path, args.n, args.davg, args.out_graph, args.out_manifest)
