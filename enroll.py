# enroll_client.py
import os, json
from hashlib import sha256

from seed_manager import decrypt_seed, derive_permutation
from matrix_graph import generate_graph_with_planted_cycle, BitMatrix, commit_matrix_rows

# ---- paramètres côté client (tu peux les lire d'un fichier config) ----
N       = 5000
D_AVG   = 4.0
SEED_PUB_HEX = "7f"*32  # exemple; en vrai tu le prends publié par le serveur
SEED_STORE   = os.path.expanduser("~/.zkp-ham/seed")  # base path de ta seed chiffrée

# ---- enrôlement client ----
def client_enroll():
    # 1) récupérer seed_client (déverrouille via passphrase/YubiKey)
    from getpass import getpass
    pw = getpass("Passphrase to decrypt seed: ")
    seed_client = decrypt_seed(pw, SEED_STORE)  # 32 bytes
    seed_pub = bytes.fromhex(SEED_PUB_HEX)

    # 2) dériver σ depuis (seed_client, seed_pub)
    sigma = derive_permutation(N, seed_client, seed_pub)

    # 3) générer le graphe avec cycle planté + bruit déterministe (seed_pub)
    bm = generate_graph_with_planted_cycle(N, seed_pub, sigma, d_avg=D_AVG)

    # 4) produire des commitments par ligne (pour démarrer le ZKP)
    #    seed_session: unique par session / par enrollement
    seed_session = sha256(b"first-enrollment-session").digest()
    commits, nonces = commit_matrix_rows(bm, seed_session)

    # 5) sérialiser et envoyer au serveur (ici on écrit localement)
    #    - la matrice binaire
    with open("graph_adjmatrix.bin","wb") as f:
        # même format que matrix_graph.py::main()
        import struct
        f.write(struct.pack(">I", N))
        for row in bm.rows:
            f.write(row)

    #    - un manifeste JSON côté client pour POST /enroll
    enroll_manifest = {
        "n": N,
        "d_avg": D_AVG,
        "seed_pub": SEED_PUB_HEX,
        "commit_scheme": "sha256(row||nonce||ctx)",
        "first_commit": commits[0].hex(),
        "commit_count": len(commits),
        # Tu peux aussi envoyer tous les commits (pas les nonces !) pour pin initial
        "commits_all": [c.hex() for c in commits],
        "protocol": "hamiltonian-zkp-v1"
    }
    with open("enroll_manifest.json","w") as f:
        json.dump(enroll_manifest, f, indent=2)

    print("[client] wrote graph_adjmatrix.bin and enroll_manifest.json")
    # Efface la seed de la RAM (best-effort)
    seed_client = None

if __name__ == "__main__":
    client_enroll()
