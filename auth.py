# auth_client_round.py (extrait illustratif)
from seed_manager import decrypt_seed, derive_permutation
from matrix_graph import BitMatrix
from hashlib import sha256
import struct, os

N = 5000
SEED_PUB_HEX = "7f"*32

def load_matrix(path):
    with open(path,"rb") as f:
        n = struct.unpack(">I", f.read(4))[0]
        row_bytes = (n + 7)//8
        bm = BitMatrix(n)
        for i in range(n):
            bm.rows[i][:] = f.read(row_bytes)
    return bm

def client_auth_round(challenge_bit, session_id_bytes=b"sid1", round_id=0):
    # 1) redérive σ
    from getpass import getpass
    pw = getpass("Passphrase: ")
    seed_client = decrypt_seed(pw, os.path.expanduser("~/.zkp-ham/seed"))
    seed_pub = bytes.fromhex(SEED_PUB_HEX)
    sigma = derive_permutation(N, seed_client, seed_pub)

    # 2) charge la matrice publique (celle uploadée à l’enrôlement)
    bm = load_matrix("graph_adjmatrix.bin")

    # 3) s’il faut commit à chaque round (version classique), tu refais les commits ici
    #    (ou tu utilises un schéma commit-and-open basé sur les commits d’enrôlement)
    ctx = sha256(session_id_bytes + round_id.to_bytes(4,"big")).digest()
    # ... commit puis selon challenge_bit:
    if challenge_bit == 0:
        # ouvrir isomorphisme π etc. (selon la variante que tu implémentes)
        pass
    else:
        # ouvrir sélectivement les arêtes du cycle (indices + nonces)
        # en prouvant qu’elles correspondent aux commits de lignes
        pass

    seed_client = None
