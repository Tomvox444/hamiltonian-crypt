# matrix_graph.py
# Python 3.9+ — pas de dépendance externe (pas de NumPy / NetworkX)
# Graphe = matrice d'adjacence binaire compacte (bitsets via bytearray)

import os, hmac, struct, random
from hashlib import sha256

# =============================
# HKDF minimal (Extract + Expand)
# =============================

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

def hkdf(ikm: bytes, salt: bytes, info: bytes, L: int) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, L)

# =============================
# PRNG déterministe (ChaCha-like simplifié via HMAC-SHA256 compteur)
# =============================

class DRBG:
    def __init__(self, key: bytes):
        self.key = key
        self.counter = 0

    def rand_u32(self) -> int:
        c = struct.pack(">Q", self.counter)
        self.counter += 1
        return int.from_bytes(hmac.new(self.key, c, sha256).digest()[:4], "big")

    def randbits(self, k: int) -> int:
        # retourne un entier sur k bits
        out = 0
        bits = 0
        while bits < k:
            out = (out << 32) | self.rand_u32()
            bits += 32
        excess = bits - k
        if excess:
            out >>= excess
        return out

    def randint(self, a: int, b: int) -> int:
        # uniforme sur [a,b]
        n = b - a + 1
        # rejection sampling sur 32 bits
        if n <= 0:
            raise ValueError("invalid range")
        t = (1 << 32) - ((1 << 32) % n)
        r = self.rand_u32()
        while r >= t:
            r = self.rand_u32()
        return a + (r % n)

# =============================
# Matrice d'adjacence bitset
# - non orienté simple (sans boucle)
# =============================

class BitMatrix:
    def __init__(self, n: int):
        self.n = n
        self.row_bytes = (n + 7) // 8
        # rows: liste de bytearray (n lignes)
        self.rows = [bytearray(self.row_bytes) for _ in range(n)]

    def _bitpos(self, j: int):
        byte_idx = j >> 3
        mask = 1 << (7 - (j & 7))
        return byte_idx, mask

    def get_bit(self, i: int, j: int) -> int:
        b, m = self._bitpos(j)
        return 1 if (self.rows[i][b] & m) else 0

    def set_bit(self, i: int, j: int, v: int):
        b, m = self._bitpos(j)
        if v:
            self.rows[i][b] |= m
        else:
            self.rows[i][b] &= (~m) & 0xFF

    def has_edge(self, u: int, v: int) -> bool:
        return self.get_bit(u, v) == 1

    def add_edge_undirected(self, u: int, v: int):
        if u == v: 
            return
        self.set_bit(u, v, 1)
        self.set_bit(v, u, 1)

    def degree(self, u: int) -> int:
        # popcount de la ligne u
        return sum(bin(byte).count("1") for byte in self.rows[u])

    def commit_row(self, i: int, nonce: bytes, context: bytes = b"") -> bytes:
        # H(row || nonce || context)
        return sha256(self.rows[i] + nonce + context).digest()

# =============================
# Dériver une permutation (Fisher–Yates) depuis une seed
# =============================

def derive_permutation(n: int, seed_client: bytes, seed_pub: bytes, context: bytes = b"ham-perm") -> list[int]:
    key = hkdf(seed_client, seed_pub, context, 32)  # 256-bit key
    drbg = DRBG(key)
    perm = list(range(n))
    for i in range(n - 1, 0, -1):
        j = drbg.randint(0, i)
        perm[i], perm[j] = perm[j], perm[i]
    return perm

# =============================
# Génération déterministe d’un graphe :
#   - cycle hamiltonien planté suivant sigma
#   - ajout d'arêtes aléatoires pour viser un degré moyen ~ d_avg
# =============================

def generate_graph_with_planted_cycle(n: int, seed_pub: bytes, sigma: list[int], d_avg: float = 4.0) -> BitMatrix:
    bm = BitMatrix(n)

    # 1) planter le cycle: arêtes (sigma[i], sigma[i+1])
    for i in range(n):
        u = sigma[i]
        v = sigma[(i + 1) % n]
        bm.add_edge_undirected(u, v)

    # 2) ajouter des arêtes aléatoires supplémentaires selon une PRNG dérivée de seed_pub
    key = hkdf(seed_pub, b"\x00"*32, b"noise-edges", 32)
    drbg = DRBG(key)
    # nombre total d'arêtes cible ~ (n * d_avg) / 2
    target_edges = int(n * d_avg / 2)
    # edges actuelles = n (cycle)
    added = 0
    trials = 0
    max_trials = n * 50  # borne pour ne pas boucler
    while added < (target_edges - n) and trials < max_trials:
        trials += 1
        u = drbg.randint(0, n - 1)
        v = drbg.randint(0, n - 1)
        if u == v:
            continue
        if bm.has_edge(u, v):
            continue
        bm.add_edge_undirected(u, v)
        added += 1
    return bm

# =============================
# Commitments par lignes (pour ZKP de type Hamiltonien)
# =============================

def commit_matrix_rows(bm: BitMatrix, seed_session: bytes, context: bytes = b"row-commit") -> tuple[list[bytes], list[bytes]]:
    n = bm.n
    # Nonces dérivés de seed_session (public/unique par session)
    key = hkdf(seed_session, b"\x00"*32, b"row-nonces", 32)
    drbg = DRBG(key)
    nonces = []
    commits = []
    for i in range(n):
        # 16 octets suffisent ; prends 32 si tu veux
        nonce = b"".join(struct.pack(">I", drbg.rand_u32()) for _ in range(4))  # 16 bytes
        nonces.append(nonce)
        commits.append(bm.commit_row(i, nonce, context))
    return commits, nonces

# =============================
# Exemple d'utilisation
# =============================

def main():
    # Paramètres
    n = 1000           # passe à 5000 si tu veux
    d_avg = 4.0        # degré moyen visé (incluant le cycle)
    # Seeds (exemples) — en vrai: os.urandom(32)
    seed_client = sha256(b"client-secret-seed").digest()  # SECRET côté client
    seed_pub    = sha256(b"public-graph-seed").digest()   # PUBLIC (regen graphe)

    # Dériver la permutation (chemin Hamiltonien) depuis la seed client
    sigma = derive_permutation(n, seed_client, seed_pub, b"ham-perm-v1")
    # Générer le graphe (matrice) avec le cycle planté + bruit
    bm = generate_graph_with_planted_cycle(n, seed_pub, sigma, d_avg=d_avg)

    # Vérifs rapides
    # - vérifier que sigma est bien un cycle (toutes arêtes présentes)
    ok = True
    for i in range(n):
        u = sigma[i]
        v = sigma[(i + 1) % n]
        if not bm.has_edge(u, v):
            ok = False
            break
    print(f"[check] cycle planted ok? {ok}")

    # - petite stat: degré min/max/moyen
    degs = [bm.degree(i) for i in range(n)]
    print(f"[deg] min={min(degs)} max={max(degs)} avg={sum(degs)/n:.2f}")

    # Commitments par ligne (pour ZKP ultérieure)
    seed_session = sha256(b"session-123").digest()  # seed unique par session
    commits, nonces = commit_matrix_rows(bm, seed_session)
    print(f"[commit] rows committed: {len(commits)} (ex: {commits[0].hex()[:16]}...)")

    # Sauvegarde simple (binaire) : n, puis lignes raw
    with open("graph_adjmatrix.bin", "wb") as f:
        f.write(struct.pack(">I", n))
        for row in bm.rows:
            f.write(row)
    with open("graph_meta.txt", "w") as f:
        f.write(f"n={n}\n")
        f.write(f"seed_pub={seed_pub.hex()}\n")
        f.write(f"d_avg={d_avg}\n")
        f.write(f"first_commit={commits[0].hex()}\n")

    print("[io] wrote graph_adjmatrix.bin (matrice) & graph_meta.txt")

if __name__ == "__main__":
    main()
