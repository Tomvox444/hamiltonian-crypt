#!/usr/bin/env python3
"""
visualize_graph_from_bin.py

Usage:
  python visualize_graph_from_bin.py graph.bin [--n N] [--format full|upper] [--out png|html] [--sample k]

If --n not provided the script will try to infer n from file size.
If --sample k is given and the graph is large, it will visualize a random induced subgraph of k nodes.
"""
import sys, os, math, argparse, random
import numpy as np
import networkx as nx
import pyvis

def infer_n_from_size(size_bytes):
    # try full: size_bits = n*n
    size_bits = size_bytes * 8
    n_full = int(round(math.sqrt(size_bits)))
    if n_full*n_full == size_bits:
        return ('full', n_full)
    # try upper triangle: size_bits = n*(n-1)/2
    # solve n^2 - n - 2*size_bits = 0
    disc = 1 + 8*size_bits
    n_tri = int((1 + math.isqrt(disc))//2)
    if n_tri*(n_tri-1)//2 == size_bits:
        return ('upper', n_tri)
    return (None, None)

def bits_from_bytes(data):
    # returns a numpy array of bits (0/1), MSB-first per byte
    arr = np.frombuffer(data, dtype=np.uint8)
    # expand bits
    bits = np.unpackbits(arr, bitorder='big')
    return bits

def build_adj_from_bits(bits, n, fmt='upper'):
    if fmt == 'full':
        expected = n*n
        bits = bits[:expected]
        mat = bits.reshape((n,n))
        return mat
    else:
        expected = n*(n-1)//2
        bits = bits[:expected]
        mat = np.zeros((n,n), dtype=np.uint8)
        # fill upper triangle (i<j) in a consistent order
        idx = 0
        for i in range(n):
            for j in range(i+1, n):
                val = bits[idx]
                mat[i,j] = val
                mat[j,i] = val
                idx += 1
        return mat

def graph_from_adj(mat):
    G = nx.from_numpy_array(mat)
    return G

def draw_static(G, outpath, sample=None):
    import matplotlib.pyplot as plt
    if sample and sample < G.number_of_nodes():
        nodes = random.sample(list(G.nodes()), sample)
        Gs = G.subgraph(nodes).copy()
    else:
        Gs = G
    plt.figure(figsize=(10,10))
    # spring layout (good for medium graphs)
    pos = nx.spring_layout(Gs, seed=42, iterations=100)
    nx.draw_networkx_nodes(Gs, pos, node_size=20)
    nx.draw_networkx_edges(Gs, pos, alpha=0.4, width=0.5)
    plt.axis('off')
    plt.tight_layout()
    plt.savefig(outpath, dpi=200)
    print(f"[OK] saved static image to {outpath}")

def export_html(G, outpath, sample=None):
    from pyvis.network import Network
    if sample and sample < G.number_of_nodes():
        nodes = random.sample(list(G.nodes()), sample)
        Gs = G.subgraph(nodes).copy()
    else:
        Gs = G
    net = Network(height='800px', width='100%', notebook=False)
    net.from_nx(Gs)
    net.show(outpath)
    print(f"[OK] saved interactive HTML to {outpath}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file", help="binary file path")
    ap.add_argument("--n", type=int, help="number of vertices (optional)")
    ap.add_argument("--format", choices=['full','upper'], help="format (optional)")
    ap.add_argument("--out", choices=['png','html','both'], default='png')
    ap.add_argument("--sample", type=int, default=None, help="sample k nodes for visualization (recommended for large graphs)")
    args = ap.parse_args()

    if not os.path.exists(args.file):
        print("File not found:", args.file); sys.exit(1)
    size = os.path.getsize(args.file)
    fmt = args.format
    n = args.n
    if not (fmt and n):
        inferred_fmt, inferred_n = infer_n_from_size(size)
        print("File size:", size, "bytes. inferred:", inferred_fmt, inferred_n)
        if not fmt:
            fmt = inferred_fmt
        if not n:
            n = inferred_n
    if fmt is None or n is None:
        print("Could not infer format/n. Provide --n and --format explicitly."); sys.exit(1)

    with open(args.file, "rb") as f:
        data = f.read()
    bits = bits_from_bytes(data)
    adj = build_adj_from_bits(bits, n, fmt=fmt)
    G = graph_from_adj(adj)
    print(f"Graph loaded: n={n}, m={G.number_of_edges()} edges, nodes={G.number_of_nodes()}")

    if args.out in ('png','both'):
        outpng = os.path.splitext(args.file)[0] + ".png"
        draw_static(G, outpng, sample=args.sample)
    if args.out in ('html','both'):
        outhtml = os.path.splitext(args.file)[0] + ".html"
        export_html(G, outhtml, sample=args.sample)

if __name__ == "__main__":
    main()
