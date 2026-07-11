#!/usr/bin/env python3
"""
WAICT transparency -- a growing (append-only) Merkle tree.

Start with an empty log. Every entry you add becomes a new leaf; after each
add, the Merkle root is recomputed and printed. That root is a single
fingerprint committing to every entry in the log so far -- it is what gets
signed and what monitors watch to detect a sneaky change.

Each entry you add is a leaf: paste the base64 SHA-256 hash you already
computed for a file (or a version). The script decodes it to 32 raw bytes and
uses it directly as the leaf -- so feeding a manifest's file hashes reproduces
that manifest's Merkle root.

Construction (kept deliberately simple):
    leaf   = the 32-byte hash you provide (base64-decoded)
    parent = SHA-256(left || right)        # raw 32-byte digests, concatenated
    a lone node at a level is promoted up unchanged

Run:
    python3 merkle_tree.py
Then paste one base64 hash per line (Enter to add, Ctrl-D or Ctrl-C to quit).
"""

import base64
import hashlib


def sha256(data):
    return hashlib.sha256(data).digest()


def merkle_root(leaves):
    """Root of an append-only Merkle tree over `leaves` (kept in order)."""
    if not leaves:
        return None
    level = leaves
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(sha256(level[i] + level[i + 1]))
            else:
                nxt.append(level[i])          # promote the lone node
        level = nxt
    return level[0]


def main():
    leaves = []
    print("Transparency log -- empty. Root: (none)")
    print("Paste a base64 SHA-256 hash to add it as a leaf (Ctrl-D to quit):")
    while True:
        try:
            entry = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nbye")
            break
        if not entry:
            continue
        try:
            leaf = base64.b64decode(entry, validate=True)
        except Exception:
            print("  ! not valid base64 -- paste a base64 SHA-256 hash")
            continue
        if len(leaf) != 32:
            print(f"  ! expected a 32-byte SHA-256 hash, got {len(leaf)} bytes")
            continue
        leaves.append(leaf)
        root = merkle_root(leaves)
        print(f"  entries: {len(leaves)}")
        print(f"  root:    {base64.b64encode(root).decode()}")
        print(f"           {root.hex()}")


if __name__ == "__main__":
    main()
