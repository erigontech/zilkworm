#!/usr/bin/env python3
# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

"""
Standalone verifier for `debug_executionWitness` preimage completeness.

Reads a witness JSON (either the raw RPC envelope or the bare result object) and
reports leaves whose preimage is missing from `witness.keys[]`.

The script does two things:

  1. Walks the account trie (and each non-empty storage subtrie) and reports every
     leaf whose preimage is missing from keys[]. This is a *superset* of the actual
     missing keys — a leaf in the witness may be a sibling along a different path
     and not strictly required to have its preimage included. Cross-reference with
    the EVM's access trace to identify true violations.

  2. Classifies a specific address via --check-addr as `present`, `absent`, or
     `blinded`. Use this when you already know (from execution) which addresses
     were accessed: any `--check-addr` whose 20-byte form is *not* in keys[] is a
     witness under-supply, regardless of `present`/`absent` verdict.

Usage:
    python3 verify_witness_preimages.py executionWitness25350549.json
    python3 verify_witness_preimages.py executionWitness25350549.json \\
        --check-addr 0x0e0c281ff05d34729cd764dcfc4fa999b720407c

Requires: pycryptodome (pip install pycryptodome)
"""
from __future__ import annotations
import argparse, json, sys
from typing import Any
from Crypto.Hash import keccak


def k256(b: bytes) -> bytes:
    h = keccak.new(digest_bits=256); h.update(b); return h.digest()


def rlp_decode(b: bytes, i: int = 0) -> tuple[Any, int]:
    p = b[i]
    if p < 0x80: return b[i:i+1], i+1
    if p < 0xb8: ln = p - 0x80; return b[i+1:i+1+ln], i+1+ln
    if p < 0xc0:
        ll = p - 0xb7; ln = int.from_bytes(b[i+1:i+1+ll], "big")
        s = i + 1 + ll; return b[s:s+ln], s + ln
    if p < 0xf8:
        ln = p - 0xc0; end = i + 1 + ln; out = []; j = i + 1
        while j < end: v, j = rlp_decode(b, j); out.append(v)
        return out, end
    ll = p - 0xf7; ln = int.from_bytes(b[i+1:i+1+ll], "big")
    end = i + 1 + ll + ln; out = []; j = i + 1 + ll
    while j < end: v, j = rlp_decode(b, j); out.append(v)
    return out, end


def nibbles(b: bytes) -> list[int]:
    return [n for x in b for n in (x >> 4, x & 0x0f)]


def decode_compact(first: bytes) -> tuple[bool, list[int]]:
    n = nibbles(first); flag = n[0]
    return (flag & 2) != 0, n[1:] if (flag & 1) else n[2:]


def walk_account_leaves(store: dict[bytes, bytes], root: bytes):
    """Yield (path_nibbles, account_rlp_bytes) for every leaf in the account trie."""
    stack = [(root, [])]
    while stack:
        h, path = stack.pop()
        if h not in store: continue  # blinded node
        node, _ = rlp_decode(store[h])
        if isinstance(node, list) and len(node) == 17:
            for i in range(16):
                child = bytes(node[i]) if node[i] else b""
                if not child: continue
                if len(child) == 32:
                    stack.append((child, path + [i]))
                else:
                    inner, _ = rlp_decode(child)
                    if isinstance(inner, list) and len(inner) == 2:
                        is_leaf, nibs = decode_compact(bytes(inner[0]))
                        if is_leaf:
                            yield path + [i] + nibs, bytes(inner[1])
                        else:
                            ref = bytes(inner[1])
                            if len(ref) == 32:
                                stack.append((ref, path + [i] + nibs))
        elif isinstance(node, list) and len(node) == 2:
            is_leaf, nibs = decode_compact(bytes(node[0]))
            if is_leaf:
                yield path + nibs, bytes(node[1])
            else:
                ref = bytes(node[1])
                if len(ref) == 32:
                    stack.append((ref, path + nibs))


def walk_path(store: dict[bytes, bytes], root: bytes, path: list[int]) -> str:
    """Return 'present', 'absent' (with diverging-leaf proof), or 'blinded'."""
    cur, depth = root, 0
    while True:
        if cur not in store: return "blinded"
        node, _ = rlp_decode(store[cur])
        if isinstance(node, list) and len(node) == 17:
            if depth == len(path): return "absent"  # branch terminates at requested depth
            nxt = bytes(node[path[depth]]) if node[path[depth]] else b""
            if not nxt: return "absent"
            depth += 1
            if len(nxt) == 32: cur = nxt; continue
            node, _ = rlp_decode(nxt)
        if isinstance(node, list) and len(node) == 2:
            is_leaf, nibs = decode_compact(bytes(node[0]))
            want = path[depth:depth+len(nibs)]
            if want != nibs:
                return "absent"
            depth += len(nibs)
            if is_leaf:
                return "present" if depth == len(path) else "absent"
            ref = bytes(node[1])
            if len(ref) != 32: return "blinded"
            cur = ref


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("witness", help="path to executionWitness JSON (RPC envelope or bare result)")
    ap.add_argument("--check-addr", action="append", default=[],
                    help="20-byte address(es) to also classify (present/absent/blinded)")
    args = ap.parse_args()

    doc = json.load(open(args.witness))
    w = doc.get("result", doc)
    keys = [bytes.fromhex(k[2:]) for k in w["keys"]]
    addr_set = {k for k in keys if len(k) == 20}
    slot_set = {k for k in keys if len(k) == 32}

    # Index trie nodes by hash.
    store = {k256(bytes.fromhex(h[2:])): bytes.fromhex(h[2:]) for h in w["state"]}

    # Pre-state root from the parent header.
    hdr_rlp = bytes.fromhex(w["headers"][-1][2:])
    hdr, _ = rlp_decode(hdr_rlp)
    state_root = bytes(hdr[3])

    print(f"witness:    {args.witness}")
    print(f"state_root: 0x{state_root.hex()}")
    print(f"keys[]:     {len(keys)} total ({len(addr_set)} addresses, {len(slot_set)} slots)")
    print(f"state[]:    {len(store)} unique trie nodes")

    # Pass 1 — every account leaf must have an address preimage in keys[].
    addr_hashes_in_keys = {k256(a): a for a in addr_set}
    missing_present = []
    leaves = 0
    storage_leaf_count_by_acct = {}
    for path, acct_rlp in walk_account_leaves(store, state_root):
        leaves += 1
        if len(path) != 64: continue
        h = bytes(n << 4 | m for n, m in zip(path[::2], path[1::2]))
        acct, _ = rlp_decode(acct_rlp)
        storage_root = bytes(acct[2])
        if h not in addr_hashes_in_keys:
            missing_present.append((h, storage_root, acct))
        # Pass 2 — for accounts with non-empty storage_root that we have the
        # subtree for, walk the storage trie and check 32-byte slot preimages.
        EMPTY_ROOT = bytes.fromhex(
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
        if storage_root != EMPTY_ROOT and storage_root in store:
            slot_hashes_in_keys = {k256(s) for s in slot_set}
            missing_slots = []
            for slot_path, _ in walk_account_leaves(store, storage_root):
                if len(slot_path) != 64: continue
                sh = bytes(n << 4 | m for n, m in zip(slot_path[::2], slot_path[1::2]))
                if sh not in slot_hashes_in_keys:
                    missing_slots.append(sh)
            if missing_slots:
                storage_leaf_count_by_acct[h] = missing_slots

    print(f"\nAccount leaves walked: {leaves}")
    print(f"PRESENT-account preimages missing: {len(missing_present)}")
    for h, sr, acct in missing_present[:20]:
        nonce = int.from_bytes(bytes(acct[0]), "big")
        bal   = int.from_bytes(bytes(acct[1]), "big")
        print(f"  path 0x{h.hex()}  nonce={nonce} balance={bal} storage_root=0x{sr.hex()[:10]}…")
    if len(missing_present) > 20:
        print(f"  … (+{len(missing_present)-20} more)")

    print(f"\nSTORAGE-slot preimages missing: "
          f"{sum(len(v) for v in storage_leaf_count_by_acct.values())} "
          f"across {len(storage_leaf_count_by_acct)} accounts")
    for h, ms in list(storage_leaf_count_by_acct.items())[:10]:
        print(f"  account-path 0x{h.hex()}: {len(ms)} missing slot preimages")
        for sh in ms[:3]:
            print(f"    slot-path 0x{sh.hex()}")

    if args.check_addr:
        print("\nClassification of --check-addr inputs:")
        for a in args.check_addr:
            ab = bytes.fromhex(a[2:] if a.startswith("0x") else a)
            in_keys = ab in addr_set
            verdict = walk_path(store, state_root, nibbles(k256(ab)))
            print(f"  0x{ab.hex()}  preimage_in_keys={in_keys}  trie_walk={verdict}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
