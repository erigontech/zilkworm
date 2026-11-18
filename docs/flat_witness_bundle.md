# Flat Witness Bundle

**Backend: DirectState.** This is the implementation-side layout reference of the MFBD flat witness
bundle, the input of the DirectState guests. The design rationale and the normative verifier
requirements are in [mfbd_design_specs.md](mfbd_design_specs.md); where the two differ, the design
spec is normative. What the backend checks on a bundle and how it runs the blocks is in
[directstate.md](directstate.md); how bundles are produced is in
[mfbd_fixture_generation.md](mfbd_fixture_generation.md).

A single byte buffer carries everything the guest needs to run a block, or a contiguous run of
blocks, and verify its post-state root: the block RLPs, the ancestor headers, the pre-state accounts
and their touched storage slots, the bytecodes and the MPT proof nodes. The guest
`reinterpret_cast`s the bytes into POD views; nothing is decoded on the hot path.

The layout described here is `kFlatBundleVersion` 14 (`flat_bundle.hpp`), `PreStateMeta` version 4
(`pre_state.hpp`) and `kMphfMapVersion` 3 (`mphf_map.hpp`). Those constants are the source of
truth; a format change bumps them, see
[the wire-format rule](mfbd_fixture_generation.md#5-wire-format-changes).

Terms:

- **CHD**: *Compress, Hash, Displace* (Belazzougui, Botelho, Dietzfelbinger, ESA 2009,
  https://doi.org/10.1007/978-3-642-04128-0_61), the minimal-perfect-hash construction of the
  bundle's `MphfMap` (§2.4). It assigns each key to a bucket, then picks a per-bucket
  *displacement* that scatters that bucket's keys to distinct final slots.
- **Fingerprint collision**: two distinct full keys (for example two 20-byte addresses) whose
  64-bit *fingerprint*, the short key the MPHF hashes over, is identical. Distinct from CHD bucket
  overflow; see §2.3.1.

## 1. Overview

| Layer | Holds | Producer | Consumer |
|---|---|---|---|
| **MFBD envelope** (outer) | magic, version, N FlatBundles | the converters (`zilk_core/dev/cli/*_to_flat_bundle.cpp`) | `StateTransition::run_mfbd()` |
| **FlatBundle blob** (inner, `FBND`) | the witness of one run of blocks | `build_flat_bundle()` | `load_flat_bundle()` |
| **`direct_state`** | accounts, storage, codes, address and block hashes, collision sidecars | `direct_state_builder.cpp` | `DirectState` constructor and `sanitize()` |
| **`node_store`** | MPT proof nodes | the converters | `DirectState::find_node_rlp` |

## 2. Wire format

### 2.1 Input envelope (outer)

An MFBD input begins with a 4-byte little-endian magic and a 4-byte version. Everything in the
bundle and its sub-bundles is 8-byte aligned: the reader `reinterpret_cast`s the bytes into POD
structs (`FlatBundleHeader`, `PreStateMeta`, `MphfMapHeader`, `Account`, …), all `alignas(8)`, and
casting a misaligned pointer to an over-aligned type is undefined behavior and a fault on some
targets.

The constants are in `zilk_core/core/types_zz/flat_bundle.hpp` (`kInputMagicMFBD`,
`kInputVersionMFBD`, `kInputHeaderSizeMFBD`). The other input kinds the guest dispatches on are in
[architecture.md](architecture.md#input-format-and-dispatch).

**MFBD** (`MPHF-based Flat Bundle`): a 16-byte little-endian header followed by N FlatBundle blobs,
each starting at an 8-byte boundary:

```
+0   u32  magic   == 'MFBD' (0x4442464D)
+4   u32  version == 1
+8   u64  n_bundles
+16  bundle_0  (FlatBundle FBND blob)
+Σ   bundle_i  (each 8-aligned)
```

`xxd` of a one-bundle MFBD envelope starts:

```
00000000: 4d46 4244 0100 0000 0100 0000 0000 0000   MFBD............
00000010: 4642 4e44 0e00 0000 ...                   FBND....
        └── FBND magic + version of bundle_0
```

### 2.2 The inner bundle: FlatBundle blob (FBND)

A FlatBundle is a POD-mmap-able witness layout. The header is fixed-size
(`alignas(8)`, 56 bytes) and points at six sections in the same allocation
(`zilk_core/core/types_zz/flat_bundle.hpp`):

```cpp
struct alignas(8) FlatBundleHeader {
    uint32_t magic;                 // 'FBND' (0x444E4246)
    uint32_t version;               // kFlatBundleVersion
    uint32_t genesis_rlp_off;       uint32_t genesis_rlp_size;
    uint32_t blocks_rlp_off;        uint32_t blocks_rlp_size;
    uint32_t ancestors_rlp_off;     uint32_t ancestors_rlp_size;
    uint32_t direct_state_off;      uint32_t direct_state_size;
    uint32_t node_store_off;        uint32_t node_store_size;
    uint32_t network_off;           uint32_t network_size;
};
```

Sections, in order they typically appear:

| Section | Content |
|---|---|
| `genesis_rlp` | Single RLP-encoded `silkworm::Block` for the chain's genesis. |
| `blocks_rlp` | `<u64 N>` followed by N RLP-encoded `silkworm::Block` payloads, each starting at and padded to 8-byte align. `N=1` is the common single-block case. |
| `ancestors_rlp` | RLP-encoded list of `silkworm::BlockHeader`s. Loaded into `DirectState` via `insert_header` so `BLOCKHASH` opcodes resolve. |
| `direct_state` | POD pre-state blob — `PreStateMeta` + addr-map MphfMap + addr-hashes + block-hashes + code-store (see §2.3). |
| `node_store` | An MphfMap of MPT proof nodes keyed by 32-byte hash. A peer top-level section, **not** part of `direct_state` (see §2.6). |
| `network` | UTF-8 string naming the target chain config (e.g. `"Mainnet"`, `"Prague"`, `"Cancun"`). Not null-terminated; size is the section length. `StateTransition::run_one_bundle` looks this up in `silkworm::test::kNetworkConfig` to pick the `ChainConfig`. |

A bundle of another version fails `load_flat_bundle`.

### 2.3 `direct_state` internals

The `direct_state` blob is a flat sequence of sub-sections fronted by
`PreStateMeta` (`zilk_core/core/state_zz/pre_state.hpp`). Magic
`'PRES' = 0x53455250` (`kMagic`), version `kVersion`:

```cpp
struct PreStateMeta {
    uint32_t magic;                  // 'PRES'
    uint32_t version;                // kVersion
    uint32_t n_accounts;
    uint32_t n_block_hashes;

    uint32_t prestate_offset;        // addr-map MphfMap (inline Accounts + Slots)
    uint32_t addr_hashes_offset;     // AddrHashEntry[n_accounts] sorted by addr_hash
    uint32_t block_hashes_offset;    // BlockHashEntry[n_block_hashes] sorted by block_number

    uint32_t code_store_offset;      // MphfMap of bytecodes keyed by code_hash[0..8]
    uint32_t code_store_size;

    uint32_t reserved[8];
};
```

Sub-section shapes:

- **`prestate_offset` → addr-map MphfMap.** Keys are `addr_key8(addr)` (the
  first 8 bytes of the address with the top byte replaced by byte 19, so
  precompiles — which share their leading 19 bytes — still get distinct
  fingerprints; see §2.4). Each data entry is `[len:u64][Account][Slot[slot_count]]`.
  The `Account` struct carries the full address, `acc_rlp_buf` (init-encoded
  leaf RLP buffer space), `storage_root`, `code_hash`, `code_store_offset` (resolved
  by `sanitize()` to point at the `code_store` body), `slot_count`, and the
  `deleted` / `modified` flags. Address-fingerprint collisions (two
  addresses sharing the same `addr_key8`) are resolved through the MphfMap's
  collision sidecar by `MphfMap::find` (§2.4), not a per-Account flag. Slots
  are stored inline immediately after their owning Account.
- **`addr_hashes`** — `AddrHashEntry[n_accounts]`, sorted by
  `addr_hash = keccak256(addr)`. Each entry carries `addr_hash[32]`,
  `addr[20]`, and `entry_offset` — the byte offset of the account's data
  entry inside the prestate MphfMap. `check_root` walks this sorted array
  directly (no per-account MPHF lookup).
- **`block_hashes`** — `BlockHashEntry[n_block_hashes]`, sorted by
  `block_number`. Consulted by `ExecutionProcessor::get_block_hash_for_evm`
  to service the `BLOCKHASH` opcode without walking a parent-hash chain.
- **`code_store`** — MphfMap keyed by `hash_key8(code_hash) = code_hash[0..8]`.
  Each body is `FlatKv::encode(code_hash, code_bytes)` (verify-key + payload).
  The `sanitize` pass resolves every `Account.code_store_offset` to point into
  this section's body, so `find_code` is an offset add at runtime — no MPHF lookup.

#### 2.3.1 Two kinds of collision

The pipeline has to reckon with two **independent** notions of "collision",
which the code keeps strictly separate. Both ultimately land in the same
`MphfCollisionEntry[]` sidecar, and the read path treats them identically — but
they arise for different reasons.

1. **Fingerprint collisions in an MphfMap** — two distinct full keys whose
   64-bit fingerprint is identical. In the addr-map that is two addresses with
   the same `addr_key8(addr)`; in the code-store and node-store it is two
   32-byte hashes with the same `hash_key8 = bytes32[0..8]`. The MPHF maps over
   the 64-bit fingerprint, so it can only land both keys at one index. One of
   them therefore spills into the `MphfCollisionEntry[]` sidecar. Resolution at
   read time: `MphfMap::find` consults the singleton slot first (memcmp the full
   key against the key bytes embedded in the body); an *empty* slot dispatches
   to the sidecar (binary-search by `.key`, then memcmp the full key inside each
   equal-key entry to disambiguate), while an occupied slot whose embedded key
   fails the memcmp is a definitive miss (§2.4).

2. **CHD bucket overflow inside the MphfMap builder** — orthogonal to (1).
   Even when every input key has a *unique* fingerprint, CHD may exhaust its
   displacement budget for a particular bucket and "spill" all of that bucket's
   keys into the same `MphfCollisionEntry[]` sidecar. A spilled key's read-time
   index may already be owned by a key CHD did place, so the builder evicts that
   owner to the sidecar as well, keeping the shared slot empty (§2.5). The
   sidecar serves both populations interchangeably — the lookup path does not
   distinguish them.

§2.4 has the lookup, §2.5 the builder and a worked example of both routes.

### 2.4 MphfMap: the minimal perfect hash map

There are three roles for an MphfMap in a bundle — the addr-map and the
`code_store` (both inside `direct_state`) and the `node_store` (a peer
section). All three share one wire format and one lookup engine. It is worth
separating three things the name "MphfMap" covers:

- **The conceptual map** — a u64 → bytes minimal-perfect-hash map with a
  collision sidecar.
- **`MphfMapHeader`** — the 56-byte `alignas(8)` POD *wire header* (version 3)
  that sits at the front of the on-disk section.
- **`MphfMap`** — a thin C++ *wrapper class* that holds a
  `const MphfMapHeader*` and the derived pointers/scalars, and exposes the
  lookup/iteration API. It owns no storage; it is a view over bytes the
  `DirectState` already holds.

Both live in `zilk_core/core/common_zz/mphf_map.hpp`.

#### The wire header

```cpp
inline constexpr uint32_t kMphfMapVersion = 3u;

struct alignas(8) MphfMapHeader {  // 56 bytes
    uint32_t magic;
    uint32_t version;                // kMphfMapVersion = 3
    uint32_t n_keys;
    uint32_t n_buckets;
    uint64_t seed;
    uint64_t seed_factor;
    uint32_t collisions_offset;
    uint32_t collisions_size;        // bytes; multiple of sizeof(MphfCollisionEntry)
    uint32_t displacement_offset;
    uint32_t slot_offsets_offset;
    uint32_t data_offset;
    uint32_t data_size;

    uint32_t index_lookup(uint64_t key) const noexcept;  // see below
};

struct MphfCollisionEntry {  // 16 bytes, natural layout (alignof 8)
    uint64_t key;     // the uint64_t fingerprint the builder was given
    uint64_t offset;  // offset inside data[] of the entry's [len:u64][body]
    // No length: the [len:u64] data-section header is the only copy (see §2.4).
};
```

Two `uint64_t`s in natural layout: every byte of the entry is defined, there is
no reserved field, and each field is a single aligned `ld` on rv64im. `offset`
is u64 on the wire but the arena it indexes is u32-sized
(`MphfMapHeader::data_size`), so a prover can author values no producer emits.
`validate_mphf` rejects `offset > data_size` *before* adding to it — the sum
cannot wrap and the high half is never silently dropped — and it is the one
place that does: `find()` and `for_each()` run only over a validated map.

Physical layout following the header:

```
header (56 B)
displacement_factors[n_buckets]  (uint64 each, CHD displacement)
slot_offsets[n_keys]             (uint32 each; 0 == not in a singleton slot)
collisions[]                     (MphfCollisionEntry[], stride 16, sorted by .key)
data[]                           (reserved [0..8) so slot==0 is unambiguous,
                                  then per-entry: [len:u64][body:<len>])
```

The body for each entry is `[len:u64][body]`; the caller verifies membership by
memcmp'ing the full key bytes embedded inside `body` (see §2.5 for the encoding
the converters use).

#### Lookup

The lookup function (`index_lookup`, the two-stage CHD hash with the `mix64_body` mixer and the
Lemire reduction) is specified in
[mfbd_design_specs.md §5](mfbd_design_specs.md#5-the-mphf-index-in-depth); the code is
`MphfMapHeader::index_lookup`, `MphfMap::find` and `MphfMap::resolve_collision` in `mphf_map.hpp`.
`MphfMap` is a view that owns no storage: it holds the header pointer and the derived table
pointers. `DirectState` holds three, `pre_state_map_`, `code_store_map_` and `node_store_map_`.

What the read path relies on:

- `slot_offsets[idx] == 0` is a sentinel for "no singleton body at this index" (`data[]` reserves
  its first 8 bytes so a real offset is never `0`). Only a zero slot dispatches to the sidecar.
- A non-zero slot whose embedded key fails the full-key `memcmp` is a definitive miss. An absent
  key therefore resolves in at most one `memcmp`.
- That is sound only under the builder's invariant: every key whose body lives in the sidecar has
  `slot_offsets[index_lookup(key)] == 0` (§2.5).
- `resolve_collision` binary-searches the sidecar by `.key`, then walks the equal-key cluster,
  comparing the full key inside each body.
- The returned span is mutable; see
  [directstate.md](directstate.md#the-witness-buffer-is-written-in-place).

`find` takes the fingerprint function as a template parameter. The functions are in
`zilk_core/core/common_zz/index_key.hpp`:

| Map | Call | Fingerprint |
|---|---|---|
| addr-map | `pre_state_map_.find<20, 0, &addr_key8>(addr.bytes)` | `addr_key8`: the address's first 7 bytes, with byte 19 as the top byte (precompile addresses differ only in byte 19) |
| node store | `node_store_map_.find<32, 0, &hash_key8>(node_hash.bytes)` | `hash_key8`: the hash's first 8 bytes |
| code store | `code_store_map_.find<32, 0, &hash_key8>(h.bytes)` | `hash_key8` |

#### Validation

`for_each<KeySize, KeyOffset>(cb)` iterates every singleton slot (skipping the
`0` sentinels) and then every sidecar entry, so it visits all bodies. It is
used by `sanitize()` to sweep the code-store, node-store, and addr-map.

Neither `find()` nor `for_each()` bounds-checks an entry. The layout invariant
has one owner, `validate_mphf<KeySize, KeyOffset>`, which every map passes
once where it is built, in the `DirectState` constructor
(`validate_prestate_layout` for the addr map and code store,
`validate_nodestore_layout` for the node store), before an `MphfMap` exists
over it. Beyond the header and section checks it walks every entry reachable
from `slot_offsets[]` or the sidecar and requires:

- `offset <= data_size` and `data_size - offset >= 8` (compared before any
  addition, so a u64 sidecar offset cannot wrap);
- `body_len <= data_size - offset - 8`, the body lies inside the arena;
- `body_len >= KeyOffset + KeySize`, the bytes `find()` memcmps exist.

Checking once is only sound if what was checked cannot change afterwards.
`data[]` is the one section written through after validation (`sanitize()`
stamps `Account` scratch fields in place, the EVM updates state), so
`validate_mphf` also requires `data_offset` to lie at or past the end of the
header, the displacement table, `slot_offsets[]` and the sidecar. Both producers
already emit `data[]` last; a header that lays it over a table is rejected,
because a write into a body could otherwise rewrite an offset after its check.

A map that fails is never constructed (the constructor aborts), which is why
the read paths carry no guard of their own.

### 2.5 MphfBuilder: how the sidecar gets populated

`MphfBuilder<KeySize>` (`zilk_core/core/common_zz/mphf_builder.{hpp,cpp}`)
constructs an MphfMap host-side. Two routes feed the collision sidecar — the
same two notions of collision from §2.3.1:

1. **`add()` duplicate eviction (fingerprint collisions).**
   `add(uint64_t key, ByteView body)` keeps an
   `unordered_map<uint64_t, vector<uint8_t>>` of unique entries. If a second
   entry arrives with the same 64-bit fingerprint, the original is moved into
   `collision_keys_` / `collision_bodies_` (its singleton slot cleared) and the
   new one is appended too. This is how distinct-identity, same-fingerprint
   collisions wind up in the sidecar.

2. **CHD spill in `chd_solve` (bucket overflow).** `chd_solve` may fail to place
   every key of a bucket within the displacement budget. It then leaves that
   bucket's displacement factor at `0` and spills all of the bucket's keys, so
   their read-time index is whatever `index_lookup` computes with `df = 0` — an
   index some already-placed key may own. `finalize()` moves each spilled key's
   body into `collision_keys_` / `collision_bodies_` exactly like an `add`-time
   duplicate.

After both routes have populated the collision arrays, `finalize()`:

- Writes singleton bodies into `data[]` and sets `slot_offsets[idx] = data_cur`
  for each non-empty entry. **Sidecar keys leave their slot zero-init**: their
  map entry survives with an emptied body, the loop skips empty bodies, and the
  blob is zero-filled to begin with, so the slot reads back as a literal `0`.
  `finalize()` never has to overwrite a slot *with* `0`, because no placed key
  owns that index by the time it runs (see below).
- Appends every collision body to `data[]`, recording `offset` back into the
  corresponding `MphfCollisionEntry`. The body length is written once, into the
  `[len:u64]` data-section header, which is also what the read path returns.
- Sorts `collision_keys_` by `.key` so the read-side `lower_bound` works.

The sort makes `MphfCollisionEntry[]` a sorted array of `(key8, offset)` pairs,
with same-key entries forming contiguous clusters that the read path walks
linearly while memcmp'ing the full identity inside each body.

Each body the converters write is `FlatKv::encode(full_key, payload)` — the full
verify-key followed by the payload — so the read-path memcmp (at `KeyOffset` 0)
always has the full key to compare.

#### The sidecar invariant

The read path reaches the sidecar only from an empty slot (§2.4), so the builder
owes it:

> every key whose body lives in the sidecar has
> `slot_offsets[index_lookup(key)] == 0`.

The `add()` route gets this for free. A duplicate-fingerprint key remains a key
of the map — its entry survives with an emptied body, CHD still places it,
placement is injective so no other key can claim its index, and `finalize()`
writes no slot for an empty body. The slot stays `0`.

The CHD-spill route has to work for it, because a spilled key's index is
computed with `df = 0` and may already be owned. `chd_solve` therefore tracks
slot ownership explicitly in `slot_owner` — the same occupancy map its
displacement search probes — and, at the end of each seed attempt, walks the
spilled list and **co-spills**: for each spilled key it looks up the owner of
the index that key will probe, and if there is one, clears the slot and appends
that owner to the spilled list as well. Both keys then resolve through the
sidecar, and the slot they share stays `0`.

The pass runs after the whole placement loop, so it sees the final layout and no
later bucket can re-occupy a slot it cleared. It cannot cascade: an evicted
owner's own probe index *is* the slot just cleared, so by the time the walk
reaches that owner the slot is already free and the walk stops there. Each slot
therefore clears at most once, and the sidecar grows by at most one entry per
originally spilled key. Co-spilling happens before the attempt is scored against
the best one so far, so the seed search still minimises the *total* sidecar size.

Nothing about the wire format changes. `n_keys` still counts distinct keys —
including those whose bodies live in the sidecar — and still sizes both
`slot_offsets` and the `index_lookup` codomain; the only observable difference is
a few more zero entries in `slot_offsets`, which the read path already handles.
The host-side `entry_offset_for_addr` probe in `direct_state_builder.cpp`, which
resolves each `AddrHashEntry.entry_offset` while the blob is being assembled,
still scans the sidecar after an occupied-slot mismatch; under this invariant
that extra scan can never match, so it agrees with `MphfMap::find` by
construction.

#### Worked example

Suppose four 20-byte addresses with these `addr_key8` fingerprints. Two of them
(`B`, `C`) share a fingerprint, so the MPHF is actually built over the three
*distinct* fingerprints `0x11/0x22/0x33`, and we assume CHD additionally fails to
place `D`'s bucket:

| Address | `addr_key8` | What happens at build |
|---|---|---|
| `A` | `0x11…` | unique fingerprint, gets a singleton slot |
| `B` | `0x22…` | unique fingerprint, gets a singleton slot |
| `C` | `0x22…` | **fingerprint collision with B** → evicted to sidecar (both B and C end up there) |
| `D` | `0x33…` | unique fingerprint, but **CHD can't place it** in its bucket → spilled to sidecar |

After `finalize()`:

- `slot_offsets[idx(A)]` → A's body. `idx(B)` is now zero (B was evicted when C
  arrived). `idx(D)` is left zero (spilled). Had `idx(D)` landed on A's slot
  instead, `chd_solve` would have co-spilled A too, clearing that slot so both
  keys resolve through the sidecar.
- The sidecar holds, sorted by `.key`: `(0x22…, B)`, `(0x22…, C)`, `(0x33…, D)`.
  Note B and C form one equal-key cluster; D is a lone-key cluster that only
  exists because of bucket overflow, not a fingerprint clash.

Read paths:

- **find(A)** → `index_lookup` hits A's singleton slot → memcmp the 20-byte
  address against the body's embedded key → match → return A.
- **find(C)** → `index_lookup` hits the slot that *was* B's, now `0` (sentinel),
  so the singleton check is skipped → sidecar `lower_bound(0x22…)` → walk the
  `{B, C}` cluster, memcmp'ing the full 20-byte address → matches C.
- **find(D)** → `index_lookup` hits a zero slot → sidecar `lower_bound(0x33…)` →
  single-entry cluster `{D}` → memcmp confirms → return D. The read path never
  knew or cared that D was a *bucket spill* rather than a fingerprint clash; the
  full-key memcmp is correct either way.
### 2.6 `node_store` — read-only MPT proof nodes (a peer section)

The `node_store` is **not** part of `direct_state`/`PreStateMeta`. It is a peer
top-level section of `FlatBundle` (see the `FlatBundleHeader` in §2.2), sitting
between `direct_state` and `network`. Layout: a single MphfMap keyed by
`hash_key8(node_hash) = node_hash[0..8]`; each body is
`FlatKv::encode(node_hash, node_rlp)`.

It is constructed host-side by the converters (`json_witness_to_flat_bundle`,
`legacy_to_flat_bundle`, `eest_to_flat_bundle`) from whatever MPT proof nodes
they observe in the witness JSON / legacy bundle / EEST trie build, then handed
to `build_flat_bundle` alongside the already-built `direct_state` blob. The two
are written into adjacent sections of the same `FlatBundle` allocation.
`load_flat_bundle` bounds the sections and requires them disjoint; the MphfMap
layout of each store is validated by `validate_mphf<32>` in the `DirectState`
constructor, where the maps are built (§2.4).

At runtime the `node_store` is read-only. The `DirectState` constructor takes its byte window as a
separate `span` and stores it in `node_store_map_`; `DirectState::find_node_rlp(node_hash)` looks a
node up through it. Who calls it, and the `USE_HASH_KEY` recovery path that also reads it, are in
[directstate.md](directstate.md#node-store-reads).

## Source references

| Topic | Symbol / File |
|---|---|
| Input envelope and FlatBundle header | `FlatBundleHeader`, `kInputMagic*`: `zilk_core/core/types_zz/flat_bundle.hpp` |
| FlatBundle parser and assembler | `load_flat_bundle`, `build_flat_bundle`: `zilk_core/core/types_zz/flat_bundle.cpp` |
| `PreStateMeta`, `Slot`, `AddrHashEntry`, `BlockHashEntry` | `zilk_core/core/state_zz/pre_state.hpp` |
| `Account` (POD and scratch fields) | `zilk_core/core/types_zz/account.hpp` |
| `FlatKv` body encoding | `zilk_core/core/types_zz/flat_kv.hpp` |
| `MphfMapHeader`, `MphfMap`, `validate_mphf` | `zilk_core/core/common_zz/mphf_map.hpp` |
| `MphfBuilder`, `chd_solve` | `zilk_core/core/common_zz/mphf_builder.{hpp,cpp}` |
| Blob assembly, `entry_offset_for_addr` | `zilk_core/core/state_zz/direct_state_builder.cpp` |
| `addr_key8`, `hash_key8` | `zilk_core/core/common_zz/index_key.hpp` |
| Rust mirror of the wire constants | `prover/stateless_validator/src/mfbd.rs` |
