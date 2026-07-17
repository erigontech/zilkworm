# Flat Witness Bundle

The **flat witness bundle** is a flat format for stateless
Ethereum block execution. A single byte buffer carries everything the guest
needs to run a block (or a contiguous run of blocks) and verify its post-state
root: the block RLPs, the ancestor headers, the pre-state accounts and their
touched storage slots, the bytecodes, and the MPT proof nodes — all
pre-laid-out so the guest can `reinterpret_cast` straight into POD views with
zero RLP decoding on the hot path.

This document describes the bundle's layout, the input envelope that
wraps it, how the state transition function consumes it,
For the minimally perfect hash function we use the CHD scheme (Belazzougui, D., Botelho, F.C., Dietzfelbinger, M. (2009). Hash, Displace, and Compress. In: Fiat, A., Sanders, P. (eds) Algorithms - ESA 2009. ESA 2009. Lecture Notes in Computer Science, vol 5757. Springer, Berlin, Heidelberg. https://doi.org/10.1007/978-3-642-04128-0_61)
- **CHD**: *Compress, Hash, Displace*, the minimal-perfect-hash construction
  used by the bundle's `MphfMap` (see §2.4). It assigns each key to a bucket,
  then picks a per-bucket *displacement* value that scatters that bucket's keys
  to distinct final slots.
- **fingerprint collision** — two distinct full keys (e.g. two 20-byte
  addresses) whose 64-bit *fingerprint* (the short key the MPHF hashes over)
  is identical. Distinct from CHD bucket overflow; see §2.3.1.

## 1. Overview

| Layer | Holds | Producer | Consumer |
|---|---|---|---|
| **Input envelope** (outer) | magic + version + N FlatBundles _or_ raw EEST JSON | `stdin_builders.rs`, `runner.cpp`, `json_witness_to_flat_bundle` | `StateTransition::run()` magic-dispatch |
| **FlatBundle blob** (inner) | Flat Witness for one set of blocks | `json_witness_to_flat_bundle`, `legacy_to_flat_bundle`, `eest_to_flat_bundle` | `load_flat_bundle()` |
| **`direct_state`** | accounts + storage + codes + addr/block hashes + collision sidecar | builder phase 10–12 | `DirectState::sanitize()` + EVM tx processor |

Pipeline (host or guest):

```
on-disk file  →  read_vec / fstream  →  envelope ByteView
                                              │
                       magic dispatch ────────┤
                                              │
                ┌─────────────────────────────┴─────────────────────────────┐
                │                                                           │
            EJSN path                                                   MFBD path
            run_ejsn():                                                 run_mfbd():
              parse JSON                                                  loop N bundles:
              blockchain_test()                                             load_flat_bundle()
              return 0/1/2                                                  run_one_bundle(FlatBundle&):
                                                                              direct.sanitize()
                                                                              insert ancestors
                                                                              Blockchain::insert_block × M
                                                                              check_root / check_root_new_block
                                                                            return Σ gas
```

Note where `load_flat_bundle()` sits: it runs in `run_mfbd()` (the caller), and
`run_one_bundle()` receives an already-loaded `FlatBundle&` (see §3.1).

## 2. Wire format

### 2.1 Input envelope (outer)

Every byte stream fed to `StateTransition` begins with a 4-byte little-endian
**magic** and a 4-byte **version**. Everything in the bundle and its
sub-bundles is 8-byte aligned.

> **Why 8-byte alignment?** The reader does not decode the wire — it
> `reinterpret_cast`s the bytes in place into POD structs (`FlatBundleHeader`,
> `PreStateMeta`, `MphfMapHeader`, `Account`, …), all declared `alignas(8)`.
> Casting a misaligned pointer to an over-aligned type is undefined behavior
> and, on some targets, a fault; aligning every section to 8 bytes lets the
> in-place cast be both UB-free and efficient (no byte-by-byte assembly).

Magics and versions are declared in `zilk_core/core/types_zz/flat_bundle.hpp`:

```cpp
inline constexpr uint32_t kInputMagicMFBD = 0x4442464Du;  // "MFBD"
inline constexpr uint32_t kInputMagicEJSN = 0x4E534A45u;  // "EJSN"
inline constexpr uint32_t kInputVersionMFBD = 1u;
inline constexpr uint32_t kInputVersionEJSN = 1u;
inline constexpr std::size_t kInputHeaderSizeMFBD = 16;
inline constexpr std::size_t kInputHeaderSizeEJSN = 8;
```

**MFBD** (`Multiple Flat Bundle`) — 16-byte header in little-endian
followed by N FlatBundle blobs, each starting at an 8-byte boundary:

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
00000010: 4642 4e44 0d00 0000 ...                   FBND....
        └── FBND magic + version of bundle_0
```

**EJSN** (`EEST JSON`) — 8-byte header followed by raw EEST `blockchain_test`
JSON bytes (no inner length prefix — body runs to envelope end):

```
+0   u32  magic   == 'EJSN' (0x4E534A45)
+4   u32  version == 1
+8   <JSON bytes …>
```

Only `MFBD` and `EJSN` are declared in code today (`flat_bundle.hpp`). A few
other four-character codes are *conventions referenced in prose only* — they are
**not** defined as constants anywhere and the dispatch does not handle them:

| Code | Hex | Status |
|---|---|---|
| `URLP` | `0x504C5255` | Legacy Unified RLP (pre-FlatBundle); not in code |
| `SFBD` | `0x44424653` | Notional "single FlatBundle" — use MFBD with `n_bundles=1`; not in code |
| `STBD` | `0x44425453` | Notional future single-transaction proving; not in code |

### 2.2 The inner bundle: FlatBundle blob (FBND)

A FlatBundle is a POD-mmap-able witness layout. The header is fixed-size
(`alignas(8)`, 56 bytes) and points at six sections in the same allocation
(`zilk_core/core/types_zz/flat_bundle.hpp`):

```cpp
struct alignas(8) FlatBundleHeader {
    uint32_t magic;                 // 'FBND' (0x444E4246)
    uint32_t version;               // 13
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

Current wire is `kFlatBundleVersion = 13`. Older bundles fail `load_flat_bundle` validation.

### 2.3 `direct_state` internals

The `direct_state` blob is a flat sequence of sub-sections fronted by
`PreStateMeta` (`zilk_core/core/state_zz/pre_state.hpp`). Magic
`'PRES' = 0x53455250`, current version `4`:

```cpp
struct PreStateMeta {
    uint32_t magic;                  // 'PRES'
    uint32_t version;                // 4
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

#### The witness buffer is mutable end-to-end

The pre-state and node-store spans are **mutable** (`std::span<uint8_t>`), not
const, all the way from the `DirectState` constructor down through `MphfMap`.
This is deliberate, not an accident of API drift:

- The `DirectState` constructor takes `std::span<uint8_t>` for both the
  pre-state and node-store windows; the member `prestate_view_` is
  `std::span<uint8_t>`.
- `MphfMap::data()` returns `uint8_t*` and `MphfMap::find()` returns
  `std::optional<std::span<uint8_t>>` — both mutable.

The buffer must be writable because `sanitize()` and the EVM both write
*scratch fields inside each `Account` in place*: `deleted`, `modified`,
`code_store_offset` / `code_store_len`, and the cached leaf RLP
(`acc_rlp_buf` / `acc_rlp_len` / `acc_rlp_sroot_off`). For example, `sanitize()`
sets `deleted = false`, stamps `modified`, and calls `rlp_into_cache(...)` on
each account; the per-block root check later re-stamps `acc_rlp_buf` after the
storage root changes. These writes land directly in the witness allocation. The
de-const refactor made this honest: there is no `const_cast` in the
execution path anymore — the mutation matches the declared type.

`sanitize()` is the identity↔hash verifier — see §2.3.2.

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
   key against the key bytes embedded in the body), and on a mismatch walks the
   sidecar (binary-search by `.key`, then memcmp the full key inside each
   equal-key entry to disambiguate).

2. **CHD bucket overflow inside the MphfMap builder** — orthogonal to (1).
   Even when every input key has a *unique* fingerprint, CHD may exhaust its
   displacement budget for a particular bucket and "spill" all of that bucket's
   keys into the same `MphfCollisionEntry[]` sidecar. The sidecar serves both
   populations interchangeably — the lookup path does not distinguish them.

See §2.4 for the lookup mechanics, §2.5 for the builder mechanics, and the
worked example in §2.5 for how each route resolves.

#### 2.3.2 `sanitize()` — the threat model

The witness is **untrusted**: it is synthesised from a geth
`debug_executionWitness` response and could be truncated, reordered, or
maliciously crafted. `sanitize()` (`zilk_core/core/state_zz/direct_state.cpp`)
runs once per bundle, before any block executes, and makes the witness prove it
is self-consistent. The checks it performs (in the order the function runs them):

1. **Identity↔hash binding.** `sanitize()` sweeps the code-store
   (`keccak256(code) == code_hash` for every body) and the node-store
   (`keccak256(node_rlp) == node_hash` for every body) first, then binds every
   account's identity to its hash as part of the coverage sweep below
   (`keccak256(addr) == addr_hash`). The trie-fold can prove that a *value*
   lives under a given hashed key, but it cannot, on its own, prove that the
   hash belongs to the claimed *identity* — that is exactly the gap this binding
   closes. Without it, a witness could hand the EVM the storage of address A
   while claiming it belongs to address B. (Storage slot *keys* are hashed and
   bound on the read path inside `check_root`, not in `sanitize()`.)

2. **`addr_hashes` 1-to-1 coverage sweep.** It walks the `addr_hashes` array
   (sorted by `keccak256(addr)`) and requires it strictly increasing (no
   duplicates — the comparison rejects `memcmp(prev, cur) >= 0`), with every
   entry's `entry_offset` resolving to an `Account` whose 20-byte address
   matches, while re-checking `keccak256(addr) == addr_hash` per entry. The
   "exactly once" guarantee rides on the `modified` scratch flag: the body walk
   stamps `modified = true` on every prestate account, the sweep clears it, and
   a final pass rejects if any account is still `modified` (never named by
   `addr_hashes`). Gaps or duplicates fail the sweep.

3. **Per-Account slot-extent bound.** This bound is enforced at `DirectState`
   construction (via `validate_prestate_layout` / `validate_or_abort`), before
   `sanitize()` runs, but it belongs to the same threat model: for each addr-map
   entry it verifies the entry's bytes — len prefix, `Account`, and all inline
   slots — fit inside the blob. In `validate_prestate_layout`'s `check_entry`:

   ```cpp
   const uint64_t slots_end = static_cast<uint64_t>(off) + 8u + sizeof(Account) +
                              static_cast<uint64_t>(acc->slot_count) * sizeof(Slot);
   if (slots_end > data_size) [[unlikely]] { /* reject: slots OOB */ }
   ```

   i.e. `off + 8 + sizeof(Account) + slot_count*sizeof(Slot) <= data_size`. This
   stops a forged `slot_count` from steering reads out of bounds.

Together these bind every byte of state the EVM will read to a verified
identity and hash, so a malformed or adversarial witness cannot smuggle in
mismatched accounts, code, or slots and still pass the post-state root check.

### 2.4 MphfMap: the minimal perfect hash map

There are three roles for an MphfMap in a bundle — the addr-map and the
`code_store` (both inside `direct_state`) and the `node_store` (a peer
section). All three share one wire format and one lookup engine. It is worth
separating three things that the name "MphfMap" used to conflate:

- **The conceptual map** — a u64 → bytes minimal-perfect-hash map with a
  collision sidecar.
- **`MphfMapHeader`** — the 56-byte `alignas(8)` POD *wire header* (version 2)
  that sits at the front of the on-disk section.
- **`MphfMap`** — a thin C++ *wrapper class* that holds a
  `const MphfMapHeader*` and the derived pointers/scalars, and exposes the
  lookup/iteration API. It owns no storage; it is a view over bytes the
  `DirectState` already holds.

Both live in `zilk_core/core/common_zz/mphf_map.hpp`.

#### The wire header

```cpp
inline constexpr uint32_t kMphfMapVersion = 2u;

struct alignas(8) MphfMapHeader {  // 56 bytes
    uint32_t magic;
    uint32_t version;                // kMphfMapVersion = 2
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

struct alignas(8) MphfCollisionEntry {  // 16 bytes
    uint64_t key;     // the uint64_t fingerprint the builder was given
    uint32_t offset;  // offset inside data[] where the body starts
    uint32_t len;     // body length in bytes
};
```

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

#### The wrapper class

```cpp
class MphfMap {
 public:
    bool valid() const noexcept;                  // h_ != nullptr
    uint32_t n_keys() const noexcept;
    uint8_t* data() const noexcept;               // MUTABLE
    const MphfMapHeader* header() const noexcept;

    uint32_t index_lookup(uint64_t key) const noexcept;

    template <std::size_t KeySize, std::size_t KeyOffset,
              uint64_t (*shorten_key)(const uint8_t (&)[KeySize])>
    std::optional<std::span<uint8_t>> find(const uint8_t (&key)[KeySize]) const noexcept;

    template <std::size_t KeySize = 32, std::size_t KeyOffset = 0, typename Cb>
    bool for_each(Cb&& cb) const noexcept;

 private:
    template <std::size_t KeySize, std::size_t KeyOffset = 0>
    std::span<uint8_t> resolve_collision(uint64_t k8, const uint8_t (&key)[KeySize]) const noexcept;

    const MphfMapHeader*      h_{nullptr};
    const uint32_t*           slot_offsets_{nullptr};
    uint8_t*                  data_{nullptr};        // MUTABLE
    const MphfCollisionEntry* collisions_{nullptr};
    const uint64_t*           displacement_{nullptr};
    uint32_t n_keys_{0}, n_buckets_{0}, data_size_{0}, n_collisions_{0};
    uint64_t seed_factor_{0};
};
```

`DirectState` holds three of these — `pre_state_map_`, `code_store_map_`,
`node_store_map_` — each constructed (or `reset()`) over the corresponding
section. The cached pointers/scalars are derived once from the header so the
hot path never re-reads offsets.

#### CHD: the lookup, with intuition

A *minimal perfect hash* maps `n` known keys onto exactly `[0, n)` with no gaps
and no collisions — but no single fixed hash function does that for an arbitrary
key set. CHD's trick is two-stage. First it hashes a key into one of
`n_buckets` *buckets*. Buckets are intentionally coarse, so several keys share a
bucket. Then, per bucket, it stores a *displacement* value chosen at build time
so that adding it to the key before a second hash scatters that bucket's keys to
distinct final slots in `[0, n_keys)`. The displacement table is small (one u64
per bucket) and is the only thing the lookup needs beyond the two hashes.

`seed` and `seed_factor` are the build-time tuning knobs: `seed_factor` is added
to the key before hashing, and the builder retries with fresh seeds until a
displacement assignment succeeds (the `mix64_body` mixer ensures each retry
produces a genuinely different bucket layout). At read time only `seed_factor`
matters.

`index_lookup(key)` computes the final `[0, n_keys)` index:

```cpp
uint32_t MphfMap::index_lookup(uint64_t key) const noexcept {
    const uint64_t z1 = key + seed_factor_;
    const uint64_t h1 = mix64_body(z1);                                 // first hash
    const uint32_t b  = fast_mod_u32((uint32_t)h1, n_buckets_);         // bucket
    const uint64_t df = displacement_[b];                               // per-bucket displacement
    const uint64_t h2 = mix64_body(z1 + df);                            // second hash
    return fast_mod_u32((uint32_t)h2, n_keys_);                         // final index
}
```

where `mix64_body` is the SplitMix64 stage-1 mixer and `fast_mod_u32` is
Lemire's multiply-shift reduction (`(x * n) >> 32`):

```cpp
inline uint64_t mix64_body(uint64_t z) noexcept {
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    return z ^ (z >> 31);
}
```

#### The lookup path: singleton slot, then sidecar

`MphfMap::find` is the read entry point. It takes the full key as a fixed-size
byte array and a `shorten_key` *non-type template parameter* — the function that
derives the 64-bit fingerprint. Callers pass `addr_key8` for 20-byte addresses
or `hash_key8` for 32-byte hashes:

```cpp
template <std::size_t KeySize, std::size_t KeyOffset,
          uint64_t (*shorten_key)(const uint8_t (&)[KeySize])>
std::optional<std::span<uint8_t>>
MphfMap::find(const uint8_t (&key)[KeySize]) const noexcept {
    if (h_ == nullptr || n_keys_ == 0) return std::nullopt;
    const uint64_t k8  = shorten_key(key);          // 64-bit fingerprint
    const uint32_t idx = index_lookup(k8);
    const uint32_t off = slot_offsets_[idx];
    if (off != 0) {                                 // singleton slot occupied
        uint8_t* body = data_ + off + 8u;
        if (std::memcmp(body + KeyOffset, key, KeySize) == 0) {
            uint64_t len; std::memcpy(&len, data_ + off, 8);
            return std::span<uint8_t>{body, (size_t)len};
        }
    }
    if (n_collisions_ > 0) {                         // sidecar fallback
        auto b = resolve_collision<KeySize, KeyOffset>(k8, key);
        if (!b.empty()) return b;
    }
    return std::nullopt;
}
```

The `slot_offsets[idx] == 0` value is a **sentinel**: it means "no singleton
body lives at this index" (recall `data[]` reserves its first 8 bytes precisely
so a real offset can never be `0`). A zero — or a non-zero slot whose embedded
key fails the memcmp — dispatches to the sidecar.

`resolve_collision` (a private member) binary-searches `collisions_` by `.key`,
then walks the contiguous equal-key cluster, memcmp'ing the full key inside each
body:

```cpp
template <std::size_t KeySize, std::size_t KeyOffset>
std::span<uint8_t>
MphfMap::resolve_collision(uint64_t k8, const uint8_t (&key)[KeySize]) const noexcept {
    if (n_collisions_ == 0) return {};
    auto it = std::lower_bound(collisions_, collisions_ + n_collisions_, k8,
        [](const MphfCollisionEntry& e, uint64_t kk) noexcept { return e.key < kk; });
    for (; it != collisions_ + n_collisions_ && it->key == k8; ++it) {
        uint8_t* body = data_ + it->offset + 8u;
        if (std::memcmp(body + KeyOffset, key, KeySize) == 0)
            return std::span<uint8_t>{body, (size_t)it->len};
    }
    return {};
}
```

The returned span is **mutable** — that is what lets the execution path stamp
the `Account` scratch fields in place (§2.3).

Concrete call patterns in `DirectState`:

```cpp
// addr-map: 20-byte address, fingerprint = addr_key8
pre_state_map_.find<20, 0, &addr_key8>(addr.bytes);

// node-store: 32-byte node hash, fingerprint = hash_key8
node_store_map_.find<32, 0, &hash_key8>(node_hash.bytes);

// code-store: 32-byte code hash, fingerprint = hash_key8
code_store_map_.find<32, 0, &hash_key8>(h.bytes);
```

The fingerprint functions live in
`zilk_core/core/state_zz/direct_state.hpp`:

```cpp
inline uint64_t hash_key8(const uint8_t (&h)[32]) noexcept {
    uint64_t v; std::memcpy(&v, h, 8); return v;   // first 8 bytes
}
// 7 MSBs + 19th byte (LSB): precompile addrs vary only in byte 19
inline uint64_t addr_key8(const uint8_t (&a)[20]) noexcept {
    uint64_t k; std::memcpy(&k, a, 8);
    k = (k & 0x00FFFFFFFFFFFFFFull) | (uint64_t(a[19]) << 56); return k;
}
```

`for_each<KeySize, KeyOffset>(cb)` iterates every singleton slot (skipping the
`0` sentinels). It is used by `sanitize()` to sweep the code-store, node-store,
and addr-map.

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

2. **CHD spill in `finalize()` (bucket overflow).** `chd_solve` may fail to
   place every key in its bucket within the displacement budget;
   bucket-overflowing keys land in `spilled_keys_out` with their index left
   pointing at a possibly already-used slot. `finalize()` then moves each
   spilled key's body into `collision_keys_` / `collision_bodies_` exactly like
   an `add`-time duplicate.

After both routes have populated the collision arrays, `finalize()`:

- Writes singleton bodies into `data[]` and sets `slot_offsets[idx] = data_cur`
  for each non-empty entry. **Spilled keys leave their slot zero-init**, even
  when the index collides with a non-spilled key's singleton slot — overwriting
  with `0` would clobber the singleton.
- Appends every collision body to `data[]`, recording `offset` and `len` back
  into the corresponding `MphfCollisionEntry`.
- Sorts `collision_keys_` by `.key` so the read-side `lower_bound` works.

The sort makes `MphfCollisionEntry[]` a sorted array of `(key, offset, len)`
triples, with same-`key` entries forming contiguous clusters that the read path
walks linearly while memcmp'ing the full identity inside each body.

Each body the converters write is `FlatKv::encode(full_key, payload)` — the full
verify-key followed by the payload — so the read-path memcmp (at `KeyOffset` 0)
always has the full key to compare.

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
  arrived). `idx(D)` is left zero (spilled).
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

This is why §2.3.1 stresses that the sidecar serves both populations
interchangeably: the lookup logic is identical, only the build-time reason for
spilling differs.

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
are written into adjacent sections of the same `FlatBundle` allocation;
`load_flat_bundle` validates each section independently (see the
`validate_mphf<32>` calls in `flat_bundle.cpp` for both `code_store` and
`node_store`).

At runtime the `node_store` is **read-only** — there is no append path. The
`DirectState` constructor takes the node-store byte window as a separate `span`
parameter (parallel to the prestate span) and stores it in `node_store_map_`
(an `MphfMap`). `DirectState::find_node_rlp(node_hash)` looks up a node's RLP
through it and is what the state-root recompute path calls:

```cpp
std::optional<ByteView>
DirectState::find_node_rlp(const evmc::bytes32& node_hash) const noexcept {
    if (auto b = node_store_map_.find<32, 0, &hash_key8>(node_hash.bytes))
        return ByteView{b->data() + FlatKv::kPayloadOffset, b->size() - FlatKv::kPayloadOffset};
    return std::nullopt;
}
```

There are **three** runtime call sites of `find_node_rlp`, all inside the shared
`GridMPT<DeletionEnabled>` template body (so they serve both the `<true>`
storage-trie and `<false>` account-trie instantiations), all reached only during
the block-0 state-root recompute:

- **`GridMPT::unfold_slot` (`zilk_core/core/trie_zz/fold_unfold.hpp`)** — when
  unfolding a node whose child is a 32-byte hash reference rather than an
  embedded RLP, it calls `state_->find_node_rlp(child)` to fetch the child node's
  RLP.
- **`GridMPT::init_from_root` (`zilk_core/core/trie_zz/grid_mpt.cpp`)** — fetches
  the previous block's `state_root` node to seed the trie. (The `GridMPT`
  constructor calls `init_from_root`, so this is how block 0 seeds the account
  trie from the parent header's committed root.)
- **`GridMPT::calc_root_from_updates` (`zilk_core/core/trie_zz/grid_mpt.cpp`)** —
  in the extension-node full-match branch, when the extension's child is a
  hash reference (`child_len >= 32`) it fetches that child via
  `state_->find_node_rlp(ext.child)`.

> All three call sites take a 32-byte child hash and resolve it through the same
> `MphfCollisionEntry[]` sidecar mechanism as any other `hash_key8` lookup; two
> MPT nodes whose first 8 hash bytes collide are disambiguated by the full
> 32-byte memcmp inside `find`.

There is also a third, fallback reader — `DirectState::recover_account_from_nodestore`,
compiled only under `USE_HASH_KEY` (default 0, i.e. compiled away): on a
prestate-map miss it walks the account trie from the parent `state_root` along
`keccak(addr)` to recover an account whose preimage was missing from the
addr-map. `witness_hide_node_test.cpp` documents the gap this guards against.

`check_root` (block 0 of a bundle) and `check_root_new_block` (subsequent
blocks) in `state_transition.cpp` drive the recomputes (§3.1). The only
"updates" to anything node-related are in-memory mutations of each `Account`'s
`acc_rlp_buf` / `acc_rlp_len` / `acc_rlp_sroot_off` cache after a successful root
check, so the next block's `HashBuilder`-based path can reuse them. The
`node_store` bytes themselves are never written through.

## 3. Full block run

Entry point: `StateTransition::run()` in
`zilk_core/dev/state_transition.cpp`. The leading 4 bytes are read and matched
against `kInputMagicEJSN` / `kInputMagicMFBD`:

```cpp
switch (magic) {
    case kInputMagicEJSN: return run_ejsn();
    case kInputMagicMFBD: return run_mfbd();
    default: sys_println("ERROR: unsupported input magic"); return kRunFailure;
}
```

### 3.1 MFBD path

`run_mfbd()` validates the 16-byte header, reads `n_bundles`, and walks the
envelope at 8-byte alignment. For each bundle it calls
`::zilkworm::load_flat_bundle(tail)` — which validates the FBND magic +
version, RLP-decodes `genesis`, `blocks` (the `<u64 N>` blocks-RLP header plus N
8-aligned payloads), and `ancestors`, and constructs the `FlatBundle`'s
`DirectState` over the prestate and node-store byte windows (no POD decoding) —
then passes the already-loaded bundle to `run_one_bundle(*fb)`. After each
bundle it advances the cursor by `align8(cursor + fb->blob.size())`.

`run_one_bundle(::zilkworm::FlatBundle& bundle)`:

1. `bundle.direct.sanitize()` — identity↔hash verification across every account,
   code, and node (§2.3.2). A failure returns `{0, false}`.
2. `bundle.direct.insert_header(h)` for each ancestor header (so `BLOCKHASH`
   resolves).
3. Resolves `bundle.network` against `silkworm::test::kNetworkConfig` and
   constructs `Blockchain{bundle.direct, cfg, bundle.genesis}`. Sets
   `bundle.direct.set_multi_block(block_rlps.size() > 1)` so the per-block
   journal arms for incremental validation.
4. For each `block` in the bundle:
   - `blockchain.insert_block(block, /*check_state_root=*/false)`; on any
     non-`kOk` result return `{0, false}`.
   - The *first* block that reaches the root check → `check_root(...)`; every
     subsequent block → `check_root_new_block(...)`. (The split is gated by a
     `first_root_check` flag flipped after the first non-skipped block, so for a
     normal all-valid bundle this is just "block 0 vs blocks 1..N-1".) Either
     path compares the recomputed root against `header.state_root` (see below).
   - `bundle.direct.insert_header(block.header)` so the next block's `BLOCKHASH`
     resolves.
   - Accumulate `cumulative_gas += block.header.gas_used`.

Returns cumulative gas across all bundles, or `0` on any failure.

#### Why block 0 and blocks 1+ check the root differently

The two root-check strategies are not arbitrary; they reflect what state is
available at each point.

**Block 0 — full recompute via GridMPT (`check_root`).** The first block of a
bundle has no prior cached leaf RLPs to lean on, so it rebuilds the account
trie and every touched storage trie *from scratch* out of the witness
`node_store`. The flow:

1. Merge the pre-state `addr_hashes` with any newly created accounts into one
   sorted-by-`addr_hash` sequence.
2. For each account, walk its pre-state and newly created slots, caching
   `keccak256(slot_key)` and encoding initial/current values, then drive
   `GridMPT<true>` to recompute that account's storage root over the witness
   nodes (`reset(storage_root)` → `calc_root_from_updates()`).
3. Re-encode each account leaf (`addr_hash` + account RLP, now carrying the new
   storage root) into `acc_updates`.
4. Drive a `GridMPT` over the account trie (the recompute path constructs it as
   `GridMPT<true>` — `state_transition.cpp` declares `mpt::GridMPT<true>
   acc_trie(direct_state, prev_root)`), seeding from the previous block's
   `state_root` (unfolded out of the keccak-verified `node_store` via
   `init_from_root`) and layering the account updates on top.
5. Compare the computed new root against `header.state_root`.

This is the expensive path: it unfolds and folds real MPT nodes for both the
account layer and every touched storage trie. It is also the *trust anchor* — it
starts from a `state_root` the parent header committed to and rebuilds forward
using only nodes whose `keccak256(node_rlp)` `sanitize()` already verified, so a
correct result proves the post-state without trusting the witness's structure.

**Blocks 1+ — incremental rebuild via HashBuilder (`check_root_new_block`).**
After block 0, every account already carries a cached leaf RLP
(`acc_rlp_buf`) that the previous block's root check stamped in place. A
subsequent block need not re-walk the MPT at all:

1. For each account the EVM changed this block, re-encode its leaf with the new
   storage root (`rlp_into_cache(storage_root)` updates `acc_rlp_buf` /
   `acc_rlp_len` / `acc_rlp_sroot_off`).
2. Collect leaves (`addr_hash` + RLP) from pre-state and created accounts,
   skipping deleted/empty accounts, and sort by `addr_hash`.
3. Feed them to `silkworm::trie::HashBuilder` (`add_leaf` per leaf,
   `root_hash()` at the end) — a pure leaf-to-root fold that touches **no
   node_store and no GridMPT**.
4. Compare against `header.state_root`.

This works because each account leaf already embeds its current storage root,
and only accounts the EVM actually changed need their leaf re-encoded; the
account layer is then re-hashed directly from leaves. It trades the full witness
walk for a single leaf-to-root pass, which is why it is markedly faster than
block 0's recompute.

| Aspect | Block 0 | Blocks 1+ |
|---|---|---|
| Engine | `GridMPT` full recompute | `HashBuilder` incremental rebuild |
| Storage tries | recomputed via witness `node_store` | reused via cached `acc_rlp_buf` |
| Account trie | `GridMPT` unfold/fold from prev `state_root` | `HashBuilder.add_leaf()` from leaves |
| Node-store use | heavy (storage + account layers) | none |
| Relative cost | slower (full witness walk) | faster (leaf hash only) |

### 3.2 EJSN path

`run_ejsn()` strips the 8-byte envelope header, parses the body as an EEST
`blockchain_test` JSON document, and runs each test sub-object via the
`blockchain_test()` helper (which constructs an in-memory `DirectState` from the
test's `pre` block and exercises one `Blockchain::insert_block` per entry in
`blocks`). Exit codes mirror the legacy EEST contract:

- `0` — all passed
- `1` — any failed
- `2` — any skipped (no failures)

## 4. SP1 input building

The Rust prover host builds an `SP1Stdin` carrying exactly one envelope per
proof request. See `prover/prover_hypercube/src/stdin_builders.rs` (and the
equivalent `prover_turbo` variant):

```rust
const INPUT_MAGIC_EJSN: u32 = 0x4E534A45;
const INPUT_VERSION_EJSN: u32 = 1;

pub fn build_stdin_from_eth_tests(path: &Path) -> Result<SP1Stdin> {
    let mut stdin = SP1Stdin::new();
    let raw = fs::read_to_string(path)?;
    let minified = serde_json::to_string(&serde_json::from_str::<Value>(&raw)?)?;
    let json_bytes = minified.as_bytes();

    let mut envelope = Vec::with_capacity(8 + json_bytes.len());
    envelope.extend_from_slice(&INPUT_MAGIC_EJSN.to_le_bytes());
    envelope.extend_from_slice(&INPUT_VERSION_EJSN.to_le_bytes());
    envelope.extend_from_slice(json_bytes);
    stdin.write_vec(envelope);
    Ok(stdin)
}

pub fn build_stdin_from_mfbd(path: &Path) -> Result<SP1Stdin> {
    let mut stdin = SP1Stdin::new();
    let raw = fs::read(path)?;        // file is already MFBD-wrapped on disk
    stdin.write_vec(raw);
    Ok(stdin)
}
```

The MFBD path slurps the on-disk bundle file unmodified — the converters
(`json_witness_to_flat_bundle`, `legacy_to_flat_bundle`, `eest_to_flat_bundle`)
write the MFBD envelope at file-write time, so no re-wrapping is required.

`SP1Stdin` layout is a single `Vec<u8>`. The guest does ONE `read_vec_raw()` and
hands the bytes straight to `StateTransition`
(`prover/guest_hypercube/src/main.cpp`):

```cpp
ReadVecResult input_buf = read_vec_raw();
std::span<uint8_t> envelope{input_buf.ptr, input_buf.len};
auto st = silkworm::cmd::state_transition::StateTransition(envelope);
uint64_t result = st.run();
```

Note: the Rust constants are an independent mirror of the C++ values in
`flat_bundle.hpp`. They are kept in sync by convention; a future binding
generator could collapse them.

## 5. Native run

The native runner is `zilk_core/dev/cli/runner.cpp` (built as the
`state_transition` executable). It accepts either a file or a directory:

- **`.json`** — `run_json_test_file()` reads the file, wraps it in an in-memory
  EJSN envelope, constructs `StateTransition`, and returns the run's exit code
  (0/1/2 per EEST semantics).
- **`.bin` / unknown** — `run_flat_bundle_file()` reads the file straight into a
  vector. The on-disk file is already MFBD-wrapped (the converters emit it that
  way), so the bytes pass through unmodified into `StateTransition`. The runner
  prints `Cumulative Gas Used: <n>` and returns 0.
- **Directory** — iterates recursively, dispatching per file extension.

The runner is the same binary the EEST harness (`make eest-blockchain-tests`)
drives via ctest.

## 6. QEMU run

`qemu_runner/` cross-compiles `zilk_core` to a RISC-V target (rv32im or rv64im)
and runs the resulting binary under QEMU semihosting. Used for cycle-accurate
instruction profiling without paying SP1 prover overhead.

`qemu_runner/src/main.cpp` reads the envelope file via semihosting into a static
200 MB buffer:

```cpp
static char ENV_BUF[200 * 1024 * 1024];

int h = sh::open_file_read("stdin_payload.bin");
// chunked read into ENV_BUF until EOF …
std::string envelope_str(ENV_BUF, ENV_BUF + total);
const uint64_t res = sample_run_wrapped(envelope_str);
sh::exit(static_cast<int>(res));
```

`qemu_runner/src/cppextern.cpp::sample_run_wrapped` constructs a
`std::span<uint8_t>` over the envelope bytes and hands them to
`StateTransition::run()` — the magic dispatch chooses MFBD or EJSN exactly as in
the SP1 guest. The wire format is the same `stdin_payload.bin` that the prover
host would have written for an SP1 run.

## 7. EEST JSON tests

The EEST corpus on disk lives at
`test-fixtures-cache/eest_stable/fixtures/blockchain_tests/` (populated by
`make test-fixtures` from the `test-fixtures.json` pin).
Two harness paths consume it:

- **Native runner** — `runner.cpp::run_json_test_file` reads a `.json` file
  byte-for-byte, prepends an 8-byte EJSN header in memory, and feeds the
  envelope to `StateTransition`. EEST JSON files on disk are never re-encoded.
- **SP1 prover via `.mfbd`** — `eest_to_flat_bundle bulk-convert` converts the
  EEST corpus into a parallel `.mfbd` tree. Freshness is managed by the
  `Makefile` (not the converter binary): `make eest-blockchain-tests` writes a
  `manifest.json` recording both the fixture submodule SHA (`eest_sha`) and the
  converter SHA (`converter_sha`), and re-runs `bulk-convert` only when that
  manifest is absent or its `converter_sha` no longer matches. The SP1 prover
  then ingests the `.mfbd` files via the MFBD path.

Both paths land in the same `StateTransition::run()` magic dispatch.

## 8. Converters

Three converters produce MFBD-wrapped FlatBundle files that the runner, the
QEMU runner, and the SP1 host can all consume unmodified.

### 8.1 `legacy_to_flat_bundle`

`zilk_core/dev/cli/legacy_to_flat_bundle.cpp`. One-shot converter from the old
`unifiedBlockAndStateRlp<N>.bin` shape (5 RLP items, in order: genesis block
[decoded as `genesis_rlp` and passed as the bundle's genesis], current block,
pre-state, ancestors, pre-trie) to a v13 FlatBundle wrapped in MFBD with
`n_bundles=1`. The output bundle's `network` section is hardcoded to
`"Mainnet"`. Self-contained — keeps the legacy decoders out of the main code
paths. Usage: `legacy_to_flat_bundle <legacy.bin> <flat.bin>`.

### 8.2 `json_witness_to_flat_bundle`

`zilk_core/dev/cli/json_witness_to_flat_bundle.cpp`. Reads a witness JSON
document on stdin (the `{block, headers, state, codes, keys}` payload that
`prover/common/src/fetcher.rs` synthesises from a geth `debug_executionWitness`
response), walks the witness state trie and per-account storage tries in C++,
fingerprints addresses, builds the addr-map and node-store MphfMaps, and
assembles a v13 FlatBundle. The output bundle's `network` section is hardcoded
to `"Mainnet"`. Output is MFBD-wrapped and written to stdout.

### 8.3 `eest_to_flat_bundle`

`zilk_core/dev/cli/eest_to_flat_bundle.cpp`. Converts EEST `blockchain_test`
JSON fixtures into MFBD-wrapped FlatBundle files. Supports `emit` (single
subtest by index) and `bulk-convert` (recursive directory walk that mirrors the
input tree to per-file `.mfbd` outputs; the `manifest.json` freshness file is
written by the `Makefile`, not by the converter). The output bundle's `network`
section is taken from the fixture's `network` field (falling back to `"Mainnet"`
when absent). Used by `make eest-blockchain-tests` to materialise an `.mfbd` mirror of
the EEST corpus that the SP1 prover ingests via the MFBD path.

All three converters call into the same `::zilkworm::build_flat_bundle`
assembler declared in `flat_bundle.hpp` and then wrap the resulting FBND blob in
a 16-byte MFBD header.

## Source references

Prose cross-references above name functions and files (not line numbers, which
rot). This table is the file-level index:

| Topic | Symbol / File |
|---|---|
| Input envelope + FlatBundle header | `FlatBundleHeader`, `kInputMagic*` — `zilk_core/core/types_zz/flat_bundle.hpp` |
| FlatBundle parser / assembler | `load_flat_bundle`, `build_flat_bundle` — `zilk_core/core/types_zz/flat_bundle.cpp` |
| `PreStateMeta`, `Slot`, `AddrHashEntry`, `BlockHashEntry` | `zilk_core/core/state_zz/pre_state.hpp` |
| `Account` (POD + scratch fields) | `zilk_core/core/types_zz/account.hpp` |
| `DirectState`, `sanitize`, `find_node_rlp`, `validate_prestate_layout` | `zilk_core/core/state_zz/direct_state.{hpp,cpp}` |
| `MphfMapHeader` + `MphfMap` class + `index_lookup` / `find` / `resolve_collision` | `zilk_core/core/common_zz/mphf_map.hpp` |
| `MphfBuilder` (host-side construction) | `zilk_core/core/common_zz/mphf_builder.{hpp,cpp}` |
| `addr_key8` / `hash_key8` | `zilk_core/core/state_zz/direct_state.hpp` |
| `GridMPT` (storage/account trie recompute) | `GridMPT::unfold_slot` — `zilk_core/core/trie_zz/fold_unfold.hpp`; `GridMPT::init_from_root` — `zilk_core/core/trie_zz/grid_mpt.cpp` |
| `StateTransition::run` dispatch, `run_one_bundle`, `check_root` / `check_root_new_block` | `zilk_core/dev/state_transition.{hpp,cpp}` |
| Native runner | `zilk_core/dev/cli/runner.cpp` |
| SP1 guest entry | `prover/guest_hypercube/src/main.cpp` |
| SP1 host stdin builders | `prover/prover_hypercube/src/stdin_builders.rs` |
| QEMU entry | `qemu_runner/src/{main.cpp,cppextern.cpp}` |
| Legacy → FlatBundle converter | `zilk_core/dev/cli/legacy_to_flat_bundle.cpp` |
| Witness JSON → FlatBundle builder | `zilk_core/dev/cli/json_witness_to_flat_bundle.cpp` |
| EEST JSON → FlatBundle converter | `zilk_core/dev/cli/eest_to_flat_bundle.cpp` |
| Fetcher (geth `debug_executionWitness` → JSON payload) | `prover/common/src/fetcher.rs` |
