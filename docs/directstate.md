# DirectState

DirectState is the state backend that reads an MFBD flat witness bundle in place. This document
covers what the backend checks and how it validates a block; the bundle's byte layout is in
[flat_witness_bundle.md](flat_witness_bundle.md).

## The witness buffer is mutable end-to-end

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

## `sanitize()` — the threat model

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
   bound on the read path inside `check_root`, not in `sanitize()` — and the
   same is true of MPHF *routing* for account reads; see check 4.)

2. **`addr_hashes` 1-to-1 coverage sweep.** It walks the `addr_hashes` array
   (sorted by `keccak256(addr)`) and requires it strictly increasing (no
   duplicates — the comparison rejects `memcmp(prev, cur) >= 0`), with every
   entry's `entry_offset` resolving to an `Account` whose 20-byte address
   matches, while re-checking `keccak256(addr) == addr_hash` per entry. The
   "exactly once" guarantee rides on the `modified` scratch flag: the body walk
   runs first and stamps `modified = true` on every prestate account, the sweep
   clears it per named entry, and a second body walk rejects if any account is
   still `modified` (never named by `addr_hashes`). Gaps or duplicates fail the
   sweep. This proves the `addr_hashes` ↔ walked-body bijection, but it
   deliberately does **not** constrain the account *read path*, `find(addr)`;
   see check 4.

3. **Per-Account slot-extent bound.** This bound is enforced at `DirectState`
   construction (via `validate_prestate_layout` / `validate_or_abort`), before
   `sanitize()` runs, but it belongs to the same threat model. It is layered:
   `validate_mphf<20>` first places every addr-map entry's `[len:u64][body]`
   inside `data[]` with `body_len >= 20` (the generic MphfMap invariant, §2.4),
   and `validate_prestate_layout`'s `check_entry` then requires the `Account`
   and all its inline slots to fit inside that body:

   ```cpp
   uint64_t body_len; std::memcpy(&body_len, data + off, 8);
   if (body_len < sizeof(Account)) [[unlikely]] { /* reject */ }
   const auto* acc = reinterpret_cast<const Account*>(data + off + 8u);
   const uint64_t slots_bytes = static_cast<uint64_t>(acc->slot_count) * sizeof(Slot);
   if (slots_bytes > body_len - sizeof(Account)) [[unlikely]] { /* reject: slots exceed body */ }
   ```

   i.e. `sizeof(Account) + slot_count*sizeof(Slot) <= body_len` and, by the
   MphfMap invariant, `off + 8 + body_len <= data_size`. This stops a forged
   `slot_count` from steering reads out of bounds, or into a neighbouring entry.

4. **MPHF routing.** This one is enforced at root-check time inside
   `check_root`, not in `sanitize()`, but it belongs to the same threat model:
   checks 1 and 2 prove that `addr_hashes` and the walked bodies are in
   bijection, yet neither constrains where `find(addr)` actually lands — a
   forged `MphfMapHeader` (e.g. a transposed `slot_offsets[]`) can make
   `find(addr)` miss an account that the body walk and `addr_hashes` both
   cover. The enforcement rides on the account read path never returning
   "nothing". `DirectState::find_or_create_account(addr)` is the single
   creation-capable lookup: the MPHF blob map first, then the
   `created_accounts_` overlay, and on a *total* miss it *materializes* a
   record in `created_accounts_` with `deleted = true`
   (`materialize_absent_account_`, the cold path). "Account does not exist" is
   thus a data property (`deleted`) on an always-present record, not a null
   pointer. `DirectStateView::get_account` (the evmone `StateView` boundary)
   routes through it and returns `std::nullopt` only when the record says
   `deleted`, so EVM-visible semantics are unchanged — but `DirectState` now
   owns a record for every address the EVM ever reads, from the first read.

   The rule is **total miss only**. If either lookup finds a record, that
   record is returned as it stands, `deleted` included. An honest selfdestruct
   followed by a later read of the same account in the same block must *not*
   materialize a twin: `keccak256(addr)` for that account already sits in
   `addr_hashes`, so a twin would trip the clash check below on a perfectly
   honest block. (Reviving a deleted record is a separate, explicit step —
   `revive_if_deleted` — taken only by the mutating accessors.)

   `read_code`, `read_storage` and `has_storage` observe the same way, through
   `observe_account_` — the const-callable half of `find_or_create_account`,
   and the reason `created_accounts_` is declared `mutable`. Their return
   values are unchanged: a `deleted` record yields the same empty code, zero
   slot value and `false` that a missing record used to. Code reads matter here
   in their own right, because the system contracts (EIP-4788, EIP-2935,
   EIP-7002, EIP-7251) reach an account only through its code, so a code read
   may be the only read an account gets.

   `read_account`, `get_balance`, `get_nonce`, `is_deleted` and
   `is_empty_account` deliberately do **not** materialize; they resolve through
   the plain `lookup_account_` and still answer "absent" and "deleted"
   identically. `check_root_new_block` and `state_root_hash` iterate
   `created_accounts_` while calling them, and an insert mid-iteration would
   invalidate the iterator.

   `check_root` then merges the pre-state `addr_hashes` with the created-set
   hashes and rejects on any overlap ("Created and existing hashes clash") —
   inside the merge loop, before it computes or compares a root at all. So a
   routing forgery against an account named by `addr_hashes` is caught even
   when the victim is only ever *read*: the misrouted read materializes an
   overlay record whose `keccak256(addr)` collides with the `addr_hashes`
   entry. Before materialization, only *written* accounts left such a trace.

   `created_accounts_` is routinely non-empty on an honest block. Every
   precompile the EVM touches lands there — `Host::access_account` calls
   `get_or_insert` before its `is_precompile` early-out — as does every
   genuinely new EOA or contract. A populated overlay is therefore never itself
   a rejection signal; the hash clash is the only discriminator.

Together these bind every byte of state the EVM will read to a verified
identity and hash, so a malformed or adversarial witness cannot smuggle in
mismatched accounts, code, or slots and still pass the post-state root check.

Three gaps remain open, and the checks above should not be read as covering
them:

- **Pure omission.** An account whose leaf exists in the real pre-trie but
  which is absent from *both* the addr-map and `addr_hashes`, and which the
  block only reads, is not caught: the materialized `deleted = true` record
  clashes with nothing and emits no trie update. A non-membership probe against
  the witness trie was prototyped and removed — real witnesses carry no
  exclusion-proof nodes for absent-account reads, so there is nothing to prove
  non-membership against.
- **Fabricated accounts.** An account present in the addr-map and `addr_hashes`
  but absent from the real pre-trie is not rejected by a read check. Its
  read-only update reaches a point in the trie that proves its key absent, and
  `calc_root_from_updates` inserts a leaf there rather than failing (§3.1).
- **`check_root_new_block`.** Every block after a bundle's first (§3.1) carries
  no clash guard at all, and decides leaf inclusion via `is_deleted`, which
  resolves through `find()` — so it inherits whatever routing the blob's MPHF
  header dictates.

Both directions of the account-read behaviour are pinned by tests in the
`zilkworm.tests` target, built on the shared harness
`zilk_core/core/state_zz/account_read_test_util.hpp`. The harness assembles a
prestate blob and matching node store, signs real transactions, executes the
block twice — once honestly, once against a forged bundle — reseals the forged
header over the *spoofed* execution's `gas_used`, `receipts_root`,
`logs_bloom` and `state_root`, and captures the guest's stdout so a test can
assert which check fired:

- `account_read_spoof_test.cpp` forges a bundle by transposing two
  `slot_offsets` entries and nothing else, then drives eight reads of the
  victim account through the EVM: `BALANCE`, `EXTCODESIZE`, `EXTCODEHASH`,
  `EXTCODECOPY`, `STATICCALL`, `DELEGATECALL`, a value-bearing `CALL`, and a
  `BALANCE` whose result is discarded. Because the header is resealed over the
  spoofed run, the bundle would verify were it not for the clash check; every
  case asserts the run is rejected on the clash message specifically, with no
  "New Root" line ever emitted. The discarded-result case is the sharpest: the
  forged block is byte-identical to the honest one — same gas, same receipts
  root, same state root — so nothing but the overlay record distinguishes them.
- `account_read_honest_test.cpp` pins the other direction, that the check does
  not over-trigger: an honest read of an address absent from the witness, a
  block whose only overlay entries are touched precompiles, a control case
  where a witness-resident read materializes nothing at all, code and storage
  reads of absent accounts, a selfdestruct followed by a read of the same
  account (which must leave the overlay empty), and a read of an absent address
  followed by a `CREATE2` that revives that record in place.

## Node-store reads

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
compiled only under `USE_HASH_KEY` (CMake option, `-DUSE_HASH_KEY=ON` at configure
time; OFF by default for host, hypercube and qemu builds, ON in the Airbender guest, whose
Makefile, CMake and image default to it): when neither
the prestate map nor the created-accounts overlay holds the address, it walks the
account trie from the parent `state_root` along `keccak(addr)` to recover an
account whose preimage was missing from the addr-map. An empty child or a
diverging path is a valid absence (the caller materializes an absent record); a
missing or malformed node halts execution. `recover_slot_from_nodestore` does the
same for a slot, from the account's storage root (the empty root once the block has
wiped its storage). Neither runs past block 0: the node store holds the tries of the
parent state only, so `check_root` ends recovery. Later blocks run on the records the
guest holds (the witness's, and those block 0 created or recovered), which it has
checked rebuild to block 0's state root (`state_root_hash()`), and
`check_root_new_block` rebuilds their roots from the same records. Nor is an address the witness carries a record of (its hash
in `addr_hashes`) recovered: only a forged addr-map lookup misses one, and the
created/existing clash in `check_root` rejects that, as without the option.
`witness_hide_node_test.cpp` documents the gap this guards against.

`check_root` (block 0 of a bundle) and `check_root_new_block` (subsequent
blocks) in `state_transition.cpp` drive the recomputes (§3.1). The only
"updates" to anything node-related are in-memory mutations of each `Account`'s
`acc_rlp_buf` / `acc_rlp_len` / `acc_rlp_sroot_off` cache after a successful root
check, so the next block's `HashBuilder`-based path can reuse them. The
`node_store` bytes themselves are never written through.

## MFBD run

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

### Why block 0 and blocks 1+ check the root differently

The two root-check strategies are not arbitrary; they reflect what state is
available at each point.

**Block 0 — full recompute via GridMPT (`check_root`).** The first block of a
bundle has no prior cached leaf RLPs to lean on, so it rebuilds the account
trie and every touched storage trie *from scratch* out of the witness
`node_store`. The flow:

1. Merge the pre-state `addr_hashes` with any newly created accounts into one
   sorted-by-`addr_hash` sequence, rejecting outright — before any root is
   computed — if the two sets intersect ("Created and existing hashes clash").
   This is the disjointness check that backstops MPHF routing (§2.3.2, check 4).
2. For each account, walk its pre-state and newly created slots, caching
   `keccak256(slot_key)` and encoding initial/current values, then drive
   `GridMPT<true>` to recompute that account's storage root over the witness
   nodes (`reset(storage_root)` → `calc_root_from_updates()`).
3. Re-encode each account leaf (`addr_hash` + account RLP, now carrying the new
   storage root) into `acc_updates`. Read-only pre-state accounts
   (`modified == false`) contribute a check node instead: `initial` set to the
   cached leaf RLP, `current` left empty.
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

An update with empty `current` is a **read check**. When its path resolves to a
leaf, `calc_root_from_updates` requires that leaf's value to equal `initial`
("Pre value mismatch in existing leaf") and then stops without inserting
anything, which binds the pre-state bytes the EVM read to the trie the parent
header committed to. It does not bind *existence*: if the path instead reaches a
point that proves the key absent — the empty-trie seed, a branch's nil child, an
extension divergence, a leaf divergence — the update inserts a leaf there rather
than failing, which is the fabricated-account gap listed in §2.3.2. Deletions
(`current = {0x80}`) and genuine inserts (non-empty `current`) follow their own
paths. All of this lives in the shared `GridMPT` template body, so it applies
identically to the account layer and every touched storage trie.

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
block 0's recompute. It also performs **no read checks and no clash guard**: the
leaf rebuild trusts every cached leaf, and it never compares the created set
against `addr_hashes`. Both guarantees therefore hold only for a bundle's first
root check (§2.3.2 lists this as an open gap).

| Aspect | Block 0 | Blocks 1+ |
|---|---|---|
| Engine | `GridMPT` full recompute | `HashBuilder` incremental rebuild |
| Storage tries | recomputed via witness `node_store` | reused via cached `acc_rlp_buf` |
| Account trie | `GridMPT` unfold/fold from prev `state_root` | `HashBuilder.add_leaf()` from leaves |
| Node-store use | heavy (storage + account layers) | none |
| Read / clash checks | pre-value check on read-only leaves; created vs existing hash clash rejected | none |
| Relative cost | slower (full witness walk) | faster (leaf hash only) |
