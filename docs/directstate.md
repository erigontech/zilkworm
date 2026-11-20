# DirectState

**Backend: DirectState.** The default state backend (`Z6M_HASH_STATE` off). It reads an MFBD flat
witness bundle in place, with no decode pass, and validates the bundle's blocks against the parent
state root. This document covers what the backend checks and how it accepts a block. The byte
layout of the bundle is in [flat_witness_bundle.md](flat_witness_bundle.md), the normative format
spec in [mfbd_design_specs.md](mfbd_design_specs.md), fixtures and corpora in
[mfbd_fixture_generation.md](mfbd_fixture_generation.md). The other backend is
[hashstate.md](hashstate.md).

| Piece | File |
|---|---|
| Backend selection (`ActiveState`) | `zilk_core/core/state_zz/active_state.hpp` |
| `DirectState`, `DirectStateView`, `sanitize`, layout validation | `zilk_core/core/state_zz/direct_state.{hpp,cpp}` |
| Bundle load (`load_flat_bundle`) | `zilk_core/core/types_zz/flat_bundle.{hpp,cpp}` |
| `run_mfbd`, `run_one_bundle`, `check_root`, `check_root_new_block` | `zilk_core/dev/state_transition.{hpp,cpp}` |
| Trie recompute (`GridMPT`) | `zilk_core/core/trie_zz/` |
| Guests | `prover/guest_hypercube/` (`make z6m_guest`), `prover/guest_airbender/` (`make z6m_guest_airbender`) |

## MFBD run

`StateTransition::run()` sends an input that starts with the `MFBD` magic to `run_mfbd()`
(the dispatch table is in [architecture.md](architecture.md#input-format-and-dispatch)).

`run_mfbd()` validates the 16-byte header, reads `n_bundles`, and walks the envelope at 8-byte
alignment. For each bundle it calls `::zilkworm::load_flat_bundle(tail)`, which validates the FBND
magic and version, RLP-decodes `genesis`, `blocks` (the `<u64 N>` header plus N 8-aligned payloads)
and `ancestors`, and constructs the bundle's `DirectState` over the prestate and node-store byte
windows. It then passes the loaded bundle to `run_one_bundle(*fb)` and advances the cursor by
`align8(cursor + fb->blob.size())`.

`run_one_bundle(::zilkworm::FlatBundle& bundle)`:

1. `bundle.direct.sanitize()`: identity-to-hash verification of every account, code and node
   ([below](#sanitize-the-threat-model)). A failure returns `{0, false}`.
2. `bundle.direct.insert_header(h)` for each ancestor header, so `BLOCKHASH` resolves.
3. Resolves `bundle.network` against `silkworm::test::kNetworkConfig` and constructs
   `Blockchain{bundle.direct, cfg, bundle.genesis}`. Sets
   `bundle.direct.set_multi_block(block_rlps.size() > 1)` so the per-block journal arms for
   incremental validation.
4. For each block of the bundle:
   - `blockchain.insert_block(block, /*check_state_root=*/false)`; any result other than `kOk`
     returns `{0, false}`.
   - The first block that reaches the root check goes to `check_root(...)`, every later one to
     `check_root_new_block(...)` (a `first_root_check` flag, flipped after the first non-skipped
     block). Both compare the recomputed root with `header.state_root`; see
     [Root check](#root-check).
   - `bundle.direct.insert_header(block.header)`, so the next block's `BLOCKHASH` resolves.
   - `cumulative_gas += block.header.gas_used`.

The run returns the cumulative gas across all bundles, or `0` on any failure.

## `sanitize()`: the threat model

The witness is untrusted: it is synthesised from a `debug_executionWitness` response and could be
truncated, reordered or crafted. `sanitize()` (`direct_state.cpp`) runs once per bundle, before any
block executes. The checks, in the order they run:

1. **Identity-to-hash binding.** `sanitize()` sweeps the code store
   (`keccak256(code) == code_hash` for every body) and the node store
   (`keccak256(node_rlp) == node_hash` for every body), then binds every account's identity to its
   hash in the coverage sweep below (`keccak256(addr) == addr_hash`). The trie fold proves that a
   value lives under a hashed key; it cannot prove that the hash belongs to the claimed identity.
   Without this binding a witness could hand the EVM the storage of address A as that of address B.
   Storage slot keys are hashed and bound on the read path inside `check_root`, not here.

2. **`addr_hashes` one-to-one coverage.** The `addr_hashes` array must be strictly increasing by
   `keccak256(addr)` (the comparison rejects `memcmp(prev, cur) >= 0`), and every entry's
   `entry_offset` must resolve to an `Account` whose 20-byte address matches, with
   `keccak256(addr) == addr_hash` re-checked per entry. "Exactly once" rides on the `modified`
   scratch flag: a first body walk stamps `modified = true` on every prestate account, the sweep
   clears it per named entry, and a second body walk rejects if any account is still `modified`.
   This proves the bijection between `addr_hashes` and the walked bodies. It does not constrain
   the account read path, `find(addr)`; that is check 4.

3. **Per-account slot extent.** Enforced at `DirectState` construction (`validate_prestate_layout`
   / `validate_or_abort`), before `sanitize()`. `validate_mphf<20>` first places every addr-map
   entry's `[len:u64][body]` inside `data[]` with `body_len >= 20`
   ([MphfMap validation](flat_witness_bundle.md#24-mphfmap-the-minimal-perfect-hash-map)), and
   `validate_prestate_layout`'s `check_entry` then requires
   `sizeof(Account) + slot_count * sizeof(Slot) <= body_len`. A forged `slot_count` cannot steer
   reads out of bounds or into a neighbouring entry.

4. **MPHF routing.** Enforced at root-check time, inside `check_root`. Checks 1 and 2 do not
   constrain where `find(addr)` lands: a forged `MphfMapHeader` (for example a transposed
   `slot_offsets[]`) can make `find(addr)` miss an account that the body walk and `addr_hashes`
   both cover. The defence is that an account read never returns "nothing"
   ([next section](#account-reads-never-return-nothing)), and `check_root` merges the pre-state
   `addr_hashes` with the created-set hashes and rejects any overlap ("Created and existing hashes
   clash") inside the merge loop, before it computes a root. A misrouted read of an account named
   by `addr_hashes` materializes an overlay record whose `keccak256(addr)` collides with that
   entry, so the forgery is caught even when the victim is only read.

Together these bind every byte of state the EVM reads to a verified identity and hash.

### Account reads never return nothing

`DirectState::find_or_create_account(addr)` is the single creation-capable lookup: the MPHF blob
map first, then the `created_accounts_` overlay, and on a total miss it materializes a record in
`created_accounts_` with `deleted = true` (`materialize_absent_account_`, the cold path). "Account
does not exist" is a data property (`deleted`) of an always-present record, not a null pointer.
`DirectStateView::get_account` (the evmone `StateView` boundary) routes through it and returns
`std::nullopt` only when the record says `deleted`, so EVM-visible semantics are unchanged.

- **Total miss only.** If either lookup finds a record, that record is returned as it stands,
  `deleted` included. A selfdestruct followed by a read of the same account in the same block must
  not materialize a twin: its `keccak256(addr)` already sits in `addr_hashes`, and a twin would
  trip the clash check on an honest block. Reviving a deleted record is a separate step
  (`revive_if_deleted`), taken only by the mutating accessors.
- **`read_code`, `read_storage` and `has_storage`** observe through `observe_account_`, the
  const-callable half of `find_or_create_account` (the reason `created_accounts_` is `mutable`). A
  `deleted` record yields empty code, a zero slot and `false`. Code reads count: the system
  contracts (EIP-4788, EIP-2935, EIP-7002, EIP-7251) reach an account only through its code.
- **`read_account`, `get_balance`, `get_nonce`, `is_deleted` and `is_empty_account`** do not
  materialize; they resolve through `lookup_account_`. `check_root_new_block` and
  `state_root_hash` iterate `created_accounts_` while calling them, and an insert mid-iteration
  would invalidate the iterator.
- **A populated overlay is not a rejection signal.** Every precompile the EVM touches lands in
  `created_accounts_` (`Host::access_account` calls `get_or_insert` before its `is_precompile`
  early-out), as does every new EOA or contract. The hash clash is the only discriminator.

### Open gaps

The checks above do not cover these:

- **Pure omission.** An account whose leaf exists in the real pre-trie, which is absent from both
  the addr-map and `addr_hashes`, and which the block only reads: the materialized
  `deleted = true` record clashes with nothing and emits no trie update. Witnesses carry no
  exclusion-proof nodes for absent-account reads, so there is nothing to prove non-membership
  against.
- **Fabricated accounts.** An account present in the addr-map and `addr_hashes` but absent from
  the real pre-trie is not rejected by a read check. Its read-only update reaches a point in the
  trie that proves its key absent, and `calc_root_from_updates` inserts a leaf there instead of
  failing ([read checks](#block-0-full-recompute-check_root)).
- **`check_root_new_block`.** Every block after a bundle's first carries no clash guard, and
  decides leaf inclusion through `is_deleted`, which resolves through `find()`, so it inherits
  whatever routing the blob's MPHF header dictates.

### Tests

Both directions of the account-read behaviour are covered in the `zilkworm.tests` target, on the
shared harness `zilk_core/core/state_zz/account_read_test_util.hpp`, which executes a block
honestly and against a forged bundle whose header is resealed over the spoofed execution:
`account_read_spoof_test.cpp` (a transposed `slot_offsets` pair must be rejected on the clash
message for every kind of account read) and `account_read_honest_test.cpp` (honest reads of absent
accounts, precompiles and selfdestructed accounts must not trigger it). `witness_hide_node_test.cpp`
documents the gap [node-store recovery](#node-store-recovery-use_hash_key) guards against.

## The witness buffer is written in place

The pre-state and node-store spans are mutable (`std::span<uint8_t>`) from the `DirectState`
constructor down through `MphfMap`: `MphfMap::data()` returns `uint8_t*` and `MphfMap::find()`
returns `std::optional<std::span<uint8_t>>`.

`sanitize()` and the EVM write scratch fields inside each `Account` where it lies: `deleted`,
`modified`, `code_store_offset` / `code_store_len`, and the cached leaf RLP (`acc_rlp_buf` /
`acc_rlp_len` / `acc_rlp_sroot_off`). `sanitize()` sets `deleted = false`, stamps `modified` and
calls `rlp_into_cache(...)` on each account; the root check re-stamps `acc_rlp_buf` after the
storage root changes. The node store is never written through.

## Root check

The first block of a bundle and the blocks after it check the state root differently.

| Aspect | Block 0 (`check_root`) | Blocks 1+ (`check_root_new_block`) |
|---|---|---|
| Engine | `GridMPT` full recompute | `HashBuilder` leaf rebuild |
| Storage tries | recomputed from the witness `node_store` | reused through the cached `acc_rlp_buf` |
| Account trie | `GridMPT` unfold/fold from the previous `state_root` | `HashBuilder::add_leaf` from leaves |
| Node-store use | storage and account layers | none |
| Read and clash checks | pre-value check on read-only leaves; created vs existing hash clash rejected | none |

### Block 0: full recompute (`check_root`)

The first block has no cached leaf RLPs, so it rebuilds the account trie and every touched storage
trie from the witness `node_store`:

1. Merge the pre-state `addr_hashes` with the newly created accounts into one sequence sorted by
   `addr_hash`, rejecting before any root is computed if the two sets intersect (check 4 above).
2. For each account, walk its pre-state and newly created slots, caching `keccak256(slot_key)` and
   encoding initial and current values, then drive `GridMPT<true>` to recompute that account's
   storage root over the witness nodes (`reset(storage_root)`, then `calc_root_from_updates()`).
3. Re-encode each account leaf (`addr_hash` plus the account RLP with its new storage root) into
   `acc_updates`. A read-only pre-state account (`modified == false`) contributes a check node
   instead: `initial` set to the cached leaf RLP, `current` left empty.
4. Drive `mpt::GridMPT<true> acc_trie(direct_state, prev_root)` over the account trie, seeded from
   the previous block's `state_root` (unfolded out of the keccak-verified `node_store` by
   `init_from_root`), with the account updates layered on top.
5. Compare the new root with `header.state_root`.

This is the trust anchor: it starts from a `state_root` the parent header committed to and rebuilds
forward using only nodes whose `keccak256(node_rlp)` `sanitize()` verified.

**Read checks.** An update with empty `current` is a read check. When its path resolves to a leaf,
`calc_root_from_updates` requires that leaf's value to equal `initial` ("Pre value mismatch in
existing leaf") and stops without inserting, which binds the pre-state bytes the EVM read to the
trie the parent header committed to. It does not bind existence: if the path reaches a point that
proves the key absent (the empty-trie seed, a branch's nil child, an extension or leaf divergence),
the update inserts a leaf there instead of failing. That is the fabricated-account gap above.
Deletions (`current = {0x80}`) and inserts (non-empty `current`) follow their own paths. The logic
is in the shared `GridMPT` template body, so it applies to the account layer and to every touched
storage trie.

### Blocks 1+: leaf rebuild (`check_root_new_block`)

After block 0 every account carries a cached leaf RLP (`acc_rlp_buf`) that the previous root check
stamped in place:

1. For each account the EVM changed this block, re-encode its leaf with the new storage root
   (`rlp_into_cache(storage_root)` updates `acc_rlp_buf` / `acc_rlp_len` / `acc_rlp_sroot_off`).
2. Collect the leaves (`addr_hash` plus RLP) of pre-state and created accounts, skipping deleted
   and empty accounts, and sort by `addr_hash`.
3. Feed them to `silkworm::trie::HashBuilder` (`add_leaf` per leaf, `root_hash()` at the end), a
   leaf-to-root fold that touches neither the `node_store` nor `GridMPT`.
4. Compare with `header.state_root`.

It performs no read checks and no clash guard: the leaf rebuild trusts every cached leaf and never
compares the created set with `addr_hashes`. Both guarantees hold only for a bundle's first root
check (an [open gap](#open-gaps)).

## Node-store reads

`DirectState::find_node_rlp(node_hash)` looks a node's RLP up in the bundle's
[`node_store`](flat_witness_bundle.md#26-node_store--read-only-mpt-proof-nodes-a-peer-section).
Its three call sites are in the shared `GridMPT<DeletionEnabled>` template body, so they serve
both the storage-trie and the account-trie instantiations, and are reached only during block 0's
recompute:

- **`GridMPT::unfold_slot`** (`zilk_core/core/trie_zz/fold_unfold.hpp`): when unfolding a node
  whose child is a 32-byte hash reference instead of an embedded RLP.
- **`GridMPT::init_from_root`** (`zilk_core/core/trie_zz/grid_mpt.cpp`): fetches the previous
  block's `state_root` node to seed the trie. The `GridMPT` constructor calls it.
- **`GridMPT::calc_root_from_updates`** (`grid_mpt.cpp`): in the extension-node full-match branch,
  when the extension's child is a hash reference (`child_len >= 32`).

Two nodes whose first 8 hash bytes collide are told apart by the full 32-byte compare inside
`MphfMap::find`.

### Node-store recovery (`USE_HASH_KEY`)

`DirectState::recover_account_from_nodestore` is compiled only under the CMake option
`USE_HASH_KEY` (OFF by default for host, hypercube and QEMU builds; ON in the Airbender guest,
whose Makefile, CMake and image default to it). When neither the prestate map nor the
created-accounts overlay holds an address, it walks the account trie from the parent `state_root`
along `keccak(addr)` to recover an account whose preimage was missing from the addr-map. An empty
child or a diverging path is a valid absence (the caller materializes an absent record); a missing
or malformed node halts execution. `recover_slot_from_nodestore` does the same for a slot, from the
account's storage root (the empty root once the block has wiped its storage).

- Neither runs past block 0: the node store holds the tries of the parent state only, so
  `check_root` ends recovery. Later blocks run on the records the guest holds (the witness's, and
  those block 0 created or recovered), which it has checked rebuild to block 0's state root
  (`state_root_hash()`); `check_root_new_block` rebuilds their roots from the same records.
- An address the witness carries a record of (its hash in `addr_hashes`) is not recovered: only a
  forged addr-map lookup misses one, and the clash in `check_root` rejects that.

The witness gap that motivates the option is described in
[airbender-docker-service.md](airbender-docker-service.md#known-limitations).
