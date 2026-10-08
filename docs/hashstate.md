# HashState

HashState is a second read-side state backend. It takes a block's
`statelessInputBytes` witness directly and works out every trie path from the
previous state root at the moment of each read, so every read is checked against
the root it claims to come from. DirectState, the default backend, reads a flat
witness bundle (MFBD) instead; see [flat_witness_bundle.md](flat_witness_bundle.md).

The backend is chosen at compile time with the `Z6M_HASH_STATE` CMake option,
OFF by default. With the flag off DirectState stays the backend and the build
behaves as before.

| Piece | File |
| --- | --- |
| Backend selection | `zilk_core/core/state_zz/active_state.hpp` |
| HashState and its per-transaction view | `zilk_core/core/state_zz/hash_state.{hpp,cpp}` |
| Open-addressed key-to-offset index | `zilk_core/core/common_zz/hash_index.hpp` |
| `statelessInputBytes` parser | `zilk_core/core/state_zz/slib_input.{hpp,cpp}` |
| Accept check (post-state root) | `zilk_core/dev/check_root_hashstate.hpp` |
| Blockchain-test runner arm | `zilk_core/dev/blockchain_test_runner.cpp` |
| Tests | `zilk_core/dev/cli/hash_state_test.cpp`, `zilk_core/dev/cli/hash_index_test.cpp` |

Corpus results and how the witness-validation negatives are scored are in
[slib_corpus_validation.md](slib_corpus_validation.md); SP1 cycle numbers are in
[slib_benchmark.md](slib_benchmark.md).

## Backend selection

`zilk_core/core/state_zz/active_state.hpp` chooses the read-side state backend at
compile time. The trie fold and the transaction-level EVM view both read state through
the aliases defined here.

| Build | `ActiveState` | `ActiveStateView` |
|---|---|---|
| `Z6M_HASH_STATE` undefined (default) | `DirectState` | `DirectStateView` |
| `Z6M_HASH_STATE` defined | `HashState` (the SSZ/slib input path) | `HashStateView` |

The default build is behaviour-identical to a DirectState-only build.

The choice is a plain type alias. There is no runtime polymorphism: `GridMPT` takes the
backend as a defaulted template parameter (`StateT` in `mpt.hpp`), so each build is fully
monomorphic and every `find_node_rlp` call into the backend stays inlined.

The header holds only forward declarations of `DirectState` and `HashState`. They are
defined in `direct_state.hpp` and `hash_state.hpp`, but neither the alias nor `GridMPT`'s
default template argument needs a complete type. Keeping the header this light is
deliberate: it stops the heavy `direct_state.hpp` / `hash_state.hpp` headers from being
pulled into every trie translation unit.

### Per-transaction state view

`ActiveStateView` is the evmone per-transaction read view over the active backend. It is
selected the same way as `ActiveState`: `DirectStateView` by default, `HashStateView`
under `Z6M_HASH_STATE`.

- Its only consumer is `ExecutionProcessor`, which constructs one view per transaction
  and one per system-call round. The processor constructs `ActiveStateView` over its
  `ActiveState&`, so switching the backend needs no other change there.
- It lives beside `ActiveState` rather than in `processor.hpp` so that all backend
  selection is in one place.
- A forward declaration is enough for the alias. Any translation unit that actually
  constructs the view already includes the defining header (`direct_state.hpp` or
  `hash_state.hpp`) for the complete type, so this alias adds no dependency, just like
  `ActiveState`.

### Pre-value check trait

`state_keeps_prevalue_check<S>` says whether the trie fold keeps the pre-value /
read-only check for backend `S`.

- `DirectState`, and any backend without a specialisation: `true`. The DirectState
  update set carries `initial_value` and read-only entries, and `calc_root_from_updates`
  binds the pre-value and short-circuits read-only keys.
- `HashState`: specialised to `false` in `hash_state.hpp`. Its update set carries no
  `initial_value` and no read-only entries, because reads are already bound to
  `prev_root` when the update set is derived. The check must therefore be compiled out of
  the fold.

The trait is a small variable template in `active_state.hpp` whose primary template
defaults to `true`. This way `mpt.hpp` and `grid_mpt.cpp` can decide the question without
a hard dependency on `hash_state.hpp` (or on `direct_state.hpp`), and a DirectState build
never has to see `HashState` to make the decision.

## HashState

`HashState` (`zilk_core/core/state_zz/hash_state.hpp`, `hash_state.cpp`) is the
state substrate for the SSZ input path, parallel to `DirectState`. It builds its
node and code stores in-guest from the witness, derives the pre-state accounts
and storage slots by walking the trie from the parent state root (`prev_root`),
layers the block's writes over that pre-state, and records every read it cannot
authenticate so the accept gate can reject the block.

### Node and code stores

`HashState` owns the two content stores that `DirectState` reads through a
serialized `MphfMap`. `HashState` builds them in-guest and indexes them with the
plain open-addressed `HashIndex<32, &hash_key8, StoredBytes>`, so there is no displacement
or collision sidecar to serialize ahead of time.

| Store      | Key               | Value             | Lookup          |
|------------|-------------------|-------------------|-----------------|
| node store | `keccak256(node)` | node RLP          | `find_node_rlp` |
| code store | `keccak256(code)` | contract bytecode | `find_code`     |

The index maps each content hash straight to a view of the bytes (`StoredBytes`, a pointer
and a `u32` length), so a hit is one probe with no length decode and no arena indirection.
The bytes are not copied on the input path:

- `add_node_borrowed` and `add_code_borrowed` keep a view of the caller's bytes.
  `parse_stateless_input` feeds the decoded `statelessInputBytes` blob through them, so the
  stores point into that blob. The blob must outlive every use of the `HashState`; it already
  had to, since the retained `StatelessInputView` points into it too.
- `add_node` and `add_code` copy the bytes into `owned_bytes_` (a `std::deque<Bytes>`, whose
  elements never move) and index a view of the copy. Tests use these for temporaries.
- Because the stores hold views, `HashState` is not copyable.
- A stored view's pointer is never null (an empty input points at a static byte), so it can
  never equal the index's empty sentinel, the value-initialized `{nullptr, 0}`.

The stores bind content to identity. `add_node` and `add_code` compute the real
keccak256 of the bytes at add time and use it as the index key, and `HashIndex`
confirms every probed bucket with a full-key `memcmp`. A forged lookup hash can
therefore never surface the wrong entry.

### Building state from the trie

`build_state_from_trie(prev_root)` fills the account cache and the storage
cache in one standalone derivation. It is a depth-first, left-to-right sweep
through the node store:

1. Push the root.
2. Unfold the leftmost child down to a leaf, and emit that leaf.
3. Fold back to the nearest parent that still has an unvisited child.
4. Repeat until the stack drains.

The sweep uses an explicit stack, not recursion, which keeps it safe on rv64im.
It borrows GridMPT's unfold/fold terms but is read-only and insert-only, so it
has none of GridMPT's delete, cascade or modified-flag machinery. It reuses the
shared node types (`mpt.hpp`) and the free RLP decoders (`decode_node`,
`rlp::decode_header`), and never calls a GridMPT method.

The traversal lives in one private helper, `sweep(root, emit_leaf)`, and both
kinds of pass run through it:

- The account pass runs `sweep(prev_root, <emit account>)`. Each leaf's decoded
  account goes into the account cache.
- Then, for every derived account whose `storage_root != kEmptyRoot`, a sibling
  storage pass runs `sweep(storage_root, <emit slot for that account>)`. Each
  `(slot_hash -> word)` goes into the storage cache.

At each leaf, `sweep` calls `emit_leaf(path, leaf_value)`, with the path packed
into a `bytes32` and the leaf value as a `ByteView`. The caller's emit decides
how to decode and cache the leaf (account or slot); the traversal is the same
for both. A hash-ref child whose node is absent is a pruned boundary: `sweep`
stops that descent without bumping `missing_count_`. `sweep` returns `false`
only when `root` itself is absent from the node store, and `true` when the
sweep ran; the caller decides whether an absent root is fail-closed (see
[Fail-closed policy](#fail-closed-policy)). `sweep` is defined in the .cpp and
instantiated only there, from the two emit lambdas in `build_state_from_trie`.

The empty trie (`prev_root == kEmptyRoot`) derives nothing and returns `kOk`.
`build_state_from_trie` also stores `prev_root` in `prev_root_`, so a later read
miss can start a single-path confirmation walk (`confirm_absent`) down the
account trie.

### Account and storage caches

The sweep only ever sees trie paths, never their preimages, so both caches are
keyed by hashes.

`get_account(addr_hash)` looks up the account cache by the 32-byte trie path,
`addr_hash == keccak256(addr)`. A hit returns a pointer to the derived `Account`
POD in the arena; a miss returns `nullptr`, meaning a blank or non-existent
account. This is the same pointer-or-null shape as `DirectState::read_account`.

- The pointer stays valid only until the next emit grows the arena. The
  intended usage is one `build_state_from_trie` run followed by reads.
- `Account::addr` is left zero. The build never sees the 20-byte address, only
  its hash (the trie path), and the cache is keyed by that hash.

`get_storage(addr_hash, slot_hash)` is the hash-space analog of
`DirectState::read_storage(addr, key)`. `DirectState` keys the preimages
(address, slot key); the derive sweep only sees their trie paths, so `HashState`
keys the hashes instead:

- `addr_hash == keccak256(addr)`, the account trie path, which is also the key
  `get_account` uses;
- `slot_hash == keccak256(slot key)`, the storage trie path.

The return shape matches `read_storage` exactly: the 32-byte word on a hit, an
all-zero `bytes32` on a miss. Zero is unambiguous as "absent" because the
storage trie never carries a zero-valued leaf (`DirectState::account_storage_root`
drops zero values).

A miss in either cache is not taken at face value; see
[Read-miss confirmation](#read-miss-confirmation).

### Fail-closed policy

`build_state_from_trie` returns a `BuildStatus`:

- `kOk`: the sweep ran, and every node it needed was either present or a
  legitimate pruned boundary, that is, a bare hash ref into an untouched
  subtree that a real EIP-8025 partial witness omits.
- `kMissingNode`: the seeding account root itself was absent. This is failure
  class B2 in `docs/mfbd_design_specs.md` (a missing node read as an empty
  subtree), and it is the one gap that is never a legitimate omission. The
  build still emits whatever it can reach, but it records the gap in
  `missing_count_` so the accept gate can hard-reject it. The failure is
  closed, never silent.

The policy is asymmetric on purpose. It is enforced at the two call sites in
`build_state_from_trie`, not inside `sweep`:

- An absent account root is a missing node, because the account root is the
  anchor of everything. It increments `missing_count_`.
- An absent storage root is not. A witness legitimately omits the storage trie
  of an account the block never touches, so a storage pass whose `sweep`
  returns `false` is skipped, not counted.
- A hash-ref child whose node is absent, reached while walking an included trie
  (account or storage), is a pruned boundary. A real `StatelessInputBytes`
  witness carries only the state the block touches and prunes every untouched
  subtree to a bare 32-byte hash ref, so an absent child is exactly that
  boundary, not an incomplete witness. `sweep` does not descend into it, does
  not bump `missing_count_`, and keeps sweeping the branch's other children.
  An extension whose hash-ref child is absent is handled the same way. The
  build therefore materializes exactly the touched leaves that the witness
  includes.

As a result, `missing_count_` (exposed as `missing_count()`) flags only a broken
account root, never a pruned subtree, and that still holds after the storage
passes.

Completeness for the pruned parts is enforced later:

- At read time, `confirm_absent` turns a read that needs a pruned node into an
  unconfirmed read (`unconfirmed_read_count_`); see
  [Read-miss confirmation](#read-miss-confirmation).
- At fold time, a write over a pruned boundary recomputes a root that does not
  match.

The accept gate in `zilk_core/dev/check_root_hashstate.hpp` accepts only when
`missing_count() == 0 && unconfirmed_read_count() == 0`.

### Read-miss confirmation

A cache miss is not trusted blindly. The build sweep collected only the keys
actually present in the trie, so a missed key is either genuinely empty or
wrongly left out of the witness. The read-miss handlers tell the two apart with
a single-path confirmation walk, `confirm_absent`, and bump
`unconfirmed_read_count_` when they cannot prove the key empty.

- `get_account` miss: `note_account_miss_` runs `confirm_absent` from
  `prev_root_` down the account trie. Proving emptiness records nothing; an
  unprovable gap records an unconfirmed read.
- `get_storage` miss: `note_storage_miss_` first consults the account cache. If
  the account is absent, or its `storage_root` is the empty-trie root, the slot
  is zero and no walk is needed. Otherwise it runs `confirm_absent` against the
  account's `storage_root`, which either proves the slot empty (nothing is
  recorded) or hits a needed node that is absent (an unconfirmed read is
  recorded). This also catches a storage root that the build legitimately
  skipped because its node was never added: `find_node_rlp` misses inside
  `confirm_absent`, so the read is recorded rather than passed off as a silent
  zero.

Either way the read still returns its blank value (`nullptr` for an account,
zero for a slot), so a value-returning caller proceeds. The accept gate rejects
later if and only if the unconfirmed count is non-zero. The failure is closed,
never a silent wrong-empty.

`find_or_create_account`, the first write to an address, is the third kind of
miss, and it is not walked at read time. A total miss (neither the overlay nor
the built cache has the address) materializes a fresh, deleted overlay record,
as `DirectState::materialize_absent_account_` does, and the claim that the
pre-state trie has no leaf for the address goes into the block's write set at
accept time instead: the gather marks the account `absent`
(`HashStateAccountWrite::absent`), and the fold checks the claim on the walk
that recomputes the root (see [Accept check](#accept-check)). A read that never
writes the address leaves the record deleted and emits a read-only claim, which
inserts nothing; a write that creates the account carries the claim with its
leaf. This is the protocol `check_root` uses for the reads of absent accounts
and slots over `DirectState`, applied to the one HashState miss that reaches
the overlay. The reads that do not (`get_account`, `get_storage`) keep the
confirmation walk above.

The handlers are defined in the .cpp, so the hot lookups in the header stay
small and the confirm and counter logic sits next to `sweep`. They are `const`,
and `unconfirmed_read_count_` is `mutable`: a read never mutates the caches,
only this diagnostic.

`confirm_absent(root, target_hash)` is a single-path descent through the node
store, starting at `root`, toward `target_hash`, a 32-byte trie path (an
`addr_hash` for the account trie, or a `slot_hash` for a storage trie). It
returns `true` only when it proves `target_hash` absent below `root`, and
`false` when it cannot. It uses the same decoders as the sweep
(`rlp::decode_header` to strip the outer list header, then `decode_node` from
`rlp_sw.hpp` for the branch / extension / leaf split), so a read confirmation
reads trie bytes exactly the way the build did.

It proves absence (returns `true`) in these cases, mirroring the sweep's own
node handling:

- At a branch, the child slot for the target's next nibble is the empty marker
  `0x80` (`decode_node` reports it as `child_len == 0`), so nothing hangs below
  that nibble.
- At an extension or leaf, the node's own path nibbles diverge from the target:
  a nibble mismatch, or a path that outlasts the target. The target cannot lie
  below this node.
- The trie is empty (`root == kEmptyRoot`), which proves every key absent.

It cannot prove absence (returns `false`) when:

- A node the walk needs (the seeding root or a hash-referenced child) is missing
  from the store, or a node on the path is malformed or undecodable. Emptiness
  is then unknown and must not be guessed.
- A leaf's path matches the target exactly. The key is then actually present,
  not absent.

### Block headers and BLOCKHASH

`HashState` implements the block-header side of the state interface: the three
`silkworm::BlockState` virtuals (`read_header`, `read_body`,
`total_difficulty`) plus a header and BLOCKHASH store (`insert_header`,
`get_block_hash`). These mirror `DirectState` with identical signatures, so
retyping the execution surface from `DirectState&` to `ActiveState&` (which is
`HashState` under `-DZ6M_HASH_STATE`) is a drop-in.

`HashState` holds the witness ancestor headers here. They come from the parsed
witness headers (`StatelessInputView::headers`, `slib_input.hpp`) plus the
genesis header: the runner (`zilk_core/dev/blockchain_test_runner.cpp`) decodes the
witness headers and calls `insert_header` for each one, and the `Blockchain`
constructor inserts the genesis header.

`get_block_hash` fails closed on a miss. evmone calls `get_block_hash` only for
an in-range ancestor: the `blockhash` instruction (evmone
`lib/evmone/instructions.hpp`) clamps `n` to `[max(N-256, 0), N-1]` and returns
zero itself for anything out of range, without calling the host. The real chain
always has the hash of an in-range ancestor. A miss therefore means the witness
omitted a required ancestor header (or the runner's ancestor-contiguity gate
rejected it), so the BLOCKHASH value is not authenticated by the header chain.

Returning a silent zero here would be unsound. In the missing-oldest-ancestor
attack, the block persists `BLOCKHASH(k)` for an omitted header `k` (for example
with `SSTORE(slot, BLOCKHASH(k))`). Execution stores the wrong value, the
attacker sets `header.state_root` to the resulting root, and the accept gate
passes: the root matches, and both completeness counters are zero because a
header or BLOCKHASH miss touches no state.

So a miss is recorded as an unconfirmed read, through the same fail-closed
channel that `get_account` and `get_storage` misses use
(`unconfirmed_read_count_`, which is `mutable` and reset by each
`build_state_from_trie`). The accept gate
(`missing_count() == 0 && unconfirmed_read_count() == 0`) then rejects the
block. `get_block_hash` still returns zero so the value-returning EVM caller
proceeds; the rejection is decided at accept time.

### Write overlay

`HashState` is a full `ActiveState` write backend. The built account and
storage caches stay pristine: they are the pre-state, the "before" side. Every
write lands in a copy-on-write overlay, and every read consults the overlay
first and the built cache second, so a written value shadows the built one.

The overlay containers are `created_accounts_`, `overflow_slots_` and
`created_code_`. They reuse `DirectState`'s container types verbatim, so the
`DirectState` to `ActiveState` retype is a drop-in.

The mutator bodies mirror `DirectState`'s line for line, except for two
deliberate divergences, each documented at its implementation site in
`hash_state.cpp`:

- **(a) Zero storage writes are retained.** `set_storage_slot` keeps a zero
  write in the overlay, where `DirectState::set_storage_slot` erases it, so the
  fold can emit it as an `0x80` delete. The `HashState` fold is incremental
  over `prev_root` and needs the explicit delete, whereas `DirectState`
  recomputes each storage root from its live slots.
- **(b) Storage wipes are a flag.** `apply_code_diff`, `destruct` and revive
  (`revive_if_deleted`) set a per-account `storage_wiped_` flag instead of
  doing `DirectState`'s in-place wipe of inline slots. The built cache is
  immutable, so there is nothing to wipe in place. A wiped account reads all
  pre-state slots as zero, and its storage fold seeds from `kEmptyRoot`.

Because zero writes are retained, the write gather (in
`zilk_core/dev/check_root_hashstate.hpp`) has to tell two kinds of zero write
apart. It uses `find_built_storage(addr_hash, slot_hash)`, a side-effect-free
probe of the built storage cache (no confirm-on-miss) that returns `true` only
when the pristine pre-state holds a leaf for that slot:

- If the slot existed in the pre-state, the zero write is a genuine delete and
  must fold as an `0x80` delete of that leaf.
- If the slot never existed, the zero write is a no-op and must be omitted,
  matching how `DirectState` erases such zeros.

Emitting `0x80` for a slot that never existed would insert it instead.
`grid_mpt.cpp` treats `0x80` as a delete only when the target leaf already
exists, so an `0x80` on the insert path seeds a spurious leaf and corrupts the
recomputed storage root.

### Created code lookup

`find_created_code_(code_hash)` looks up code created during the block by its
keccak `code_hash`. It checks the `created_code_` overlay and then its
key8-collision spill, `created_code_collisions_`. A hit returns the stored
bytes; a miss returns an empty `ByteView`. Each `created_code_` entry carries
the real code hash and every hit is confirmed with a full-hash `memcmp`, so the
lookup can never surface the wrong bytes. A non-empty `code_hash` always maps to
non-empty bytes, so an empty result unambiguously means a miss.

`read_code` uses it on two paths:

- The created-code sentinel path, for an account whose `code_store_offset` is
  `kCreatedCodeOffset` (code set in the block through `set_code` or
  `apply_code_diff`).
- The fallback after a miss in the witness code store. A contract created in the
  block with the same `code_hash` makes witness code that was omitted
  legitimately derivable (EIP-8025 optional proofs: the "create the same hash,
  then read" case).

If neither the witness code store nor the created-code overlay has the bytes
for a non-empty `code_hash`, `read_code` records an unconfirmed read instead of
executing empty code.

### HashStateView

`HashStateView` is the per-transaction evmone read view over `HashState`. It
mirrors `DirectStateView` method for method (the same `evmone::state::StateView`
interface, and the same bodies with `DirectState` replaced by `HashState`), so
retyping `DirectStateView` to `ActiveStateView` (`active_state.hpp`) is a
drop-in.

- `HashState`'s address-keyed readers hash the 20-byte address and the 32-byte
  slot key internally, so the view forwards them raw, exactly as
  `DirectStateView` does; it never hashes anything either.
- The balance is read with a plain `memcpy` (native-endian).
  `Account::balance` stores the `intx` byte layout verbatim (`store_be_u256` and
  `load_be_u256` in `hash_state.cpp` are `memcpy`), the same convention
  `DirectState` uses, so the mirror is byte-correct.

## Hash index

`zilk_core/core/common_zz/hash_index.hpp` defines `HashIndex<KeySize, Key8, Value>`, the
HashState backend's in-guest index from a key to a small value: a `u32` arena offset (the
default, used by the account and storage caches) or a `StoredBytes` view (the node and code
stores). On the SSZ input
path it replaces the minimal perfect hash (`MphfMap`) with a plain open-addressed hash
table built in the guest, so no displacement or collision sidecar has to be serialised
ahead of time.

### Index key

The 64-bit index key ("key8") folds a full key into 64 bits. The caller supplies the
function as the `Key8` template parameter, in the same way `MphfMap::find` takes
`shorten_key`. All of them are in `zilk_core/core/common_zz/index_key.hpp`, shared by the
MPHF maps and `HashIndex`:

| Function | Full key | key8 |
| --- | --- | --- |
| `hash_key8` | 32-byte keccak hash (code, trie node, account hash) | its first 8 bytes |
| `addr_key8` | 20-byte address | its first 7 bytes, with byte 19 as the top byte |
| `storage_key8` | 64-byte `addr_hash ‖ slot_hash` | XOR of the two halves' first 8 bytes |

- A plain 8-byte prefix would give every precompile the same `addr_key8`, because
  precompile addresses are zero in every byte but the last.
- `storage_key8` depends on the slot as well as the account. Keyed on the `addr_hash`
  prefix alone, every slot of an account would share one home bucket.
- A key8 only has to tell keys apart: `HashIndex` mixes it before bucketing, and every hit
  is confirmed against the full key (see "Collision safety").
- The Rust MFBD encoder (`prover/stateless_validator/src/mfbd.rs`) has its own
  `addr_key8` and `hash_key8`, which must stay in step.

### Buckets and probing

- The home bucket for a key is `mix64_body(key8) % capacity`. Capacity is always a power
  of two, so the code computes it as `& (capacity - 1)`. It cannot leave that to the
  compiler: capacity is a runtime value, and GCC emits a division for the `%` (`divq` on
  x86-64, `remu` on RV64IM), even with `[[assume(std::has_single_bit(capacity))]]`.
- Probing is linear and wraps around at the end of the table.
- Capacity is sized to about twice the expected entry count (load factor about 0.5).
  This keeps probe runs short and guarantees that a free bucket exists, so every lookup
  terminates on the empty sentinel. A value-initialized `Value` is reserved as that
  sentinel (offset `0`, or a null view), and `insert` rejects it, so real entries never
  carry it.

### Collision safety

Two distinct keys can share a key8, and therefore a home bucket. Every occupied bucket a
probe visits is confirmed with a full-key `memcmp` before it counts as a hit, and a
bucket whose full key differs is skipped. A collision can therefore never return the
wrong key's value. This is the same invariant `MphfMap::find` upholds with its
embedded-key `memcmp`.

### Growth past the size hint

`insert` grows the table before the load factor could exceed 0.5, not after.

- The constructor's entry count (the expected counts passed to the `HashState`
  constructor) is a best-effort hint, not a hard cap. A witness with more nodes, codes,
  accounts or slots than the hint, such as a state-heavy block, would otherwise overflow
  a fixed table. Later entries would be dropped from the index and, worse, the guaranteed
  free bucket that lets `find` stop on the empty sentinel would disappear.
- Growth rehashes every entry into a table twice the size. The table is never full, and
  every inserted key stays findable regardless of the hint.
- The check runs before the probe, so an update of a key that is already present (a
  dedupe, which adds no entry) can still trigger growth. This can over-grow the table by
  at most one doubling, which is harmless.

## Trie fold under HashState

`zilk_core/core/trie_zz/grid_mpt.cpp` implements the `GridMPT` fold declared in
`zilk_core/core/trie_zz/mpt.hpp`. `GridMPT<DeletionEnabled, StateT>` takes the node-store
backend as `StateT`, which defaults to `ActiveState` (see "Backend selection"). Node
lookups go through `StateT::find_node_rlp`, whose signature is the same on both backends.

When the fold reaches an existing leaf for an update key, the pre-value bind and the
read-only short-circuit run only if `state_keeps_prevalue_check<StateT>` is `true` (see
"Pre-value check trait"). For `HashState` that block is compiled out.

`grid_mpt.cpp` instantiates the fold explicitly:

- `GridMPT<false, DirectState>` and `GridMPT<true, DirectState>` are always emitted.
  `DirectState` is named explicitly rather than left to the `StateT` default so these
  lines produce the DirectState fold whichever backend `Z6M_HASH_STATE` selects. If they
  relied on the default, then with the flag on `GridMPT<false>` would resolve to
  `GridMPT<false, HashState>` and collide with the HashState instantiations.
- `GridMPT<false, HashState>` and `GridMPT<true, HashState>`, together with the
  `hash_state.hpp` include, are emitted when `Z6M_HASH_STATE` is defined or on any
  host/native build (`!__riscv`), so the fold-over-HashState unit test links in the
  default build. The rv64im DirectState guest (flag off, `__riscv`) includes neither.

Naming `DirectState` explicitly does not change the instantiated type: in the default
build `GridMPT<false>` already is `GridMPT<false, DirectState>`. A defaulted template
argument still appears in the Itanium mangled name, so these symbols carry
`DirectState` in either spelling.

## StatelessInputBytes parsing

`zilk_core/core/state_zz/slib_input.hpp` is the SSZ front-end for the "default
path" input: it turns a `StatelessInputBytes` blob (schema_id `0x1501`,
ProtocolFork.Amsterdam) into a populated `HashState`.

### Scope of the decoder

The decoder is a targeted, hand-written reader for this one container. It is
deliberately not a general SSZ library. The wire layout below was confirmed
against the tests-zkevm@v0.8.0 release source and a real sample.

### Wire layout

```
raw = schema_id (2 bytes, big-endian: 15 01) || SSZ encode(SszStatelessInput)

SszStatelessInput     fixed region 20 bytes
  @0    off(new_payload_request)    (== 20)
  @4    off(witness)
  @8    chain_id: uint64            (inline)
  @16   off(public_keys)

SszExecutionWitness   fixed region 12 bytes
  @0    off(state)                  (== 12)
  @4    off(codes)
  @8    off(headers)

  state       : ProgressiveList[ByteList[1024]]    RLP MPT nodes      (no spec count cap)
  codes       : ProgressiveList[ByteList[65536]]   contract code      (no spec count cap)
  headers     : List[ByteList[1024], 256]          RLP block headers  (count cap 256)

public_keys   : ProgressiveList[ByteVector[65]]    fixed 65-byte stride, no offset table
```

- Every SSZ variable-field offset is a `u32` little-endian value, relative to
  the start of the container it lives in.
- A list of variable-size byte strings serializes as an offset table of `N`
  `u32` LE values followed by the concatenated elements, with
  `N = first_offset / 4`. `ProgressiveList` and `List` are byte-identical here,
  so one routine decodes `state`, `codes` and `headers`.

### Validation and guest safety

- Every marker, offset and length is validated before use (see
  `decode_stateless_input`). The decoder never reads out of bounds and fails
  cleanly, returning `std::nullopt`, on any malformed input.
- It is rv64im-safe: no exceptions or RTTI, multi-byte reads go through
  `memcpy` (so they do not depend on 8-byte alignment), and only native copies
  are used.
- It is additive and host-testable, and it is kept out of the DirectState
  rv64im guest, in the same way as `HashState` itself.

## Accept check

`zilk_core/dev/check_root_hashstate.hpp` holds `check_root_hashstate`, the
`HashState` accept check. It is an additive sibling of
`StateTransition::check_root` in `zilk_core/dev/state_transition.cpp`. It folds
only a block's writes over a `HashState` whose account and storage caches were
already built from the pre-state trie (`build_state_from_trie`), recomputes the
post-state root with the same shared trie code `check_root` uses (`GridMPT`),
and decides whether to accept the block.

### Fold structure

The function mirrors the two-level fold of `check_root` exactly:

1. For each touched account, fold its storage trie first (`reset()` from the
   account's current `storage_root`) to get the account's new `storage_root`,
   then patch the account leaf with that root.
2. Fold the account trie from `prev_root`.

### Accept decision

The accept decision is what differs from `check_root`, and it is the reason
this is a separate function rather than a branch inside `check_root`.
`check_root` runs the pre-value / read-only check inside the fold. That check
is compiled out for the `HashState` instantiation
(`state_keeps_prevalue_check<HashState> == false`, specialized in
`hash_state.hpp` and checked with `if constexpr` in `grid_mpt.cpp`). In its place, the accept gate adds two
witness-completeness counters that the `HashState` build and reads accumulate:

```
accept  <=>  !acc_trie.failed()
             && new_root == header_state_root
             && hash_state.missing_count()          == 0
             && hash_state.unconfirmed_read_count() == 0
```

In words, a block is accepted only when all of these hold:

- No walk failed. A storage walk that fails rejects at once; the account walk's
  `failed()` is part of the gate. A failed walk (a node missing or malformed, a
  claim of absence refuted) returns a zero root, which only a header committing
  to one would match.
- Every account the block read as absent, or created, is absent from the
  pre-state trie. Its update claims so with a `0x80` pre-value
  (`HashStateAccountWrite::absent`). The walk accepts the claim where the key
  leaves the trie (`GridMPT::claims_absent`: an empty branch slot or a
  diverging path, where a read inserts nothing) and refutes it at a leaf (the
  HashState arm of the leaf match in `grid_mpt.cpp`, the one pre-value check
  that stays compiled in).
- The recomputed root matches the header.
- The seeding account root was present. `missing_count()` flags only a broken
  root: a real EIP-8025 partial witness prunes untouched subtrees to bare hash
  references, and the build treats those as legitimate boundaries.
- Every read either hit the cache or was proven genuinely empty (fail-closed;
  see the read path in `hash_state.hpp`).

A write or a claim whose fold has to descend into a pruned boundary is caught
the same way: `GridMPT` cannot unfold the absent node and flags the walk
failed.

### Supplying the write set

The write set can be supplied in two ways:

- The span-based overload takes it as input (`HashStateAccountWrite`), shaped
  the way `check_root` shapes its internal update set (sorted `TrieNodeFlat`).
- The gather overload (no span argument) builds the same set from the
  `HashState` write overlay, then delegates to the span-based overload
  unchanged. It is described below.

### Gather overload

The gather overload is the analog of the gather `check_root` runs over
`DirectState`. It produces the same sorted update set from a different
substrate, so the real execution path can accept a block right after running
it, with no hand-supplied span. It mirrors `check_root`'s gather step for step:

- **Iterate the overlay.** It walks `created_accounts()`. Only written
  accounts live there, so this is `check_root`'s `modified` split expressed
  structurally: read-only accounts never enter.
- **Hash the address.** For each account, the 20-byte address is hashed with
  keccak to its `addr_hash`.
- **Absent accounts.** Whether the pre-state trie has a leaf for the address
  is the side-effect-free `find_built_account` probe, not `get_account`, so a
  legitimate miss never bumps `unconfirmed_read_count_` and wrongly rejects
  the block. An address the probe misses is one `find_or_create_account`
  materialized on a total miss, and its write is marked `absent`: the span
  overload gives its update the `0x80` pre-value, the claim that the key is
  absent, which the fold checks (see [Accept decision](#accept-decision)).
- **Destructed accounts.** A destructed account (`deleted`) that has a
  pre-trie leaf emits an `account == nullptr` write, which becomes a `0x80`
  leaf delete. One without a pre-trie leaf (read as absent, or created and
  destructed again) emits an `account == nullptr` write marked `absent`: a
  read-only claim of absence, which inserts nothing.
- **Storage writes of a live account.** The account's overlay storage writes
  become a `TrieNodeFlat` set sorted by slot hash (raw-key order is not
  `keccak(key)` order). Each value is encoded the way `check_root` encodes it,
  `rlp::encode_into_small(buf + 40, zeroless_view(v))` at `current_off = 40`,
  so a zero value encodes as `0x80` and folds as a delete. This is why
  `HashState` retains zero writes (overlay divergence (a): `set_storage_slot`
  keeps zero writes where `DirectState` erases them). See
  [Zero storage writes](#zero-storage-writes) for which zero writes are kept.
- **Storage-fold seed.** The seed is the account's pre-write `storage_root`,
  taken from the overlay POD. That value is frozen at copy-on-write, exactly
  like `check_root`'s `pa->storage_root`. When `storage_wiped()` is set, the
  seed is overridden to `kEmptyRoot`, because a contract-creation wipe leaves
  the POD's `storage_root` stale (overlay divergence (b): a wipe sets a
  per-account `storage_wiped_` flag instead of wiping slots in place). The
  frozen overlay copy is used rather than "the built account, else zero"
  because a created account with no storage writes must seed `kEmptyRoot`, not
  zero: the span overload only normalizes zero to `kEmptyRoot` when
  `storage_updates` is non-empty, and the overlay POD already carries
  `kEmptyRoot` for created and revived accounts.
- **Account leaf.** The span overload re-encodes the leaf through
  `account->rlp_into` on the overlay POD. `rlp_into` reads `code_hash` and
  never `code_store_offset` (see `account.cpp`), so an account whose code came
  from the witness (`code_store_offset == 0`) still encodes its real
  `code_hash`.
- **Sort and delegate.** The writes are sorted by `addr_hash` (`memcmp`
  order), which is the span overload's contract, and passed to it.

### Zero storage writes

`HashState` retains zero storage writes, while `DirectState` erases them. When
the gather overload folds them:

- A zero write is a genuine delete only when the slot existed in the pre-state
  trie and the account was not wiped this block. It must then fold as a `0x80`
  delete of that leaf.
- A zero write to a slot that never existed is a no-op and must be omitted.
  Emitting a `0x80` leaf for it would insert a spurious leaf: `grid_mpt.cpp`
  treats `0x80` as a delete only when the target leaf already exists, and
  otherwise seeds a leaf on the insert path, which corrupts the storage root.

### Build guard

The header is compiled only into `HashState` guest builds and host/native
builds (the unit tests). Its guard, `#if defined(Z6M_HASH_STATE) ||
!defined(__riscv)`, mirrors the one in `grid_mpt.cpp`, so the rv64im
`DirectState` guest pulls in nothing from here and no HashState code reaches
its ELF. Nothing in that guest includes this header; the guard is a
second line of defence.

## Blockchain-test runner

`zilk_core/dev/blockchain_test_runner.cpp` runs EEST blockchain tests, the
EJSN input that `StateTransition::run` (in `state_transition.cpp`) dispatches to
it. Under the `HashState` build (`Z6M_HASH_STATE`), `blockchain_test` runs the
slib arm described here instead of the `DirectState` body. The same file also
holds the classifier for stateless witness-validation negatives. How the corpus
is scored overall is summarized in
[slib_corpus_validation.md](slib_corpus_validation.md).

### Slib arm

Under the `HashState` build, `Blockchain` binds `ActiveState == HashState`.
Instead of building a `DirectState` from `pre`, the arm works per block:

- Each block's own witness (`blocks[i].statelessInputBytes`, schema_id
  `0x1501`) reconstructs the pre-state trie into a fresh `HashState`
  (`run_slib`, which is `parse_stateless_input` followed by
  `build_state_from_trie`).
- The block runs over that `HashState`.
- The gather overload of `check_root_hashstate` decides acceptance by folding
  the block's writes over `prev_root` (see [Accept check](#accept-check)).

The `#else` branch keeps the `DirectState` path.

A fixture identified as a stateless witness-validation negative must be
rejected. `run_slib_arm` runs the ordinary slib flow and returns its natural
`Status`; the witness-negative inversion is applied to that `Status` after the
lambda returns. Any rejection path that yields `kFailed` inside the lambda is
therefore the desired outcome for a negative.

### Witness ancestor headers

The witness ancestor headers arrive as RLP and are fed to the `HashState` so
`BLOCKHASH` resolves (the analog of `run_one_bundle`'s ancestor loop). They are
unauthenticated bytes, keyed by number with no linkage, so two checks run
before they are trusted.

**Contiguous chain.** The headers must form a single contiguous parent-hash
chain. The witness ships them oldest-first (ascending by number), and each
header's `parent_hash` must equal `keccak256(rlp(...))` of the header before
it. A reordered, broken or spliced set is a witness-integrity failure and is
rejected fail-closed (the non-contiguous-chain negative).

Completeness of the chain is enforced separately and lazily by
`HashState::get_block_hash`, which fails closed on any in-range ancestor whose
header is absent (the missing-oldest-ancestor negative). The contiguity check
therefore requires no particular anchor or length. That keeps legitimate
partial witnesses working unchanged: they ship exactly the ascending run of
ancestors they reference, sometimes with one extra unused older header.

**Mandatory parent (EIP-8025 witness-integrity anchor).** The block's parent
header must be present in this block's witness ancestor set, matched by the
block's own `parent_hash`. This is strictly stronger than both checks above:
the contiguity check proves the shipped headers form one chain but fixes no
anchor or length, and `get_block_hash`'s lazy completeness only fires for an
ancestor that an executed `BLOCKHASH` actually reaches.

Without this anchor, a block whose witness ships zero ancestor headers still
resolves its parent from the genesis header the `Blockchain` constructor
inserts, and is wrongly accepted. That is the
`validation_headers_empty_block_missing_mandatory_parent` witness negative
(empty block #1, zero witness headers). The constructor's genesis header is a
block-lookup convenience, never a substitute for the mandatory witness parent.

Verified across the whole fixtures corpus (27,184 witnessed blocks): the only
blocks that omit their parent are the three `witness_validation_headers`
negatives. Every legitimate block, including empty block #1 and blocks whose
parent is genesis, ships its parent header, so this check rejects only
negatives.

### Expected-invalid label relaxation

When a block carries `expectException` and is rejected with a label that does
not match, the runner can still accept the rejection. The precise rejection
label is trustworthy only when the block's own witness supplied every account
the validation gates read.

- An EEST `expectException` block that is rejected in pre-validation
  (`INSUFFICIENT_ACCOUNT_FUNDS`, `SENDER_NOT_EOA`, ...) is derived from a state
  test and ships a minimal witness that prunes the sender itself; the sender
  was never needed to re-execute a transaction that never runs.
- With the sender pruned, `HashState` reads it back blank (nonce, balance and
  code all zero), and an earlier gate fires with the wrong label
  (`kWrongNonce` / `kInsufficientFunds`).
- `HashState` flags exactly this case: a read that could not be confirmed
  against the pruned trie bumps `unconfirmed_read_count_`.

So when that counter is non-zero, the exact reason cannot be derived from this
witness, while the block is still correctly rejected (the full-state reference
marks it invalid), and the runner accepts the rejection. A complete witness
(counter zero) still demands the exact label, so a genuine reconstruction or
validation bug is never masked.

### Scoring witness-validation negatives

EEST's EIP-8025 "optional proofs" feature ships a family of stateless
witness-validation negatives. The block itself is valid: a full-state client,
and the `DirectState` build, accept it. Its per-block `statelessInputBytes`
witness is deliberately broken: a required trie or code node removed, a header
dropped, malformed or reordered, or the SSZ blob itself corrupted. A correct
stateless verifier must reject these, yet the fixtures carry no block-level
`expectException`, because that field describes block validity, not witness
integrity. The ordinary slib scoring ("no exception means accept") is wrong for
them, so it is inverted: pass if and only if the slib path rejects.

**Identifying them.** No fixture field marks this intent. The block JSON is
structurally identical to a valid-witness positive, and `_info` carries only
prose ("… should fail." versus "… should still validate."). Matching on prose
substrings is imprecise; it would wrongly flag valid-block cases such as:

- `witness_codes_auth_nonce_mismatch` ("rejected")
- `witness_codes_failed_create_*` ("fails")
- `witness_state_failed_call_*` ("failed CALL")
- `validation_wrong_chain_id` ("fails under chain 2")

The precise machine-readable key is the EEST pytest node-id, which is the
fixture's top-level JSON key and is passed in as `fixture_name`.
`is_stateless_witness_negative` matches only inside the
`eip8025_optional_proofs` feature, where the witness-negative naming convention
captures exactly this set. It excludes the positives (`…extra_unused…`,
`…unsorted_but_complete…`) and the chain-id, public-key and versioned-hash
families. The matched names are:

| Pattern | Fixture files |
| --- | --- |
| `test_validation_codes_missing_*` | 9 |
| `test_validation_state_missing_*` | 6 |
| `test_validation_headers_*` | 5 (all negatives) |
| `test_invalid_stateless_input_bytes_are_rejected` | 1 (8 parametrized cases) |

That is 21 fixture files, verified across the whole fixtures tree to match zero
valid-block fixtures. A false match there would mask a real slib bug by scoring
a wrong rejection as a pass. One fixture in the first family is exempted; see
[Delegated-code exemption](#delegated-code-exemption).

**The scoring rule.** The rule is applied uniformly to every selected fixture,
not only to the ones that already reject: pass if the slib path rejected, fail
if it accepted every block.

- "Rejected" is any rejection signal the flow can raise: malformed
  `StatelessInputBytes`, a missing seeding root, a missing node or a non-zero
  `missing_count` / `unconfirmed_read_count`, a root mismatch, or a validation
  error. All of these land as a natural `kFailed`.
- "Accepted" is a natural `kPassed`: the fold matched the header and both
  completeness counters were zero.
- A natural `kSkipped` is returned unchanged, since it cannot be classified.

This deliberately surfaces witness-strictness leniencies: a broken witness
that slib wrongly accepts is scored as a failure instead of a pass.

### Delegated-code exemption

`validation_codes_missing_delegated_code_on_insufficient_balance_call` is
classified by EEST as a negative, but it is not a witness-integrity failure for
a fail-closed stateless verifier. It is scored as an ordinary valid block
instead of a must-reject.

- The block CALLs an EIP-7702 delegated target with insufficient balance. The
  CALL reverts on the balance check before the delegated code is ever loaded,
  so that code never executes, and pruning it from the witness is legitimate
  EIP-8025 optional-proofs behavior.
- `HashState::read_code` is already fail-closed: any code the execution
  actually needs but the witness omits leaves the read unresolvable and rejects
  the block.
- Here nothing needs the pruned code. `DirectState` accepts, and the slib path
  recomputes the correct post-state root, so slib correctly accepts.

The fixture encodes a stricter reading ("the witness must carry every
delegated-target code even when unreachable") than EIP-8025 requires. The match
is exact (this one full test-function name, not a prefix), so it excludes only
this fixture and never swallows the other `::test_validation_codes_missing_*`
negatives. The fixture then passes through the normal valid-block path.

### Raw StatelessInput dispatch

`StateTransition::run` dispatches on the input magic (`EJSN` or `MFBD`). The
"default path" input is a raw StatelessInput blob (schema_id `0x1501`, on-wire
big-endian prefix `15 01`), and it is not wired in yet. The intended design is
to detect it in the `default` case of that switch
(`envelope_[0] == 0x15 && envelope_[1] == 0x01`) and dispatch to a runner that
parses it into a `HashState` (`parse_stateless_input` followed by
`build_state_from_trie`, from `slib_input.hpp`) and then executes the block.

The parser and build front-end already exist and are unit-tested; full block
execution over `HashState` on this entry path is what remains. Until then the
path still rejects the input as an unsupported magic, so the `MFBD` and `EJSN`
guests behave as before.

## Build flag and benchmark targets

The build-side pieces: the `Z6M_HASH_STATE` option in both CMake projects, the
`make` targets that run the tests-zkevm corpus and the SP1 benchmark, and the
benchmark workflow.

### Build flag and test targets

`Z6M_HASH_STATE` is a CMake option, OFF by default. OFF makes `ActiveState`
`DirectState`, and the build behaves as it did before HashState existed. ON
makes it `HashState` (see "Backend selection").

- **Host build.** The top-level `CMakeLists.txt` defines the `Z6M_HASH_STATE`
  macro for every target created after the option (`zilk_core`,
  `zilkworm.tests`, ...). With the flag on, `zilkworm.tests` leaves out the
  suites that execute blocks over a DirectState witness
  (`addr_hash_orphan_test`, `account_read_spoof_test`,
  `account_read_honest_test`, `delegation_clearing_storage_test`,
  `code_store_collision_len_test`), because the flag-on processor takes
  HashState.
- **Guest build.** `prover/guest_hypercube` is a separate CMake project, so the
  top-level option never reaches it. It declares its own `Z6M_HASH_STATE`
  option. The option must stay before the guest's `add_subdirectory()` calls so
  the define reaches `zilk_core`, evmone and the `z6m_guest` target.
- **`make eest-zkevm-tests`** runs the tests-zkevm `statelessInputBytes` corpus
  the way `eest-blockchain-tests` runs its corpus: configure, build, then
  ctest, with each fixture file a `state_transition <path>` ctest case. It
  differs in two ways:
  - It points `EEST_JSON_DIR` at the raw zkevm `blockchain_test` JSON, like
    `eest-blockchain-tests-json`, rather than at pre-converted MFBD bundles.
    HashState reads `statelessInputBytes` straight from the JSON, so there is
    no `eest_to_flat_bundle` step.
  - It builds with `-DZ6M_HASH_STATE=ON` in its own `build/zkevm` tree, since
    the flag differs from the shared `build` tree the other targets use.

  `make zkevm-fixtures` downloads the corpus (`tests-zkevm@v0.8.0`). The
  harness runs end to end; current results are in
  [slib_corpus_validation.md](slib_corpus_validation.md).

### SP1 cycle benchmark

`make slib-benchmark` measures the HashState guest's SP1 cycles on the
`tests-zkevm-benchmark@v0.8.2` blocks; results are in
[slib_benchmark.md](slib_benchmark.md).

- **Amsterdam support.** The benchmark fixtures are Amsterdam
  `statelessInputBytes` blocks, so both the guest ELF and the host need the full
  Amsterdam EVM semantics: the zilk_core fork plumbing for
  glamsterdam-devnet-8 and the matching evmone submodule.
- **Our numbers only.** The targets emit this project's cycle counts. The reth
  baseline is produced elsewhere and compared on dashboards.
- **One prover run per case.** `execute --is-test --file-name` sums cycles
  across every case in a JSON file, so the target first splits each fixture
  into one case per file (`tools/scripts/slib_split_fixtures.py`) and runs the
  prover once per case, giving one cycle number per block. The prover prints
  `Executed block N (gas_used=..., cycles=..., prover_gas=..., syscall_count=...)`.
  The target rewrites that into the
  `block N executed, gas_used=..., cycle_count=..., prover_gas=...` line that
  `cycle_stats.py` parses, using a running index as the block number because
  every benchmark block is chain block 1. It also writes a per-case CSV.
- **CI.** `.github/workflows/hypercube-slib-benchmark.yml` runs the benchmark
  on `workflow_dispatch` only; it is not wired to pushes or PRs. Its run step is
  `continue-on-error`, so it never gates CI, and it uploads the log, CSV and
  plot as artifacts.

## Tests

The HashState unit tests live in two files under `zilk_core/dev/cli/`, both part of the
`zilkworm.tests` target. `hash_index_test.cpp` tests the `HashIndex` table on its own.
`hash_state_test.cpp` tests `HashState` itself, from the node and code store up to the accept
check. It also uses the sample fixture in `slib_sample_fixture.hpp`.

### HashIndex lookups and collisions

`HashIndex` is the HashState backend's in-guest replacement for `MphfMap` on the SSZ input path:
a plain open-addressed hash table instead of a serialized minimal perfect hash. It reuses the
same key8 derivations as `MphfMap` (`hash_key8` for 32-byte hashes, `addr_key8` for 20-byte
addresses) and the same `mix64_body` mixer, so two distinct keys can land in the same home bucket.

Lookup soundness therefore rests on the full-key `memcmp` done at every occupied bucket the probe
visits. A collision must never return the wrong key's offset.

The forced-collision cases build keys that share a key8, and so share a home bucket. They check
that each key still resolves to its own value, and that an absent key stops at the empty
sentinel. `HashIndex forced collision resolved by probe + full-key compare` covers 32-byte keys,
and `HashIndex 20-byte address keys` adds a collision between two addresses.

### Node and code store

`HashState` is the node and code store for the SSZ input path, parallel to `DirectState`'s
serialized `MphfMap` stores. `add_node` and `add_code` key their input by its real keccak256 and
record a view of a stored copy in an open-addressed `HashIndex<32, &hash_key8, StoredBytes>`;
`find_node_rlp` and `find_code` return that view.

The store tests cover round-trip, dedupe, a definitive miss, and the case that carries the most
weight: the full-key `memcmp` gate under a home-bucket collision.

`HashState full-key gate on home-bucket collision` checks that two distinct real keccak hashes
forced into the same index home bucket each resolve to their own payload (open-address probe plus
full-key `memcmp`), and that a third colliding hash that was never added still misses.

A literal 8-byte key8 collision cannot feasibly be constructed under real keccak, so the test uses
a home-bucket collision instead, where the home bucket is `mix64_body(hash_key8(h)) &
(capacity - 1)`. `mix64_body` is public in `mphf_map.hpp`, but the exact home bucket also depends
on the table's capacity and mask. A sibling `HashIndex` sized with the same expected count
reproduces both, so its public `index_of()` gives the same home bucket the real node index uses.

### Trie sweep tests

The `build_state_from_trie` tests hand-build small account tries with the project's own MPT node
encoders (`encode_leaf`, `encode_branch` and `encode_ext` in `rlp_sw.hpp`). They add the
referenced nodes to the store under their real keccak, run `build_state_from_trie(root)`, and
check the account cache it produces. Using the shared encoders rather than raw RLP bytes keeps the
fixtures canonical and readable: they are the same bytes `decode_node` reads back.

`HashState build_state_from_trie account sweep` includes an embedded inline leaf E under a deep
branch: `root[0x8]` -> extension (60 nibbles) -> `branch2` -> embedded leaf (2 nibbles, 1-byte
value).

- Embedded inline children only ever hang off a branch. An extension's child is always a 32-byte
  hash reference, and `decode_node` rejects an inline list as an extension child.
- The 60-nibble extension puts the branch deep enough that the leaf's 2-nibble remainder plus its
  1-byte value fit in fewer than 32 bytes, so the leaf is inlined into `branch2`'s RLP instead of
  being hash-referenced.
- The leaf is not added to the store. `build_state_from_trie` must decode it inline, with no
  lookup, so `missing_count()` stays 0.
- Its 1-byte value is not a decodable account. A real account leaf is always longer than 32 bytes
  (it holds two 32-byte hashes), so it can never be embedded. The leaf is counted as reached but
  never cached.

### Partial-witness reads

The build sweep only collects keys that are actually present in the trie. A cache miss is
therefore either a key that is genuinely empty or one wrongly left out of the witness.
`get_account` and `get_storage` cannot tell which in advance, so on a miss they run a single-path
confirmation walk (`confirm_absent`) down the key's path:

- If the walk proves the key empty, the read returns blank and records nothing. Proof is an empty
  `0x80` branch slot for the key's next nibble, or an extension or leaf whose path diverges from
  the key.
- If a node the walk needs is missing, absence is not confirmed. The read still returns blank, so
  a value-returning caller can proceed, but it records an unconfirmed read so the accept gate
  rejects later.

These fixtures are hand-built with the same MPT encoders as the build-sweep fixtures.

### GridMPT fold over HashState

The fold tests exercise `GridMPT<true, HashState>`, the compile-time-selected shared-trie path: the
templated GridMPT bound to HashState's node store, where `state_->find_node_rlp` resolves through
the HashState open-addressed index. The pre-value / read-only check is compiled out for this
instantiation (`state_keeps_prevalue_check<HashState> == false`).

The fold reads nodes only from the node store (`add_node`), so it runs directly off the witness.
It does not consult the account and storage caches that `build_state_from_trie` fills.

The expected root is a hand-computed root, not the output of a DirectState fold. Building a
DirectState from raw nodes is impractical here, because DirectState reads a serialized `MphfMap`
bundle produced by the host-side flat-bundle builders. Instead the tests compute the post-write
Ethereum trie root directly with the same canonical encoders the fold uses internally:
`encode_line` in `rlp_sw.hpp` sends a branch to `encode_branch` and a leaf to `encode_leaf`. That
makes `keccak(encode_branch(post-state root))` a valid oracle for the fold's output.

### Accept check tests

`check_root_hashstate` (`check_root_hashstate.hpp`) is the HashState accept check, an additive
sibling of `StateTransition::check_root`. It folds only a block's writes over a HashState whose
caches were built from the pre-state trie, recomputes the post-state root with the same
`GridMPT<true, HashState>` fold, and accepts if and only if:

```
new_root == header_state_root && missing_count() == 0 && unconfirmed_read_count() == 0
```

The pre-value / read-only check is compiled out for HashState; the two counts replace it. In the
span-based overload the write set is supplied as input (`HashStateAccountWrite`), shaped like
`check_root`'s internal update set. The expected root is hand-computed with the fold's own
canonical encoders (`encode_leaf`, `encode_branch`), the same oracle used by the fold tests.

The gather overload recomputes the accept decision from HashState's own write overlay, without a
hand-supplied span. It iterates `created_accounts()`, `overflow_slots_` and `storage_wiped_`,
rebuilds the same sorted `HashStateAccountWrite` set that `StateTransition::check_root` builds from
DirectState, and delegates to the span-based overload. The gather tests drive real writes through
the overlay mutators (see "Write overlay and mutators") and check that:

- the gathered decision matches an independent hand-built oracle,
- it also matches the span-based overload given a hand-built span for the same writes, and
- an unconfirmed read still makes it reject.

### Omitted BLOCKHASH ancestor

`check_root_hashstate rejects a BLOCKHASH read of an omitted in-range ancestor` is a soundness
regression test for the missing-oldest-ancestor exploit. A block that reads `BLOCKHASH(k)` for an
in-range ancestor whose header the witness omitted must be rejected, even when the recomputed
post-state root matches `header.state_root`.

evmone's `blockhash` instruction (`instructions.hpp`) clamps k to `[max(N-256, 0), N-1]` and only
then calls `host.get_block_hash(k)`, which reaches `HashState::get_block_hash(k)`. The real chain
always has that ancestor's hash, so a store miss means the witness omitted a required header.

Before the fix, `get_block_hash` returned a silent zero and left both completeness counters at
zero. A block that persisted `BLOCKHASH(k)` (`SSTORE(slot, BLOCKHASH(k))`) with header k omitted,
and with `header.state_root` set to that forged execution's root, was accepted. With the fix, the
omitted-ancestor read fails closed: it increments `unconfirmed_read_count_`, and the accept gate
rejects.

A read of an ancestor that is present still costs nothing, so legitimate partial witnesses, which
ship every ancestor they reference, keep validating.

### Stateless input front end

The slib front-end tests decode a StatelessInputBytes blob (schema_id `0x1501`) into a HashState,
then run `build_state_from_trie`. There are two kinds of input:

1. The real tests-zkevm@v0.8.0 sample in `slib_sample_fixture.hpp`. It shows that the hand-written
   SSZ reader parses the exact wire format, and that parse plus build reconstruct the committed
   pre-state accounts.
2. A synthetic blob that the test encodes into the exact wire layout from a small complete trie.
   It covers the clean `missing_count() == 0` path and a storage cross-check. The real sample is an
   "optional proofs" partial witness with no touched storage, so it cannot exercise either of
   those on its own.

Malformed-input tests must also fail cleanly: they return `std::nullopt` with no out-of-bounds read
and no crash.

`slib_sample_fixture.hpp` is generated; do not edit it by hand. Its source is the tests-zkevm@v0.8.0
release tarball `fixtures_zkevm.tar.gz`, streamed with the command below, followed by
`tar --occurrence=1 -xzf` to extract the one case:

```
gh release download tests-zkevm@v0.8.0 --repo ethereum/execution-specs -p fixtures_zkevm.tar.gz
```

The case is
`blockchain_tests/for_amsterdam/amsterdam/eip8025_optional_proofs/witness_bytecodes_call_variants/witness_codes_call_existing_contract.json`
(`test_witness_codes_call_existing_contract ... -call`).

- `kBlobHex` is that case's `blocks[0].statelessInputBytes`: schema_id `0x1501` followed by the SSZ
  body.
- The witness is an EIP-8025 "optional proofs" partial trie. It carries the 9 pre accounts the
  block touches and prunes 2 untouched system accounts (the beacon deposit contract and the CREATE2
  deployer) to bare hash refs.
- `kPresent` holds the 9 recovered accounts, with every field cross-checked against `pre`.
  `kPrunedAddrs` holds the 2 pruned addresses.
- The fixture defines `kExpectedMissing = 2` for the two pruned accounts, but nothing reads it.
  `build_state_from_trie` treats a pruned child as a boundary rather than a missing node, so the
  real-sample test expects status `kOk` and `missing_count() == 0`. Reading a pruned account
  returns blank and records an unconfirmed read.

### Write overlay and mutators

These tests drive the copy-on-write overlay that HashState grows on top of its pristine built
account and storage caches, along with its mutators and address-keyed readers.

- The address-keyed readers hash the address internally. Any fixture that must be reached through
  the built cache is therefore keyed by the real `keccak256(addr)` path (`add_single_account`,
  `keccak_addr`, `nibbles_of`).
- Overlay-only scenarios use any real address on an empty-trie HashState. They run
  `build_state_from_trie(kEmptyRoot)` first, so a fresh account's `confirm_absent` proves absence
  and records nothing.

Each of the two deliberate divergences from DirectState has its own case:

- (a) A zero storage write is retained, not erased:
  `HashState storage write read-back and zero-write retention (divergence a)`.
- (b) `apply_code_diff`, destruct and revive set a `storage_wiped_` flag: the wipe cases, starting
  with `HashState apply_code_diff wipes storage on contract creation (divergence b)`.

### Per-transaction read view

`HashStateView` is the per-transaction evmone read view over HashState. It mirrors
`DirectStateView` (`direct_state.hpp`) method for method over the same
`evmone::state::StateView` interface, forwarding to the address-keyed readers described in "Write
overlay and mutators".

These cases check that the forwarding is faithful:

- a present account's fields, storage and code come through;
- `has_storage` reflects the account's `storage_root`;
- empty and absent keys give the right blank results.

All of these run off the pristine built cache, which the address-keyed readers hash into
internally.
