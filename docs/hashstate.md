# HashState

**Backend: HashState** (also called slib). Built with `-DZ6M_HASH_STATE=ON`, it takes a block's
EIP-8025 `statelessInputBytes` witness directly and works out every trie path from the previous
state root, so every read is checked against the root it claims to come from. It is the guest the
ERE harness runs and a release publishes as `stateless-validator-zilkworm-sp1-<SP1 version>`
([release.md](release.md#hypercube-guests)). The default backend, DirectState, reads MFBD flat
witness bundles instead; see [directstate.md](directstate.md).

The backend is chosen at compile time. With the flag off, no HashState code reaches the guest.

| Piece | File |
| --- | --- |
| Backend selection | `zilk_core/core/state_zz/active_state.hpp` |
| HashState and its per-transaction view | `zilk_core/core/state_zz/hash_state.{hpp,cpp}` |
| Open-addressed key-to-offset index | `zilk_core/core/common_zz/hash_index.hpp` |
| `statelessInputBytes` parser, payload decoder | `zilk_core/core/state_zz/slib_input.{hpp,cpp}`, `slib_payload.{hpp,cpp}` |
| SSZ reading and merkleization | `zilk_core/core/common_zz/ssz_read.hpp`, `ssz_merkle.{hpp,cpp}` |
| Accept check (post-state root) | `zilk_core/dev/check_root_hashstate.hpp` |
| Runner (`run_sib`, the EEST slib arm) | `zilk_core/dev/blockchain_test_runner.cpp` |
| Tests | `zilk_core/dev/cli/hash_state_test.cpp`, `zilk_core/dev/cli/hash_index_test.cpp` |
| Guest | `prover/guest_hypercube/` (`make z6m_guest_slib`, staged for ERE by `make ere-bin`) |

Running the corpora is in [slib_corpus_validation.md](slib_corpus_validation.md), the SP1 cycle
benchmark in [slib_benchmark.md](slib_benchmark.md), the ERE harness in
[ere_integration.md](ere_integration.md).

## Backend selection

`zilk_core/core/state_zz/active_state.hpp` chooses the read-side state backend at
compile time. The trie fold and the transaction-level EVM view both read state through
the aliases defined here.

| Build | `ActiveState` | `ActiveStateView` |
|---|---|---|
| `Z6M_HASH_STATE` undefined (default) | `DirectState` | `DirectStateView` |
| `Z6M_HASH_STATE` defined | `HashState` (the SSZ/slib input path) | `HashStateView` |

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
plain open-addressed `HashIndex<32, &hash_key8_at, StoredBytes>`, so there is no displacement
or collision sidecar to serialize ahead of time.

| Store      | Key               | Value             | Lookup          |
|------------|-------------------|-------------------|-----------------|
| node store | `keccak256(node)` | node RLP          | `find_node_rlp` |
| code store | `keccak256(code)` | contract bytecode | `find_code`     |

`find_node_rlp` has two forms that run the same probe. The `evmc::bytes32` form is the
seam the trie fold and `DirectState` share. The raw-pointer form,
`find_node_rlp(const uint8_t* hash32)`, reads the hash in place from any address: the
trie sweep and the confirmation walk hand it the child hash ref inside a node's RLP (or
inside a decoded branch), so no probe copies the hash into a stack `bytes32` first. A
raw pointer carries no size, so every such caller keeps its own `== 32` length check as
the guarantee that 32 bytes are readable there.

The index maps each content hash straight to a view of the bytes (`StoredBytes`, a pointer
and a `u32` length), so a hit is one probe with no length decode and no arena indirection.
The bytes are not copied on the input path:

- `add_node_borrowed` and `add_code_borrowed` keep a view of the caller's bytes.
  `parse_stateless_input` feeds the decoded `statelessInputBytes` blob through them, so the
  stores point into that blob. The blob must outlive every use of the `HashState`; it already
  had to, since the retained `StatelessInputView` points into it too.
- `add_node` and `add_code` copy the bytes into `owned_bytes_` (a `std::deque<Bytes>`, whose
  elements never move) and index a view of the copy. Tests use these for temporaries.
- A borrowed add is one index probe (`HashIndex::try_insert`): an absent hash claims a
  bucket, a present one is left as it is. A repeated node or code therefore keeps the view
  added first (the same bytes under the same hash) and costs no separate lookup before the
  insert.
- `parse_stateless_input` sizes both stores, and the account and storage caches, from the
  element counts the SSZ lists announce before the first add (`HashState::reserve_stores`,
  see "Growth past the size hint" and "Store sizing from the offset tables"), so a witness
  larger than the constructor's hints fills tables of their final size instead of growing
  them on the way.
- Because the stores hold views, `HashState` is not copyable.
- A stored view's pointer is never null (an empty input points at a static byte), so it can
  never equal the index's empty sentinel, the value-initialized `{nullptr, 0}`.

The stores bind content to identity. `add_node` and `add_code` compute the real
keccak256 of the bytes at add time and use it as the index key, and `HashIndex`
confirms every probed bucket against the full key. A forged lookup hash can
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
shared `nibbles64` path type (`mpt.hpp`) and the size-safe `rlp::decode_header`,
and never calls a GridMPT method. It decodes no whole node:

- A stack frame (`HashState::SweepFrame`, 24 bytes) is a branch whose children
  are still being visited. It holds a cursor into the branch's RLP list payload
  (`cur`, `end`), the slot the cursor is at (`next_slot`) and the length of the
  path down to the branch (`path_len`). Node bytes live in the input blob or in
  `owned_bytes_` and never move, so a frame points at them directly and nothing
  is copied. The stack is a member, reserved once for the deepest well-formed
  trie (one frame per branch on a 64-nibble path, so at most 64 are live) and
  cleared at every sweep entry. `sweep` is therefore not reentrant;
  `confirm_absent` keeps its own stackless walk.
- A node is classified by the extents of its first two items, the rule
  `decode_node` applies: exactly two items is an extension or leaf, more is a
  branch. An extension's or leaf's two items are decoded with
  `rlp::decode_header`, and the HP path nibbles are appended straight into the
  sweep's path buffer (the grammar of `hp_decode`). A branch is only pushed; its
  children are read one item at a time as the main loop reaches them, with the
  three-case child grammar of `fill_branch_child_rlp` (`0x80` empty, `0xa0` plus
  32 bytes a hash ref, `0xc0..0xf7` an embedded node of at most 31 payload
  bytes) and a bounds check against the payload's end on every item. A hash ref
  is probed in place, and an embedded child is decoded in place from the
  parent's bytes.
- One `nibbles64` path buffer serves the whole sweep. Each child visit resets
  its length to the frame's `path_len` and appends the child's nibble; an
  extension or leaf then appends its own nibbles. A write only ever lands at or
  past the top frame's `path_len`, so the prefixes of the frames below stay
  intact. A branch is pushed only while the path is shorter than 64 nibbles,
  and an extension or leaf whose nibbles would pass 64 stops the descent, so
  every write stays inside the buffer.
- A leaf's value is decoded straight into its arena slot. An account leaf grows
  the account arena by one `Account` (value-initialised, so every field the
  decode does not set is zero) and `decode_trie_account` fills it in place; the
  slot is given back when the value is not an account. A storage leaf grows the
  storage arena by 32 bytes and right-aligns the trimmed word into them; a value
  that is not an RLP string of at most 32 bytes inside the leaf is skipped.

Child validation is lazy: the sweep applies the strict child grammar to all
sixteen slots and stops a branch at the first malformed item, after the
children before it were swept. The witness is then malformed,
`build_state_from_trie` returns `kMalformed`, and the block is rejected.

Every node the sweep reads is bound to the root by keccak: it was fetched from
the node store by its hash (the store keys a node by its real keccak, and every
hit is confirmed against all 32 bytes) or sits embedded inside such a node. A
root taken from a real chain therefore never leads to a malformed shape, but a
hand-built or hostile witness can. Every shape the sweep treats as malformed
sets `malformed_witness_` where it meets it: a referenced node that is not a
list, a truncated or list-typed path or value item, a path past 64 nibbles (a
branch at depth 64, or an extension or leaf that would pass it), a leaf with no
value or one over `kMaxLeafValueSize`, an extension whose child is not a 32-byte
string, a malformed branch child item, and a branch whose 17th item (its value)
is not the lone `0x80` that ends the payload. The account and storage tries have
fixed-length keys, so no branch carries a value. A hash-ref child absent from the
node index is not malformed, it is a pruned boundary.

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
  zero. A miss the walk proves absent is memoized for the build under its
  `addr_hash ‖ slot_hash` key (`absent_slots_`, a
  `HashIndex<64, &storage_key8_at, uint8_t>` holding a constant 1 per entry), so a
  repeated miss of the same slot, which a block often makes, is answered from
  the memo without another walk. Only a proven miss is entered; an unprovable
  one is recorded on every read. The memo is sound because a proof
  reads nothing that changes between builds: the account's `storage_root` in
  the append-only arena record the build wrote, and keccak-bound nodes that a
  later add can neither alter nor turn into the key. `build_state_from_trie`
  clears it (`HashIndex::clear`) with the counter. It is consulted only by
  `note_storage_miss_`, after the account and empty-root early-outs:
  `read_storage` returns before `get_storage` for a wiped account, so a wiped
  account never reaches it, and `find_built_storage` and the accept check's
  gather never probe it.

Either way the read still returns its blank value (`nullptr` for an account,
zero for a slot), so a value-returning caller proceeds. The accept gate rejects
later if and only if the unconfirmed count is non-zero. The failure is closed,
never a silent wrong-empty.

The handlers are defined in the .cpp, so the hot lookups in the header stay
small and the confirm and counter logic sits next to `sweep`. They are `const`,
and `unconfirmed_read_count_` is `mutable`: a read never mutates a built cache;
besides entering a proven storage miss in `absent_slots_`, it records only this
diagnostic.

`confirm_absent(root, target_hash)` is a single-path descent through the node
store, starting at `root`, toward `target_hash`, a 32-byte trie path (an
`addr_hash` for the account trie, or a `slot_hash` for a storage trie). It
returns `true` only when it proves `target_hash` absent below `root`, and
`false` when it cannot. It reads a node the way the sweep does, and only as
much of it as the one path needs:

- It strips the outer list header with `rlp::decode_header` and classifies the
  node by the extents of its first two items (exactly two is an extension or
  leaf, more a branch), the rule `decode_node` applies. No node is decoded
  whole: there is no `BranchNode`, no unpacked path and no copy of a child.
- At a branch, the target's next nibble selects the slot. The nibble is read in
  place from the key byte (`target_nibble`) rather than from a 64-nibble unpack
  of the key, since a walk looks at only a few of them. The walk reads the
  child items from the first up to that slot, one at a time with the strict
  three-case child grammar (`next_branch_child`, shared with the sweep: `0x80`
  is an empty slot, `0xa0` plus 32 bytes a hash ref, `0xc0..0xf7` an embedded
  node of at most 31 payload bytes; anything else, or an item past the
  payload's end, is malformed), and stops there. The siblings past the slot and
  the value item are never read. A hash child is fetched from the store
  straight from its bytes in the node; an embedded child is followed in place,
  since node bytes live in the input blob or `owned_bytes_` and never move
  (should node storage ever become transient, an embedded child would need a
  stable copy again).
- At an extension or leaf, the two items are decoded with `rlp::decode_header`
  (the canonical-form checks `decode_node` has), and the HP-encoded path is
  compared nibble by nibble in place against the target's remainder, with a
  running byte pointer and a high/low toggle, under `hp_decode`'s grammar and
  its 64-nibble bound. The compare stops at the first mismatch, which usually
  comes within a few nibbles.

Validation is lazy, as it is in the sweep: a malformed child item at or before
the target's slot stops the walk unconfirmed, one past it is not seen. Both are
confined to shapes a keccak-bound root cannot reach (see
[Building state from the trie](#building-state-from-the-trie)); the slot of a
genuine branch is read exactly.

It proves absence (returns `true`) in these cases, mirroring the sweep's own
node handling:

- At a branch, the child slot for the target's next nibble is the empty marker
  `0x80`, so nothing hangs below that nibble.
- At an extension or leaf, the node's own path nibbles diverge from the target:
  a nibble mismatch, or a path that outlasts the target. The target cannot lie
  below this node.
- The trie is empty (`root == kEmptyRoot`), which proves every key absent.

It cannot prove absence (returns `false`) when:

- A node the walk needs (the seeding root or a hash-referenced child) is missing
  from the store, or a node on the path is malformed where the walk reads it: an
  outer item that is not a list, a truncated first or second item, a child item
  at or before the target's slot that is not in the child grammar, a branch at
  depth 64 (no nibble is left to index it), a path of more than 64 nibbles, a
  leaf without a value, or an extension whose child is not a 32-byte hash.
  Emptiness is then unknown and must not be guessed.
- A leaf's path matches the target exactly. The key is then actually present,
  not absent.

### Block headers and BLOCKHASH

`HashState` implements the block-header side of the state interface: the three
`silkworm::BlockState` virtuals (`read_header`, `read_body`, `total_difficulty`)
plus `insert_header` and `get_block_hash`, with the signatures `DirectState`
has, so the execution surface retypes from `DirectState&` to `ActiveState&`
unchanged.

`insert_header` keeps a header under its own hash. The headers come from the
witness (`StatelessInputView::headers`): the runner decodes them, checks that
they chain by parent hash and end at the block's parent, and inserts them.

`get_block_hash(header, n)` walks the parent hashes back from the executing
block's own header: block N-1 is `header.parent_hash`, block N-2 the parent
hash of the header found under it, and so on, so every hash it returns is bound
to the block. A header is never found by its number: one chained after the
parent and numbered like an ancestor is never BLOCKHASH of that number. Block
n's own header must be held as well, as stateless validation derives BLOCKHASH
from the witness headers. The walk is memoized per block, as
`DirectState::get_block_hash` does: the first call records the contiguous run
of held headers below the block, parent first, and every call after it is one
index, where an unmemoized walk to `BLOCKHASH(N-256)` is 255 lookups.

evmone calls `get_block_hash` only for an ancestor in `[max(N-256, 0), N-1]`
and returns zero itself outside that range. A walk that does not reach block n
means the witness omitted a header the block needs, and a silent zero would be
unsound: a block that stores `BLOCKHASH(k)` for an omitted `k` would execute
with the wrong value and the attacker's `header.state_root` would match it. So
the miss sets `ancestor_missing()` and counts as an unconfirmed read, through
the channel `get_account` and `get_storage` misses use, and the accept gate
rejects the block; `get_block_hash` still returns zero so execution proceeds to
that decision.

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

Because zero writes are retained, the write gather has to tell a genuine delete from a
no-op. It uses `find_built_storage(addr_hash, slot_hash)`, a side-effect-free probe of the
built storage cache (no confirm-on-miss) that returns `true` only when the pristine
pre-state holds a leaf for that slot; see [Zero storage writes](#zero-storage-writes).

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

- `HashIndex` takes the pointer forms (`hash_key8_at`, `storage_key8_at`), which read through
  `memcpy` and so work at any alignment; the array forms above forward to them.
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
- Every bucket is 8-byte aligned (`alignas(8)` on the bucket struct), so every stored
  key starts on an 8-byte boundary and the bucket stride is a multiple of 8. A bucket is
  40 bytes in the account index (32-byte key plus a `u32` offset, padded from 36), 72 in
  the storage index (64-byte key, padded from 68) and 48 in the node and code stores
  (32-byte key plus a 16-byte view), where the alignment was already natural.
- `find_ptr(const uint8_t*)` takes the probe key as a raw pointer and reads it in place,
  at any alignment; `find` (array reference) is a thin wrapper over it, and `insert`
  uses the same compare. The caller guarantees `KeySize` readable bytes. This is what
  lets the trie sweep and the confirmation walk probe straight from a child hash ref
  inside node RLP, with no copy of the hash.
- The full-key compare is inline, word by word, with no library `memcmp` or `memcpy`
  call. The stored key loads as whole aligned 64-bit words (the bucket alignment above,
  asserted at compile time). The probe key goes through an 8-byte `memcpy` into a local
  per word, which the strict-alignment guest target compiles to byte loads (a misaligned
  `ld` traps there) and the host to one load. The leading word is tested first, since
  keys that share a home bucket without sharing a key8 differ there, and the remaining
  words are folded with XOR/OR so a hit is reported only when every word is equal. The
  stored key's first word is never compared against the key8: that shortcut is right for
  `hash_key8` only, while `storage_key8` and `addr_key8` fold more than the leading
  bytes, and the gate must be the full key. A key size that is not a multiple of 8 (none
  of HashState's) keeps `memcmp`.
- The bucket claim (`insert`, `try_insert` and the growth rehash) writes the key the same
  way, word by word through an 8-aligned bucket pointer, and then the value as one struct
  store, so no claim calls the library `memcpy`.
- Capacity is sized to about twice the expected entry count (load factor about 0.5).
  This keeps probe runs short and guarantees that a free bucket exists, so every lookup
  terminates on the empty sentinel. `capacity_for` computes the size in 64 bits and clamps
  it at 2^31, so a count at or above 2^30 cannot wrap the doubling or hand `std::bit_ceil`
  a value it cannot represent. A value-initialized `Value` is reserved as that
  sentinel (offset `0`, or a null view), and `insert` rejects it, so real entries never
  carry it.

### Collision safety

Two distinct keys can share a key8, and therefore a home bucket. Every occupied bucket a
probe visits is confirmed against the full key (the inline word compare above) before it
counts as a hit, and a bucket whose full key differs is skipped. A collision can
therefore never return the wrong key's value. This is the same invariant `MphfMap::find`
upholds with its embedded-key `memcmp`.

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
- `reserve(expected)` pre-sizes an EMPTY table by the constructor's rule (the power of two
  at or above twice the count, never below the minimum), for a caller that learns the entry
  count only after construction. The final capacity is the one growth would have reached,
  so lookups cost the same; what is saved is every intermediate doubling, each of which
  zero-fills a new table and rehashes every entry. It never
  shrinks, and it is a no-op once the table holds an entry, so it can never reset a table
  in use. `HashState::reserve_stores` calls it on the four indexes and reserves the two
  arenas; `parse_stateless_input` supplies the counts.
- `try_insert(key, value)` is the one-probe "insert if absent": an empty bucket is
  claimed (`kInserted`), a full-key match is left with its existing value (`kExisted`,
  first wins), and the sentinel value is rejected (`kFull`, also the cannot-happen
  no-free-bucket case). It grows the table exactly as `insert` does. `insert` keeps its
  overwrite semantics; the node and code stores add through `try_insert`.
- `clear()` empties a table in place, keeping its capacity: every bucket goes back to the
  sentinel and the count to zero, with no reallocation. HashState's memo of proven-absent
  storage slots is cleared this way at every build.

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

The decoder is a hand-written reader for this one container, not a general SSZ
library. The wire layout below is the tests-zkevm v21.0.1 schema
(execution-specs `amsterdam/stateless.py`), the one ere-guests
`stateless-validator-common` decodes.

### Wire layout

```
raw = schema_id (2 bytes, big-endian: 15 01) || SSZ encode(StatelessInput)

StatelessInput        fixed region 16 bytes
  @0    off(new_payload_request)    (== 16)
  @4    off(witness)
  @8    chain_id: uint64            (inline)

ExecutionWitness      fixed region 12 bytes
  @0    off(state)                  (== 12)
  @4    off(codes)
  @8    off(headers)

  state       : ProgressiveList[ByteList[1024]]    RLP MPT nodes      (no spec count cap)
  codes       : ProgressiveList[ByteList[65536]]   contract code      (no spec count cap)
  headers     : List[ByteList[1024], 256]          RLP block headers  (count cap 256)
```

- Every SSZ variable-field offset is a `u32` little-endian value, relative to
  the start of the container it lives in.
- A list of variable-size byte strings serializes as an offset table of `N`
  `u32` LE values followed by the concatenated elements, with
  `N = first_offset / 4`. `ProgressiveList` and `List` are byte-identical here,
  so one routine (`ssz::decode_byte_lists`, `common_zz/ssz_read.hpp`) decodes
  `state`, `codes`, `headers` and the payload's transactions.

`new_payload_request` is decoded by `state_zz/slib_payload.hpp`, see
[The payload](#the-payload).

### Validation and guest safety

- Every marker, offset and length is validated before use (see
  `decode_stateless_input`). The decoder never reads out of bounds and fails
  cleanly, returning `std::nullopt`, on any malformed input.
- It is rv64im-safe: no exceptions or RTTI, multi-byte reads go through
  `memcpy` (so they do not depend on 8-byte alignment), and only native copies
  are used.
- It is additive and host-testable, and it is kept out of the DirectState
  rv64im guest, in the same way as `HashState` itself.

### The payload

`NewPayloadRequest` has the Gloas shape of the Amsterdam schema:
`{execution_payload: ExecutionPayloadV4, versioned_hashes, parent_beacon_block_root,
execution_requests: ExecutionRequestsGloas}`. `decode_slib_payload` cuts it into
views with the same offset discipline (the fixed regions are 44, 540 and 20
bytes; the withdrawals and the five request lists are fixed-size items back to
back), and two functions consume the result:

- `slib_payload_root` is `hash_tree_root(NewPayloadRequest)`, the root the
  validation result commits to. The payload and the requests are EIP-7495
  progressive containers, the lists EIP-7916 progressive lists; the
  merkleization lives in `common_zz/ssz_merkle.hpp` and follows libssz-merkle,
  whose reference roots `ssz_merkle_test.cpp` reproduces.
- `slib_payload_block` is the block the request describes: the header fields
  the payload does not carry are derived (empty ommers, zero difficulty and
  nonce, the transactions and withdrawals roots, the EIP-7685 requests hash
  from the typed request lists, the EIP-7928 block access list hash). The block
  hash is left for the caller to check against the payload's `block_hash`.

### Store sizing from the offset tables

`parse_stateless_input` does not materialise the state and code lists. It validates the
outer framing (the schema marker, the two fixed regions and the section offsets), reads
the element count of each of the two lists from its first offset (`N = first_offset / 4`,
with the list-level checks: a positive multiple of 4 within the section, and `N` at or
below the count cap; a count over the cap rejects the blob before anything is sized),
sizes the stores with `HashState::reserve_stores`, and then streams each list straight into
`add_node_borrowed` / `add_code_borrowed`: one `u32` read per element (the element's end
offset, carried into the next iteration as its start), the same checks as the materialising
decoder in the same order, and the element fed as soon as it is validated. The headers keep
the vector form; `decode_stateless_input`, the materialising decoder the tests use, shares
the framing split and the per-element checks (`ssz::byte_list_count`, `ssz::for_each_byte_list`
and `ssz::decode_byte_lists`, in `common_zz/ssz_read.hpp`).

The hints handed to `reserve_stores`:

| Store | Hint |
| --- | --- |
| node store | the state list's count, capped at 65,536 |
| code store | the codes list's count, capped at 65,536 |
| account cache | `max(1024, nodes / 8)` |
| storage cache | 4,096 (the constructor's value) |

The cap is `HashState::kMaxReserve` (65,536). `reserve_stores` clamps every hint to it, so
the bound holds for any caller, not only the parser. The parser also clamps the node count
before deriving the account hint from it, which keeps that hint at 8,192 or below.

The cap bounds what a hostile offset table can cost: one announcing the count cap (2^20
elements, a 4 MB table) cannot make the guest zero-fill on the order of 100 MB of buckets per
store up front. Growth backstops any count above a hint.

Because the lists are fed as they are validated, a malformed element part-way through
leaves the `HashState` holding the elements before it. `parse_stateless_input` returns
`std::nullopt` and the caller discards that `HashState`; both production callers (the
`state_transition` slib runner and the blockchain-test runner's slib arm) run on a fresh
`HashState` per block.

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

- The recomputed root matches the header.
- The seeding account root was present. `missing_count()` flags only a broken
  root: a real EIP-8025 partial witness prunes untouched subtrees to bare hash
  references, and the build treats those as legitimate boundaries.
- Every read either hit the cache or was proven genuinely empty (fail-closed;
  see the read path in `hash_state.hpp`).
- The account fold did not fail (`!acc_trie.failed()`).

A write whose fold has to descend into a pruned boundary is caught: the fold
fails on the absent node (`GridMPT` sets its failure flag), and a failed
storage walk is rejected on the spot.

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

- **Iterate the overlay.** It walks `created_accounts()`. Every account the
  block loaded lives there, not only the written ones: `HashStateView::get_account`
  and `apply_state_diff` (evmone's `build_diff` reports every loaded account)
  go through `find_or_create_account`, which copies a built account into the
  overlay on its first read, with `modified` false.
- **Hash the address.** For each account, the 20-byte address is hashed with
  keccak to its `addr_hash`.
- **Destructed accounts.** A destructed account (`deleted`) that has a
  pre-trie leaf (`find_built_account` hits) emits an `account == nullptr`
  write, which becomes a `0x80` leaf delete. A created-then-destructed account
  (`find_built_account` misses) is skipped. The probe is the side-effect-free
  `find_built_account`, not `get_account`, so a legitimate miss never bumps
  `unconfirmed_read_count_` and wrongly rejects the block.
- **Built accounts the block only read.** A built record that is neither
  `deleted` nor `modified` is a verbatim copy of its pre-state leaf: every
  mutator that changes a leaf field (nonce, balance, code hash, a storage
  slot) and every wipe or revive sets `modified`, and destruct sets `deleted`
  (noted at `created_accounts_` in `hash_state.hpp`; every new mutator must
  keep it). The gather skips such a record. This is sound because its update
  would carry the leaf's own value, which the fold treats as not modified, so
  the root is unchanged either way: `rlp_into` reproduces the decoded leaf
  byte for byte, since a built record carries no stamped RLP cache
  (`acc_rlp_sroot_off == 0`) and re-encodes its fields canonically. No claim
  is needed for it: the value was bound to `prev_root` by the build sweep,
  unlike `check_root` over `DirectState`, whose witness values are bound only
  by the fold's walk and which therefore folds every read-only account too.
  This is `check_root`'s `modified` split; it saves the leaf encode, the sort
  entry and the unfolds down to each such leaf. The skip requires a pre-trie leaf
  (`find_built_account` hits): a materialized-absent record stays `deleted`
  until a revive, which sets `modified`, so a record without one is never
  skipped. The mutators the invariant covers are `set_account_from_diff`,
  `set_storage_slot`, `apply_code_diff` (including the empty-code arm),
  `revive_if_deleted_slow`, `set_balance`, `add_to_balance`,
  `subtract_from_balance`, `set_nonce`, `set_code` and `destruct`; `HashState`
  has no journal rollback, so no path restores a record.
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
Instead of building a `DirectState` from `pre`, the arm works per block, through
`run_sib_block`, which the raw-input runner shares:

- Each block's own witness (`blocks[i].statelessInputBytes`, schema_id
  `0x1501`) reconstructs the pre-state trie into a fresh `HashState`
  (`run_slib`, which is `parse_stateless_input` followed by
  `build_state_from_trie`).
- The witness headers are checked and inserted (next section).
- The block runs over that `HashState`.
- The gather overload of `check_root_hashstate` decides acceptance by folding
  the block's writes over `prev_root` (see [Accept check](#accept-check)).

The JSON arm keeps the block RLP gates and the `expectException` matching of
`run_json_block` around that core; the `#else` branch keeps the `DirectState`
path.

A fixture identified as a stateless witness-validation negative must be
rejected. `run_slib_arm` runs the ordinary slib flow and returns its natural
`Status`; the witness-negative inversion is applied to that `Status` after the
lambda returns. Any rejection path that yields `kFailed` inside the lambda is
therefore the desired outcome for a negative.

### Witness ancestor headers

The witness ancestor headers arrive as RLP, unauthenticated. Before they are
inserted, `run_sib_block` requires what execution-specs `validate_headers`
requires: the headers form one contiguous parent-hash chain, oldest first, and
the last of them is the block's parent (matched by the block's `parent_hash`).
A reordered, broken or spliced set, or a witness without the parent, is a
witness-integrity failure and rejects the block.

Soundness does not rest on these checks: BLOCKHASH walks the parent hashes back
from the block (see [Block headers and BLOCKHASH](#block-headers-and-blockhash)),
so a header the walk does not reach is never used, and an ancestor the walk
needs but the witness omits rejects the block at accept time. The checks make a
malformed witness fail early and keep the parent, whose state root anchors the
pre-state, explicit.

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
marks it invalid), and the runner accepts the rejection and logs the waived
label (`STRICT: label waived ...`), so the waivers of a corpus run can be
counted. A complete witness (counter zero) still demands the exact label, so a
genuine reconstruction or validation bug is never masked.

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

| Pattern | What the witness breaks |
| --- | --- |
| `test_validation_codes_missing_*` | a required code is omitted |
| `test_validation_state_missing_*` | a required trie node is omitted |
| `test_validation_headers_*` | a header is dropped, malformed or reordered |
| `test_invalid_stateless_input_bytes_are_rejected` | the SSZ blob itself is corrupted |
| `test_witness_header_ssz_*` | a witness header padded to the `ByteList[1024]` limit and past it; 256 headers that fail the chain check, 257 that fail to decode |
| `test_witness_state_rejects_*` | a trie path longer than the 64-nibble key |
| `test_validation_state_unchanged_*`, `missing_*` variants only | a proof dropped for an account, slot or request queue the block reads but leaves unchanged; the `complete_witness` variants must be accepted |

Verified across the whole fixtures tree to match no fixture whose
`statelessOutputBytes` reports a successful validation. A false
match there would mask a real slib bug by scoring a wrong rejection as a pass. No fixture is exempted: evmone reads an EIP-7702
delegate's code while resolving the call target, as execution-specs does, so a
witness that omits it is rejected like any other omitted code.

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

### Raw StatelessInput dispatch

A raw `statelessInputBytes` blob starts with its big-endian schema prefix `15 01`
(`kInputMagicSIB`), and `StateTransition::run` sends it to `StateTransition::run_sib`. This is the
entry point the ERE harness uses. The dispatch table for every input kind and build is in
[architecture.md](architecture.md#input-format-and-dispatch).

`run_sib` decodes the input and the payload, takes the payload's hash tree root,
and selects the chain config by `chain_id` (1 is the generated EEST corpus,
Amsterdam from genesis; 11155111 is Sepolia; the devnets by their ids). The
block comes out of `slib_payload_block`, its hash and the versioned hashes are
checked against the request (`engine_mismatch`, as the MFBD path does), a block
whose canonical RLP exceeds `kMaxRlpBlockSize` is rejected from Osaka
(EIP-7934), the parent is the last witness header and its state root anchors the
pre-state, and `run_sib_block` runs and accepts the block.

The guest commits the 43-byte SSZ `StatelessValidationResult`; its layout and the
all-zero result of an undecodable input are in
[architecture.md](architecture.md#public-output).

## Build flag and benchmark targets

### Build flag and test targets

`Z6M_HASH_STATE` is a CMake option, OFF by default. OFF makes `ActiveState`
`DirectState`; ON makes it `HashState` (see "Backend selection").

- **Host build.** The top-level `CMakeLists.txt` defines the `Z6M_HASH_STATE`
  macro for every target created after the option (`zilk_core`,
  `zilkworm.tests`, ...). With the flag on, `zilkworm.tests` leaves out the
  suites that execute blocks over a DirectState witness (the `if(NOT
  Z6M_HASH_STATE)` list in `CMakeLists.txt`), because the flag-on processor
  takes HashState; the trie suites name `GridMPT<*, DirectState>` and run under
  both. The `unit-tests-hashstate` job of `unit-tests.yml` builds and runs the
  flag-on binary on every PR.
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

  `make zkevm-fixtures` downloads the corpus, the `tests-zkevm` release the
  Makefile pins as `ZKEVM_RELEASE_VERSION`. How to read a run is in
  [slib_corpus_validation.md](slib_corpus_validation.md).
- **Guest targets.** `make z6m_guest_slib` builds the flag-on guest in its own
  tree, `prover/guest_hypercube/build-slib`, so the flag-off tree is never
  reconfigured; `make z6m_prover_slib` builds the prover with `Z6M_GUEST_ELF`
  naming that ELF, which `prover/prover_hypercube/build.rs` embeds in place of
  the DirectState guest; `make ere-bin` stages the ELF and its verifying key
  for ERE.

### SP1 cycle benchmark

`make slib-benchmark` runs the HashState guest over the `tests-zkevm-benchmark`
corpus under the SP1 executor, one prover run per case. The steps, outputs,
knobs and the manual workflow are in [slib_benchmark.md](slib_benchmark.md).

## Tests

The HashState unit tests are `hash_index_test.cpp` (the `HashIndex` table on its own) and
`hash_state_test.cpp` (`HashState` from the stores up to the accept check), both in
`zilk_core/dev/cli/` and part of `zilkworm.tests`. The `unit-tests-hashstate` job of
`unit-tests.yml` runs the flag-on binary on every PR. This section records what each group pins
and the fixture choices that are not obvious from the test code; the behaviour under test is
described in the sections above.

### HashIndex lookups and collisions

Two distinct keys can share a key8 and so a home bucket; lookup soundness rests on the full-key
compare at every occupied bucket a probe visits (see "Buckets and probing"). The suite pins:

- forced collisions for 32-byte, 20-byte and 64-byte keys, each key resolving to its own value
  and an absent key stopping at the empty sentinel. A 20-byte key is not a multiple of 8, so it
  exercises the `memcmp` fallback. The 64-byte case uses two keys with the same `storage_key8`
  but different leading words, which a compare of the stored key's first word against the key8
  would miss;
- `find_ptr` against `find` on every collision, sentinel and wraparound case, and from offsets
  1, 3, 5 and 7 of an 8-aligned buffer;
- a one-bit flip at every byte position of a stored key giving a miss, so a word the compare
  skipped would show;
- the bucket sizes (40, 72, 24 and 48 bytes), asserted at compile time through `bucket_bytes()`;
- the key functions against keys assembled by hand in little-endian order, array forms and
  `_at` forms, at several alignments;
- `reserve`, `try_insert` (first wins, where `insert` overwrites) and `clear`, as specified in
  "Growth past the size hint".

### Node and code store

Round-trip, dedupe, a definitive miss, the raw-pointer `find_node_rlp` against the `bytes32`
form, `reserve_stores` with borrowed adds (first wins) and the `kMaxReserve` clamp.

The case that carries the most weight is the full-key gate under a home-bucket collision: two
distinct real keccak hashes forced into one home bucket each resolve to their own payload, and a
third colliding hash that was never added misses. A literal key8 collision cannot feasibly be
built under real keccak, so the test collides the home bucket,
`mix64_body(hash_key8(h)) & (capacity - 1)`. That bucket depends on the table's capacity, so a
sibling `HashIndex` sized with the same expected count reproduces it through its public
`index_of()`.

### Trie sweep tests

The `build_state_from_trie` tests hand-build small account tries with the project's own MPT node
encoders (`encode_leaf`, `encode_branch` and `encode_ext` in `rlp_sw.hpp`), add the referenced
nodes under their real keccak and check the account cache. The shared encoders keep the fixtures
canonical: they are the bytes the sweep reads back.

Fixture notes:

- **Embedded leaf.** The account-sweep fixture is `root[0x8]` -> extension (60 nibbles) ->
  `branch2` -> embedded leaf (2 nibbles, 1-byte value). The 60-nibble extension puts the branch
  deep enough that the leaf fits in fewer than 32 bytes and is inlined into `branch2`. The leaf
  is not added to the store, so the build must decode it in place and `missing_count()` stays 0.
  Its 1-byte value is not a decodable account (a real account leaf holds two 32-byte hashes and
  can never be embedded), so it is reached but never cached. An extension's child is always a
  32-byte hash reference.
- **Shared path buffer.** Sibling subtrees behind extensions of 50 and 2 nibbles key correctly
  only if each child visit resets the path to the parent's prefix.
- **Depth bounds.** A branch at depth 63 with empty-path leaves at exactly 64 nibbles is swept; a
  branch at depth 64 and a leaf path past 64 nibbles give `kMalformed` without touching a
  counter. The 62- and 63-nibble extension paths are 32-byte strings, the item shape a hash ref
  also has.
- **Malformed shapes.** One hand-built node per shape `decode_node` rejects, each expected to
  give `kMalformed`, with a well-formed twin as the control; a branch stops at its first
  malformed child with the children before it cached. Two cases pin the tests-zkevm
  `witness_state_overlength` leaves.
- **Arena give-back.** A hashed leaf whose value is not an account is counted, not cached, and
  the accounts swept after it land intact.
- A build from an absent root followed by a build from a present one on the same instance.

### Partial-witness reads

The `confirm_absent` cases pin the walk's decision table ("Read-miss confirmation") along every
kind of path a miss can take, on the fixtures of the sweep tests: every root-branch slot from
first to last, a pruned child that leaves every read of it unconfirmed, an embedded child
followed in place, depth 63 and past 64 nibbles, one-nibble and even HP paths, a leaf at the
exact key (refuted on every read), and a malformed sibling before the probe's slot (every slot
from it on is left unconfirmed). One case compares the in-place HP compare with `hp_decode` over
1,000 random single-node tries.

The memo of proven-absent slots (`absent_slot_count()` is its size): a proven miss enters once,
an unprovable miss never does and is recorded on every read, a miss answered before the memo
enters nothing, a rebuild clears it, and a wiped account never reaches it.

### GridMPT fold over HashState

The fold tests exercise `GridMPT<true, HashState>`. The fold reads nodes only from the node store
(`add_node`), not from the caches `build_state_from_trie` fills.

The expected root is computed by hand, not by a DirectState fold: DirectState reads a serialized
`MphfMap` bundle produced by the host-side builders, which is impractical to assemble from raw
nodes. The tests compute the post-write root with the canonical encoders the fold uses
(`encode_line` in `rlp_sw.hpp` sends a branch to `encode_branch` and a leaf to `encode_leaf`), so
`keccak(encode_branch(post-state root))` is a valid oracle.

### Accept check tests

The span-based overload is checked against the hand-computed oracle of the fold tests. The gather
tests drive real writes through the overlay mutators and check that:

- the gathered decision matches the oracle and the span-based overload given a hand-built span
  for the same writes,
- an unconfirmed read still makes it reject,
- a built account the block only read is skipped: the root stays the pre-state's, the same
  account is folded once `set_nonce` modifies it, and one read and then destructed still folds
  as an `0x80` delete next to a skipped one,
- every mutator, including each `apply_state_diff` shape, leaves a read built record `modified`
  or `deleted`, the premise of the skip.

One case runs the skip over the tests-zkevm sample: folding all the built accounts the payload
names gives the parent root, which the gather (skipping them all) accepts.

### Omitted BLOCKHASH ancestor

A soundness regression test. A block that reads `BLOCKHASH(k)` for an in-range ancestor whose
header the witness omitted must be rejected even when the recomputed post-state root matches
`header.state_root`: a block that persists `SSTORE(slot, BLOCKHASH(k))` over a silent zero, with
`header.state_root` set to that execution's root, would otherwise be accepted. The read fails
closed through `unconfirmed_read_count_` (see "Block headers and BLOCKHASH"). A second case pins
that a witness header numbered like an ancestor but not on the parent chain is never BLOCKHASH of
that number. A read of a present ancestor records nothing.

### Stateless input front end

Two kinds of input are decoded into a HashState and built:

1. The tests-zkevm v21.0.1 sample in `slib_sample_fixture.hpp`: the payload's hash tree root is
   checked against the root its `statelessOutputBytes` commits to, the rebuilt block's hash
   against the payload's `block_hash`, and the pre-state is built against the parent header's
   state root.
2. A synthetic blob encoded into the exact wire layout from a small complete trie, for the clean
   `missing_count() == 0` path and a storage cross-check.

Malformed inputs return `std::nullopt` with no out-of-bounds read. The streamed feed has its own
cases: a non-monotone offset part-way through leaves exactly the elements before it fed (the
contract that the caller discards a partially fed `HashState`), a list announcing more than the
count cap is rejected before any store is sized, and counts past `kMaxReserve` size the indexes
like `kMaxReserve`. `ssz_merkle_test.cpp` reproduces the roots ere-guests asserts for its
synthetic payloads and request containers.

`slib_sample_fixture.hpp` is generated; do not edit it by hand. Its source is the tests-zkevm
v21.0.1 corpus as ere-guests ships it (`crates/stateless-validator-test/fixtures`), case
`shanghai/eip4895_withdrawals/withdrawals/newly_created_contract.json`, the smallest
single-payload valid block with a transaction and a withdrawal. The constants are the fixture's
`statelessInputBytes`, `statelessOutputBytes` and `blockHash`, and the counts the SSZ framing
gives.

### Write overlay and mutators

The address-keyed readers hash the address internally, so a fixture that must be reached through
the built cache is keyed by the real `keccak256(addr)` path (`add_single_account`, `keccak_addr`,
`nibbles_of`). Overlay-only scenarios use any address on an empty-trie HashState and run
`build_state_from_trie(kEmptyRoot)` first, so a fresh account's `confirm_absent` proves absence
and records nothing.

Each of the two divergences from DirectState ("Write overlay") has its own case: (a) a zero
storage write is retained, and (b) `apply_code_diff`, destruct and revive set the
`storage_wiped_` flag.

### Per-transaction read view

`HashStateView` forwards faithfully: a present account's fields, storage and code come through,
`has_storage` reflects the account's `storage_root`, and empty and absent keys give the blank
results. The cases run off the pristine built cache.
