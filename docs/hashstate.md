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
  insert. No mainnet witness in the benchmark corpus repeats a node or a code.
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
  cleared at every sweep entry.
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
  storage arena by 32 bytes and right-aligns the trimmed word into them.

Child validation is lazy. `decode_node` validated the child items before any
child was visited (items 2 to 15 strictly, items 0 and 1 through the looser
`fill_branch_child`, which tolerated a string item there), so a malformed item
in a branch dropped the whole branch; the sweep applies the strict grammar to
all sixteen slots and stops a branch at the first malformed item, after the
children before it were swept. Either way the witness is malformed and
`build_state_from_trie` returns `kMalformed`, so the block is rejected.

Every shape `decode_node` rejects sets `malformed_witness_` where the sweep meets
it: a referenced node that is not a list, a truncated or list-typed path or value
item, a path past 64 nibbles (a branch at depth 64, or an extension or leaf that
would pass it), a leaf with no value or one over `kMaxLeafValueSize`, an
extension whose child is not a 32-byte string, a malformed branch child item, and
a branch whose 17th item (its value) is not the lone `0x80` that ends the
payload. The account and storage tries have fixed-length keys, so no branch
carries a value. A hash-ref child absent from the node index is not malformed,
it is a pruned boundary.

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
  `HashIndex<64, &storage_key8, uint8_t>` holding a constant 1 per entry), so a
  repeated miss of the same slot, which a block often makes, is answered from
  the memo without another walk. Only a proven miss is entered; an unprovable
  one is recorded on every read, as before. The memo is sound because a proof
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
and `unconfirmed_read_count_` is `mutable`: a read never mutates the caches,
only this diagnostic.

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
index. A block that calls `BLOCKHASH(N-256)` a million times otherwise walks
255 lookups each time (the `test_blockhash[block_1]` benchmark case went from
4.1 T to the cost of the other BLOCKHASH cases).

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
  inside node RLP: the sweep probes the node index once per present child ref (most of
  them pruned-sibling misses), and a 32-byte copy per probe was a library `memcpy` call
  from an arbitrarily aligned blob pointer.
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
  store. A plain `memcpy` of the key bytes into the bucket compiled, in the guest, to a
  library `memcpy` call per claim (a 32- or 64-byte block move with an unknown-alignment
  side is over the strict-alignment inline limit) followed by byte stores of the 16-byte
  view value through `memcpy`'s untyped return pointer: about fifty avoidable
  instructions per witness node and code added, and per entry rehashed.
- Capacity is sized to about twice the expected entry count (load factor about 0.5).
  This keeps probe runs short and guarantees that a free bucket exists, so every lookup
  terminates on the empty sentinel. A value-initialized `Value` is reserved as that
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
  zero-fills a new table and rehashes every entry (a 1,024-node hint against an average
  mainnet witness of about 11,500 nodes doubled the node index four times). It never
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

The cap is 2.6x the largest mainnet witness in the benchmark corpus (24,678 nodes), so a
real block pays no growth, while a hostile offset table announcing the count cap (2^20
elements, a 4 MB table) cannot make the guest zero-fill on the order of 100 MB of buckets
per store up front. Growth still backstops any count above a hint. Accounts run near
`nodes / 15` on the corpus (at most 1,685), so `nodes / 8` covers them; the storage cache's
4,096 covers the corpus maximum of 3,606 slots, and a bigger storage table would only cost
its zero-fill of 72-byte buckets.

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
accept  <=>  new_root == header_state_root
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

A write whose fold has to descend into a pruned boundary is still caught
without a fourth condition: `GridMPT` cannot unfold the absent node, so it
recomputes a non-matching (zero) root and `new_root == header_state_root`
fails.

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
- **Destructed accounts.** A destructed account (`deleted`) that has a
  pre-trie leaf (`find_built_account` hits) emits an `account == nullptr`
  write, which becomes a `0x80` leaf delete. A created-then-destructed account
  (`find_built_account` misses) is skipped. The probe is the side-effect-free
  `find_built_account`, not `get_account`, so a legitimate miss never bumps
  `unconfirmed_read_count_` and wrongly rejects the block.
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

| Pattern | Fixture files |
| --- | --- |
| `test_validation_codes_missing_*` | 9 |
| `test_validation_state_missing_*` | 6 |
| `test_validation_headers_*` | 5 (all negatives) |
| `test_invalid_stateless_input_bytes_are_rejected` | 1 (8 parametrized cases) |
| `test_witness_header_ssz_*` | 1 (a witness header padded to the `ByteList[1024]` limit and past it; 256 headers that fail the chain check, 257 that fail to decode) |
| `test_witness_state_rejects_*` | 1 (a trie path longer than the 64-nibble key) |
| `test_validation_state_unchanged_*`, `missing_*` variants only | 3 (a proof dropped for an account, slot or request queue the block reads but leaves unchanged; the `complete_witness` variants must be accepted) |

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

`StateTransition::run` dispatches on the input's first bytes: the `EJSN` and
`MFBD` magics, or the big-endian schema prefix `15 01` of a raw
statelessInputBytes blob (`kInputMagicSIB`, reserved next to the magics in
`flat_bundle.hpp`; no other magic starts with `0x15`). The latter goes to
`StateTransition::run_sib`, the entry point the ERE harness uses: ere-hosts
hands the guest the fixture's `statelessInputBytes` unchanged on stdin and
compares the public values with its `statelessOutputBytes`.

`run_sib` decodes the input and the payload, takes the payload's hash tree root,
and selects the chain config by `chain_id` the way the host adapter does (1 is
the generated EEST corpus, Amsterdam from genesis; 11155111 is Sepolia; the
devnets by their ids). The block comes out of `slib_payload_block`, its hash
and the versioned hashes are checked against the request (`engine_mismatch`,
as the MFBD path does), the parent is the last witness header and its state
root anchors the pre-state, and `run_sib_block` runs and accepts the block.

The public values are the 43-byte SSZ `StatelessValidationResult`
`{new_payload_request_root, successful_validation, chain_id, schema_id}`: a
rejected block is a result with `successful_validation` false, not a failed
run, and only an input that does not decode leaves the result all zero
(`schema_id` 0). The guest writes those 43 bytes and nothing else
(`prover/guest_hypercube/src/main.cpp`). The DirectState guest reports the
input as unsupported.

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

  `make zkevm-fixtures` downloads the corpus (`tests-zkevm@v21.0.6`, the
  release ere-guests tests against). Results are in
  [slib_corpus_validation.md](slib_corpus_validation.md).

### SP1 cycle benchmark

`make slib-benchmark` measures the HashState guest's SP1 cycles on the
`tests-zkevm-benchmark@v21.0.5` blocks (the 30M-gas tarball); the results, and
the same corpus through ERE's cost estimator, are in
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

Lookup soundness therefore rests on the full-key compare done at every occupied bucket the probe
visits (see "Buckets and probing"). A collision must never return the wrong key's offset.

The forced-collision cases build keys that share a key8, and so share a home bucket. They check
that each key still resolves to its own value, and that an absent key stops at the empty
sentinel. `HashIndex forced collision resolved by probe + full-key compare` covers 32-byte keys,
and `HashIndex 20-byte address keys` adds a collision between two addresses (a 20-byte key is
not a multiple of 8, so this one exercises the `memcmp` fallback). `HashIndex 64-byte storage
keys` covers the storage index: two keys with the same `storage_key8` (the same XOR of the two
halves' prefixes) but different leading words each resolve to their own value, which a compare
of the stored key's first word against the key8 would wrongly miss.

The collision, sentinel and wraparound cases run every lookup through `find_ptr` as well as
`find`. `HashIndex find_ptr through an unaligned pointer` probes from offsets 1, 3, 5 and 7 of
an 8-aligned buffer and expects the same hit, value and miss as the array form. `HashIndex
full-key compare covers every byte of a 32-byte key` (and the per-byte loop in the 64-byte
case) flips one bit at every byte position of a stored key and expects a miss from each, so a
word the compare skipped would show. The bucket sizes (40, 72, 24 and 48 bytes) are asserted at
compile time through `bucket_bytes()`.

`HashIndex reserve pre-sizes an empty table` checks `reserve` against the constructor's sizing
rule for a range of counts, that the reserved number of inserts then triggers no growth (the
capacity is unchanged afterwards and the load factor is at most 0.5), that a smaller reserve
never shrinks the table, and that a reserve on a table holding an entry is a no-op. `HashIndex
try_insert is first-wins where insert overwrites` checks the three outcomes: a first
`try_insert` claims the bucket, a repeat reports the key present and leaves the first value in
place (also after an `insert` overwrote it), a colliding neighbour is claimed by probing rather
than taken for the first key, the sentinel value is rejected, and filling past the hint grows
the table with every key still findable.

`HashIndex clear empties the table in place` checks `clear` on a memo-shaped table (64-byte
keys, `uint8_t` values): a no-op when empty, then every key misses, the count is zero and
the capacity unchanged, and the table takes keys again with no growth.

### Node and code store

`HashState` is the node and code store for the SSZ input path, parallel to `DirectState`'s
serialized `MphfMap` stores. `add_node` and `add_code` key their input by its real keccak256 and
record a view of a stored copy in an open-addressed `HashIndex<32, &hash_key8, StoredBytes>`;
`find_node_rlp` and `find_code` return that view.

The store tests cover round-trip, dedupe, a definitive miss, and the case that carries the most
weight: the full-key compare gate under a home-bucket collision.

`HashState full-key gate on home-bucket collision` checks that two distinct real keccak hashes
forced into the same index home bucket each resolve to their own payload (open-address probe plus
full-key compare), and that a third colliding hash that was never added still misses.
`HashState find_node_rlp by raw pointer matches the bytes32 overload` checks the raw-pointer
form the sweep and the confirmation walk use: from an unaligned pointer it returns the very
same stored view as the `bytes32` form, and misses on a never-added hash.
`HashState reserve_stores then borrowed adds dedupe first-wins` sizes a tiny-hinted store for
3,000 nodes through `reserve_stores`, adds them borrowed and finds each as the borrowed view
itself, then adds a repeat from a different buffer and checks the count is unchanged and the
view added first is the one indexed (for the code store too); a later `reserve_stores` on the
populated stores changes nothing.

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
fixtures canonical and readable: they are the same bytes the sweep reads back.

`HashState build_state_from_trie account sweep` includes an embedded inline leaf E under a deep
branch: `root[0x8]` -> extension (60 nibbles) -> `branch2` -> embedded leaf (2 nibbles, 1-byte
value).

- Embedded inline children only ever hang off a branch. An extension's child is always a 32-byte
  hash reference; the sweep, like `decode_node`, stops at an inline list as an extension child.
- The 60-nibble extension puts the branch deep enough that the leaf's 2-nibble remainder plus its
  1-byte value fit in fewer than 32 bytes, so the leaf is inlined into `branch2`'s RLP instead of
  being hash-referenced.
- The leaf is not added to the store. `build_state_from_trie` must decode it inline, with no
  lookup, so `missing_count()` stays 0.
- Its 1-byte value is not a decodable account. A real account leaf is always longer than 32 bytes
  (it holds two 32-byte hashes), so it can never be embedded. The leaf is counted as reached but
  never cached.

The sweep's frames and shared path buffer have their own fixtures:

- `resets the path per child across sibling extensions`: two subtrees of the root behind
  extensions of 50 and 2 nibbles, the long one first and ending in a branch with two leaves,
  then a direct leaf. All four accounts key correctly only if each child visit resets the
  shared path buffer to the root's prefix.
- `sweeps a branch at depth 63 and stops past 64 nibbles`: a branch at depth 63 whose
  children are empty-path leaves (HP byte `0x20`) at exactly 64 nibbles, a 63-nibble extension
  ending in an empty-path leaf, and two malformed subtrees (a branch at depth 64, a 71-nibble
  leaf path) that stop without emitting or touching a counter and make the build report
  `kMalformed`. The 62- and 63-nibble extension
  paths are 32-byte strings, the item shape a hash ref also has.
- `stops a branch at its first malformed child item`: a hand-built branch with hash refs at
  slots 0 and 1, a 1-byte string at slot 2 and a hash ref at slot 5. The leaves under slots 0
  and 1 are cached, nothing under slot 5 is, no counter moves and the build reports
  `kMalformed`: the lazy child validation described under
  [Building state from the trie](#building-state-from-the-trie).
- `rejects every node shape decode_node rejects`: one hand-built node per shape (a root that
  is not a list, a branch with a non-empty, missing or over-long 17th item, a leaf with no
  value or an oversized one, an extension with a short-string or inline-list child, a list
  where a path belongs, an item running past its node), each expected to give `kMalformed`,
  plus a well-formed branch with its last slot present as the control.
- `decodes one-nibble leaf paths, hashed and embedded`: a one-nibble HP path is a single byte
  below `0x80`, carried with no RLP header, here as a hash-referenced account leaf and as a
  3-byte embedded storage leaf decoded in place from its branch's bytes.
- `after a missing-root build derives the next root`: a build from an absent root followed by
  a build from a present one on the same instance.
- `caches nothing for an undecodable hashed leaf`: a leaf whose value is not an account is
  counted, not cached, and the accounts swept after it land intact, so the arena slot it was
  decoded into was given back.

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

The walk's own cases (`HashState confirm_absent ...`) pin its decision table along every kind
of path a miss can take, with the same fixtures:

- `reads the probe's root-branch slot, first to last`: diverging leaves at root slots 0, 1, 7
  and 15 (the first two are the items the walk classifies the node by, the last is reached
  after every sibling was skipped) and the empty slots 2 and 14, all proven.
- `skips to a pruned storage slot and records the read`: the same through `get_storage`, with
  a pruned child at slot 15 that leaves every read of it unconfirmed.
- `follows an embedded child in place`: root -> ext(60) -> branch -> embedded leaf(2). Probes
  that diverge inside the extension, at an empty slot of the deep branch, or on either nibble
  of the embedded leaf are proven; the leaf's own key, which the build did not cache (its
  value is no account), is refuted.
- `at a branch at depth 63 and past 64 nibbles`: an empty slot of a branch at depth 63 and a
  divergence inside its 62-nibble extension are proven, so is a leaf path that outlasts the
  key, while a branch at depth 64 and a 66-nibble HP path cannot confirm.
- `compares one-nibble and even HP paths`: divergences on a hashed and on an embedded
  one-nibble leaf, on the last nibble of an even extension and the first of an odd one, and
  at an empty slot of a deep storage branch.
- `refutes a leaf at the key the build did not cache`: the exact key is recorded on every
  read; a key one nibble off is proven by the same leaf.
- `stops at a malformed sibling before the probe's slot`: the hand-built branch with a 1-byte
  string at slot 2. The slots before it are proven exactly as the sweep swept them; every
  slot from it on, the empty marker right after it included, is left unconfirmed.
- `HP compare matches hp_decode on random paths`: 1,000 random single-node tries (a leaf or
  an extension with 0..64 path nibbles) probed with keys that share a random-length prefix
  with the path; the expected answer is computed from `hp_decode` over the node's own HP
  string and `nibbles64::from_bytes32` over the probe.

The memo of proven-absent slots (`absent_slot_count()` is its size):

- `HashState get_storage memoizes a proven-absent slot until the next build`: a proven miss
  enters the memo once and a repeat of it adds no entry and no record; an unprovable miss is
  never entered and is recorded on every read; a miss answered before the memo (an account the
  cache lacks, an empty storage root) enters nothing; a rebuild clears it and the first read
  after it walks again.
- `HashState read_storage of a wiped account never reaches the absent-slot memo`: before the
  wipe a cold slot is entered and a pruned one recorded; after it the memoized, the pruned and
  a fresh cold slot read zero with no entry and no record added.

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
then calls `host.get_block_hash(k)`, which reaches `HashState::get_block_hash(header, k)`: the walk
from the block's parent hash down to k. The real chain always has that ancestor's hash, so a walk
that stops at a header the store does not hold means the witness omitted a required header.

Before the fix, `get_block_hash` returned a silent zero and left both completeness counters at
zero. A block that persisted `BLOCKHASH(k)` (`SSTORE(slot, BLOCKHASH(k))`) with header k omitted,
and with `header.state_root` set to that forged execution's root, was accepted. With the fix, the
omitted-ancestor read fails closed: it increments `unconfirmed_read_count_`, and the accept gate
rejects. `HashState BLOCKHASH takes an ancestor's hash from its child, not from a header of its
number` covers the other half: a witness header numbered like an ancestor but not on the parent
chain is never BLOCKHASH of that number.

A read of an ancestor that is present still costs nothing, so legitimate partial witnesses, which
ship every ancestor they reference, keep validating.

### Stateless input front end

The slib front-end tests decode a statelessInputBytes blob (schema_id `0x1501`) into a HashState,
then run `build_state_from_trie`. There are two kinds of input:

1. The tests-zkevm v21.0.1 sample in `slib_sample_fixture.hpp`. The test decodes it, takes the
   payload's hash tree root and checks it against the root the fixture's `statelessOutputBytes`
   commits to, rebuilds the block and checks its hash against the payload's `block_hash`, and
   builds the pre-state against the parent header's state root.
2. A synthetic blob that the test encodes into the exact wire layout from a small complete trie.
   It covers the clean `missing_count() == 0` path and a storage cross-check.

Malformed-input tests must also fail cleanly: they return `std::nullopt` with no out-of-bounds read
and no crash. `ssz_merkle_test.cpp` reproduces the roots ere-guests asserts for its synthetic
payloads and request containers, field by field, and checks the padding and progressive shapes.
Two of the malformed-input tests cover the streamed feed. `slib stops the streamed feed at a
non-monotone state-list offset` corrupts the third offset of a three-node state list and expects
`std::nullopt` with exactly the first node fed (the element before the violation) and neither of
the others present, so the contract that a failed parse leaves a partially fed `HashState` for
the caller to discard is pinned. `slib rejects a state list announcing more than the node count
cap` builds a state list whose offset table really is `(cap + 1) * 4` bytes long (every entry the
table end, so the elements are well-formed and empty) and expects `std::nullopt` with nothing
fed, which is the count check rejecting it before any store is sized; the same shape with three
elements parses.

`slib_sample_fixture.hpp` is generated; do not edit it by hand. Its source is the tests-zkevm
v21.0.1 corpus as ere-guests ships it (`crates/stateless-validator-test/fixtures`), case
`shanghai/eip4895_withdrawals/withdrawals/newly_created_contract.json`, the smallest
single-payload valid block with a transaction and a withdrawal. The constants are the fixture's
`statelessInputBytes`, `statelessOutputBytes` and `blockHash`, and the counts the SSZ framing gives.

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
