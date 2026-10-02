# MFBD Design and Specifications — the MPHF-based Flat Bundle

*This document declares MFBD in principle: what it is, why it has the shape it has, and what a conforming verifier must check. The key words MUST, MUST NOT, SHOULD, and MAY are used as in [RFC 2119](https://www.rfc-editor.org/info/rfc2119). The byte-level layout is also documented, from the implementation's side, in [flat_witness_bundle.md](flat_witness_bundle.md); where the two differ, this document is normative.*

---

## 1. Introduction

A witness is the collection of state and other data necessary for a stateless node to process the state transition for a given set of blocks. In the zkVM context, the guest program does this by consuming it from the input bytes passed by the host.

The job of the state-transition function is to check that the given bits of state can be traced to the `pre_state_root` and that the given block(s) result in the claimed `post_state_root`.

Passing the witness on as an SSZ- or RLP-encoded byte string keeps it straightforward but comes with the added cost of decoding and memory operations. These are expensive on a bare-metal RISC-V system, and more so when proving in zkVMs such as Succinct SP1 and ZkSync Airbender.

This document describes the new design of a flat witness scheme based on a quasi-minimal perfect hash function (qMPHF). The target is to eliminate the need to create maps or copy bytes from the witness into newly created objects within the guest. The guest can instead reuse the memory-mapped witness region directly as its working objects and operate on that. The qMPHF is also operationally faster than other hash maps and has been further optimized for this use case.

### 1.1 The minimal perfect hash

A minimal perfect hash function (MPHF) is a function built for one fixed set of n keys that maps those keys onto exactly the slots 0 … n−1 with no collisions. It is built by starting with a fixed key-set and iterating over various trial "seeds" until the combination of the function and the seed set yields a perfect one-to-one map for the key-set.

The core idea is to create an MPHF-based Flat Bundle scheme (MFBD) where accounts are mapped by address, nodes and codes by their hashes, and everything is addressed by offset.

Further, the choice and use of the hash function exploit the fact that there is enough entropy in the hashes and addresses (all keccak-derived) that, for a small number of keys, only the first 8 bytes (64 bits) suffice, with extremely rare collisions. So we get fast O(1) lookups with 64-bit keys.

### 1.2 Witness as memory-mapped bytes instead of decoded

The governing intention of the format follows directly. The witness is a flat byte image that the guest maps in place and reads directly. It is not decoded.

The contrast is with an SSZ- or RLP-encoded witness, and it is worth making precisely, because the formats carry the same fundamental information (if supplemented with plain keys). An SSZ-encoded witness is a container of lists — a list of trie nodes, a list of code blobs, a list of headers — each list an offset table over variable-length elements.

To use it, the guest must first decode it into usable maps and objects. That is allocation, copying, and work proportional to the whole witness, and it happens before the first state read can be answered. Then, to find anything, the guest must search. Further, if the plain keys are not available, every piece of state would first need a traversal down the trie after hashing its key (address or slot).

The design here is tuned to its application. We are proposing to use a Plain-State scheme where addresses are unhashed and the intermediate trie nodes are looked up directly by their hashes. The MFBD maps `address->Account`, `storage_slot->value`, `code_hash->code` and `node_hash->node_RLP`.

In MFBD a read is: hash the key to a slot, read the slot's offset, read a fixed-width record at that offset. The record is used where it lies, through unaligned-safe loads or through a typed view whose alignment has been validated. There is no decode pass or fresh allocation, because the on-wire image of every record is its in-memory image.

For security, however, the verifier must sweep the whole input, including a sanitization pass over every element of these MPHF maps, as discussed later in this document.

### 1.3 Key shortening, collisions, and the quasi-MPHF

For an honest key-set, `key8` collisions are not a practical concern. The shortening keeps 64 bits, so among n keys that are uniformly distributed (as keccak outputs and keccak-derived addresses are) the expected number of colliding pairs is about n(n−1)/2 ÷ 2⁶⁴ ≈ n²/2⁶⁵: roughly 3×10⁻¹² for ten thousand keys, 3×10⁻⁸ for a million, and a collision only becomes more likely than not near 2³² (about 4×10⁹) keys, far beyond any witness.

Collisions must nonetheless be handled, for two reasons. First, the key-set is adversarial. Anyone who can deploy contracts or write storage chooses keys, and finding two keys of their own that share a `key8` — two `CREATE2` addresses, two pieces of code, two trie nodes — is a birthday search of about 2³² keccak evaluations, which is cheap on commodity hardware. (Matching the `key8` of one specific existing key is a 2⁶⁴ preimage search and remains infeasible, but that is not what the attacker needs.) Second, a truly perfect placement can be expensive to find, and the producer's cost is bounded by design: the parameter search is capped at a fixed number of trials (§5), after which the keys that could not be placed are spilled to a sidecar rather than retried.

We therefore treat collisions as an inherent property of this map and provide for handling them safely. In that sense, ours is a quasi-MPHF.

**Key shortening.** The MPHF does not hash the full 20- or 32-byte key. It hashes `key8`, a 64-bit shortening of the key, defined as follows.

For a 32-byte key — a code hash or a node hash — `key8` is the key's first eight bytes read as one unsigned 64-bit little-endian integer: byte 0 of the key is the least significant byte of the word and byte 7 the most significant.

For a 20-byte address, `key8` is the address's first eight bytes read the same way, except that the most significant byte of the word is taken from the address's last byte, byte 19, instead of byte 7. The exception exists for the precompile addresses, which are zero in every byte but the last: a shortening taken from the first eight bytes alone would give all of them one `key8`, and the whole set would become a single `key8` collision.

**2-stage lookup.** `key8` enters the lookup through two rounds of one hash. The verifier adds the map's salt (`seed_factor`) to `key8`, mixes the sum once with a one-round SplitMix64 stage-1 mixer (the first xorshift-multiply-xorshift stage of Stafford's Mix13 finalizer, which SplitMix64 adopted; the second multiply round is dropped), and reduces the low 32 bits of the result to a bucket with the [Lemire multiply-high reduction](https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/); it then adds that bucket's 64-bit displacement to the salted key, mixes the sum again with the same mixer, and reduces its low 32 bits again, this time into the range of slots. Every addition wraps at 64 bits.

The one-round variant is a deliberate trade. The full finalizer's second multiply buys avalanche quality that a hash table does not need: the mixer's only job here is to spread the salted key across the bucket and slot ranges well enough that the producer can find displacements, and the producer verifies that empirically for the exact key-set it ships. Dropping the round saves one 64-bit multiply and one shift per mix, two per lookup, on the proving path. The variant is not cryptographic and does not need to be: a bad or malicious mix can only produce a miss (§3.4), never a wrong hit.

**Why 64 bits.** An unsigned 64-bit integer is the native integer on both host and guest; both are little-endian, so forming `key8` from a hash is one 8-byte load of the key's first word with no byte swap, and the address form adds one byte load and three bit operations. Every step from there to the slot — the addition of the salt, SplitMix64's shift, xor, and multiply, and the Lemire reduction, whose 32×32-bit product fits in one 64-bit register so that taking its high half is a single multiply and a shift — is a handful of single-register native instructions on one value.

This avoids any loop over the key's bytes and any multi-limb arithmetic, and the only memory traffic on the way to the slot is the key's first word, one displacement, and one slot offset. Mixing the full 20 or 32 bytes to the same quality would take several dependent rounds over three or four words on every read. And because every lookup is confirmed against the full-length key, collisions included, the shortening is both cheap and safe.

**Collision handling.** A collision can occur in two ways:

1. **`key8` collision.** Shortening two distinct full keys yields the same `key8` value.
2. **Placement spill.** Two `key8` values map to the same slot index because the producer exhausted its placement trials (§5).

Both are handled in the same fashion: the slot offset assigned to the colliding keys in the final lookup table is 0, which is the convention that directs a second lookup to the collision sidecar. The collision sidecar is placed just before the MPHF data section and contains a sorted list of (`key8`, offset) pairs (see §5).

### 1.4 The three MPHF maps stored in MFBD

An MPHF is the right structure for exactly one access pattern, and MFBD uses it for exactly the elements that have it. The pattern is: read by key, at random, many times, with a fixed-width key, where O(1) per read matters because the reads are on the proving path. Three elements of the witness fit it, and three MPHFs are what the format carries.

- Accounts by address (magic `MPHA`)
- Contract code by 32-byte code hash (magic `MPHC`)
- RLP-encoded trie nodes by 32-byte hash (magic `MPHN`)

Besides these, the bundle carries:

- The address-hash array — keccak(address) for every account, sorted by hash.
- Storage slots, placed inline with their account and sorted by slot key. These are small sets, where a plain array scan is faster than a map lookup.
- Blocks, genesis, and ancestor headers, as plain RLP.

---

## 2. The bundle at a glance

The witness is one MFBD envelope — a 16-byte header of magic, version, and count — carrying one or more FlatBundles. Each FlatBundle is a fixed 56-byte header of offset-and-size pairs followed by six sections in a fixed order, each beginning on an 8-byte boundary: `genesis`, `blocks`, `ancestors`, `pre_state`, `node_store`, and `network`.

The three MPHF maps and the plain arrays of §1.4 live in `pre_state` and `node_store`; the other sections are RLP or raw bytes. Every element is reached by offset from the mapped base and read where it lies (§1.2).

```
MFBD envelope  [16 B: magic "MFBD" 0x4442464D · version 1 · n_bundles u64]
└─ FlatBundle × n_bundles, each padded to 8 B  [header "FBND" v13, 56 B]
   ├─ genesis     RLP-encoded block
   ├─ blocks      [n_blocks u64] · block RLPs · optional flags[n_blocks], 1 B each
   ├─ ancestors   RLP list of headers, oldest first; the last is the parent
   ├─ pre_state   blob  [magic "PRES" v4, 68 B + 4 B zero pad]
   │  ├─ acc map      "MPHA": address → Account 256 B · Slot[slot_count] 96 B each
   │  ├─ addr hashes  [n_accounts] addr_hash 32 · addr 20 · entry_offset u32; sorted
   │  ├─ block hashes [n_block_hashes] block_number u64 · block_hash 32; sorted
   │  └─ code map     "MPHC" code_hash → [code_hash : 32][code bytes]
   ├─ node_store  "MPHN" node_hash → [node_hash : 32][MPT node RLP]
   └─ network     chain name, raw UTF-8, no terminator

each MPHF map:  [MphfMapHeader 56 B, v2] · displacement[n_buckets] u64 · slot_offsets[n_keys] u32 · collisions[] 16 B each · data arena of [body_len u64][body], 8-B padded
records:        Account 256 B · Slot 96 B, inline after its Account · hash-keyed body = [key : 32][payload], variable length
```

**What each section is for.**

- **Envelope** — format guard and bundle count.
- **FlatBundle header** — locates the six sections by offset and size.
- **genesis** — the chain's starting block for this bundle.
- **blocks** — the full RLP of each block to execute, in order, with an optional flag trailer for negative test cases.
- **ancestors** — the headers `BLOCKHASH` may reach; the last is the parent of the first block, and `pre_state_root` is its `state_root`.
- **pre_state (PreState)** — the account map with each account's storage slots inline, the address-hash array, the block-hash entries that answer `BLOCKHASH`, and the code map (§1.4).
- **node_store** — the trie nodes the root recompute walks from `pre_state_root`.
- **network** — the chain configuration under which the blocks execute.

Each section's layout, checks, and construction are given in §4; the MPHF map layout shared by the three maps in §5.

---

## 3. Validations

Two attack vectors recur often enough to be named, and the labels are used throughout §3–§5:

- **B1 — code-length forgery.** Code stored in the code map under a hash it does not have, or a length carried anywhere other than the code body itself (an account field, a sidecar entry) that would truncate or extend what the EVM executes.
- **B2 — missing node as empty subtree.** A trie node absent from the node store on a walked path, which a verifier that does not fail closed would treat as an empty (absent) subtree, letting present state be read as absent.

### 3.1 Trie membership validations

Since the state is passed in full and used directly instead of being derived from the trie, it must be validated against the trie. In principle, every element read from the `pre_state` passed in through MFBD MUST be traced to its previous state root, and every "empty" read MUST be verified to have a terminating empty path or leaf within the trie.

The process is straightforward, and it also closes off some attack vectors. The `address_hashes` list gives a sorted list of the hashed addresses present in the `pre_state`. This list can be walked, and the initial account and storage-slot values for each address derived from or verified against the trie. The trie MUST be traversed for each entry in this check.

Further, all empty reads MUST be recorded, and a post-block check MUST verify that each recorded empty read is indeed empty in the trie. This also requires the witness (MFBD or any other format) to carry absence proofs for all empty reads (the completeness assumption).

### 3.2 Structural guards

**Magic and Version.** The verifier MUST require the correct magic and version for the bundle and each sub-section to avoid misinterpretation.

**Alignment guards.** The producer lays every section and every sub-region out on an 8-byte boundary (§4). The verifier MUST check 8-byte alignment wherever it lays a typed view over the bytes: the envelope base and each FlatBundle, the `pre_state` and `node_store` offsets, and inside them every MPHF region, record array, and data-arena entry (§4.2, §4.3, §5). Regions the verifier only decodes as RLP or reads as raw bytes — `genesis`, `blocks`, `ancestors`, `network` — carry no alignment requirement the verifier depends on. The one 4-aligned structure, the PreState meta header, is followed by four bytes of padding so that everything after it is 8-aligned (§4.3).

**Size.** Every section MUST be at least as large as its expected header. Every expected item MUST have at least the minimum size for its type. Offsets MUST lie within the bounds of their section and before the end of the overall MFBD byte region.

**Non-overlap.** All sections and sub-sections MUST be pairwise non-overlapping.

**Chain anchoring.** The ancestor headers MUST form a linked chain ending at the parent of the first block; the pre_state_root is taken from that parent header.

*Mitigates:* a foreign or mis-versioned byte image read under a layout it was not written to; crafted offsets and lengths that read out of bounds, land on an unaligned address, or fault the guest; sections that overlap so one region masquerades as another; an unanchored or forked ancestor chain that would let `pre_state_root` or a `BLOCKHASH` answer come from a header of the adversary's choosing.

### 3.3 Data Sanity

**Code sanity.** Every code in the MPHC section MUST match its declared index, cross-checked with keccak(code). Every code hash declared by an account whose code is read during execution MUST be present in the code map. MPHC MUST NOT contain duplicates.

**Node sanity.** Every node's index MUST agree with the keccak of the node RLP stored in the node_store. All required nodes MUST be present in the store. MPHN MUST NOT contain duplicates.

**Addr sanity.** Address hashes MUST match the keccak of every address present in the `pre_state`, and those hashes MUST be the ones used for the trie validation paths. There MUST NOT be duplicate account entries in the `pre_state` or in the addr_hashes list.

**Data Length.** Every variable-length byte item from the state MUST have a length consistent with the keccak that references it in the trie. An Account body MUST be large enough to hold `slot_count` 96-byte `Slot` records.

**Order.** Every list that is expected to be sorted MUST be sorted; this includes the addr_hashes list, storage slots, block hashes, and the collision sidecar.

**Flags.** Test and debug flags exist for testing and debugging only; they MUST NOT influence production verification.

**Scratch.** Scratch fields inside records MUST be zeroed or ignored before use so no attacker-chosen bytes reach execution.

*Mitigates:* B1 — code stored under a hash it does not have, or a wire code length that truncates or extends what the EVM executes; a trie node substituted under a genuine reference; an address table with duplicate, unordered, or misrouted entries, or an `addr_hash` that is not the trie key of its address; a slot array that runs past its body; a mis-sorted table that hides an entry from a binary search; a flag that tells the verifier which answer to give; wire scratch read as state.

### 3.4 Execution

**Lookup.** Every MPHF hit and every collision-sidecar entry MUST be confirmed by comparing the full 20- or 32-byte key; a mismatch MUST be treated as a miss, never a match, and an occupied slot whose key differs MUST NOT fall through to the sidecar. A slot offset of 0 means consult the sidecar, never a body. The salt in use MUST be `seed_factor` as stored; `seed` MUST be ignored and the index MUST NOT be rebuilt.

**Body length.** A record's length MUST be read from the `body_len` prefix in the data arena — the only length source; neither the index nor a sidecar entry carries one.

**Reads.** Every state read, including one that finds nothing, MUST produce a durable record that the recompute walks — no read is invisible.

**BLOCKHASH.** A `BLOCKHASH` query MUST be answered only from an entry whose hash equals that of the ancestor header of the same number; an in-range request with no entry MUST fail closed.

*Mitigates:* a misrouting index or forged sidecar that lands a query on another key's record — the only outcome is a miss, so a hostile index can move accept to reject, never reject to accept; B1 via a length carried in a sidecar entry that would truncate or extend code; a present item omitted so the EVM sees it as absent — the recorded empty read is walked and fails; a forged or omitted `BLOCKHASH` entry.

---

## 4. Bundle Specifications: section by section

The container is a strict tree of length-delimited sections, each beginning on an 8-byte boundary. Every multi-byte scalar is little-endian. Hashes, addresses, storage keys, and storage values are raw byte arrays in their natural on-chain order. There is no checksum and no MAC anywhere: integrity comes from the keccak bindings and the root recompute, and the magic and version fields are format guards, not integrity checks. The trees below give field names and sizes.

Each section is described four ways: what the bytes mean (Interpret), how the verifier consumes them (Process), what MUST be checked (Verify), and what the producer MUST do (Create).

### 4.1 The envelope

```
MFBD envelope                         16-byte header, then the bundles
├─ magic          u32                 "MFBD" = 0x4442464D
├─ version        u32                 1
├─ n_bundles      u64                 number of FlatBundles that follow
└─ bundles[]                          FlatBundle × n_bundles, each padded to an 8-byte boundary
```

**Interpret.** Sixteen bytes — a magic, a version, and a count — followed by that many FlatBundles. There is no per-bundle length: a bundle's extent is defined by the section spans in its own header, and the envelope trusts nothing about it beyond that.

**Process.** The reader positions a cursor at the end of the header, parses one FlatBundle, and advances the cursor to the next 8-byte boundary past that bundle's extent. It repeats `n_bundles` times.

**Verify.** The reader MUST require the magic and version shown. Every bundle MUST begin on an 8-byte boundary relative to the envelope, and the envelope itself MUST lie on an 8-byte boundary in memory before any typed view is laid over it.

**Create.** The producer writes the header, then each FlatBundle, padding to an 8-byte boundary between bundles. The last bundle MAY be written without trailing padding. A mainnet producer emits exactly one bundle; a test producer MAY pack several.

### 4.2 The FlatBundle

```
FlatBundle                            sections in this order, each starting 8-byte aligned
├─ FlatBundleHeader    56 B           "FBND" = 0x444E4246, version 14
│  ├─ magic, version   u32 × 2
│  ├─ genesis_rlp      off, size      u32 × 2
│  ├─ blocks_rlp       off, size      u32 × 2
│  ├─ ancestors_rlp    off, size      u32 × 2
│  ├─ pre_state        off, size      u32 × 2     off MUST be a multiple of 8
│  ├─ node_store       off, size      u32 × 2     off MUST be a multiple of 8
│  └─ network          off, size      u32 × 2
├─ genesis                            RLP-encoded block
├─ blocks
│  ├─ n_blocks         u64
│  ├─ block[i]                        full block RLP, each padded to 8 bytes; length from its own RLP header
│  └─ flags[n_blocks]  1 B each       OPTIONAL trailer; bit 0x01 = EXPECT_INVALID
├─ ancestors                          RLP list of ancestor headers, oldest first; the last is the parent
├─ pre_state                          PreState blob, "PRES" version 4          (§4.3)
├─ node_store                         node MPHF, "MPHN"                        (§4.4)
└─ network                            chain name, raw UTF-8, no terminator
```

**Interpret.** The header is a magic, a version, and six offset-and-size pairs locating the sections after it. `genesis` and `ancestors` are standard Ethereum RLP — MFBD adds no framing or encoding of its own: `genesis` is the chain's starting block for this bundle — a header-only encoding of the parent on mainnet, the actual genesis block on a test bundle; `ancestors` lists the headers `BLOCKHASH` may reach, oldest first, its last element the parent of the first block, whose `state_root` is `pre_state_root`. `blocks` opens with a count and holds each block's complete RLP padded to 8 bytes — no per-block length, because RLP is self-delimiting — followed by an optional one-byte-per-block trailer marking blocks the producer expects to be rejected, so a bundle can carry negative test cases. `network` names the chain configuration under which the blocks execute.

**Process.** The verifier decodes each block in turn — advancing by the length its RLP header declares, rounded up to the next 8-byte boundary — lays the PreState view over `pre_state`, and opens `node_store` as an MPHF. The verifier resolves the parent block by looking up the first block's `parent_hash` in the headers supplied by `genesis` and `ancestors`; that header's `state_root` becomes `pre_state_root`, and a bundle whose parent header is absent MUST be rejected. The trailer is present if and only if at least `n_blocks` bytes remain in the section after the last block's padding.

**Verify.** The structural guards of §3.2 apply to the header and every section: magic and version, offset plus size within the bundle, `pre_state` and `node_store` at multiples of 8, non-empty sections pairwise non-overlapping. The node store's MPHF regions MUST be validated before any lookup (§5). Chain anchoring is concrete here: the last ancestor MUST be the parent of the first block — its number one less, its hash equal to the block's `parent_hash` — and each earlier ancestor MUST be the parent of the next; otherwise `pre_state_root` is unanchored and the bundle MUST be rejected. `network` MUST name a chain configuration the verifier recognizes.

**Create.** The producer lays the sections out in the order shown, aligning each to 8 bytes, and records the resulting offsets and sizes in the header. It MUST write the parent header as the last ancestor and MUST fail rather than emit a bundle whose ancestor chain does not end at the parent. It MUST write the flag trailer if any block is flagged and MAY omit it otherwise.

### 4.3 pre_state — the PreState blob

```
pre_state  (PreState blob)            all offsets relative to the blob start
├─ PreStateMeta        68 B           "PRES" = 0x53455250, version 4; the one 4-aligned structure
│  ├─ magic, version         u32 × 2
│  ├─ n_accounts             u32
│  ├─ n_block_hashes         u32
│  ├─ prestate_offset        u32      → account MPHF ("MPHA")
│  ├─ addr_hashes_offset     u32      → AddrHashEntry[n_accounts]
│  ├─ block_hashes_offset    u32      → BlockHashEntry[n_block_hashes]
│  ├─ code_store_offset      u32      → code MPHF ("MPHC")
│  ├─ code_store_size        u32      0 = no code map
│  └─ reserved               32 B     written as zero
│  (4 bytes of zero padding; the account MPHF begins at 72)
├─ account MPHF        "MPHA" = 0x4148504D, 20-byte key = address
│  └─ body per key:    Account (256 B) followed inline by Slot[slot_count] (96 B each)
├─ AddrHashEntry[n_accounts]          56 B each, sorted strictly ascending by addr_hash
│  ├─ addr_hash        32 B           keccak(address) — the account's state-trie key
│  ├─ addr             20 B
│  └─ entry_offset     u32            offset of this account's entry in the MPHA data arena
├─ BlockHashEntry[n_block_hashes]     40 B each, sorted strictly ascending by block_number
│  ├─ block_number     u64
│  └─ block_hash       32 B
└─ code MPHF           "MPHC" = 0x4348504D, 32-byte key = code_hash
   └─ body per key:    [code_hash : 32][code bytes]
```

**Interpret.** The pre-state the blocks read. The meta header is the one structure in the format whose natural alignment is 4 rather than 8 — nine 32-bit fields and a reserved tail — so four bytes of zero padding follow it and the account MPHF begins at offset 72. The **account MPHF** is keyed by the raw 20-byte address; each body is an `Account` followed immediately by that account's touched storage slots, so an account and its slots are one contiguous record. The **code MPHF** is keyed by the 32-byte `code_hash`; each body is the code under its hash. Between them sit two sorted arrays: `AddrHashEntry` lists every account by its trie key `keccak(address)`, ascending, with the address and the offset of the account's body — the ordered view the walk of §3.1 needs, precomputed so the verifier does not derive it; `BlockHashEntry` lists ancestor block hashes by number for `BLOCKHASH`.

**Process.** During execution the verifier reads accounts and slots through the account MPHF, by address, and code through the code MPHF, by hash. During the root recompute it iterates `AddrHashEntry` in order, going from each trie key straight to its account body through `entry_offset` without a second index probe. `BLOCKHASH` binary-searches `BlockHashEntry` by number.

**Verify.** The structural guards of §3.2 apply to the blob and every offset in it, and both MPHFs' regions MUST be validated before any lookup (§5). The sanitization pass (§3.3) MUST then establish the **account bijection**: `AddrHashEntry` strictly ascending by `addr_hash` with no duplicates; `keccak(addr)` equal to `addr_hash` for every entry; `entry_offset` naming the body the account MPHF routes `addr` to, so its `Account.addr` equals `addr`; and every account body in the region reached by exactly one entry. This ties the trie-key view to the keyed store, so that the walk of §3.1 enumerates exactly the records the EVM read. Every code body MUST re-hash to its `code_hash`; for every account with `code_store_len > 0` the code MUST be present in the code MPHF, and the executed code length MUST be derived from the code body's own length, never from the account's wire field (B1; §3.3, §3.4). `BlockHashEntry` MUST be strictly ascending by number, and `BLOCKHASH` MUST be answered only from an entry whose hash equals that of the ancestor header with that number; an in-range ancestor with no entry MUST fail closed (§3.4).

**Create.** The producer serializes each touched account and its slots, builds the account MPHF over the addresses and the code MPHF over the distinct code hashes, writes one `AddrHashEntry` per account with `entry_offset` set to where the freshly built account MPHF placed that account's body, sorts the entries by `addr_hash`, writes one `BlockHashEntry` per ancestor header sorted by number, lays the parts out in the order shown with 8-byte alignment, and fills in the meta offsets. `code_store_size` MUST be 0 when no account carries code. `reserved` MUST be written as zero.

### 4.4 node_store — the trie nodes

```
node_store                            one MPHF, "MPHN" = 0x4E48504D, 32-byte key = node hash
└─ body per key:
   ├─ node_hash        32 B           keccak(payload)
   └─ payload          …              one hexary-MPT node, standard RLP (branch, extension, or leaf)
```

**Interpret.** A single MPHF keyed by node hash. Each payload is an unmodified Ethereum Merkle-Patricia-trie (MPT) node exactly as it hashes on chain — no bespoke encoding; the store is a content-addressed set of the nodes the recompute walks, and nothing else. Only nodes whose RLP is 32 bytes or longer appear; a shorter child is embedded inline in its parent by the MPT encoding and is read from there.

**Process.** The root recompute starts at `pre_state_root`, fetches the node with that hash, decodes it, and descends along each touched key, fetching each 32-byte child reference from the store as it reaches it. Nodes not on any walked path are never fetched; untouched subtrees stay behind their parent's original reference.

**Verify.** The MPHF regions MUST be validated when the bundle loads (§5), and node sanity (§3.3) MUST re-hash every payload and require `keccak(payload) == node_hash`. This ties a node's content to the 32-byte reference its parent carries, so the walk from `pre_state_root` (§3.1) can reach only content that hashes to what the committed tree says is there. A missing node on a walked path MUST be a failure, never an assumed-empty subtree (B2).

**Create.** The producer collects every trie node of 32 bytes or more on every path the block's execution walks — including the nodes that terminate the path of every absent key it reads — and builds the node MPHF over `keccak(node) → node`. It MUST NOT place a node shorter than 32 bytes in the store; the recompute never consults the store for one.

### 4.5 The value records: Account, Slot, and the hash-keyed bodies

```
Account   256 B
├─ addr                20 B           also the MPHA embedded key
├─ (runtime flags)      4 B           zero on the wire
├─ nonce               u64
├─ balance             32 B           unsigned 256-bit integer, LITTLE-ENDIAN
├─ code_hash           32 B           keccak(code)
├─ storage_root        32 B
├─ code_store_offset   u32            0 on the wire; resolved by the verifier
├─ code_store_len      u32            code length; re-derived by the verifier
├─ slot_count          u32            number of Slots that follow inline
├─ acc_rlp_buf        112 B           runtime scratch; zero on the wire
└─ padding              4 B           zero

Slot      96 B, laid out inline after its Account, sorted ascending by key
├─ key                 32 B
├─ initial             32 B           pre-block value
└─ current             32 B           equals initial on the wire

Hash-keyed body   shape of every body in the code store and the node store; variable length
├─ embedded_key        32 B           at body offset 0: code_hash or node_hash
└─ payload             …              at body offset 32: code bytes, or the RLP node; length = body_len − 32 (§5)
```

**Interpret.** `Account` and `Slot` are fixed-width plain-data records: an `Account` is always 256 bytes and a `Slot` always 96, so a typed view can be laid over them and any of their fields reached at a constant offset. The bodies of the two hash-keyed stores are not fixed-width: each is the full 32-byte key followed by a payload — code bytes or a trie node — whose length is whatever the arena's `body_len` prefix (§5) leaves after the key. Nothing about a payload's length is fixed or guaranteed by the format; only `body_len` delimits it. An `Account` carries the five fields the EVM and the trie care about — address, nonce, balance, code hash, storage root — plus `slot_count`, the number of `Slot` records that follow it inline, and `code_store_len`, non-zero when the account has code in the code store. The remaining bytes are scratch the verifier owns at run time; on the wire they are zero and meaningless. A `Slot` carries its key and two copies of its value: `initial` is the pre-block value the recompute compares against, `current` the working value execution mutates. In every store the embedded key sits at body offset 0 — `Account.addr` for the address map, the hash for the two hash-keyed stores — so the full-key comparison always reads the first `key_size` bytes of a body.

**Process.** The verifier reads fields in place. An account's slots are the `slot_count` records immediately after it. A non-zero `code_store_len` directs the verifier to the code MPHF under the account's `code_hash`; the sanitization pass records where that code was found and how long it is, and execution reads code from there.

**Verify.** The verifier MUST NOT trust any scratch field (§3.3) and MUST treat `code_store_offset` as unresolved on the wire. The code length used for execution MUST be the code body's own length — the `body_len` prefix in the MPHF data arena, less the 32-byte key — and MUST NOT be taken from any other copy (B1; §3.4). Every `Slot` MUST have `initial == current` on the wire, and slots within a body MUST be strictly ascending by key (§3.3). `balance` MUST be decoded as a little-endian 256-bit integer (§6).

**Create.** The producer writes each touched account as 256 bytes with its slots sorted and inline, encodes `balance` little-endian, writes `code_store_offset = 0`, writes `code_store_len` as the code length or 0, and zeros every scratch field and all padding. It MUST NOT include a slot whose pre-block value is zero: a zero slot is absent from the storage trie, and presenting it as present would misstate the pre-state.

---

## 5. The MPHF index in depth

One index structure is used three times — over addresses (`MPHA`), over code hashes (`MPHC`), and over node hashes (`MPHN`) — distinguished by magic and by key size, 20 or 32 bytes. It is what makes every state read constant-time and decode-free.

```
MPHF map                              header + four regions; all offsets relative to the header start
├─ MphfMapHeader       56 B           magic ∈ {"MPHA","MPHC","MPHN"}, version 3
│  ├─ magic, version         u32 × 2
│  ├─ n_keys                 u32      entries in the slot table
│  ├─ n_buckets              u32      entries in the displacement table
│  ├─ seed                   u64      informational; the lookup MUST ignore it
│  ├─ seed_factor            u64      the salt added to every key
│  ├─ collisions_offset      u32
│  ├─ collisions_size        u32      16 B per entry
│  ├─ displacement_offset    u32
│  ├─ slot_offsets_offset    u32
│  ├─ data_offset            u32
│  └─ data_size              u32
├─ displacement[n_buckets]   u64 each
├─ slot_offsets[n_keys]      u32 each  offset into the data arena; 0 = no placed entry
├─ collisions[]              16 B each, sorted ascending by key8 (equal key8 values permitted)
│  ├─ key8                   u64
│  └─ offset                 u64      into the data arena (the arena itself is u32-sized; see the checks below)
└─ data arena
   ├─ bytes [0, 8)                    reserved zero, so that offset 0 is unambiguously "none"
   └─ entries                         [body_len u64][body …], each padded to 8 bytes
```

**The lookup function.** A read maps `key8` (§1.3) to a body, using the header's `seed_factor`, `n_buckets`, and `n_keys`, and the three tables above. All arithmetic is on 64-bit words, wrapping; `reduce` is Lemire's reduction, defined below.

```
lookup(key8):
    z   = key8 + seed_factor
    b   = reduce(low32(m(z)), n_buckets)
    h2  = m(z + displacement[b])
    i   = reduce(low32(h2), n_keys)
    off = slot_offsets[i]                     # u32, into the data arena
    if off != 0:
        return body_at(off)                   # key mismatch here is a final miss
    for e in run(collisions, key8):           # binary search, then the equal-key8 run in order
        if body_at(e.offset): return body_at(e.offset)
    return MISS

m(x):                                         # one-round SplitMix64 stage-1 mixer (§1.3)
    x ^= x >> 30
    x *= 0xBF58476D1CE4E5B9
    x ^= x >> 31
    return x

reduce(x, n):                                 # x, n < 2^32
    return (x * n) >> 32                      # high half of the 64-bit product

body_at(off):                                 # [body_len u64][body ...]; body starts with the full key
    return body if body.key == query_key else NONE
```

1. **Mix.** `m` is a bijection on 64-bit words (every operation is invertible); its job is to move every bit of the salted key into the low 32 bits before reduction.
2. **Bucket and displacement.** `displacement[b]` is added to the salted key `z`, not to `m(z)`, and the sum is mixed again. An empty bucket, or one the producer could not place, carries `0`.
3. **Slot.** `n_keys` is the number of distinct `key8` values indexed: one slot per distinct `key8`.
4. **Slot offset.** `off != 0` names the single candidate body. `off == 0` means nothing was placed here: the key is absent, or it is one of the two collision kinds of §1.3.
5. **Sidecar.** Equal `key8` values form one run; the verifier walks it in order, checking each entry's `offset` (u64) the same way. The first matching body is the answer; no entry, or an exhausted run, is a miss.
6. **Body.** The body starts with the full 20- or 32-byte key (§4.5). The verifier MUST compare every byte of the query key against it before trusting the body. Equal: a hit whose length is `body_len` and nothing else. Different: from a slot, a definite miss that MUST NOT fall through to the sidecar (§3.4); from the sidecar, the next entry of the run. `key8` chooses where to look, never what is found.

**Lemire's reduction.** `reduce(x, n) = (x * n) >> 32` for `x, n < 2^32`: the high half of the 64-bit product. It maps [0, 2^32) onto [0, n) monotonically, cutting the inputs into n consecutive ranges and sending the k-th range to k, so it replaces `x % n` with one multiply and a shift. It is not a modulo: it keeps the high bits of x and drops the low ones, so any structure in x passes straight through, which is why `m` runs first. `lookup` feeds it `low32` of the mixed word and discards the high 32. Reference: D. Lemire, "Fast Random Integer Generation in an Interval", ACM TOMACS 29(1), 2019.

**What the producer solved for.** A verifier never re-derives these; it evaluates the function above with the `seed_factor` and `displacement[]` the bundle carries.

```
n_buckets   = max(1, ceil(n_keys / 4))                     # bucket load 4
seed_factor = seed * 0x9E3779B97F4A7C15                    # seed = 0, 1, ... at most 32 trials
d_j         = ((seed ^ j ^ 0x9E3779B97F4A7C15) - seed) * 0x9E3779B97F4A7C15    # j = 0 .. 2^20
```

Within a trial, buckets are placed largest first; for each bucket the first `d_j`, in order of `j`, that sends its keys to distinct free slots is stored in `displacement[]` as that 64-bit value, not as `j`; the bound is fixed, so the build always terminates. The first trial that places every key is taken; otherwise the trial with the fewest spills is kept, its unplaced buckets set to `0` and their keys moved to the sidecar. The invariant the reader relies on: for every sidecar key, the slot its lookup lands on reads 0. The producer keeps it by also spilling the owner of any slot a spilled key would probe, which is what lets a mismatch at an occupied slot be final (§3.4). Every failure to place is therefore a first-class sidecar entry beside the `key8` collisions, the sense in which the index is quasi-minimal (§1.3).

**The full-key comparison and the sidecar.** The arithmetic produces a guess that is never trusted: the verifier MUST compare all 20 or 32 bytes of the query key against the key embedded at offset 0 of the candidate body, and a difference is a definite miss. On every path the length of a returned body MUST be taken from the `body_len` prefix in the data arena — the prefix that delimits exactly the bytes the keccak check covered; the sidecar entry is exactly `key8` and `offset` (two u64, 16 bytes, no reserved bytes) and carries no length of its own (B1; body length, §3.4); entries are 8-byte aligned and each field is a single native load. The data arena is u32-sized, so a verifier MUST reject an `offset` unless `offset < data_size`, before doing any arithmetic with it. The verifier MUST use `seed_factor` as stored and MUST ignore `seed`.

**The cost of a read.** Two mixes, two reductions, two table loads, one comparison, and a pointer (§1.3); a read that falls to the sidecar adds one binary search over a short table and the same comparison. The structural cost is paid once, off-chain, in the producer, which ships flat tables — about one 64-bit displacement per four keys, one 32-bit slot offset per key, and 16 bytes per sidecar entry — that the guest reads with plain loads. The tables are deliberately uncompressed: entropy-coding the displacement array would shrink the witness and move the decode cost back into the guest, the trade §1.2 rejects.

**Why the producer's build can be left unchecked.** The displacement table, the slot offsets, and the sidecar are attacker-supplied bytes, and the verifier neither rebuilds nor checks the perfect-hash property. The checks of §3 bound what a hostile index can do. The full-key comparison (§3.4) lets a wrong or malicious index route a query only to a body whose key does not match — a miss, never a body for the wrong key; code and node sanity (§3.3) mean a body that does match cannot carry the wrong content. A miss, in turn, is not absorbed: it becomes a recorded empty read (§3.4) that the trie walk of §3.1 checks from `pre_state_root`, where an empty read of a key that is in fact present fails the pre-value comparison or meets a missing node. The worst a hostile index can do is therefore make a key unfindable — accept to reject, never the other way (§3.4).

**Consequence.** Because the verifier never rebuilds the index and confirms every hit and every body, two conforming producers given the same input MAY emit byte-different bundles and both MUST be accepted. Determinism of the build is a test oracle; no verifier check relies on it. MFBD fixes the wire layout and leaves the build free.

---

## 6. Rationale threads (brief)

**Plain keys.** Each MPHF is keyed by the natural identifier of what it stores (§1.2), and `key8` is a fixed slice of that identifier, so a lookup costs no additional keccak. The trie key `keccak(address)` is needed only for the ordered walk of §3.1 and travels explicitly in the `AddrHashEntry` table, where the sanitization pass binds it back to the keyed record (§4.3).

**Fixed-width plain-data records.** Fixed width is what makes the format zero-copy (§1.2); 8-byte alignment is what makes zero-copy safe on `rv64im`. The one 4-aligned structure, the PreState meta header, is padded so that everything after it stays 8-aligned (§4.3).

**Little-endian scalars.** Every multi-byte scalar is little-endian so that the producer's host and the guest both read it as a native load, with no byte swap on the read path. Hashes, addresses, storage keys, and storage values stay in their on-chain byte order because they are only ever compared or hashed, never interpreted. `Account.balance` is the one 32-byte field that is a scalar rather than a byte array and therefore follows the scalar rule.

**The accept rule.** The verifier MUST accept a bundle only when three conjuncts hold: the root recompute completed without flagging a failure (no missing node, no failed pre-value comparison, no unwalkable empty read); the recomputed root is non-zero; and the recomputed root equals the claimed `post_state_root`. Three conjuncts rather than one, because the header side of the comparison belongs to the adversary: equality of the recomputed and claimed roots is the only positive statement; the failure flag and the zero guard exist to make sure that nothing the recompute could not finish is ever allowed to look like something it did.
