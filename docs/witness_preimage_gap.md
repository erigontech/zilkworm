# Known issue: missing address preimages in `debug_executionWitness`

Status: **open — upstream (witness provider) issue; no client-side fix planned.**
Last updated: 2026-07-16.

## Symptom

Occasional recent-mainnet blocks fail execution with `kWrongReceiptsRoot`
(and would also produce a wrong state root). Observed on blocks
**25538620, 25540940, 25540990** — roughly 2 per hour of head-following in
July 2026. The proving service's JIT preflight detects and skips such
blocks (`SKIPPED: guest validation failure` in `provingLogs.log`), so they
cost a ~0.6 s dry run but no GPU time and no crash.

## Root cause

Erigon's `debug_executionWitness` returns the trie nodes and a `keys`
section of key preimages. For accounts whose address exists **only as a
runtime-computed value** — CREATE2 counterfactual deposit addresses used
by exchange sweepers — the address preimage is **missing** from `keys`,
even though the account's trie leaf is present in the node store.

The flat-bundle builder (`zilk_core/dev/cli/json_witness_to_flat_bundle.cpp`)
keys the pre-state by raw address, so a leaf without a preimage cannot be
placed in the address-keyed map and is dropped. Execution then reads
`BALANCE` = 0 for that address.

Reference case (block 25538620, diagnosed 2026-07-15): tx 57
(`withdraw(address,uint256)` on `0x7c5a…f716`) sweeps CREATE2 deposit
address `0x25b5b68f8f4a7ae233c22ace0fda3ee29defd23b` holding 3.0618 ETH.
The leaf is reachable from the parent state root (trie key
`52a9994ffff1e4b7…`), but the raw address appears nowhere in the witness.
16 of 707 reachable accounts in that block's witness had no preimage; the
other 15 had zero balance, so only this one diverged.

## Why there is no client-side fix

If the preimage is absent, the client cannot conjure the address; any
address-keyed pre-state necessarily drops the leaf. A hash-keyed pre-state
(key accounts by `keccak256(address)`, hash at lookup) was prototyped and
verified — it makes the reference block pass — but was **rejected and
reverted**: state lookups keyed through hashing were judged too expensive
a design for the guest. See commit `705e1ce0` (implementation) and its
revert `4e898ffc` on `som/airbender-bigint-secp` if the approach is ever
revisited.

The correct fix is **upstream**: the witness provider must include key
preimages for every account/slot the block's execution touches, including
addresses that are computed at runtime (CREATE2). This should be reported
against Erigon's `debug_executionWitness`.

## Current mitigation

- The prover service preflights every block in the JIT before proving and
  skips validation failures (see `prover/prover_airbender/src/service.rs`,
  commit `29a8c3b0`), logging them to `provingLogs.log`.
- Affected bundles are preserved for reproduction under
  `temp/airbender_test/blocks/<N>/` (e.g. 25538620).
- The soundness angle — the builder silently dropping reachable leaves —
  is documented by `witness_hide_node_test`; a stateless prover must not
  be fed an incomplete pre-state.

## Action items

1. File an issue against Erigon: `debug_executionWitness` omits `keys`
   preimages for CREATE2-computed addresses touched by execution.
2. Until fixed upstream, expect sporadic skipped blocks in the service
   (visible in `provingLogs.log` and as dangling `queued` entries on
   ethproofs).
