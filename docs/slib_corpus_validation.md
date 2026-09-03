# HashState/slib corpus validation

Status of the HashState/slib state backend (the `statelessInputBytes` / SSZ
read-side path) against the EEST stateless corpus, and how the harness scores
it.

## Status

**All 3259 fixtures passing** on the tests-zkevm@v0.8.0 stateless corpus
(`make eest-zkevm-tests`), on top of the Amsterdam (glamsterdam-devnet-8)
integration. The `bad_v_r_s` case that used to fail is described below; it is
fixed by the shared EIP-2 low-s rejection, not by anything slib-specific.

## How the witness-validation negatives are scored

EEST's EIP-8025 "optional proofs" feature ships a family of **stateless
witness-validation negatives**: the block itself is valid (a full-state client
accepts it), but its per-block `statelessInputBytes` witness is deliberately
broken — a required trie or code node removed, an ancestor header dropped,
malformed, or reordered, or the SSZ blob corrupted. A correct stateless
verifier must reject these.

There is **no machine-readable expect-reject marker** for them: the fixtures
carry no block-level `expectException` (that field describes block validity,
not witness integrity), and the `_info` prose is too imprecise to match on. The
slib runner therefore identifies them by the EEST **pytest node-id convention**
(the fixture's top-level JSON key: the `test_validation_codes_missing_*`,
`test_validation_state_missing_*`, `test_validation_headers_*`, and
`test_invalid_stateless_input_bytes_are_rejected` names inside
`eip8025_optional_proofs`) and scores them **pass iff the slib path rejects**.
Any rejection signal counts — a malformed witness, a missing node, a non-zero
completeness counter, a root mismatch, or a validation error. A broken witness
the verifier wrongly accepts is scored as a failure, so leniency bugs surface
instead of hiding.

## Two documented judgment calls

1. **Delegated-code exemption.** One EEST "negative"
   (`validation_codes_missing_delegated_code_on_insufficient_balance_call`) is
   scored as an ordinary valid block, not a must-reject. The block CALLs an
   EIP-7702 delegated target with insufficient balance; the CALL reverts on the
   balance check before the delegated code is ever loaded, so pruning that code
   from the witness is legitimate EIP-8025 optional-proofs behavior. HashState's
   code reads are fail-closed — any code the execution actually needs but the
   witness omits rejects the block — so nothing is weakened; the fixture just
   encodes a stricter "carry every delegated-target code even when unreachable"
   reading than EIP-8025 requires.

2. **Parent-header requirement.** The block's parent header must be present in
   the block's own witness ancestor set (matched by the block's `parent_hash`),
   and the shipped ancestor headers must form one contiguous parent-hash chain.
   Without the anchor, a witness shipping zero ancestor headers could still
   resolve its parent from the harness's genesis header and be wrongly
   accepted. Verified across the whole corpus (27,184 witnessed blocks): the
   only blocks omitting their parent are the three witness-negative fixtures,
   so the requirement rejects no legitimate block.

## Expected-invalid label relaxation

When a fixture marks a block `expectException`, the harness normally demands
the exact rejection label. That label is trustworthy only when the block's own
witness supplied every account the validation gates read. Many expected-invalid
blocks are state-test-derived and ship a minimal witness that prunes the sender
itself (never needed to re-execute a transaction that never runs); HashState
then reads the sender back blank and an earlier gate fires with a different
label (e.g. `kWrongNonce` instead of `kInsufficientFunds`).

The relaxation accepts such a rejection **only when the fail-closed counter
proves the witness pruned a label-determining account**: HashState bumps
`unconfirmed_read_count_` on every read it could not confirm against the pruned
trie, and the exact-label demand is waived only when that counter is non-zero.
The block is still correctly rejected; only the precise reason is unknowable
from that witness. A complete witness (counter zero) still demands the exact
label, so a genuine reconstruction or validation bug is never masked.

## Former limitation: `bad_v_r_s` (EIP-2 high-s signature)

Now passing: `pre_validate_transaction` rejects the high-s signature with
`kInvalidSignature` again. The original analysis follows.

One subtest of the `bad_v_r_s` fixture — a
legacy (type-0) transaction with `s = SECP256K1N//2 + 1`, above the EIP-2
low-s limit but below the curve order — expects
`TransactionException.INVALID_SIGNATURE_VRS`, but the code rejects it as
`kInsufficientFunds`.

This is a **shared silkworm gap, not slib-attributable**: the EIP-2 low-s
rejection in `pre_validate_transaction`
(`zilk_core/core/protocol/validation.cpp:45`) is commented out, so the gate is
a no-op. The in-range high-s signature still recovers *a* (wrong, unfunded)
sender, and the balance gate fires first with the wrong label. The failure
reproduces **byte-identically on DirectState** — same gate, same message, same
exit code — so it lives entirely in shared transaction validation, outside the
slib/HashState overlay. The signature predicate itself
(`zilk_core/core/crypto/secp256k1n.cpp`) is correct; a fix is just re-enabling
the rejection, which touches both backends and is out of slib scope. The other
19 `bad_v_r_s` subtests pass (typed transactions reject at the
signature-shape/RLP stage; `s >= n` makes recovery fail).

## SP1 corpus sample

A guest-side sample of the corpus (325 accepting witnessed blocks run under the
SP1 executor) shows the slib read path is cheap at real-block scale: **median
~6.29M cycles per block** (min 4.33M, mean 41.7M; the max, 3.55B, is a single
heavy-precompile outlier).
