# HashState/slib corpus validation

Status of the HashState/slib state backend (the `statelessInputBytes` / SSZ
read-side path) against the EEST stateless corpus, and how the harness scores
it.

## Status

The corpus is tests-zkevm v21.0.1, the release ere-guests tests against.
`make eest-zkevm-tests` runs its 3417 fixture files through the HashState
runner: **3293 pass, 124 skipped, 0 fail**. A skipped file is one whose blocks
carry no `statelessInputBytes` (the pre-fork blocks of fork-transition tests);
every witnessed block passes. 31 expected-invalid labels are waived under the
relaxation below, each logged.

On the guest, the `eip8025_optional_proofs` engine fixtures of the same release
(182 cases, every witness-validation negative among them) run through
`make ere-validate` against their `statelessOutputBytes`: 182/182 matched.

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
`test_validation_state_missing_*`, `test_validation_headers_*`,
`test_invalid_stateless_input_bytes_are_rejected` and
`test_witness_header_ssz_size_limit` names inside `eip8025_optional_proofs`)
and scores them **pass iff the slib path rejects**.
Any rejection signal counts — a malformed witness, a missing node, a non-zero
completeness counter, a root mismatch, or a validation error. A broken witness
the verifier wrongly accepts is scored as a failure, so leniency bugs surface
instead of hiding.

## Parent-header requirement

The shipped ancestor headers must form one contiguous parent-hash chain ending
at the block's parent, as execution-specs `validate_headers` requires. BLOCKHASH
walks the parent hashes back from the block, so a header the walk does not
reach is never used; the check makes a malformed witness fail early and keeps
the anchor of the pre-state explicit.

No negative is exempted: evmone reads an EIP-7702 delegate's code while
resolving the call target, as execution-specs does, so
`validation_codes_missing_delegated_code_on_insufficient_balance_call` rejects
like any other omitted code.

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
from that witness; the waived label is logged. A complete witness (counter
zero) still demands the exact label, so a genuine reconstruction or validation
bug is never masked.

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

A guest-side sample of the tests-zkevm v0.8.0 corpus (325 accepting witnessed
blocks run under the SP1 executor) shows the slib read path is cheap at real-block scale: **median
~6.29M cycles per block** (min 4.33M, mean 41.7M; the max, 3.55B, is a single
heavy-precompile outlier).
