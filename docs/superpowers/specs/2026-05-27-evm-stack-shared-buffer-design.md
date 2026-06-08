# EVM Stack: Shared Dense Buffer Across Call Frames

Date: 2026-05-27
Scope: `third_party/evmone` (zevmone fork)

## Motivation

Each EVM call frame currently allocates its own 32 KB stack space on the heap:

- `lib/evmone/execution_state.hpp:30-51` — `StackSpace` holds `std::unique_ptr<Storage>` with `uint256[1024]`.
- `lib/evmone/vm.cpp:88-97` — `VM::get_execution_state(depth)` constructs each `ExecutionState` lazily; each construction pays one `make_unique<Storage>` (32 KB).

In SP1 zkVM, every touched memory cell costs prover cycles. Per-frame heap allocations also force the working set across cache lines unnecessarily even on a native host. EVM execution within a `VM` instance is single-threaded.

## Design

### 1. Per-VM static stack buffer

Add to `class VM` in `lib/evmone/vm.hpp`:

```cpp
static constexpr size_t MAX_DEPTH = 1024;
static constexpr size_t MAX_STACK_PER_FRAME = 1024;

alignas(sizeof(intx::uint256))
intx::uint256 m_stack_buffer[MAX_DEPTH * MAX_STACK_PER_FRAME]; // 32 MB

intx::uint256* m_stack_tail = m_stack_buffer;
```

Size = 1024 frames × 1024 slots × 32 B = 32 MB. Worst-case bound for fully-loaded frames at max depth. On real hosts, untouched BSS pages have no resident cost; in SP1 only touched cells cost cycles.

`m_stack_tail` is the bottom slot for the **next** frame to be entered.

### 2. ExecutionState no longer owns stack memory

In `lib/evmone/execution_state.hpp`:

- Delete `class StackSpace` (or reduce it to a `static constexpr size_t limit = 1024;` shim used by existing constants).
- Replace the `StackSpace stack_space;` member with `intx::uint256* stack_bottom = nullptr;`.
- `reset(...)` does not touch `stack_bottom`; `stack_bottom` is set by the caller (`baseline::execute`) right after `reset`.

Usages in `baseline_execution.cpp`:
- Line 197 / 263 — `state.stack_space.bottom()` → `state.stack_bottom`.
- Line 78 — `stack_bottom + StackSpace::limit` for the overflow check → reuse the same constant (kept as a top-level `constexpr` or as `StackSpace::limit`).

### 3. Dense frame bottoms

The bottom of frame `d+1` = the live stack-top of frame `d` at the moment of the inter-frame call.

#### Entry to a frame

`baseline::execute(VM& vm, ..., const evmc_message& msg, ...)`:

```cpp
auto& state = vm.get_execution_state(static_cast<size_t>(msg.depth));
state.reset(msg, rev, host, ctx, analysis.raw_code());

if (msg.depth == 0)
    vm.m_stack_tail = vm.m_stack_buffer;   // fresh tx root
state.stack_bottom = vm.m_stack_tail;
```

Rationale for `msg.depth == 0` reset: each top-level call into `baseline::execute` is the root of a transaction's call tree. The host driver never reenters at depth 0 inside a tx.

#### Before a nested call

`instructions_calls.cpp`'s `call_impl` and `create_impl`, immediately before `state.host.call(msg)`:

```cpp
vm.m_stack_tail = stack;   // hand current stack top to the nested frame
```

`stack` (the `StackTop` arg) points one past the live top. Using it as the inner frame's bottom is **safe by construction**: even if the outer frame's "args region" sits just below `stack`, that region is never modified by the inner frame because the inner frame writes only to addresses ≥ its bottom.

This is conservative — depending on op, fewer than 7 cells below `stack` are still live for the outer frame after the inner returns — but the cost (a handful of unused uint256 slots per nesting level) is negligible compared to the simplicity gain.

#### Restoring after return

No explicit restore is needed. The outer frame's next nested call will overwrite `m_stack_tail` again. After the outermost frame returns, the next top-level `execute(depth==0)` resets the tail (see above).

### 4. Plumbing: `VM*` on `ExecutionState`

`call_impl` / `create_impl` need to write `vm.m_stack_tail`. They receive `ExecutionState&` but not `VM&`. Options considered:

- **Add a `VM* vm` field to `ExecutionState`.** Set once when `execute` enters a frame. Lowest-touch.
- Pass `VM&` through `dispatch` and instruction-call signatures. Wider churn; rejected.

Adopted: option 1. `ExecutionState::vm` (raw, non-owning pointer). Set right after `reset()` in `baseline::execute`.

### 5. VM constructor

`VM::VM()` keeps `m_execution_states.reserve(1025)`. The buffer is part of the `VM` object — `new VM{}` now allocates ~32 MB. This is fine: a `VM` is a long-lived EVM instance, typically one per process. Documented in a comment on the field.

## Out of scope

- Advanced interpreter (`AdvancedExecutionState`): unused by the SP1 path. Will keep behavior matching the new layout where it inherits `ExecutionState`, but no optimization there.
- EOF (when/if enabled in zevmone): same plumbing applies; EOF's `EXTCALL` path lives in `instructions_calls.cpp` and inherits the same `vm.m_stack_tail` update.

## Risks

- **Overflow of the global buffer**: 1024 × 1024 slots is the worst case; the dense layout cannot exceed it because (a) each frame is capped at 1024 items by the existing overflow check, and (b) `msg.depth ≤ 1024` by EVM protocol. No new overflow path. Assert in debug.
- **Re-entrancy from EVMC host into the same VM**: not supported today; not introduced by this change.

## Verification

1. Build host evmone and run `ctest` — all 2829 unit tests must pass.
2. Build SP1 prover guest + native prover.
3. Run `sp1-benchmark` skill on the mainnet block witness set, before vs after this change. Expect:
   - `gas_used` identical (correctness).
   - `cycle_count` reduced or unchanged. Reduction comes from eliminating per-frame stack init + better memory locality on the dense buffer.

## File list

- `lib/evmone/vm.hpp` — add 32 MB buffer + tail pointer on `VM`.
- `lib/evmone/execution_state.hpp` — keep `StackSpace` shell (just `static constexpr size_t limit = 1024;`); drop the `unique_ptr<Storage>`. Replace `stack_space` member with `uint256* stack_bottom`. Add `VM* vm` pointer.
- `lib/evmone/baseline_execution.cpp` — set `state.stack_bottom` / `state.vm` after `reset`; reset `m_stack_tail` at depth 0. Replace `state.stack_space.bottom()` (lines 197, 263).
- `lib/evmone/instructions_calls.cpp` — write `state.vm->m_stack_tail = stack` before `state.host.call(msg)` in `call_impl` and `create_impl`.
- `lib/evmone/advanced_analysis.hpp` — replace 3 uses of `stack_space.bottom()` with `stack_bottom` in `AdvancedExecutionState` (lines 41, 59, 79). The Advanced interpreter must continue to compile but isn't used by SP1.
- `lib/evmone/instructions.hpp` — replace `state.stack_space.bottom()` at lines 969, 989, 1009 with `state.stack_bottom`.

`StackSpace::limit` references (baseline_execution.cpp:78, advanced_instructions.cpp:147) keep working because we retain the `StackSpace::limit` constant.

No tests need to change; the host stack semantics are identical.
