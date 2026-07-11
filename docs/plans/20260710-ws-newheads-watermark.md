# WS newHeads Tip Watermark for Prover Service (PR 1 of 3)

## Overview

The live prover service (`prover_hypercube --service`) discovers new blocks by polling `eth_blockNumber` every 2 seconds and issues one such call per loop iteration even while catching up a backlog. This wastes up to 2s of the proving window per block and generates constant RPC chatter.

This plan adds an opt-in `--ws-url` flag. When set, the service opens one WebSocket connection to the EL node and:
- subscribes to `eth_subscribe("newHeads")`, using announced heads purely as a **tip watermark**;
- routes the per-block fetch RPCs (`eth_getBlockByNumber`, `debug_getRawBlock`, `debug_executionWitness`) over that same connection.

When the flag is absent, behavior is **byte-identical** to today — same poll cadence, same retry counts, same log lines. This is a hard requirement.

This is PR 1 of a 3-PR series: PR 2 adds an erigon-side witness push subscription (`debug_subscribe("executionWitnesses")` with encoding negotiation), PR 3 adds push consumption in zilkworm (`PushWithFallback`). PR 1 leaves seams for PR 3 but implements only what is exercisable against today's erigon/reth.

## Context (from discovery)

- Repo `erigontech/z6m` @ `5a54ce87`, branch to create: `awskii/ws-newheads-watermark` (from `main`).
- `prover/prover_hypercube/src/service.rs` — `run_service()` at :579-830; live-mode poll at :611-623; cursor init :584-594, increment :820; `ServiceConfig` :157-169; local `get_block_number_with_retry` :833-860 (flat 2s delay, distinct from fetcher's exponential one).
- `prover/prover_hypercube/src/main.rs` — clap `Args` :19-82 (no env attrs on existing flags), `Fetch`/`Prove` one-shot paths :285-309.
- `prover/common/src/fetcher.rs` — `fetch_block_and_witness()` :187; builds its own provider via `ProviderBuilder::new().connect_http(url)` :188-189; witness acquisition 3-path match :258-290; raw-reqwest geth path :105-135 (its retry wrapper :138-165); retry helpers with `2^attempts` capped backoff :329-458.
- `FetchRequest` is constructed at exactly three sites: `main.rs:295` (Fetch one-shot), `service.rs:305` (`#[allow(dead_code)] fetch_block`), `service.rs:667` (run_service loop). The Prove one-shot builds no `FetchRequest`.
- **`prover/prover_hypercube/build.rs:10-13` panics unless `prover/guest_hypercube/build/z6m_guest.elf` exists** (`canonicalize().expect("C++ guest ELF not found – run `make z6m_guest` first")`) — every `cargo build/test/clippy -p z6m_prover` needs the guest ELF built first (see Setup).
- `prover_hypercube` is **binary-only** (`Cargo.toml:10-12 [[bin]]`, no `[lib]`) — a `tests/` directory cannot import `HeadSource` etc.; integration-style tests must live in in-crate `#[cfg(test)]` modules.
- alloy 1.0 with `features=["full"]` (`prover/prover_hypercube/Cargo.toml:33-37`) — `alloy-transport-ws`/`alloy-pubsub`/`tokio-tungstenite` already in `Cargo.lock`, zero call sites. `node-bindings` (Anvil) also available.
- **No Rust tests exist anywhere in `prover/`** — test modules added here are the first.
- **`prover_turbo` does not compile** (`service.rs:253` `let client2 = Exe`, undeclared `latest`). Never run bare `cargo build`/`cargo test` from `prover/`; always `-p z6m_prover` / `-p z6m_common` or `--manifest-path`. Do not touch `prover_turbo`.
- Makefile target `z6m_prover` (Makefile:23) builds the hypercube binary; keep it green.
- New source files get the existing header: `// Copyright 2026 The Zilkworm Authors` + `// SPDX-License-Identifier: Apache-2.0`.

## Development Approach

- **Testing approach**: Regular (code then tests in the same task), with one exception per repo owner's rule — the fetcher refactor in Task 6 is *cover-first*: seam tests are written before construction is moved.
- Setup before Task 1 (all three are preconditions for every verification command below):
  1. `git checkout -b awskii/ws-newheads-watermark` from clean `main`.
  2. Build the C++ guest ELF: `make z6m_guest` (CMake + the SP1 RISC-V toolchain required; if the environment cannot build it, obtain `z6m_guest.elf` out-of-band and place it at `prover/guest_hypercube/build/z6m_guest.elf`). Without it, `build.rs` panics and no `-p z6m_prover` command runs. `-p z6m_common` is unaffected.
  3. Sanity-check the harness: `cd prover && cargo check -p z6m_prover` must pass before starting Task 1.
- Complete each task fully before moving to the next; small focused changes.
- Every task ends with its tests written and `cargo test -p z6m_prover` (and `-p z6m_common` when touched) passing, plus the diff-scoped lint gate below.
- **Lint/format gate — diff-scoped, NOT repo-wide.** `main` has pre-existing clippy and rustfmt debt in both crates (verified: `cargo clippy` errors under `-D warnings` and `cargo fmt --check` fails on untouched files; there is no clippy/fmt CI). The gate is: run `cargo clippy -p z6m_prover -p z6m_common` and confirm NO warning/error points at a line this branch changed (`git diff main` is the scope); new files must be warning-free. Format only the files this plan touches (`rustfmt <file>` or targeted `cargo fmt`), and only your own hunks must be fmt-clean. **NEVER fix pre-existing lints or reformat code outside the plan's file scope — baseline cleanup is explicitly out of scope and pollutes the PR diff.**
- Backward compatibility is the acceptance bar: no `--ws-url` → identical behavior, log lines, and RPC pattern.
- Update this plan file when scope changes during implementation.

## Testing Strategy

- **Unit tests**: required for every task; live in `#[cfg(test)]` modules next to the code. Head-source semantics are tested via an injected head-stream seam (tokio mpsc), never a live socket. Time-dependent tests use `tokio::time::pause()`/`advance()` — no real sleeps.
- **Integration test**: `#[ignore]`d Anvil tests (`node-bindings`) living in an in-crate `#[cfg(test)]` module (the crate is binary-only — a `tests/` dir cannot link against it), run manually via `cargo test -p z6m_prover -- --ignored ws_` (requires `anvil` in PATH).
- **E2E**: not automatable (Anvil lacks `debug_executionWitness`) — manual verification against an erigon node, see Post-Completion.
- The `BEGIN_FETCH`/`BEGIN_EXEC`/`END_EXEC` println markers and the `"[{ts}] Received block number from RPC {}"` line are parsed downstream — formats must remain byte-identical (asserted in Task 9).

## Progress Tracking

- mark completed items with `[x]` immediately when done
- add newly discovered tasks with ➕ prefix
- document issues/blockers with ⚠️ prefix
- keep plan in sync with actual work done

## Solution Overview

**Cursor/watermark split.** The `next_block` cursor stays the sole driver of what gets fetched/proved — strictly sequential, `prove_every`/`execute_every` gating untouched. The WS subscription is only an alternative source of the `latest` watermark that the poll currently produces. This is what makes behind-tip operation (start or reconnect on an old block) work: during catch-up the loop never waits on WS, it drains buffered heads non-blockingly and keeps processing the backlog.

**Watermark rule (Ws mode only)**: `latest = max(latest, announced_height)`. Reorg re-announcements at the same or lower height can never move the cursor backward; each height is processed exactly once, canonical-at-fetch-time — today's contract, unchanged. Poll mode keeps today's *memoryless* comparison against the fresh per-iteration poll value — persisting a max there would diverge from current behavior when `eth_blockNumber` decreases (byte-identity requirement).

**Watermark seeding (Ws mode)**: `latest` is seeded with one `eth_blockNumber` call at service start regardless of `--start-block` (today the initial poll at service.rs:587 runs only when `start_block` is unset). Without seeding, a behind-tip start would route the first iteration to `await_tip` and stall — violating "catch-up never waits on WS".

**Degradation**: the subscription is disposable. Stream death → re-establish with capped exponential backoff; while down, a ~24s backstop poll keeps the service live. Initial WS connect failure → warn, run on backstop, keep retrying. The service never exits because of the flag. alloy-pubsub's own reconnect behavior is verified but not relied on.

**One connection**: in WS mode the fetch RPCs ride the same connection as the subscription (alloy multiplexes requests and subscriptions over one socket). Wire formats are unchanged — standard JSON `debug_executionWitness`; encoding negotiation is PR 2 material.

**Fetch fallback while WS is down**: a dead WS connection must not skip blocks that HTTP could serve (the loop skips a block on fetch error, service.rs:679-682). In WS mode, a failed `fetch_block_and_witness` is retried once with `provider: None` (HTTP built from `--rpc-url`) before the existing skip. If the initial WS connect failed at startup (backstop mode), fetch passes `None` until the subscription is first established. alloy's own reconnect may heal the WS handle for requests; the HTTP retry covers when it doesn't.

## Technical Details

- `HeadSource` enum in `service.rs` (no new module):
  - `Poll { provider }` — extraction of today's logic, verbatim semantics: poll every iteration (6 retries, flat 2s), memoryless fresh `latest` per iteration (NO persisted max), 2s sleep at tip, 30s sleep on retry exhaustion.
  - `Ws { url, heads: Option<HeadStream>, backstop, backoff_attempt }` — `drain_tip(latest) -> u64` (non-blocking; used while `next_block <= latest`) and `await_tip(latest) -> u64` (`tokio::select!` of next head vs `WS_BACKSTOP` (~24s const) timer firing the backstop; used at tip). Handles (re)subscribe inline with `2^attempts` capped backoff.
- `HeadStream` is a thin seam over `alloy Subscription<Header>` mapped to block heights (`u64`), so unit tests inject a channel. Subscription lag/drop is harmless — only `max(height)` matters.
- The backstop is injected behind its own tiny seam (boxed async closure or alloy's mocked provider/`Asserter`): prod = one `eth_blockNumber` on a provider; tests = canned value. Without this, the "backstop fires" test can't run under the no-live-sockets rule.
- WS connection setup must raise the max WS message size to ≥128MB — tungstenite's ~64MiB default would *reject* an 80MB witness response, so this is a correctness item, applied where the connection is built (Task 3). If alloy 1.0's `WsConnect` doesn't expose the knob, an explicit `alloy-transport-ws`/`tokio-tungstenite` manifest entry (already in Cargo.lock via `full`) is acceptable — call it out in the diff.
- `ServiceConfig.ws_url: Option<String>`, validated (`ws`/`wss` scheme) at startup by a pure function; malformed flag = startup error (fail fast); runtime connect failures never fatal.
- Fetcher: `FetchRequest` gains `provider: Option<DynProvider>`; `None` → build `connect_http(rpc_url)` exactly as today (CLI paths pass `None`); `Some` → use injected (service passes the WS provider iff `--ws-url`). Raw-reqwest geth path (`--geth`) stays HTTP-only — out of scope.
- `WitnessSource` seam in fetcher: the witness-acquisition 3-path match (:258-290) moves behind a thin enum with single variant `Request`; PR 3 adds `PushWithFallback` without touching `run_service`.
- Alloy API facts to verify at implementation time (Task 3 checkboxes): `WsConnect`/`connect_ws` shape, `subscribe_blocks()` return type and header height field, subscription channel lag semantics, and the WS max-message-size knob — witness responses are 10-80MB hex JSON and must not be capped below ~128MB.
- If `DynProvider` proves awkward in alloy 1.0, fall back to a small generic parameter on `FetchRequest`/`fetch_block_and_witness` — decide in Task 6, note the choice here.

## What Goes Where

- **Implementation Steps** (checkboxes): all code, tests, and docs changes in this repo.
- **Post-Completion** (no checkboxes): manual e2e vs erigon, latency measurement, PR creation, PR 2/3 follow-ups.

## Implementation Steps

### Task 1: Extract `HeadSource::Poll` (pure refactor, verbatim semantics)

**Files:**
- Modify: `prover/prover_hypercube/src/service.rs`

- [x] add `enum HeadSource` with `Poll { provider }` variant; move the live-mode tip logic (service.rs:611-623) and `get_block_number_with_retry` usage into it, preserving exact semantics: poll on every live iteration, **memoryless comparison against the fresh poll value** (no persisted max — persisting would diverge when `eth_blockNumber` decreases), 6 retries with flat 2s delay, 2s sleep when `next_block > latest`, 30s sleep + skip-iteration on retry exhaustion
- [x] add pure helper `advance_watermark(latest: u64, announced: u64) -> u64` (max) — used ONLY by the `Ws` arm from Task 3 on; the Poll arm must not call it (byte-identity)
- [x] wire `run_service` to construct `HeadSource::Poll` unconditionally (flag arrives in Task 2); the loop body reads identically apart from the extraction
- [x] write tests: `advance_watermark` (advance, equal, lower/reorg cases) in a new `#[cfg(test)]` module (first tests in the crate — verify test harness runs)
- [x] verify: `cd prover && cargo build -p z6m_prover && cargo test -p z6m_prover`, then the diff-scoped clippy gate (no new warnings on changed lines; pre-existing debt stays untouched); confirm by reading the diff that poll cadence/retry/sleep constants and all println formats are untouched

### Task 2: `--ws-url` flag, `ServiceConfig` plumbing, scheme validation

**Files:**
- Modify: `prover/prover_hypercube/src/main.rs`
- Modify: `prover/prover_hypercube/src/service.rs`

- [x] add `#[arg(long)] ws_url: Option<String>` to `Args` (top level, next to `rpc_url`; no env attr — consistent with existing flags) and plumb into `ServiceConfig.ws_url: Option<String>`
- [x] add pure `fn validate_ws_url(url: &str) -> eyre::Result<Url>` accepting only `ws`/`wss` schemes with an actionable error message; call it at `run_service` startup before any connection attempt (malformed flag = immediate startup error)
- [x] write tests: `validate_ws_url` accepts `ws://host:8545` and `wss://host`, rejects `http://`, `https://`, schemeless, and garbage
- [x] run tests — must pass before Task 3

### Task 3: `HeadStream` seam + `HeadSource::Ws` tip semantics

**Files:**
- Modify: `prover/prover_hypercube/src/service.rs`
- Modify (only if the message-size knob needs it): `prover/prover_hypercube/Cargo.toml`

- [x] verify alloy 1.0 facts and record them as code comments where used: `WsConnect`/`ProviderBuilder` ws connection API, `subscribe_blocks()` return type and height field access, subscription lag/drop semantics (verified against alloy 1.0.35: `WsConnect::with_config(WebSocketConfig)`; `ProviderBuilder::connect_ws(WsConnect).await?.erased()`; `subscribe_blocks() -> Subscription<Header>`, `Header` derefs to `alloy_consensus::Header` → `number: u64`; `Subscription::{try_recv,recv}` for non-blocking/awaiting drain, both cancel-safe — comments live in `connect_ws_head_stream`/`HeadStream`)
- [x] configure the WS connection's max message size ≥128MB at construction (tungstenite default ~64MiB rejects large witness responses — correctness, not tuning); if `WsConnect` doesn't expose it, add the explicit `alloy-transport-ws`/`tokio-tungstenite` manifest entry (already in Cargo.lock via `full`) and note it in the plan — **`WsConnect::with_config` DOES expose the knob, so no new runtime manifest entry was needed; set `WS_MAX_MESSAGE_SIZE = 256 MiB` on both `max_message_size` and `max_frame_size`**
- [x] add `HeadStream` seam: production impl wraps the alloy subscription mapped to `u64` heights; test impl backed by `tokio::sync::mpsc`
- [x] add `HeadSource::Ws` variant with `drain_tip(latest) -> u64` (non-blocking drain of all buffered heads via the seam; never awaits) and `await_tip(latest) -> u64` (`tokio::select!` over next head vs `WS_BACKSTOP` timer (~24s const) firing the backstop)
- [x] inject the backstop behind its own seam (boxed async closure or alloy mocked provider/`Asserter`): prod = one `eth_blockNumber` call; tests = canned value — implemented as a small `Backstop` enum (`Provider(DynProvider)` / `#[cfg(test)] Canned(u64)`), mirroring the `HeadStream` seam
- [x] write tests (channel-injected, `tokio::time::pause()` for timing): heads advance the watermark; equal/lower reorg heads don't regress it; `drain_tip` returns immediately on an empty channel; `await_tip` returns on first head; backstop fires (canned backstop) when no heads arrive
- [x] run tests — must pass before Task 4

**Task 3 scope notes (per "update the plan when scope changes"):**
- ➕ Added `[dev-dependencies] tokio = { features = ["test-util"] }` to `prover/prover_hypercube/Cargo.toml`. tokio's `full` does NOT include `test-util`, which the `tokio::time` pause/auto-advance timing tests require. Dev-only — the binary build never pulls it in; `Cargo.lock` is unchanged (feature-only on already-locked tokio 1.47.1). This is the sole `Cargo.toml` change (the message-size knob needed none), so Task 9's diff-stat exception for `prover_hypercube/Cargo.toml` applies.
- ⚠️ `Ws` variant shape refined vs Technical Details (`{ url, heads, backstop, backoff_attempt }` → `{ provider: Option<DynProvider>, heads, backstop, backoff_attempt }`): resubscribe (Task 4) re-calls `subscribe_blocks()` on the retained provider rather than rebuilding from a URL (alloy multiplexes subscriptions/requests over the one live connection), so the provider is the field that must be kept. The validated `Url` is still consumed by `connect_ws_head_stream(&Url)` at construction.
- `Ws`/`drain_tip`/`await_tip`/`connect_ws_head_stream`/`Backstop::Provider` carry `#[allow(dead_code)]` (constructed only by tests until Task 4 reconnect + Task 5 run_service wiring); remove those allows as they are wired.

### Task 4: WS reconnect with capped backoff; never fatal

**Files:**
- Modify: `prover/prover_hypercube/src/service.rs`

- [x] extract pure `fn backoff_delay(attempt: u32) -> Duration` (`2^attempts` capped, mirroring `fetcher.rs` constants; deliberate small duplication — the fetcher helpers are private to `z6m_common`)
- [x] on head-stream end/error inside `await_tip`: drop the stream, re-establish subscription with `backoff_delay`, reset backoff on success; while down, the backstop poll continues to supply the watermark
- [x] initial connect failure at service start: `warn!` and enter backstop mode with retries — the service must never exit due to `--ws-url` runtime failures (resilience mechanism delivered: `await_tip`'s down-branch treats `heads: None` — from a dead stream OR a never-established subscription — as backstop mode, retrying `try_resubscribe` on capped backoff each iteration and never erroring/exiting; the startup `warn!` + `HeadSource` construction that first enters this state lives at the Task 5 wiring site)
- [x] write tests: stream close → source keeps yielding watermarks via backstop and attempts resubscribe; `backoff_delay` progression and cap
- [x] run tests — must pass before Task 5

**Task 4 scope notes:**
- Reconnect re-issues `subscribe_blocks()` on the **retained pubsub provider** (`try_resubscribe`), per the Task 3 shape decision — alloy manages the WS transport's own reconnection, so re-subscribing picks up a healed connection. `backoff_delay` = `2_u64.pow(attempt.min(5))` s (1→2→4→8→16→32, capped), mirroring the fetcher.
- ⚠️ Consequence for Task 5: an **initial connect failure** leaves `provider: None`, so `try_resubscribe` can never succeed and the source runs on the backstop **indefinitely** (never-fatal, but no WS recovery). Full-connect retry after an initial failure would need the validated `Url` retained in the `Ws` variant and reconnect via `connect_ws_head_stream(&url)` instead — out of scope for never-fatal; Task 5 may add it if initial-failure WS recovery is required. A stream death **after** a successful connect is fully covered (provider retained → resubscribe with backoff).
- Backoff-counter semantics: the stream-end (`Ended`) transition only clears `heads` (no resubscribe attempted yet → counter unchanged); the down-branch is where `try_resubscribe` runs and bumps the counter on failure / resets to `0` on success.

### Task 5: Wire `HeadSource` selection into `run_service`

**Files:**
- Modify: `prover/prover_hypercube/src/service.rs`

- [x] add pure `fn head_source_kind(cfg: &ServiceConfig) -> HeadSourceKind` (Ws iff `ws_url` set) and construct the matching `HeadSource` at service start; one startup `info!` naming the mode (new startup-only line; per-block formats untouched)
- [x] Ws mode: seed `latest` with one `eth_blockNumber` call at service start regardless of `--start-block` (unseeded `latest=0` would send a behind-tip start into `await_tip` and stall catch-up); Poll mode startup unchanged
- [x] live-mode loop: Poll mode keeps today's per-iteration poll exactly; Ws mode calls `drain_tip` during catch-up (`next_block <= latest`, zero polling) and `await_tip` at tip
- [x] confirm `"[{ts}] Received block number from RPC {}"`, `BEGIN_FETCH`, and dispatch logic are byte-identical in both modes (verified: only the live-mode gate call changed to `wait_for_tip_live`; Poll delegates to the Task 1 `wait_for_tip` verbatim; all marker formats match `main` byte-for-byte)
- [x] write tests: `head_source_kind` selection for both configs; behind-tip first-iteration routing given a seeded watermark (pure decision fn or channel-injected `HeadSource`)
- [x] run tests — must pass before Task 6

**Task 5 scope notes:**
- Backstop provider decision: the `Ws` backstop is backed by the **HTTP `--rpc-url` provider**, not the WS pubsub provider. This is what makes the degradation contract hold — the backstop `eth_blockNumber` keeps advancing the watermark even when WS is fully down or was never established (initial connect failure leaves `provider: None`). The `Backstop` enum doc was updated from the Task 3 "over the WS provider" wording accordingly. The WS pubsub provider is retained only in `Ws.provider` for resubscribe (and the Task 6 WS-routed fetch).
- Initial-failure WS recovery was **not** added (the Task 4 note flagged it as optional here): the HTTP backstop already satisfies never-fatal, so `provider: None` after an initial connect failure runs on the backstop indefinitely with no WS resubscribe, exactly as Task 4 documented. A stream death *after* a successful connect is still fully covered (provider retained → resubscribe with backoff).
- New live-mode dispatcher `HeadSource::wait_for_tip_live(next_block, &mut latest)`: Poll delegates to the existing `wait_for_tip` (byte-identical, `latest` untouched); Ws drains during catch-up and awaits at tip, reporting `NotReady` (loop re-awaits, no busy spin) until the watermark reaches `next_block`. Removed the Task 3/4 `#[allow(dead_code)]` markers now that `Ws`/`drain_tip`/`await_tip`/`connect_ws_head_stream`/`backoff_delay`/`try_resubscribe`/`advance_watermark`/`Backstop::Provider` are reachable from `run_service`.

### Task 6: Fetcher provider injection (cover-first) + WS-routed fetch

**Files:**
- Modify: `prover/common/src/fetcher.rs`
- Modify: `prover/prover_hypercube/src/service.rs`
- Modify: `prover/prover_hypercube/src/main.rs`

- [ ] **cover first**: add `fn resolve_provider(injected: Option<DynProvider>, rpc_url: &str) -> eyre::Result<DynProvider>` with tests written BEFORE moving construction: `None` → builds HTTP provider from `rpc_url` (offline-safe — alloy HTTP providers construct lazily), `Some` → returns the injected provider; both arms construct without error
- [ ] refactor `fetch_block_and_witness`: `FetchRequest` gains `provider: Option<DynProvider>`; internal `connect_http` (:188-189) replaced by `resolve_provider`; raw-reqwest geth path (:105-135) untouched and documented HTTP-only
- [ ] update ALL THREE `FetchRequest` construction sites: `main.rs:295` (Fetch one-shot → `None`), `service.rs:305` (dead-code `fetch_block` → `None`), `service.rs:667` (run_service → `Some(ws_provider.clone())` iff WS mode and the subscription has been established at least once, `None` otherwise)
- [ ] WS-mode fetch fallback: on `fetch_block_and_witness` error with a `Some` provider, retry the block once with `provider: None` (HTTP from `--rpc-url`) before the existing skip at service.rs:679-682 — a dead WS connection must not skip blocks HTTP could serve
- [ ] write/extend tests for the refactor (both `resolve_provider` arms; `FetchRequest` construction from the call-site shapes)
- [ ] verify: `cargo build -p z6m_common -p z6m_prover && cargo test -p z6m_common -p z6m_prover`, then the diff-scoped clippy gate (no new warnings on changed lines)

### Task 7: `WitnessSource` seam in fetcher

**Files:**
- Modify: `prover/common/src/fetcher.rs`
- Modify: `prover/common/Cargo.toml` (add `[dev-dependencies] tempfile` — lock-transitive crates are not importable without an explicit entry)

- [ ] extract the witness-acquisition 3-path match (:258-290 — disk cache / geth / alloy) behind a thin `WitnessSource` enum with single variant `Request`; signature takes the resolved provider + block number + cache paths; `fetch_block_and_witness` delegates to it (PR 3 adds `PushWithFallback` here without touching `run_service`)
- [ ] keep the seam minimal — no config surface, no trait objects beyond what the two future variants need
- [ ] write tests: disk-cache-hit path returns a parsed witness from a fixture `executionWitness<N>.json` in a temp dir without any network
- [ ] run tests — must pass before Task 8

### Task 8: Anvil integration tests (`#[ignore]`, in-crate)

**Files:**
- Modify: `prover/prover_hypercube/src/service.rs` (tests live in the in-crate `#[cfg(test)]` module — the crate is binary-only, a `tests/` file cannot import `HeadSource`)

- [ ] add `#[tokio::test] #[ignore]` tests (names prefixed `ws_`) spawning Anvil via `node-bindings` with `--block-time 1`, connecting a real `HeadSource::Ws` to its ws endpoint
- [ ] test: watermark advances as Anvil mines (bounded wait, generous timeout)
- [ ] test: behind-tip start — mine 5 blocks first, seed the watermark via the startup poll (Task 5 semantics), assert an in-test cursor loop observes heights strictly sequentially to ≥5 via `drain_tip` only, never entering `await_tip` during catch-up
- [ ] mark both `#[ignore]` with a comment: requires `anvil` in PATH; run via `cargo test -p z6m_prover -- --ignored ws_`
- [ ] run the ignored tests locally once — must pass before Task 9

### Task 9: Verify acceptance criteria

- [ ] no `--ws-url` → byte-identical: diff-audit the Poll arm against pre-branch `service.rs` (cadence, retry counts, sleeps, memoryless per-iteration `latest`, all println/log formats); `grep -n 'BEGIN_FETCH\|BEGIN_EXEC\|Received block number' prover/prover_hypercube/src/service.rs` formats match `main`
- [ ] `git diff --stat main` touches only: `prover/prover_hypercube/src/{main,service}.rs`, `prover/common/src/fetcher.rs`, `prover/common/Cargo.toml`, `prover/Cargo.lock`, this plan, and (only if Task 3 needed the dep) `prover/prover_hypercube/Cargo.toml`; **zero `prover_turbo` changes**
- [ ] full suite: `cd prover && cargo test -p z6m_common -p z6m_prover`, then the diff-scoped clippy gate over both crates and fmt-cleanliness of this branch's hunks only (pre-existing clippy/fmt debt on `main` stays untouched — see Development Approach)
- [ ] `make z6m_prover` (Makefile:22) still builds
- [ ] re-read Overview requirements and confirm each is implemented (opt-in flag, watermark-only WS, seeded watermark + catch-up never waits, reconnect non-fatal, WS-routed fetch with HTTP fallback, formats unchanged)

### Task 10: Documentation + wrap-up

- [ ] add `--ws-url` to the service-mode docs if any exist (check `docs/architecture.md` service section; `--help` text otherwise suffices)
- [ ] update this plan's checkboxes to final state
- [ ] move this plan to `docs/plans/completed/`

## Post-Completion

**Manual e2e verification** (requires an erigon node with `--ws` enabled; witness serving needs `--prune.experimental.include-commitment-history`):
- run `--service --rpc-url http://… --ws-url ws://…` and a poll-only control; compare head→`BEGIN_FETCH` latency using the existing `now_ms` markers. Expect ~1s average (poll) → near-0 (ws).
- behind-tip scenario: start with `--start-block <tip-200>`, confirm sequential catch-up with zero `eth_blockNumber` calls in WS mode, then seamless switch to push-paced operation at tip.
- deep catch-up witnesses are bounded by the node's commitment-history retention; witness-cache accelerates only the last ≤96 blocks (slower, still correct, beyond).

**PR** (terse body, per repo owner's style): problem = live service wastes up to 2s/block polling and issues one `eth_blockNumber` per iteration even during catch-up; change = opt-in `--ws-url` newHeads tip watermark + fetch routed over the same WS connection; cursor loop, wire formats, and all CLI paths untouched without the flag. No Testing section, no session links.

**Series follow-ups** (not this repo/PR):
- PR 2 (erigon): `debug_subscribe("executionWitnesses")` push from the witness cache, subscribe-param encoding negotiation (`json` default; `rlp` base64 envelope later — kills zilkworm's hex→binary→hex→binary round trips).
- PR 3 (z6m): `WitnessSource::PushWithFallback` — at-tip pushed-as-announced, timeout → request fallback (also covers reorg/cache-miss/dropped-push).
