#!/usr/bin/env bash
# Checks debug_executionWitness responses against Reth stateless-validator.
# Requires: rustup with 1.93+, curl, python3, network access.

set -euo pipefail

KEEP_DIR=0
RLP_PATH=""
WITNESS_PATH=""
COUNT=1
POLL_SECS=4
while [ $# -gt 0 ]; do
    case "$1" in
        --keep-dir) KEEP_DIR=1; shift ;;
        --rlp)      RLP_PATH="$2"; shift 2 ;;
        --witness)  WITNESS_PATH="$2"; shift 2 ;;
        --block)    BLK="$2"; shift 2 ;;
        --count|-n) COUNT="$2"; shift 2 ;;
        --poll-secs)POLL_SECS="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,4p' "$0"; echo
            echo "Env:   RPC=<rpc-url>  BLK=<block-num>  DIR=<existing-dir>"
            echo "Flags: --keep-dir            keep the auto-generated project dir on exit"
            echo "       --block <N>           single-block mode: check this block (or use BLK env)"
            echo "       --count|-n <N>        poll for the next-latest block N times (default 1)"
            echo "       --poll-secs <S>       seconds between polls when waiting for a new tip (default 4)"
            echo "       --rlp <path>          use this blockRlp JSON instead of fetching via RPC"
            echo "       --witness <path>      use this witness JSON (or .json.gz / .json.tar.gz) instead of RPC"
            echo "Provide both --rlp and --witness (with --block or BLK) to skip RPC entirely (implies --count 1)."
            exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

# Validate --rlp/--witness pairing.
if { [ -n "$RLP_PATH" ] && [ -z "$WITNESS_PATH" ]; } || { [ -z "$RLP_PATH" ] && [ -n "$WITNESS_PATH" ]; }; then
    echo "--rlp and --witness must be passed together" >&2; exit 1
fi
LOCAL_INPUT=0
if [ -n "$RLP_PATH" ]; then
    [ -n "${BLK:-}" ] || { echo "--rlp/--witness require --block N or BLK env" >&2; exit 1; }
    [ -f "$RLP_PATH" ]     || { echo "rlp file not found: $RLP_PATH" >&2; exit 1; }
    [ -f "$WITNESS_PATH" ] || { echo "witness file not found: $WITNESS_PATH" >&2; exit 1; }
    [ "$COUNT" -eq 1 ]    || { echo "--rlp/--witness implies --count 1" >&2; exit 1; }
    LOCAL_INPUT=1
fi

RPC=${RPC:-http://localhost:8545}
DIR_AUTO=0
if [ -z "${DIR:-}" ]; then
    DIR=$(mktemp -d -t reth-check.XXXXXX)
    DIR_AUTO=1
fi
cleanup() {
    if [ "$KEEP_DIR" -eq 0 ] && [ "$DIR_AUTO" -eq 1 ]; then
        rm -rf "$DIR"
    fi
}
trap cleanup EXIT

rpc() {  # rpc <method> <params-json> -> .result JSON to stdout
    curl -fsS -X POST -H "Content-Type: application/json" \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"$1\",\"params\":$2,\"id\":1}" "$RPC" \
        | python3 -c "import json,sys; json.dump(json.load(sys.stdin)['result'], sys.stdout)"
}

rustup show active-toolchain 2>/dev/null | grep -qE "1\.(9[3-9]|[0-9]{3,})" \
    || rustup install 1.93.1 >/dev/null 2>&1

echo "Using project dir: $DIR"
mkdir -p "$DIR/src" && cd "$DIR"

# --- Clone + patch paradigmxyz/stateless so calculate_state_root surfaces every
# --- blinded-node position (addr_hash + slot_hash + missing-node nibble path)
# --- instead of swallowing the first error and returning a generic string.
STATELESS_REV=e5480e71a8031641ff471cad9dc482a7a14b32d5
STATELESS_DIR="$DIR/stateless-patch"
if [ ! -d "$STATELESS_DIR/.git" ]; then
    git clone --quiet https://github.com/paradigmxyz/stateless.git "$STATELESS_DIR"
fi
(cd "$STATELESS_DIR" && git fetch --quiet --depth 1 origin "$STATELESS_REV" && git reset --hard --quiet "$STATELESS_REV")

cat > "$STATELESS_DIR/blinded-trace.patch" <<'PATCH'
diff --git a/crates/stateless/src/validation.rs b/crates/stateless/src/validation.rs
--- a/crates/stateless/src/validation.rs
+++ b/crates/stateless/src/validation.rs
@@ -61,12 +61,12 @@ pub enum StatelessValidationError {
     ConsensusValidationFailed(#[from] ConsensusError),

     /// Error during stateless state root calculation.
-    #[error("stateless state root calculation failed")]
-    StatelessStateRootCalculationFailed,
+    #[error("stateless state root calculation failed: {0}")]
+    StatelessStateRootCalculationFailed(String),

     /// Error calculating the pre-state root from the witness data.
-    #[error("stateless pre-state root calculation failed")]
-    StatelessPreStateRootCalculationFailed,
+    #[error("stateless pre-state root calculation failed: {0}")]
+    StatelessPreStateRootCalculationFailed(String),

     /// Error when required ancestor headers are missing (e.g., parent header for pre-state root).
     #[error("missing required ancestor headers")]
@@ -113,11 +113,11 @@ impl From<StatelessTrieError> for StatelessValidationError {
             StatelessTrieError::WitnessRevealFailed { pre_state_root } => {
                 Self::WitnessRevealFailed { pre_state_root }
             }
-            StatelessTrieError::StatelessStateRootCalculationFailed => {
-                Self::StatelessStateRootCalculationFailed
+            StatelessTrieError::StatelessStateRootCalculationFailed(s) => {
+                Self::StatelessStateRootCalculationFailed(s)
             }
-            StatelessTrieError::StatelessPreStateRootCalculationFailed => {
-                Self::StatelessPreStateRootCalculationFailed
+            StatelessTrieError::StatelessPreStateRootCalculationFailed(s) => {
+                Self::StatelessPreStateRootCalculationFailed(s)
             }
             StatelessTrieError::PreStateRootMismatch { got, expected } => {
                 Self::PreStateRootMismatch { got, expected }
diff --git a/crates/tries/src/error.rs b/crates/tries/src/error.rs
--- a/crates/tries/src/error.rs
+++ b/crates/tries/src/error.rs
@@ -13,12 +13,12 @@ pub enum StatelessTrieError {
     },

     /// Error during state root calculation.
-    #[error("stateless state root calculation failed")]
-    StatelessStateRootCalculationFailed,
+    #[error("stateless state root calculation failed: {0}")]
+    StatelessStateRootCalculationFailed(String),

     /// Error calculating the pre-state root from the witness data.
-    #[error("stateless pre-state root calculation failed")]
-    StatelessPreStateRootCalculationFailed,
+    #[error("stateless pre-state root calculation failed: {0}")]
+    StatelessPreStateRootCalculationFailed(String),

     /// Error when the computed pre-state root does not match the expected one.
     #[error("mismatched pre-state root: {got} \n {expected}")]
diff --git a/crates/tries/src/default.rs b/crates/tries/src/default.rs
--- a/crates/tries/src/default.rs
+++ b/crates/tries/src/default.rs
@@ -97,7 +97,7 @@ impl StatelessSparseTrie {
         state: HashedPostState,
     ) -> Result<B256, StatelessTrieError> {
         calculate_state_root(&mut self.inner, state)
-            .map_err(|_e| StatelessTrieError::StatelessStateRootCalculationFailed)
+            .map_err(|e| StatelessTrieError::StatelessStateRootCalculationFailed(alloc::format!("{e:?}")))
     }
 }

@@ -168,7 +168,7 @@ fn verify_execution_witness(
     // Calculate the root
     let computed_root = trie
         .root(&provider_factory)
-        .map_err(|_e| StatelessTrieError::StatelessPreStateRootCalculationFailed)?;
+        .map_err(|e| StatelessTrieError::StatelessPreStateRootCalculationFailed(alloc::format!("{e:?}")))?;

     if computed_root == pre_state_root {
         Ok((trie, bytecode))
@@ -296,47 +296,56 @@ fn calculate_state_root(
     let storage_provider = DefaultTrieNodeProvider;

     for (address, storage) in state.storages.into_iter().sorted_unstable_by_key(|(addr, _)| *addr) {
-        // Take the existing storage trie (or create an empty, "revealed" one)
         let mut storage_trie =
             trie.take_storage_trie(&address).unwrap_or_else(RevealableSparseTrie::revealed_empty);

         if storage.wiped {
-            storage_trie.wipe()?;
+            if let Err(e) = storage_trie.wipe() {
+                println!("[blinded-trace] storage_wipe addr_hash=0x{:x} err={:?}", address, e);
+                storage_results.push((address, storage_trie));
+                continue;
+            }
         }

-        // Apply slot‑level changes
+        let mut account_failed = false;
         for (hashed_slot, value) in
             storage.storage.into_iter().sorted_unstable_by_key(|(slot, _)| *slot)
         {
+            if account_failed { break; }
             let nibbles = Nibbles::unpack(hashed_slot);
-            if value.is_zero() {
-                storage_trie.remove_leaf(&nibbles, &storage_provider)?;
+            let res = if value.is_zero() {
+                storage_trie.remove_leaf(&nibbles, &storage_provider)
             } else {
                 storage_trie.update_leaf(
                     nibbles,
                     alloy_rlp::encode_fixed_size(&value).to_vec(),
                     &storage_provider,
-                )?;
+                )
+            };
+            if let Err(e) = res {
+                println!(
+                    "[blinded-trace] storage_write addr_hash=0x{:x} slot_hash=0x{:x} value=0x{:x} err={:?}",
+                    address, hashed_slot, value, e
+                );
+                account_failed = true;
             }
         }

-        // Finalise the storage‑trie root before pushing the result
         storage_trie.root();
         storage_results.push((address, storage_trie));
     }

-    // Insert every updated storage trie back into the outer state trie
     for (address, storage_trie) in storage_results {
         trie.insert_storage_trie(address, storage_trie);
     }

-    // 2. Apply account‑level updates and (re)encode the account nodes
     for (hashed_address, account) in
         state.accounts.into_iter().sorted_unstable_by_key(|(addr, _)| *addr)
     {
-        trie.update_account_stateless(hashed_address, account, &provider_factory)?;
+        if let Err(e) = trie.update_account_stateless(hashed_address, account, &provider_factory) {
+            println!("[blinded-trace] account_update addr_hash=0x{:x} err={:?}", hashed_address, e);
+        }
     }

-    // Return new state root
     trie.root(&provider_factory)
 }
diff --git a/crates/tries/src/lib.rs b/crates/tries/src/lib.rs
--- a/crates/tries/src/lib.rs
+++ b/crates/tries/src/lib.rs
@@ -7,8 +7,7 @@
 )]
 #![cfg_attr(docsrs, feature(doc_cfg))]
 #![cfg_attr(not(test), warn(unused_crate_dependencies))]
-#![no_std]
-
+// no_std removed by stateless-patch so we can use `println!` from default.rs.
 extern crate alloc;

 /// Default trie implementation based on `reth_trie_sparse`.
PATCH
(cd "$STATELESS_DIR" && git apply --quiet blinded-trace.patch)

cat > Cargo.toml <<'EOF'
[package]
name = "reth-check"
version = "0.1.0"
edition = "2021"

[workspace]
exclude = ["stateless-patch"]

[dependencies]
serde_json = "1"
anyhow = "1"
hex = "0.4"
alloy-rlp = "0.3"
alloy-consensus = { version = "2", default-features = false }
alloy-primitives = "1"
reth-chainspec           = { git = "https://github.com/paradigmxyz/reth", tag = "v2.1.0" }
reth-evm-ethereum        = { git = "https://github.com/paradigmxyz/reth", tag = "v2.1.0" }
reth-ethereum-primitives = { git = "https://github.com/paradigmxyz/reth", tag = "v2.1.0" }
reth-primitives-traits   = "0.3"
stateless = { git = "https://github.com/paradigmxyz/stateless", rev = "e5480e71a8031641ff471cad9dc482a7a14b32d5", default-features = false }
tries     = { git = "https://github.com/paradigmxyz/stateless", rev = "e5480e71a8031641ff471cad9dc482a7a14b32d5" }

[patch."https://github.com/paradigmxyz/stateless"]
stateless = { path = "stateless-patch/crates/stateless" }
tries     = { path = "stateless-patch/crates/tries" }
EOF

cat > rust-toolchain.toml <<'EOF'
[toolchain]
channel = "1.93.1"
EOF

cat > src/main.rs <<'EOF'
use std::sync::Arc;
use anyhow::{Context, Result};
use alloy_consensus::{transaction::SignerRecoverable, Header};
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_rlp::Decodable;
use reth_chainspec::MAINNET;
use reth_ethereum_primitives::Block;
use reth_evm_ethereum::EthEvmConfig;
use reth_primitives_traits::RecoveredBlock;
use stateless::{stateless_validation_recovered, ExecutionWitness};
use tries::default::StatelessSparseTrie;

fn parse_slot_account(msg: &str) -> Option<(B256, B256)> {
    let take = |s: &str, after: &str| -> Option<B256> {
        let i = s.find(after)? + after.len();
        s[i..].chars().take_while(|c| c.is_ascii_hexdigit()).collect::<String>().parse().ok()
    };
    Some((take(msg, "slot 0x")?, take(msg, "account 0x")?))
}

fn preimage_of<'a>(w: &'a ExecutionWitness, target: B256, len: usize) -> Option<&'a [u8]> {
    w.keys.iter().find(|k| k.len() == len && keccak256(k) == target).map(|k| k.as_ref())
}

/// Strict-witness check using `StatelessSparseTrie` (same semantics as Reth's stateless
/// validator). `Ok(0)` = exclusion proof present (slot proven zero); `Ok(non-zero)` =
/// inclusion proof present; `Err(_)` = witness incomplete for this (addr, slot).
fn report_missing(w: &ExecutionWitness, pre_state_root: B256, slot_hash: B256, account_hash: B256) -> Result<()> {
    let (trie, _codes) = StatelessSparseTrie::new(w, pre_state_root)
        .map_err(|e| anyhow::anyhow!("StatelessSparseTrie::new: {e}"))?;
    let addr_bytes = preimage_of(w, account_hash, 20)
        .context("account preimage not in witness.keys[]")?;
    let slot_bytes = preimage_of(w, slot_hash, 32)
        .context("slot preimage not in witness.keys[]")?;
    let addr = Address::from_slice(addr_bytes);
    let slot = U256::from_be_slice(slot_bytes);
    println!("  state_trie  path (hashed_address): 0x{}", hex::encode(account_hash));
    println!("  storage_trie path (hashed_slot):    0x{}", hex::encode(slot_hash));
    println!("  address (preimage): 0x{}", hex::encode(addr));
    println!("  slot    (preimage): 0x{}", hex::encode(slot.to_be_bytes::<32>()));
    match trie.storage(addr, slot) {
        Ok(v) if v.is_zero() => println!("  -> exclusion proof PRESENT (slot proven zero)"),
        Ok(v) => println!("  -> inclusion proof PRESENT (slot value 0x{:x})", v),
        Err(e) => println!("  -> EXCLUSION PROOF MISSING: {e}"),
    }
    Ok(())
}

fn main() -> Result<()> {
    let mut a = std::env::args().skip(1);
    let dir = a.next().context("usage: reth-check <dir> <block_num>")?;
    let n: u64 = a.next().context("block_num")?.parse()?;
    let rlp_hex: String =
        serde_json::from_str(&std::fs::read_to_string(format!("{dir}/blockRlp{n}.json"))?)?;
    let mut bytes: &[u8] = &hex::decode(rlp_hex.trim_start_matches("0x"))?;
    let block: Block = Block::decode(&mut bytes)?;
    let w: ExecutionWitness =
        serde_json::from_str(&std::fs::read_to_string(format!("{dir}/executionWitness{n}.json"))?)?;
    let senders = block.body.transactions.iter()
        .map(|t| t.recover_signer().context("recover"))
        .collect::<Result<Vec<_>>>()?;
    let h = alloy_primitives::keccak256(alloy_rlp::encode(&block.header));
    let recovered = RecoveredBlock::new(block, senders, h.into());
    let msg = match stateless_validation_recovered(
        recovered, w.clone(), Arc::new((*MAINNET).clone()), EthEvmConfig::mainnet(),
    ) {
        Ok(_) => { println!("VALID"); return Ok(()); }
        Err(e) => format!("{e}"),
    };
    println!("INVALID -> {msg}");
    if let Some((slot_hash, acct_hash)) = parse_slot_account(&msg) {
        // Reconstruct pre-state root from the parent header in the witness.
        let parent_rlp = w.headers.last().context("witness has no headers")?;
        let mut prh: &[u8] = parent_rlp.as_ref();
        let parent_hdr = Header::decode(&mut prh).context("decode parent header")?;
        report_missing(&w, parent_hdr.state_root, slot_hash, acct_hash)?;
    }
    Ok(())
}
EOF

fetch_block() {  # fetch_block <BLK> -> writes data/<BLK>/blockRlp<BLK>.json + executionWitness<BLK>.json
    local BLK="$1"
    local HEX
    HEX=$(printf '0x%x' "$BLK")
    mkdir -p "data/$BLK"
    for M in debug_getRawBlock debug_executionWitness; do
        local F
        F=$([ "$M" = "debug_getRawBlock" ] && echo blockRlp || echo executionWitness)
        rpc "$M" "[\"$HEX\"]" > "data/$BLK/${F}${BLK}.json"
    done
}

# Build once so per-block runs are fast.
cargo build --release --quiet

if [ "$LOCAL_INPUT" -eq 1 ]; then
    HEX=$(printf '0x%x' "$BLK")
    echo "Checking block $BLK ($HEX) from local files"
    mkdir -p "data/$BLK"
    cp "$RLP_PATH" "data/$BLK/blockRlp${BLK}.json"
    case "$WITNESS_PATH" in
        *.tar.gz|*.tgz) tar -xOf "$WITNESS_PATH" > "data/$BLK/executionWitness${BLK}.json" ;;
        *.gz)           gunzip -c "$WITNESS_PATH" > "data/$BLK/executionWitness${BLK}.json" ;;
        *)              cp "$WITNESS_PATH" "data/$BLK/executionWitness${BLK}.json" ;;
    esac
    ./target/release/reth-check "data/$BLK" "$BLK"
elif [ "$COUNT" -eq 1 ]; then
    BLK=${BLK:-$(rpc eth_blockNumber '[]' | python3 -c "import json,sys; print(int(json.load(sys.stdin),16))")}
    HEX=$(printf '0x%x' "$BLK")
    HASH=$(rpc eth_getBlockByNumber "[\"$HEX\",false]" | python3 -c "import json,sys; print(json.load(sys.stdin)['hash'])")
    echo "Checking block $BLK ($HEX) hash=$HASH from $RPC"
    fetch_block "$BLK"
    ./target/release/reth-check "data/$BLK" "$BLK"
else
    # Poll for the next-latest block COUNT times.
    echo "Polling $RPC for $COUNT next-latest blocks (poll interval ${POLL_SECS}s)"
    SEEN=0
    LAST=0
    while [ "$SEEN" -lt "$COUNT" ]; do
        TIP=$(rpc eth_blockNumber '[]' | python3 -c "import json,sys; print(int(json.load(sys.stdin),16))")
        if [ "$TIP" -le "$LAST" ]; then
            sleep "$POLL_SECS"; continue
        fi
        BLK="$TIP"
        HEX=$(printf '0x%x' "$BLK")
        HASH=$(rpc eth_getBlockByNumber "[\"$HEX\",false]" | python3 -c "import json,sys; print(json.load(sys.stdin)['hash'])")
        SEEN=$((SEEN + 1))
        echo "--- [$SEEN/$COUNT] block $BLK ($HEX) hash=$HASH ---"
        fetch_block "$BLK"
        ./target/release/reth-check "data/$BLK" "$BLK" || true
        LAST="$BLK"
        echo
    done
fi
