---
name: fetch-blocks
description: Use to fetch Ethereum mainnet blocks from an RPC URL and save them on a local directory. Use it to acquire blocks for later execution/proving.
allowed-tools: Bash, Read, Glob
---

# Fetch Ethereum Blocks from RPC URL and Save to Local Directory

## Overview
The `z6m_prover` command with `--service` option runs a service fetching blocks at the tip or specified range and execute.

## Command Syntax

```bash
prover/target/release/z6m_prover --service --rpc-url <URL> --data-dir temp/mainnet --save-all-responses [other-flags] > temp/mainnet/fetch.log 2>&1
```

## Required Flags

- `--rpc-url`: URL of the RPC server to fetch blocks from (required). Use the `$RPC_URL` environment variable. If `$RPC_URL` is not set, ask the user for the URL.

## Usage Patterns

### Fetch and Execute Blocks at the Tip Until Stopped
```bash
prover/target/release/z6m_prover --service --rpc-url <URL> --data-dir temp/mainnet --save-all-responses > temp/mainnet/fetch.log 2>&1
```

### Fetch Blocks at the Tip Executing One In Every Million Until Stopped
```bash
prover/target/release/z6m_prover --service --rpc-url <URL> --data-dir temp/mainnet --save-all-responses --execute-every 1000000 > temp/mainnet/fetch.log 2>&1
```

### Fetch Blocks Range Without Executing
```bash
prover/target/release/z6m_prover --service --rpc-url <URL> --data-dir temp/mainnet --save-all-responses --start-block 24620000 --end-block 24620199 --execute-every 1000 > temp/mainnet/fetch.log 2>&1
```

## Important Considerations

### Fetching Without Executing
When specifying both `--start-block` and `--end-block`, you can use a value for `--execute-every` greater than the block range size to only fetch blocks without ever executing.

### Before Running
1. **Ensure z6m_prover binary is built**: run `make z6m_prover` to build it

## Workflow

When the user wants to fetch Ethereum blocks and save them to a local directory:

1. **Confirm parameters**
    - Ask for target RPC URL if not already known from context

2. **Run command**

## Error Handling

Common issues:
- **"Failed to get initial block number after retries"**: Verify the RPC URL is correct

## Examples

### Example 1: Fetch Blocks at the Tip From Public Reth Until Stopped
```bash
prover/target/release/z6m_prover --service --rpc-url $RPC_URL --data-dir temp/mainnet --save-all-responses --execute-every 1000000 > temp/mainnet/fetch.log 2>&1
```

### Example 2: Fetch Blocks Range [24620000, 24620199] Without Executing
```bash
prover/target/release/z6m_prover --service --rpc-url $RPC_URL --data-dir temp/mainnet --save-all-responses --start-block 24620000 --end-block 24620199 --execute-every 1000 > temp/mainnet/fetch.log 2>&1
```

## Tips

- If building from source, use `make z6m_prover` within the project home folder to build the binary at `prover/target/release/z6m_prover`
