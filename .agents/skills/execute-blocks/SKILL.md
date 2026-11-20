---
name: execute-blocks
description: Use to execute Ethereum mainnet blocks from a local directory (dry run). Use it to execute downloaded blocks without proving.
allowed-tools: Bash, Read, Glob
---

# Execute Ethereum Blocks Without Proving from Local Directory

## Overview
The `z6m_prover` command with `--test-service` option executes the specified range of blocks from a local directory.

## Command Syntax

```bash
prover/target/release/z6m_prover --test-service --data-dir temp/mainnet --start-block <START> --end-block <END> --execution-log-file=temp/mainnet/logs/<feature>_<commit>.log
```

## Required Flags

- `--start-block`: The first block to execute (required)
- `--end-block`: The last block to execute (required)

## Important Considerations

### Before Running
1. **Ensure z6m_prover binary is built**: run `make z6m_prover` to build it

## Workflow

When the user wants to execute Ethereum Blocks from local directory:

1. **Confirm parameters**
    - Ask for the block range to execute if not already known from context

2. **Run command**

## Examples

### Example 1: Execute Blocks Without Proving in the Specified Block Range
```bash
prover/target/release/z6m_prover --test-service --data-dir temp/mainnet --start-block 24620000 --end-block 24620199 --execution-log-file=temp/mainnet/logs/<feature>_<commit>.log
```

## Tips

- If building from source, use `make z6m_prover` within the project home folder to build the binary at `prover/target/release/z6m_prover`
