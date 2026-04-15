

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo_224_80_white.svg">
    <source media="(prefers-color-scheme: light)" srcset="assets/logo_224_80.svg">
    <img alt="Project Logo" src="docs/assets/logo-light.png" width="320">
  </picture>
</p>

<p align="center">
    <strong>A fast, modular, optimized ZKEVM core written in C++</strong>
</p>


🚧 [ALPHA STAGE: This is in pre-release. Functional for block execution and proof generation, but not yet production-ready.] 🚧


Zilkworm is a prototype implementation of a ZKEVM (Zero-Knowledge Ethereum Virtual Machine) generating ZK proofs that an        
Ethereum block was executed correctly, without requiring re-execution of the block itself.

Zilkworm is written in C++ (with a Rust orchestration layer) building on past works within Silkworm and EVMOne to run on
zkVM provers with native support for RISC-V targets (e.g. rv32im).
At the moment, the zkVM integrated is Succint's SP1 Hypercube.
                                                                                                                                                                                            
## High-Level Workflow

1. _Fetch_ — Retrieve a block + its execution witness from an Ethereum RPC node (Reth/Geth)
2. _Execute_ (dry-run) — Run the EVM inside the zkVM without proof generation (for testing)
3. _Prove_ — Generate a full ZK proof of correct block execution
4. _Verify_ — Verify a previously generated proof
5. _Service_ — Continuously poll a node and prove blocks as they arrive

## Architecture

For a high-level overview of the system, see [here](docs/architecture.md).

### How ZK Ethereum Provers Work Generally

The broader idea: a ZK prover takes an Ethereum block + pre-state witness, re-executes all transactions inside a zkVM
and produces a cryptographic proof that the execution was done correctly. This proof can be verified cheaply by anyone
on a lighter hardware without re-executing the block. This also enables other applications like light clients,
bridges, and rollup verification.

Zilkworm sits alongside other ZKEVM provers in this ecosystem, differentiated by its approach of running a C++ EVM
inside the zkVM rather than a Rust one.


## How to Run

At the moment building from source requires elaborate setup with conan, linux packages and SP1 Turbo SDK pre-requisites. It's recommended to use the pre-built docker image.

To run with pre-built docker

```
$ docker run somnergy/z6m_prover --help
```
```
Usage: z6m_prover [OPTIONS] [COMMAND]

Commands:
  setup    Run setup to generate proving and verifying keys
  fetch    Fetch block and witness from RPC
  execute  Execute the guest program without proving
  prove    Generate a proof for a block
  verify   Verify a proof using a verification key
  help     Print this message or the help of the given subcommand(s)

Options:
      --service                                      
      --rpc-url <RPC_URL>                            
      --data-dir <DATA_DIR>                          [default: temp]
      --save-all-responses                           
      --prove-every <PROVE_EVERY>                    
      --execute-every <EXECUTE_EVERY>                
      --post-every <POST_EVERY>                      
      --start-block <START_BLOCK>                    
      --end-block <END_BLOCK>                        
      --pk-path <PK_PATH>                            [default: pk.bin]
      --proof-type <PROOF_TYPE>                      [default: compressed]
      --ethproofs-endpoint <ETHPROOFS_ENDPOINT>      
      --ethproofs-token <ETHPROOFS_TOKEN>            
      --ethproofs-cluster-id <ETHPROOFS_CLUSTER_ID>  
  -h, --help  
```

### First Fetch the block
```
Usage: z6m_prover fetch [OPTIONS]

Options:
      --rpc-url <RPC_URL>            RPC endpoint URL
      --block-number <BLOCK_NUMBER>  Block number to fetch
      --data-dir <DATA_DIR>          Output directory
      --save-all-responses           Whether to save all the json files to disk after download
      --build-eth-test               Whether to create an ethereum/tests format json file too
  -h, --help                         Print help

```
### Dry run execute - just use --block-number for this

```
Usage: z6m_prover execute [OPTIONS]

Options:
      --block-number <BLOCK_NUMBER>  Block number to execute [default: 0]
      --file-name <FILE_NAME>        Whether the input file is an Ethereum/tests file
      --is-test                      
      --data-dir <DATA_DIR>          Data directory
  -h, --help                         Print help

```
### Fire up the prover
```
Usage: z6m_prover prove [OPTIONS]
Options:
      --block-number <BLOCK_NUMBER>  JSON file to load ethereum/tests format test from [default: 0]
      --file-name <FILE_NAME>        Whether the input file is an Ethereum/tests file
      --is-test                      
      --data-dir <DATA_DIR>          Data directory
      --pk-path <PK_PATH>            Proving key path [default: pk.bin]
      --proof-path <PROOF_PATH>      Proof output path
      --proof-type <PROOF_TYPE>      Proof type: core, compressed, groth16, plonk [default: compressed]
  -h, --help                         Print help

```

### Test service (offline batch execution)

Execute a range of blocks from disk without RPC or prover key setup:

```bash
z6m_prover --test-service \
  --data-dir /path/to/witness_blocks \
  --start-block 24490786 --end-block 24490805 \
  --execute-every 1
```

Blocks are read from `<data-dir>/blocks/<block_number>/unifiedBlockAndStateRlp<block_number>.bin`. Missing blocks are skipped with a warning. Results are appended to `<data-dir>/executionLogs.log`.

### Single block execute from disk

```bash
z6m_prover execute --file-name /path/to/unifiedBlockAndStateRlp24490786.bin --data-dir /path/to/output
```

### Cycle stats

Install the Python dependencies first:

```bash
pip install -r requirements.txt
```

Plot execution metrics from the log file:

```bash
python3 prover/prover_hypercube/src/stats/cycle_stats.py \
  -i /path/to/executionLogs.log \
  -o /path/to/results_plot.png \
  --no-display
```

## NVIDIA CUDA Accelerated proving
First make sure to install NVIDIA drivers and the NVIDIA Container Toolkit https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html
```
$ user@machine-with-gpu
docker run --gpus all --rm --network host -v "$PWD:/work:rw" -v /var/run/docker.sock:/var/run/docker.sock  -w /work -it --entrypoint bash somnergy/z6m_prover

root@instance-20250919-091229:/work# 
SP1_PROVER=cuda RUST_BACKTRACE=full RUST_LOG=info --prove --n 1 --file-name test.json
```

## Testing

### Native build

1. Download and unpack the latest stable [EEST release](https://github.com/ethereum/execution-spec-tests/releases).
2. Configure and build the CMake project with the path to the blockchain tests of the EEST:
   ```bash
   cmake -B build/release -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON -DTESTS_DIR=/path/to/fixtures/blockchain_tests
   cmake --build build/release
   ```
3. Run all tests with CTest:
   ```bash
   ctest --test-dir build/release --parallel
   ```
4. Run specific unified RLP-encoded block file:
    ```bash
    build/release/zilk_core/dev/cli/state_transition temp/blocks/23519000/unifiedBlockAndStateRlp23519000.bin
    ```

## Acknowledgements
We thank the hard work done by the teams and people behind
1. Silkworm
2. EVMOne (especially @chfast)
3. Succicnt (for SP1 and rsp)
4. RISCV
5. C++ Conglomerate
6. The Rust community

