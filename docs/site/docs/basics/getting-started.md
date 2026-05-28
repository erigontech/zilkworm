---
title: Getting Started
description: Run the Zilkworm prover via the pre-built Docker image — setup, block fetch, dry-run execute, prove, and CUDA acceleration.
sidebar_position: 1
---


### How to Run

At the moment the building from source requires elaborate setup with Conan, Linux packages and SP1 Turbo SDK pre-requisites. It's recommended to use the pre-built Docker image.

To run with pre-built Docker

```bash
$ docker run somnergy/z6m_prover --help
```

```text
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

#### First Fetch the block

```text
Usage: z6m_prover fetch [OPTIONS]

Options:
      --rpc-url <RPC_URL>            RPC endpoint URL
      --block-number <BLOCK_NUMBER>  Block number to fetch
      --data-dir <DATA_DIR>          Output directory
      --save-all-responses           Whether to save all the json files to disk after download
      --build-eth-test               Whether to create an ethereum/tests format json file too
  -h, --help                         Print help

```

#### Dry run execute - just use --block-number for this

```text
Usage: z6m_prover execute [OPTIONS]

Options:
      --block-number <BLOCK_NUMBER>  Block number to execute [default: 0]
      --file-name <FILE_NAME>        Whether the input file is an Ethereum/tests file
      --is-test                      
      --data-dir <DATA_DIR>          Data directory
  -h, --help                         Print help

```

#### Fire up the prover

```text
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

### NVIDIA CUDA Accelerated proving

First make sure to install NVIDIA drivers and the NVIDIA Container Toolkit https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html

```bash
$ user@machine-with-gpu
docker run --gpus all --rm --network host -v "$PWD:/work:rw" -v /var/run/docker.sock:/var/run/docker.sock  -w /work -it --entrypoint bash somnergy/z6m_prover

root@instance-20250919-091229:/work# 
SP1_PROVER=cuda RUST_BACKTRACE=full RUST_LOG=info --prove --n 1 --file-name test.json
```
