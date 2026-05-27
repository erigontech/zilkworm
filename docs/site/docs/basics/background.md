---
title: Background
description: Why Zilkworm exists — Ethereum scaling, ZK proofs, and the case for a native C++ ZKEVM core.
sidebar_position: 3
---


There are several factors to take into account when thinking about the ZK future of EVMs and blockchains.

Firstly, today's validators on Ethereum-like chains are limited by the speed with which data can be transmitted across the network and then how fast a block can be re-executed. Verifying zero-knowledge proofs of blocks are much more efficient at achieving scaling than on the low end of the infrastructure spectrum. Following a successful rollout of this vision, consensus can progress without needing execute whole blocks. The end goal is then to provide a streamlined end to end application that can generate EVM + State Transition proofs for Ethereum or a similar blockchain.

Secondly, the ZK flow de-facto enables transaction privacy, as the exact nature or contents of the transactions are no longer needed to verify their correctness. This separates EVM itself from the consensus game and enables possibilities like private blockchains. This is not dissimilar to ZK-rollups themselves, but only more native to Ethereum itself with Zilkworm (and similar).

Thirdly, ZK prover backends have never been so performant and easy to work with. There has been an immense jump in prover performance over the past 2 years that makes real-time proving a reality today.

### RISC and no risk

Software technology cannot evolve in isolation and it thrives when the stars of various software domains align. RISC-V's open source minimal ISA has seen massive growth of interest and innovation both in interesting high-performance low-power use cases as well as with provable computation sphere.

The current generation of provers target minimal general purpose ISAs like RISC-V. That means existing client code and EVM code execution can be directly proved. Of course, this is a fairly new domain and it makes a ton more sense for a C++ or Rust software that has mature toolchains for this niche.

For zero-knowledge proofs based EVM/blockchains the proof systems and the overall stacks used to be hand-crafted before and it used to take a while. Whereas now it means feature iterations aren't dependent on heavy developer turnaround time. Additionally, existing (native compilable) projects like EVMOne fits right into become.

### EVM x zkVM = zkEVM

Zilkworm aims to make it easy to integrate different prover backends (zkVMs) that act on a similar ISA (currently only riscv32im and riscv64im). That means it integrates with prover solutions like Succinct's SP1, RISC0, Pico GPU Prover and so on.

Essentially, it's a stateless execution engine that takes the pre-state of a block from an existing execution trace and generates a proof of the state transition function.
