---
title: Ethereum Block Proofs
description: Generate verifiable ZK proofs of full Ethereum mainnet block execution with Zilkworm — the foundational use case.
sidebar_position: 1
---


Generating full state transition proofs for Ethereum mainnet was one of the first motivations for Zilkworm. This article explores Ethereum's ZK perspective and Zilkworm's contributions.

### Scale through ZK Proofs

The ongoing narrative is that once you have a STARK proof for a full block state transition, you can just verify and apply state root changes without having to download blocks and re-execute all transactions. As of today, network and hardware restrictions limit the block size to less than 100M gas (so, typically 60M gas is safe). And the limit can't be raised too high without affecting decentralization of validators.\
\
zkVMs have now ramped up performance and parallelization enough to have now been able to prove a whole block in less than 15 seconds. This means a relatively low-end hardware could run as a validator for massive blocks!

### How the Validator now looks

Post-merge Ethereum block progression would happen through a Consensus Layer (CL) and an Execution Layer (EL) client, together with a validator software that signs off on new blocks. The driver of this is the Consensus Layer that requests the EL to check if a new block is valid by asking it to download it or by providing the "payload" of a new block obtained from the p2p network. The EL upon receiving the payload/new block would execute the state transition function by running protocol checks and processing the transactions through the EVM.

In the post ZKalyptic times the validator can simply attest new blocks "as they come" with proofs without needing either the CL or the EL. The CL still needs to find its way through any malicious blocks to find the canonical block and the EL is simply replaced by a database. That holds, if it is not a block-builder.

What about the state changes? Well, interestingly, the leading proponent on the EL side for Glamsterdam hard-fork is Block-Level Access Lists that would contain the set of all writes to happen to a database. That means a BAL + Proof is all you need to keep your database up-to-date with the canonical "block"!

### The STARK way

STARKs are post-quantum resistant, faster to generate and don't need a "trusted" setup, as against SNARKs - the other popular paradigm of ZK proofs in this generation.

Currently, though, STARKs are huge when looking at the verification time and the size of the proofs. In some cases the verification time of a STARK proof could be comparable or even more than that of the naive execution of the block itself. That's why another approach to the final proving is to generate a SNARK proof of the verification of the STARK proof with constant sizes and verification time for the final proof that's very manageable.

As the protocol, the prover technology and cryptography itself evolves, it's to be seen what final form of ZK we adopt for this use case.
