---
title: Introduction
description: The Zilkworm project at a glance.
sidebar_position: 2
---


### The Naming

Zilkworm is an evolution of Silkworm Ethereum Client implementation by Erigon team in C++. This is one focussed on zero-knowledge proof systems that use RISCV backend. The existing EVMOne implementation is re-used, with tweaks targeted towards the prover SDK (such as Succinct SP1). While Silkworm was more focussed on RPC's, full scale integration with Erigon and features of full database layer, Zilkworm is more focussed on the core that runs state\_transition of blocks, such as the EVM, signature validation and Merkle Patricia Trie.

### The Driver

The driving inspiration for ZK proofs of full block state transition is align with the Ethereum's overall vision to scale the L1, focus on privacy and embrace a new RISC-V paradigm.&#x20;

Of course, fulfilling these objectives together is a massive engineering challenge. It's a great time right now to be targetting RISC-V based provers which have shown promise in the recent years. Now it needs much push and optimization from the protocol side of things, including well thought out client core implementation itself

Full Ethereum block proofs further open innovations for Layer-2 chains with possibilities of faster finality and fast 2-way interactions. Typically this was not thought to be possible earlier because of the economics of the proving itself.

### The Objective

After initial successes in being able to prove full Ethereum blocks, we aim to further investigate opportunites of tuning the system to achieve close to real time proving from a home computer with one or two GPUs.

To that end Zilkworm's objective would be to enhance and optimize its core and provide an end to end solution for creating economic full type-1 EVM chain block proofs.
