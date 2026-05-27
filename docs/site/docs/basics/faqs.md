---
title: FAQs
description: Frequently asked questions about Zilkworm — benchmarks, team, timeline, integration plans, and prover backends.
sidebar_position: 5
---


### Can we see some Benchmarks?

Yes, find Zilkworm's proofs by going to [EthProofs](https://ethproofs.org/)

We are rapidly working to publish continuous results on [EthProofs](https://ethproofs.org/) and they will be published soon.\
Case by case benchmarks and Tests-Matrix would be released in a couple of weeks.

### Who's working on it?

At the moment the work is being led by Erigon developers. This is a short term "experiment" and we are looking to partner with other organisations to further the efforts.  (reach out to [som@erigon.tech](mailto:som@erigon.tech) or  [pawel.bylica@erigon.tech](mailto:pawel.bylica@erigon.tech) for developer queries)

### What are the timelines?

We'll be the first team to deliver real-time Ethereum Block proofs on 2 GPUs by 31 March 2026 - bet us on that.

### Challenges of C++ work in a Rust world?

There are quite a few challenges especially with the provided gcc toolkit on a limited `rv32im` target. We have ironed out most of them. It's not easy though as there is a "first-mover" advantage of some of the prover libraries initially being written in Rust.\
Having said that, RUST ↔ CPP bridge has zero bottlenecks and works perfectly within Zilkworm.

### Do you have it integrated in Erigon?

We have plans for this integration in two ways

* As a replacement for the current Erigon core for faster performance on x86 and ARM hardware
* As a prover through JSON-RPC integration

We will publish such plans in a later iteration of Zilkworm

### Can I use Zilkworm with another EL client like Nethermind or Besu?

Yes, the integration into other clients for prover would be the same way - over RPC. But in order to use the core directly as an executor, it would need closer collaboration with these other EL clients.

### Prover Killer Performance

For the proof generation itself the performance of intensive crypto operation would be dictated by the underlying prover backend (for instance SP1 or RISC0 or something else). We will publish more results on it in future.

### Plans for integration with other ZKVMs/Prover backends

The first rollout will have SP1 as the prover. We will rollout with others in due course of time.
