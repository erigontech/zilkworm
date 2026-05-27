---
title: Ethereum Execution Tests (EESTs)
description: Run the Ethereum Execution Spec Tests (EELS-derived fixtures) against Zilkworm to verify EVM correctness across forks.
sidebar_position: 1
---


:::tip
zilkworm is up-to-date with Osaka implementation and passes 100% of EESTs till Osaka
:::

### What are EESTs (Ethereum Execution Spec Tests)

Ethereum Execution Spec Tests (EESTs) are the **canonical, specification-aligned test vectors** for validating Ethereum Execution Layer (EL) behavior across forks and edge cases. If you are building an execution engine or any block execution component, EESTs are one of the fastest ways to detect **consensus-breaking discrepancies** and prevent regressions.

These tests are based on standardized "reference-implementation" that we now call the Ethereum Execution Layer Specifications (EELS). The team behind these specs and the tests make regular releases over at https://github.com/ethereum/execution-spec-tests and more information can be found at their documentation at [**https://eest.ethereum.org/**](https://eest.ethereum.org/)

#### **The Fixtures**

The fixtures for the tests can be obtained directly by downloading the tarball of the latest release of EESTs. But our experience with working on Erigon Client nudges us to use a submodule approach for integrating them more cleanly across different  environments.

At the time of writing this, we are re-using the Erigon's fixture repository at https://github.com/erigontech/eest-fixtures. This contains the latest production EEST release fixtures (.json files). This also includes the large and heavy ones that are stored with `git-lfs`.

***

### Running EESTs with Zilkworm

Zilkworm provides a Makefile target to run the EEST **blockchain tests** suite. These tests validate multi-block execution flows (as opposed to single state transitions) and are especially useful for ensuring correctness across sequences of blocks and transactions.

#### Prerequisites

Before running the tests, make sure the following tools are installed:

* `gcc/g++` (**15+)**
* `cmake,ninja` &#x20;
* `git,git-lfs`
* `python3,python3-pip,pipx` &#x20;
* `ctest` (usually shipped with CMake, but ensure it’s available on your PATH)

> `git-lfs` is required because some test fixtures have very large files.

#### Clone the repository

Get the latest source for zilkworm

```bash
git clone https://github.com/erigontech/zilkworm
```

Make sure to get the submodules (there are a few). This may take a bit of time:

```bash
git submodule update --init --recursive
```

#### Run the EEST blockchain tests

From the **root of the Zilkworm repository**, run:

```bash
make eest-blockchain-tests
```
