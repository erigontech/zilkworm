---
title: "RISCV Testing: EESTs on rv32im via QEMU"
description: Full guide to running and understanding EESTs for the RISCV target architecture with QEMU.
sidebar_position: 2
---


When running something Ethereum-adjacent, it’s more important to have testing as close to the actual environment as possible. “It works mostly” is far worse than “It needs some work still”.\
For the Ethereum Execution Layer, that test suite is the Ethereum Execution Spec Tests (EEST): a Python framework and collection of test cases that generate fixtures (JSON) used by execution clients to verify correctness across forks, edge cases, and consensus-critical behaviour - as also mentioned in [Ethereum Execution Tests (EESTs)](https://zilkworm.erigon.tech/documentation/testing/ethereum-execution-tests-eests) article\
Now we are concerned about the actual environment that is the minimal RISC-V target of rv32im which will be executed and proved within the zkVM enclave (such as Succinct Turbo).

### Quickstart

As mentioned in [Ethereum Execution Tests (EESTs)](https://zilkworm.erigon.tech/documentation/testing/ethereum-execution-tests-eests) we will be using the fixtures released officially and use a submodule of [erigontech/eest-fixtures](https://github.com/erigontech/eest-fixtures). To make things easier, we will be using the included `make` directive to run this one as well

**Prerequisites**

Before running the tests, make sure the following tools are installed:

* `ubuntu` (24.04+)
* `cmake,ninja`
* `git,git-lfs`
* `python3,python3-pip,pipx`
* `ctest` (usually shipped with CMake, but ensure it’s available on your PATH)
* `qemu-system-riscv`&#x20;
* `nodejs, npm`

> `git-lfs` is required because some test fixtures have very large files.

**Get the right toolchain (xpack's RISC-V toolchain)**

We'll be using [xpack's toolchain](https://xpack-dev-tools.github.io/riscv-none-elf-gcc-xpack/docs/install/) for this guide. You can go ahead and install it from the link.

```bash
npm i -g xpm
xpm install @xpack-dev-tools/riscv-none-elf-gcc@latest --global --verbose
export PATH=$HOME/.local/xPacks/@xpack-dev-tools/riscv-none-elf-gcc/15.2.0-1.1/.content/bin:$PATH
```

This guide involves cross-compiling, so you can expect some hassle as it's not a straightforward build from x86/ARM to RISC-V for troubleshooting some issues.

**Clone the repository**

Get the latest source for zilkworm and the submodules. Also get all the lfs hosted files:

```bash
git clone https://github.com/erigontech/zilkworm
git submodule update --init --recursive
git submodule foreach 'git lfs pull'
```

#### **Run EEST blockchain tests on RV32IM (via QEMU)**

```bash
cd zilkworm/qemu_runner
make rv32im_eest_blockchain_tests
```

That would build the project for rv32im and invoke `ctest` to launch a bunch of `qemu-system-riscv32` instances in the background. Each of these instances is passed with a JSON file to run as a test.\
The test completion can take a long time (several hours) as the baremetal emulation of rv32im that qemu has isn’t super-fast (to say the least). Added to that is the heavy text-manipulation of JSON-based tests

#### Testing completeness focusing on the architecture

The best workflow to use while doing a full test-driven-development is to run both:

* EESTs on your laptop natively: fast dev iteration, easy to debug, quick to catch logic errors
* EESTs via qemu: Useful to catch issues related to width and ABI assumptions, alignment, ISA-specific issues and assumptions (talked about in the next section). This serves as the ultimate compatibility and portability test.

So as a rule of thumb, if a test

* fails on both systems: it’s typically a logic or a spec mismatch issue
* fails only in rv32im: it could be an indication of an architecture-specific issue. It can even expose many functional and performance issues as well.
* passes on rv32im but fails on x86: could be a functional issue or one related to using a different processor construct for a code path (such as hardware accelerators)

### Thinking deeper around targets

Usually when not cross-compiling we rely on our habits and age-old customs and libraries for writing code. But the language doesn’t matter (but you should use C++ when you can). It’s the final machine code binary that the language compiles to is&#x20;

#### The cross-bugs being hunted for here

Running on RV32IM exposes a class of portability and architecture-bound correctness bugs that can remain invisible on typical 64-bit or non-RISC-V developer platforms. Here’s a curated list that is applicable to Zilkworm (and perhaps to other such clients)

**1) 32-bit width and narrowing bugs**

On RV32, core types like `size_t`, `uintptr_t`, and `long` are typically 32-bit, which tends to surface:

* accidental truncation when storing pointers/offsets in “integer-like” fields
* implicit narrowing when converting between 64-bit intermediates and 32-bit indices
* overflow in size calculations like `count * element_size` or buffer growth logic
* incorrect assumptions that `sizeof(long) == 8`

These issues frequently show up as memory corruption, wrong indexing, or incorrect boundary checks.

**2) Undefined behaviour that becomes observable on a different target**

Even when code compiles, cross-architecture execution can expose patterns like:

* signed overflow that was “benign” on one platform but not another
* shifts or bit operations with assumptions about type widths
* dependence on compiler-specific optimisation outcomes

**3) Alignment and memory layout assumptions**

RV32 environments are less forgiving of sloppy alignment expectations. RV32IM runs can reveal:

* incorrect struct packing assumptions
* unaligned access patterns that only *happened* to work elsewhere (typically not applicable here, but prevalent in languages like golang or C#)
* ABI/calling convention differences that may cause divergence in low-level code

If you’re doing performance-oriented execution work (as most clients do), this is where subtle bugs hide.

**4) Accidental dependencies on missing ISA features**

`rv32im` is intentionally minimal (32-bit base + integer and multiply). It does not include extensions like atomics (`A`) or floating point (`F/D`). That makes it excellent at catching:

* accidental use of floating point in code paths assumed to be integer-only
* implicit reliance on atomics (even in libraries), which may pull in unexpected runtime behaviour

**5) Expensive code-paths on rv32im specifically**

This is not a functional correctness bug, but it’s a practical consequence: RV32IM runs can expose instruction-count blowups where a path is acceptable on x86\_64 but becomes a performance cliff on a proving target.That matters because in ZK, slow execution often translates into quite expensive proving.
