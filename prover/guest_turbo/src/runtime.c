// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// Bare-metal heap source for newlib malloc. The prebuilt libnosys.a _sbrk stub
// always returns -1, so malloc fails and the guest dereferences null; provide a
// real bump allocator (same shape as the hypercube guest's sp1_runtime.cpp
// _sbrk).
//
// Layout constraint: sp1-zkvm's embedded allocator bumps the RUST heap UP from
// &_end, with its limit at EMBEDDED_RESERVED_INPUT_START = MAX_MEMORY
// (0x78000000) - 1 GB = 0x38000000 (sp1-zkvm 5.2.x src/allocators/embedded.rs).
// Starting the C++ heap at a fixed base well above anything the Rust side
// allocates (the envelope Vec tops out at ~2x the largest bundle, a few tens
// of MB) keeps the two disjoint; the C++ heap then has the ~640 MB up to
// 0x38000000 to itself. Starting at &_end — the tempting choice — overlaps the
// Rust heap and corrupts both.

#include <stddef.h>

extern char _end;  // linker-provided end of BSS; the Rust heap's base

#define Z6M_CXX_HEAP_BASE ((char *)0x10000000)

static char *_heap_ptr = Z6M_CXX_HEAP_BASE;

void *_sbrk(ptrdiff_t incr)
{
    char *prev = _heap_ptr;
    char *next = _heap_ptr + incr;
    if (incr < 0 || next < prev || next >= Z6M_CXX_HEAP_BASE + 0x28000000) {
        return (void *)-1;  // exhausted or bad request
    }
    _heap_ptr = next;
    return prev;
}
