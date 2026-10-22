// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// Bare-metal heap source for newlib malloc. The prebuilt libnosys.a _sbrk stub
// always returns -1, so malloc fails and the guest dereferences null; provide a
// real bump allocator growing from the end of BSS (same shape as the hypercube
// guest's sp1_runtime.cpp _sbrk). The guest is short-lived and single-threaded:
// memory is never returned, which is fine for a per-block run.
//
// The Rust side allocates its own heap (sp1-zkvm's embedded allocators), so this
// region only serves the C++ standard library.

#include <stddef.h>

extern char _end;  // linker-provided end of BSS

static char *_heap_ptr = &_end;

void *_sbrk(ptrdiff_t incr)
{
    char *prev = _heap_ptr;
    _heap_ptr += incr;
    return prev;
}
