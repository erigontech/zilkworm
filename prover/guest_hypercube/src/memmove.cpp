// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// Optimized memmove for SP1 zkVM.
//
// In SP1, memmove is called extensively by std::string operations
// (append, resize, copy) which never overlap. Forward to memcpy on
// the fast path with a backward byte copy fallback for the rare
// overlapping case.

#include <cstring>

extern "C" void *__wrap_memmove(void *dest, const void *src, size_t n) noexcept {
    auto *d = static_cast<unsigned char *>(dest);
    const auto *s = static_cast<const unsigned char *>(src);
    if (d <= s || d >= s + n) [[likely]]
        return memcpy(dest, src, n);

    // Overlapping, dest > src: copy backward.
    d += n;
    s += n;
    while (n--)
        *--d = *--s;
    return dest;
}
