// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

/* Size-class free lists; dlmalloc for the rest. */

#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" {
struct _reent;
extern struct _reent *_impure_ptr;
void *_malloc_r(struct _reent *, std::size_t);
void _free_r(struct _reent *, void *);
void *_realloc_r(struct _reent *, void *, std::size_t);
void *_sbrk(std::ptrdiff_t);
}

namespace {

constexpr unsigned kNClass = 64;      // caps 16..1024 step 16
constexpr unsigned kArenaShift = 20;  // 1 MiB per class
constexpr std::size_t kArenaSz = std::size_t{1} << kArenaShift;

void *g_state[3 * kNClass];
std::uintptr_t g_small_base;

[[gnu::always_inline]] inline void *class_alloc(std::size_t n) noexcept {
    unsigned idx = (unsigned)((n - 1) >> 4);
    if (idx < kNClass) [[likely]] {
        void *p = g_state[idx];
        if (p) [[likely]] {
            g_state[idx] = *static_cast<void **>(p);
            return p;
        }
        auto *b = static_cast<char *>(g_state[kNClass + idx]);
        if (b <= static_cast<char *>(g_state[2 * kNClass + idx])) [[likely]] {
            g_state[kNClass + idx] = b + ((idx + 1) << 4);
            return b;
        }
    }
    return nullptr;
}

[[gnu::always_inline]] inline bool class_free(void *p) noexcept {
    unsigned idx = (unsigned)((reinterpret_cast<std::uintptr_t>(p) - g_small_base) >> kArenaShift);
    if (idx < kNClass) [[likely]] {
        *static_cast<void **>(p) = g_state[idx];
        g_state[idx] = p;
        return true;
    }
    return false;
}

}  // namespace

/* Before dlmalloc's first sbrk; enables range free. */
extern "C" void zisk_alloc_init() noexcept {
    auto cur = reinterpret_cast<std::uintptr_t>(_sbrk(0));
    std::uintptr_t base = (cur + kArenaSz - 1) & ~(kArenaSz - 1);
    _sbrk(static_cast<std::ptrdiff_t>((base - cur) + (std::size_t{kNClass} << kArenaShift)));
    g_small_base = base;
    for (unsigned i = 0; i < kNClass; ++i) {
        auto *a = reinterpret_cast<char *>(base + (std::uintptr_t{i} << kArenaShift));
        g_state[kNClass + i] = a;
        g_state[2 * kNClass + i] = a + kArenaSz - ((i + 1) << 4);
    }
}

extern "C" void *malloc(std::size_t n) noexcept {
    if (void *p = class_alloc(n)) [[likely]]
        return p;
    return _malloc_r(_impure_ptr, n);
}

extern "C" void free(void *p) noexcept {
    if (!p) [[unlikely]]
        return;
    if (class_free(p)) [[likely]]
        return;
    _free_r(_impure_ptr, p);
}

extern "C" void *calloc(std::size_t a, std::size_t b) noexcept {
    if (a != 0 && b > (std::size_t)-1 / a) [[unlikely]]
        return nullptr;
    std::size_t n = a * b;
    void *p = malloc(n);
    if (p) [[likely]]
        std::memset(p, 0, n);
    return p;
}

extern "C" void *realloc(void *p, std::size_t n) noexcept {
    if (!p) [[unlikely]]
        return malloc(n);
    if (!n) [[unlikely]] {
        free(p);
        return nullptr;
    }
    unsigned old = (unsigned)((reinterpret_cast<std::uintptr_t>(p) - g_small_base) >> kArenaShift);
    if (old >= kNClass) [[unlikely]]
        return _realloc_r(_impure_ptr, p, n);
    unsigned idx = (unsigned)((n - 1) >> 4);
    if (idx == old) [[likely]]
        return p;
    void *q = malloc(n);
    if (!q) [[unlikely]]
        return nullptr;
    std::size_t keep = (old + 1) << 4;
    if (keep > n)
        keep = n;
    std::memcpy(q, p, keep);
    free(p);
    return q;
}

#if defined(ZISK)

// Inlinable replacements for libstdc++ archive ops.
extern "C" [[noreturn]] void _ZSt17__throw_bad_allocv();

[[gnu::always_inline]] inline void *zisk_new(std::size_t n) {
    if (n == 0) [[unlikely]]
        n = 1;
    if (void *p = class_alloc(n)) [[likely]]
        return p;
    void *p = _malloc_r(_impure_ptr, n);
    if (!p) [[unlikely]]
        _ZSt17__throw_bad_allocv();
    return p;
}

[[gnu::always_inline]] inline void zisk_delete(void *p) noexcept {
    if (!class_free(p) && p) [[unlikely]]
        _free_r(_impure_ptr, p);
}

// Strong defs; weak ones lose to new_op.o.
[[gnu::always_inline]] void *operator new(std::size_t n) { return zisk_new(n); }
[[gnu::always_inline]] void *operator new[](std::size_t n) { return zisk_new(n); }
[[gnu::always_inline]] void operator delete(void *p) noexcept { zisk_delete(p); }
[[gnu::always_inline]] void operator delete(void *p, std::size_t) noexcept { zisk_delete(p); }
[[gnu::always_inline]] void operator delete[](void *p) noexcept { zisk_delete(p); }
[[gnu::always_inline]] void operator delete[](void *p, std::size_t) noexcept { zisk_delete(p); }

#endif  // ZISK
