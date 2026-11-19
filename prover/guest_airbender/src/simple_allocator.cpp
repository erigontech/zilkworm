#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <new>

#ifdef GUEST_ALLOCATOR_HOST_TEST
// The host test (guest_allocator_test.cpp) compiles this text with renamed operators and a throwing finish_error.
#include <new>
namespace airbender {
[[noreturn]] void finish_error() {
    throw std::bad_alloc{};
}
}
#else
#include "include/airbender_csr.hpp"
#endif

extern "C" {
extern uint8_t _sheap[];
extern uint8_t _eheap[];
}

// externally_visible keeps LTO from folding heap_end; constinit, as constructors before main allocate.
#if defined(__GNUC__) && !defined(__clang__)
#define GUEST_EXTERNALLY_VISIBLE __attribute__((externally_visible))
#else
#define GUEST_EXTERNALLY_VISIBLE
#endif
constinit uint8_t* heap_next = _sheap;
GUEST_EXTERNALLY_VISIBLE constinit uint8_t* heap_end = _eheap;

// _sheap/_eheap are 2 MiB-aligned (link.x): rounding heap_next to <= 2 MiB stays <= heap_end.
static constexpr size_t kMaxAlign = 2097152;

// Null when the request does not fit; throwing operator new forms must never return null, so they end the run.
static void* bump_allocate(size_t size) {
    // Align to 8 bytes so that any naturally-aligned type can be stored.
    uintptr_t p = (reinterpret_cast<uintptr_t>(heap_next) + 7u) & ~uintptr_t{7u};
    // Compare against the room left: p + size wraps for huge sizes.
    if (size > reinterpret_cast<uintptr_t>(heap_end) - p) {
        return nullptr;
    }
    heap_next = reinterpret_cast<uint8_t*>(p + size);
    return reinterpret_cast<void*>(p);
}

// A request past the free heap cannot continue: end at finish_error so it cannot be proven.
static void* bump_allocate_or_finish(void* ptr) {
    if (ptr == nullptr) {
        airbender::finish_error();
    }
    return ptr;
}

void* operator new(size_t size) {
    return bump_allocate_or_finish(bump_allocate(size));
}

void* operator new(size_t size, const std::nothrow_t&) noexcept {
    return bump_allocate(size);
}

void* operator new[](size_t size) {
    return bump_allocate_or_finish(bump_allocate(size));
}

void* operator new[](size_t size, const std::nothrow_t&) noexcept {
    return bump_allocate(size);
}

static void* bump_allocate_aligned(size_t size, size_t align) {
    if (align < 8) {
        align = 8;
    }
    if (align > kMaxAlign) {
        return nullptr;
    }
    uintptr_t p = (reinterpret_cast<uintptr_t>(heap_next) + (align - 1)) & ~(align - 1);
    if (size > reinterpret_cast<uintptr_t>(heap_end) - p) {
        return nullptr;
    }
    heap_next = reinterpret_cast<uint8_t*>(p + size);
    return reinterpret_cast<void*>(p);
}

// Over-aligned types must not reach libstdc++'s versions: newlib's memalign puts chunk headers in unallocated heap.
void* operator new(size_t size, std::align_val_t al) {
    return bump_allocate_or_finish(bump_allocate_aligned(size, static_cast<size_t>(al)));
}

void* operator new[](size_t size, std::align_val_t al) {
    return bump_allocate_or_finish(bump_allocate_aligned(size, static_cast<size_t>(al)));
}

void* operator new(size_t size, std::align_val_t al, const std::nothrow_t&) noexcept {
    return bump_allocate_aligned(size, static_cast<size_t>(al));
}

void* operator new[](size_t size, std::align_val_t al, const std::nothrow_t&) noexcept {
    return bump_allocate_aligned(size, static_cast<size_t>(al));
}

// Every delete is empty so LTO drops the calls and free-only destructor loops; do not mark them noinline.
void operator delete(void*) noexcept {}
void operator delete[](void*) noexcept {}
void operator delete(void*, size_t) noexcept {}
void operator delete[](void*, size_t) noexcept {}
void operator delete(void*, const std::nothrow_t&) noexcept {}
void operator delete[](void*, const std::nothrow_t&) noexcept {}
void operator delete(void*, std::align_val_t) noexcept {}
void operator delete[](void*, std::align_val_t) noexcept {}
void operator delete(void*, size_t, std::align_val_t) noexcept {}
void operator delete[](void*, size_t, std::align_val_t) noexcept {}
void operator delete(void*, std::align_val_t, const std::nothrow_t&) noexcept {}
void operator delete[](void*, std::align_val_t, const std::nothrow_t&) noexcept {}

// C allocation shares the bump allocator: newlib's arena would overlap _sheap and corrupt the witness blob.
extern "C" {

void* malloc(size_t size) {
    return bump_allocate(size);
}

void free(void*) {
}

void* calloc(size_t nmemb, size_t size) {
    size_t total;
    if (__builtin_mul_overflow(nmemb, size, &total)) {
        return nullptr;
    }
    // No zeroing: no byte is handed out twice and untouched RAM reads 0; reusing memory would need zeroing back.
    return bump_allocate(total);
}

void* realloc(void* ptr, size_t size) {
    if (ptr == nullptr) {
        return malloc(size);
    }
    if (size == 0) {
        return nullptr;
    }
    void* q = malloc(size);
    if (q != nullptr) {
        // Size untracked: over-copy stays in RAM, callers zero the rest; memmove, the tail may overlap.
        __builtin_memmove(q, ptr, size);
    }
    return q;
}

static inline bool is_pow2(size_t x) {
    return x != 0 && (x & (x - 1)) == 0;
}

void* memalign(size_t align, size_t size) {
    return is_pow2(align) ? bump_allocate_aligned(size, align) : nullptr;
}

void* aligned_alloc(size_t align, size_t size) {
    return memalign(align, size);
}

int posix_memalign(void** out, size_t align, size_t size) {
    if (!is_pow2(align) || align % sizeof(void*) != 0) {
        return EINVAL;
    }
    void* p = memalign(align, size);
    if (p == nullptr) {
        return ENOMEM;
    }
    *out = p;
    return 0;
}

struct _reent;
void* _malloc_r(struct _reent*, size_t size) { return malloc(size); }
void _free_r(struct _reent*, void* ptr) { free(ptr); }
void* _realloc_r(struct _reent*, void* ptr, size_t size) { return realloc(ptr, size); }
void* _calloc_r(struct _reent*, size_t nmemb, size_t size) { return calloc(nmemb, size); }
void* _memalign_r(struct _reent*, size_t align, size_t size) { return memalign(align, size); }

}  // extern "C"
