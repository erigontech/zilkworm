#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <new>

extern "C" {
extern uint8_t _sheap[];
extern uint8_t _eheap[];
}

// The bump state: the next free byte and the end of the heap. Pointers rather than an offset
// from _sheap, so operator new forms neither bound nor their difference. Two variables, not a
// struct: each access then relaxes to one gp-relative lw or sw (link.x's gp window), where a
// struct's fields share an address formed by an extra addi. heap_end holds _eheap so that it
// is one load instead of an auipc+addi. Nothing writes it, so LTO would make it read-only and
// fold it back into the symbol; externally_visible keeps it from assuming that. constinit keeps
// both out of .init_array: constructors that run before main allocate.
#if defined(__GNUC__) && !defined(__clang__)
#define GUEST_EXTERNALLY_VISIBLE __attribute__((externally_visible))
#else
#define GUEST_EXTERNALLY_VISIBLE  // clang rejects the attribute (-Wunknown-attributes) and has no such LTO folding
#endif
constinit uint8_t* heap_next = _sheap;
GUEST_EXTERNALLY_VISIBLE constinit uint8_t* heap_end = _eheap;

// _sheap and _eheap are ALIGN(2097152) in link.x, so heap_next rounded up to any alignment up to
// that stays at or below heap_end: the room left, heap_end minus the rounded pointer, cannot wrap.
static constexpr size_t kMaxAlign = 2097152;

void* operator new(size_t size) {
    // Align to 8 bytes so that any naturally-aligned type can be stored.
    uintptr_t p = (reinterpret_cast<uintptr_t>(heap_next) + 7u) & ~uintptr_t{7u};
    // Compare against the room left: p + size wraps for huge sizes.
    if (size > reinterpret_cast<uintptr_t>(heap_end) - p) {
        return nullptr;
    }
    heap_next = reinterpret_cast<uint8_t*>(p + size);
    return reinterpret_cast<void*>(p);
}

void* operator new[](size_t size) {
    return operator new(size);
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

// Over-aligned types (alignas(32) buffers, ...) must not fall through to the libstdc++
// versions: those call newlib's memalign, which keeps chunk headers inside the heap and
// writes them next to blocks this allocator has not handed out yet.
void* operator new(size_t size, std::align_val_t al) {
    return bump_allocate_aligned(size, static_cast<size_t>(al));
}

void* operator new[](size_t size, std::align_val_t al) {
    return bump_allocate_aligned(size, static_cast<size_t>(al));
}

void* operator new(size_t size, std::align_val_t al, const std::nothrow_t&) noexcept {
    return bump_allocate_aligned(size, static_cast<size_t>(al));
}

void* operator new[](size_t size, std::align_val_t al, const std::nothrow_t&) noexcept {
    return bump_allocate_aligned(size, static_cast<size_t>(al));
}

// We do not free memory. Every replaceable delete is defined here, the sized ones included:
// C++14 sized deallocation sends each std::allocator free to operator delete(void*, size_t),
// which libstdc++ would otherwise supply as a jump to operator delete(void*). Seeing the empty
// definitions, LTO drops the calls, and with them the destructor loops that only walk nodes to
// free them; destructors with other effects still run. Do not mark these noinline: the calls go
// because the empty bodies are found to have no side effects, not by inlining (the libraries
// are -fPIC and this file is not, which blocks inlining across them).
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

// C allocation entry points routed to the same bump allocator.
//
// Without these, malloc/realloc (used by evmone::Memory and newlib
// internals) come from newlib's arena, which grows from `end`
// (~0x0443xxxx) via an unbounded libnosys _sbrk while operator new hands
// out memory from _sheap (0x04600000). Once the arena grows past _sheap
// the two allocators serve overlapping bytes and EVM memory writes
// corrupt the witness blob. One allocator, one heap.
extern "C" {

void* malloc(size_t size) {
    return operator new(size);
}

void free(void*) {
    // Bump allocator: no reuse.
}

void* calloc(size_t nmemb, size_t size) {
    size_t total;
    if (__builtin_mul_overflow(nmemb, size, &total)) {
        return nullptr;
    }
    // No zeroing: the heap never hands a byte out twice (free and delete are no-ops, realloc
    // copies into a fresh block), nothing writes past heap_next (the stack sits below
    // .heap, the mem builtins and the input reader write exactly their n bytes, and newlib's
    // memalign, the one writer outside its block, is replaced above), and RAM nobody has
    // written reads 0, as .bss already relies on. _calloc_r inherits this. Reusing memory
    // would need the zeroing back. Not malloc + memset: GCC folds that into a calloc call.
    return operator new(total);
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
        // Old block size is not tracked; over-copying reads garbage past the
        // old block but stays inside the flat RAM heap (no MMU). Callers like
        // evmone::Memory::grow zero the extension themselves. memmove because
        // the tail of the source range can overlap the new block.
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

// newlib reentrant variants — keep libc internals on the same heap.
struct _reent;
void* _malloc_r(struct _reent*, size_t size) { return malloc(size); }
void _free_r(struct _reent*, void* ptr) { free(ptr); }
void* _realloc_r(struct _reent*, void* ptr, size_t size) { return realloc(ptr, size); }
void* _calloc_r(struct _reent*, size_t nmemb, size_t size) { return calloc(nmemb, size); }
void* _memalign_r(struct _reent*, size_t align, size_t size) { return memalign(align, size); }

}  // extern "C"
