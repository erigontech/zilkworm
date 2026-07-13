#include <stdint.h>
#include <stddef.h>

extern "C" {
extern uint32_t _sheap;
extern uint32_t _eheap;
}

size_t allocated_bytes = 0;

void* operator new(size_t size) {
    uint8_t* heap_begin = reinterpret_cast<uint8_t*>(&_sheap);
    uint8_t* heap_end = reinterpret_cast<uint8_t*>(&_eheap);
    size_t heap_size = static_cast<size_t>(heap_end - heap_begin);
    // Align to 8 bytes so that any naturally-aligned type can be stored.
    allocated_bytes = (allocated_bytes + 7u) & ~static_cast<size_t>(7u);
    if (allocated_bytes + size <= heap_size) {
        void* ptr = heap_begin + allocated_bytes;
        allocated_bytes += size;
        return ptr;
    }
    return nullptr; 
}

void operator delete(void* ptr) noexcept {
    // We do not free memory
}

void* operator new[](size_t size) {
    return operator new(size);
}

void operator delete[](void* ptr) noexcept {
    operator delete(ptr);
}

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
    uint8_t* p = static_cast<uint8_t*>(operator new(total));
    if (p != nullptr) {
        for (size_t i = 0; i < total; ++i) p[i] = 0;
    }
    return p;
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

// newlib reentrant variants — keep libc internals on the same heap.
struct _reent;
void* _malloc_r(struct _reent*, size_t size) { return malloc(size); }
void _free_r(struct _reent*, void* ptr) { free(ptr); }
void* _realloc_r(struct _reent*, void* ptr, size_t size) { return realloc(ptr, size); }
void* _calloc_r(struct _reent*, size_t nmemb, size_t size) { return calloc(nmemb, size); }

}  // extern "C"
