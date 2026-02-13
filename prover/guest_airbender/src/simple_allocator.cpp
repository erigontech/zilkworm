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
