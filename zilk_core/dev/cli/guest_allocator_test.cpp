// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The Airbender guest's bump allocator (prover/guest_airbender/src/simple_allocator.cpp), run on the
// host. The file replaces the global operator new/delete and malloc, so the build compiles its text
// with those names mapped to guest_* (see CMakeLists.txt) and this test calls them directly; the
// heap is an array that stands for the linker's _sheap.._eheap. The checks:
//   - the address sequence of the pointer-bump version equals the one of the offset-based
//     allocator it replaced (kept below as RefAllocator), on random request streams that end in
//     exhaustion and on sizes that wrapped the old bound check;
//   - the room-left comparison does not wrap, the aligned path stays at or below the heap end;
//   - every replaceable delete, the sized ones included, frees nothing;
//   - the heap pointers are statically initialized (constructors that run before main allocate).
// Divergences from the replaced allocator that the comparison accounts for: (1) a size close to
// 2^N made its bound check wrap, so it handed out memory outside the heap (and moved its offset
// backwards), where this one returns nullptr; (2) it advanced its offset before a failed aligned
// bound check, this one leaves the state alone, so after a failure the comparison restarts from
// the state of the allocator under test. Returned addresses on success are compared from equal
// states.

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <random>
#include <vector>

#include <catch2/catch_test_macros.hpp>

// The renamed guest allocator.
void* guest_new(std::size_t);
void* guest_new_array(std::size_t);
void* guest_new(std::size_t, std::align_val_t);
void* guest_new_array(std::size_t, std::align_val_t);
void* guest_new(std::size_t, std::align_val_t, const std::nothrow_t&) noexcept;
void* guest_new_array(std::size_t, std::align_val_t, const std::nothrow_t&) noexcept;
void guest_delete(void*) noexcept;
void guest_delete_array(void*) noexcept;
void guest_delete(void*, std::size_t) noexcept;
void guest_delete_array(void*, std::size_t) noexcept;
void guest_delete(void*, const std::nothrow_t&) noexcept;
void guest_delete_array(void*, const std::nothrow_t&) noexcept;
void guest_delete(void*, std::align_val_t) noexcept;
void guest_delete_array(void*, std::align_val_t) noexcept;
void guest_delete(void*, std::size_t, std::align_val_t) noexcept;
void guest_delete_array(void*, std::size_t, std::align_val_t) noexcept;
void guest_delete(void*, std::align_val_t, const std::nothrow_t&) noexcept;
void guest_delete_array(void*, std::align_val_t, const std::nothrow_t&) noexcept;
extern uint8_t* heap_next;
extern uint8_t* heap_end;
extern "C" {
void* guest_malloc(std::size_t);
void guest_free(void*);
void* guest_calloc(std::size_t, std::size_t);
void* guest_realloc(void*, std::size_t);
void* guest_memalign(std::size_t, std::size_t);
void* guest_aligned_alloc(std::size_t, std::size_t);
int guest_posix_memalign(void**, std::size_t, std::size_t);
void* guest__malloc_r(void*, std::size_t);
void* guest__calloc_r(void*, std::size_t, std::size_t);
void* guest__realloc_r(void*, void*, std::size_t);
void* guest__memalign_r(void*, std::size_t, std::size_t);
void guest__free_r(void*, void*);

// The heap the linker script provides: _sheap is 2 MiB aligned, _eheap is the end of the region.
constexpr std::size_t kMaxAlign = 2097152;
constexpr std::size_t kArea = 4 * kMaxAlign;
alignas(kMaxAlign) uint8_t _sheap[kArea];
uint8_t _eheap[1];
}

namespace {

// What the heap pointers hold, and what the first allocation returns, when static initializers run
// (before main and before any test case touches them), as for a constructor in the guest.
struct Boot {
    uint8_t* next;
    uint8_t* end;
    void* first;
    Boot() : next(heap_next), end(heap_end), first(guest_new(16)) {}
} const boot;

uint8_t* area_begin() { return _sheap; }

uintptr_t addr(const void* p) { return reinterpret_cast<uintptr_t>(p); }

// Points the allocator at the area [begin_off, end_off) and restores the pointers on exit.
class HeapWindow {
public:
    HeapWindow(std::size_t next_off, std::size_t end_off) : saved_next_(heap_next), saved_end_(heap_end) {
        REQUIRE(next_off <= end_off);
        REQUIRE(end_off <= kArea);
        heap_next = area_begin() + next_off;
        heap_end = area_begin() + end_off;
    }
    ~HeapWindow() {
        heap_next = saved_next_;
        heap_end = saved_end_;
    }
    HeapWindow(const HeapWindow&) = delete;
    HeapWindow& operator=(const HeapWindow&) = delete;

private:
    uint8_t* saved_next_;
    uint8_t* saved_end_;
};

// The allocator the guest ran before (the round-5 base): the next free offset from _sheap, rounded up
// before each allocation, the bound compared as offset + size <= heap size.
struct RefAllocator {
    std::size_t heap_size;
    std::size_t allocated;
    std::size_t max_align = kMaxAlign;

    // Null is returned as ~0 (offsets are never that large).
    static constexpr std::size_t kNull = ~std::size_t{0};

    std::size_t alloc(std::size_t size) {
        allocated = (allocated + 7u) & ~std::size_t{7u};
        if (allocated + size <= heap_size) {
            const std::size_t off = allocated;
            allocated += size;
            return off;
        }
        return kNull;
    }
    std::size_t alloc_aligned(std::size_t size, std::size_t align) {
        if (align < 8) {
            align = 8;
        }
        if (align > max_align) {
            return kNull;
        }
        allocated = (allocated + (align - 1)) & ~(align - 1);
        if (allocated <= heap_size && size <= heap_size - allocated) {
            const std::size_t off = allocated;
            allocated += size;
            return off;
        }
        return kNull;
    }
    // Whether the offset arithmetic of the request wraps: the one case the old version got wrong.
    bool wraps(std::size_t size) const {
        return size > std::numeric_limits<std::size_t>::max() - ((allocated + 7u) & ~std::size_t{7u});
    }
};

std::size_t offset_of(const void* p) {
    return p == nullptr ? RefAllocator::kNull : static_cast<std::size_t>(addr(p) - addr(area_begin()));
}

}  // namespace

TEST_CASE("guest allocator: heap pointers are statically initialized", "[guest_allocator]") {
    // Not a dynamic initializer: this constructor ran before main and got the heap start.
    CHECK(boot.next == area_begin());
    CHECK(boot.end == _eheap);
    CHECK(boot.first == area_begin());
}

TEST_CASE("guest allocator: operator new hands out 8-aligned increasing blocks", "[guest_allocator]") {
    HeapWindow w(0, 4096);
    void* a = guest_new(1);
    void* b = guest_new(1);
    void* c = guest_new(0);
    void* d = guest_new_array(13);
    void* e = guest_malloc(8);
    CHECK(offset_of(a) == 0);
    CHECK(offset_of(b) == 8);
    CHECK(offset_of(c) == 16);  // zero bytes still returns the next address, as before
    CHECK(offset_of(d) == 16);
    CHECK(offset_of(e) == 32);
    CHECK(heap_next == area_begin() + 40);
}

TEST_CASE("guest allocator: exhaustion returns nullptr and leaves the state", "[guest_allocator]") {
    HeapWindow w(0, 64);
    CHECK(guest_new(63) == area_begin());
    uint8_t* const after = heap_next;
    CHECK(guest_new(2) == nullptr);   // 63 -> rounds to 64, nothing left but a size of 0
    CHECK(heap_next == after);        // a failure moves nothing (the old one moved to the rounded offset)
    CHECK(guest_new(0) == area_begin() + 64);
    CHECK(guest_new(1) == nullptr);

    HeapWindow exact(0, 64);
    CHECK(guest_new(64) == area_begin());
    CHECK(guest_new(1) == nullptr);

    HeapWindow one_over(0, 64);
    CHECK(guest_new(65) == nullptr);
    CHECK(heap_next == area_begin());
    CHECK(guest_new(64) == area_begin());  // still usable after the failure

    HeapWindow empty(0, 0);
    CHECK(guest_new(1) == nullptr);
    CHECK(guest_malloc(1) == nullptr);
    CHECK(guest_new(0) == area_begin());
}

TEST_CASE("guest allocator: huge sizes do not wrap the bound check", "[guest_allocator]") {
    constexpr std::size_t kMax = std::numeric_limits<std::size_t>::max();
    for (const std::size_t next_off : {std::size_t{0}, std::size_t{1}, std::size_t{9}, std::size_t{4096}}) {
        HeapWindow w(next_off, 8192);
        uint8_t* const before = heap_next;
        for (const std::size_t size : {kMax, kMax - 1, kMax - 7, kMax - 4095, kMax - 4096, kMax / 2 + 1,
                 std::size_t{1} << 32, (std::size_t{1} << 32) - 1, std::size_t{1} << 31}) {
            INFO("next_off=" << next_off << " size=" << size);
            CHECK(guest_new(size) == nullptr);
            CHECK(guest_new_array(size) == nullptr);
            CHECK(guest_malloc(size) == nullptr);
            CHECK(guest_new(size, std::align_val_t{16}) == nullptr);
            CHECK(guest_memalign(64, size) == nullptr);
            CHECK(guest_calloc(1, size) == nullptr);
            CHECK(heap_next == before);
        }
    }
    // calloc: the product overflows.
    HeapWindow w(0, 8192);
    CHECK(guest_calloc(kMax / 2 + 1, 2) == nullptr);
    CHECK(guest_calloc(std::size_t{1} << 40, std::size_t{1} << 40) == nullptr);
    CHECK(heap_next == area_begin());
    CHECK(guest_calloc(4, 8) == area_begin());
    CHECK(guest_calloc(0, kMax) == area_begin() + 32);
}

TEST_CASE("guest allocator: aligned requests", "[guest_allocator]") {
    HeapWindow w(0, kArea);
    for (std::size_t align = 1; align <= kMaxAlign; align *= 2) {
        INFO("align=" << align);
        guest_new(3);  // an odd next pointer
        void* p = guest_new(5, std::align_val_t{align});
        REQUIRE(p != nullptr);
        CHECK(addr(p) % std::max<std::size_t>(align, 8) == 0);
        CHECK(p >= area_begin());
        CHECK(addr(p) + 5 <= addr(heap_end));
        CHECK(heap_next == static_cast<uint8_t*>(p) + 5);
        // Every aligned entry point agrees on the next block.
        const uintptr_t next = addr(heap_next);
        const std::size_t want = std::max<std::size_t>(align, 8);
        const uintptr_t expected = (next + want - 1) & ~(want - 1);
        void* q = guest_new_array(1, std::align_val_t{align}, std::nothrow);
        CHECK(addr(q) == expected);
        void* r = guest_new(0, std::align_val_t{align}, std::nothrow);
        CHECK(addr(r) == addr(heap_next));
        if (align >= 8 && align <= 4096) {
            void* m = guest_memalign(align, 7);
            CHECK(addr(m) % align == 0);
            void* a = guest_aligned_alloc(align, 7);
            CHECK(addr(a) % align == 0);
        }
        // Refill the window so every size starts from the same room.
        heap_next = area_begin();
    }

    // Above kMaxAlign: refused, state untouched.
    heap_next = area_begin() + 1;
    for (const std::size_t align : {kMaxAlign * 2, kMaxAlign * 4, std::size_t{1} << 40}) {
        INFO("align=" << align);
        CHECK(guest_new(8, std::align_val_t{align}) == nullptr);
        CHECK(guest_new_array(8, std::align_val_t{align}, std::nothrow) == nullptr);
        CHECK(guest_memalign(align, 8) == nullptr);
        CHECK(heap_next == area_begin() + 1);
    }
    // memalign wants a power of two.
    for (const std::size_t align : {std::size_t{0}, std::size_t{3}, std::size_t{24}, std::size_t{4097}}) {
        CHECK(guest_memalign(align, 8) == nullptr);
        CHECK(guest_aligned_alloc(align, 8) == nullptr);
    }
    CHECK(heap_next == area_begin() + 1);
}

TEST_CASE("guest allocator: the room left is taken from the rounded pointer", "[guest_allocator]") {
    // The aligned block starts 61 bytes past heap_next, and the last 3 bytes of room are not enough
    // for it once it is rounded: counting from the unrounded pointer would let it run past the end.
    {
        HeapWindow w(3, 64);
        CHECK(guest_new(8, std::align_val_t{64}) == nullptr);  // rounds to 64: no room for 8
        CHECK(heap_next == area_begin() + 3);
        CHECK(guest_new(0, std::align_val_t{64}) == area_begin() + 64);
    }
    // A heap end that is a multiple of the alignment: rounding never passes it.
    HeapWindow w(kMaxAlign - 8, kMaxAlign);
    CHECK(guest_new(16, std::align_val_t{kMaxAlign}) == nullptr);
    CHECK(heap_next == area_begin() + kMaxAlign - 8);
    CHECK(guest_new(0, std::align_val_t{kMaxAlign}) == area_begin() + kMaxAlign);
    CHECK(guest_new(1) == nullptr);
}

TEST_CASE("guest allocator: C entry points", "[guest_allocator]") {
    HeapWindow w(0, 4096);
    CHECK(offset_of(guest__malloc_r(nullptr, 10)) == 0);
    CHECK(offset_of(guest__calloc_r(nullptr, 3, 5)) == 16);
    CHECK(offset_of(guest__memalign_r(nullptr, 64, 1)) == 64);

    // realloc: a null pointer is a malloc, size 0 allocates nothing, otherwise a fresh block that holds
    // the old bytes.
    uint8_t* const before = area_begin() + 72;  // heap_next is at 65 here, 72 after the rounding
    CHECK(heap_next == area_begin() + 65);
    CHECK(guest_realloc(nullptr, 24) == before);
    CHECK(guest_realloc(area_begin(), 0) == nullptr);
    CHECK(heap_next == before + 24);
    uint8_t* src = static_cast<uint8_t*>(guest_malloc(40));
    for (int i = 0; i < 40; ++i) {
        src[i] = static_cast<uint8_t>(0xA0 + i);
    }
    uint8_t* dst = static_cast<uint8_t*>(guest_realloc(src, 40));
    REQUIRE(dst != nullptr);
    CHECK(dst == src + 40);
    CHECK(std::memcmp(dst, src, 40) == 0);
    // Failure leaves the old block alone and returns nullptr.
    HeapWindow full(0, 64);
    uint8_t* blk = static_cast<uint8_t*>(guest_malloc(48));
    std::memset(blk, 0x5C, 48);
    CHECK(guest_realloc(blk, 48) == nullptr);
    CHECK(blk[0] == 0x5C);
    CHECK(blk[47] == 0x5C);

    // posix_memalign.
    HeapWindow pm(0, 4096);
    void* out = nullptr;
    CHECK(guest_posix_memalign(&out, 64, 10) == 0);
    CHECK(out == area_begin());
    void* keep = out;
    CHECK(guest_posix_memalign(&out, 0, 10) == EINVAL);
    CHECK(guest_posix_memalign(&out, 24, 10) == EINVAL);
    CHECK(guest_posix_memalign(&out, 2, 10) == EINVAL);
    CHECK(guest_posix_memalign(&out, 64, 1u << 20) == ENOMEM);
    CHECK(out == keep);
}

TEST_CASE("guest allocator: every delete frees nothing", "[guest_allocator]") {
    HeapWindow w(0, 4096);
    void* p = guest_new(32);
    void* q = guest_new_array(32, std::align_val_t{64});
    uint8_t* const next = heap_next;
    uint8_t* const end = heap_end;
    const std::nothrow_t& nt = std::nothrow;
    const std::align_val_t al{64};
    for (void* ptr : {p, q, static_cast<void*>(nullptr)}) {
        guest_delete(ptr);
        guest_delete_array(ptr);
        guest_delete(ptr, std::size_t{32});
        guest_delete_array(ptr, std::size_t{32});
        guest_delete(ptr, nt);
        guest_delete_array(ptr, nt);
        guest_delete(ptr, al);
        guest_delete_array(ptr, al);
        guest_delete(ptr, std::size_t{32}, al);
        guest_delete_array(ptr, std::size_t{32}, al);
        guest_delete(ptr, al, nt);
        guest_delete_array(ptr, al, nt);
        guest_free(ptr);
        guest__free_r(nullptr, ptr);
    }
    CHECK(heap_next == next);
    CHECK(heap_end == end);
    // The next block is still fresh memory, not a reused one.
    CHECK(guest_new(8) == next);
}

namespace {

struct Request {
    enum Kind { New, NewArray, Malloc, Calloc, AlignedNew, AlignedNewArray, AlignedNothrow, Memalign, PosixMemalign };
    Kind kind;
    std::size_t size;
    std::size_t align;
    std::size_t count;
};

std::size_t random_size(std::mt19937_64& rng, std::size_t room) {
    constexpr std::size_t kMax = std::numeric_limits<std::size_t>::max();
    switch (rng() % 10) {
        case 0: return 0;
        case 1: return rng() % 9;
        case 2: case 3: return rng() % 200;
        case 4: return rng() % 5000;
        case 5: return rng() % (room / 8 + 16);
        case 6: return room + rng() % 3 - 1;       // the room left, one less, one more
        case 7: return rng() % 16 == 0 ? kMax - rng() % 64 : rng() % 64;  // wraps the old bound check
        case 8: return rng() % 16 == 0 ? (std::size_t{1} << 32) - rng() % 64 : rng() % 100;
        default: return rng() % 64;
    }
}

// One random stream from a start state against the old allocator. window_end is a multiple of
// max_align_used; aligned requests stay at or below it.
void run_differential(std::mt19937_64& rng, std::size_t start, std::size_t window_end, std::size_t align_log_max,
    std::size_t requests, long& nulls, long& compared) {
    HeapWindow w(start, window_end);
    RefAllocator ref{window_end, start};
    uint8_t* prev_end = area_begin();
    for (std::size_t i = 0; i < requests; ++i) {
        const std::size_t room = window_end - std::min<std::size_t>(window_end, ref.allocated);
        Request r{};
        r.kind = static_cast<Request::Kind>(rng() % 9);
        r.size = random_size(rng, room);
        r.align = std::size_t{1} << (rng() % (align_log_max + 1));
        r.count = r.size == 0 ? 1 : 1 + rng() % 3;
        if (r.kind == Request::Calloc) {
            // size = count * unit, sometimes overflowing
            r.size = r.size / r.count;
        }

        // The states are equal before each request (after a failure they are brought together below).
        REQUIRE(heap_next == area_begin() + ref.allocated);

        const bool aligned = r.kind >= Request::AlignedNew;
        const bool is_pow2 = (r.align & (r.align - 1)) == 0;  // always true here
        REQUIRE(is_pow2);
        std::size_t expected;
        bool ref_wrapped = false;
        const std::size_t total = r.kind == Request::Calloc ? r.size * r.count : r.size;
        if (aligned) {
            expected = ref.alloc_aligned(total, r.align);
        } else {
            ref_wrapped = ref.wraps(total);
            expected = ref.alloc(total);
        }

        void* got = nullptr;
        switch (r.kind) {
            case Request::New: got = guest_new(r.size); break;
            case Request::NewArray: got = guest_new_array(r.size); break;
            case Request::Malloc: got = guest_malloc(r.size); break;
            case Request::Calloc: got = guest_calloc(r.count, r.size); break;
            case Request::AlignedNew: got = guest_new(r.size, std::align_val_t{r.align}); break;
            case Request::AlignedNewArray: got = guest_new_array(r.size, std::align_val_t{r.align}); break;
            case Request::AlignedNothrow:
                got = guest_new(r.size, std::align_val_t{r.align}, std::nothrow);
                break;
            case Request::Memalign: got = guest_memalign(r.align, r.size); break;
            case Request::PosixMemalign: {
                void* out = nullptr;
                const int rc = r.align % sizeof(void*) == 0 ? guest_posix_memalign(&out, r.align, r.size) : EINVAL;
                if (rc == 0) {
                    got = out;
                }
                break;
            }
        }
        // posix_memalign with align < sizeof(void*) is refused before allocating: not a request.
        const bool refused = r.kind == Request::PosixMemalign && r.align % sizeof(void*) != 0;
        INFO("request " << i << " kind=" << r.kind << " size=" << r.size << " count=" << r.count
                        << " align=" << r.align << " start=" << start << " end=" << window_end);
        if (refused) {
            REQUIRE(got == nullptr);
            ref.allocated = static_cast<std::size_t>(heap_next - area_begin());
            continue;
        }

        if (got == nullptr) {
            ++nulls;
        } else {
            // Invariants of every block: inside the heap, aligned, after the previous block.
            const std::size_t want = aligned ? std::max<std::size_t>(r.align, 8) : 8;
            REQUIRE(addr(got) >= addr(area_begin()));
            REQUIRE(total <= window_end - offset_of(got));
            REQUIRE(addr(got) % want == 0);
            REQUIRE(static_cast<uint8_t*>(got) >= prev_end);
            prev_end = static_cast<uint8_t*>(got) + total;
        }

        if (ref_wrapped) {
            // The old version returned a block outside the heap here; this one must refuse.
            REQUIRE(got == nullptr);
        } else {
            ++compared;
            REQUIRE(offset_of(got) == expected);
        }
        if (got == nullptr) {
            // The old one moves on a failed request (rounds its offset): continue from the new state.
            ref.allocated = static_cast<std::size_t>(heap_next - area_begin());
        } else {
            // A success leaves both at the same place: the end of the block.
            REQUIRE(heap_next == area_begin() + ref.allocated);
        }
    }
}

}  // namespace

TEST_CASE("guest allocator: same addresses as the offset-based allocator", "[guest_allocator]") {
    std::mt19937_64 rng(20261008);
    long nulls = 0;
    long compared = 0;

    // Small heaps, a multiple of 64 long, aligned requests up to 64 bytes: runs end in exhaustion.
    for (int trial = 0; trial < 600; ++trial) {
        const std::size_t end = 64 * (rng() % 1024);
        const std::size_t start = end == 0 ? 0 : rng() % std::min<std::size_t>(end, 64) ;
        run_differential(rng, start, end, 6, 400, nulls, compared);
    }
    // The guest's shape: a heap end at a multiple of 2 MiB, every alignment up to 4 MiB (the last
    // doubling is above kMaxAlign and refused).
    for (int trial = 0; trial < 200; ++trial) {
        const std::size_t end = kMaxAlign * (rng() % 5);
        const std::size_t start = end == 0 ? 0 : rng() % 9;
        run_differential(rng, start, end, 22, 600, nulls, compared);
    }
    CHECK(nulls > 10000);   // exhaustion, refusals and wraps all happen
    CHECK(compared > 50000);
}

TEST_CASE("guest allocator: a long new/malloc stream with sized deletes matches the offset-based allocator", "[guest_allocator]") {
    // A realistic stream: lots of small blocks of mixed sizes with a few big ones, freed by sized delete.
    HeapWindow w(0, kArea);
    RefAllocator ref{kArea, 0};
    std::mt19937 rng(7);
    for (int i = 0; i < 20000; ++i) {
        const std::size_t size = (rng() % 8 == 0) ? rng() % 4096 : rng() % 80;
        const std::size_t expected = ref.alloc(size);
        void* got = i % 2 ? guest_new(size) : guest_malloc(size);
        REQUIRE(offset_of(got) == expected);
        guest_delete(got, size);
    }
    CHECK(heap_next == area_begin() + ref.allocated);
}
