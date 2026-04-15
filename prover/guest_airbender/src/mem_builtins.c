// Optimized memory builtins for rv32im (Airbender zkVM guest).
//
// Uses CSR MEMCOPY (0x7CA) for 32-byte aligned chunks when possible,
// falling back to word-aligned (uint32_t) loads/stores.
// Compiled with -fno-builtin -fno-tree-loop-distribute-patterns so GCC
// will NOT transform these back into library calls.

#include "stddef.h"
#include "stdint.h"

// CSR MEMCOPY: copies 32 bytes from [x11] to [x10] in ~4 instructions.
// Both src and dst must be 4-byte aligned (32-byte alignment not required
// for correctness, but gives best performance).
static inline __attribute__((always_inline))
void csr_memcopy32(void *dst, const void *src) {
    register uintptr_t a0 __asm__("x10") = (uintptr_t)dst;
    register uintptr_t a1 __asm__("x11") = (uintptr_t)src;
    register uint32_t  a2 __asm__("x12") = 0x80;
    __asm__ __volatile__("csrrw x0, 0x7CA, x0"
        : "+r"(a2) : "r"(a0), "r"(a1) : "memory");
}

// ---------------------------------------------------------------------------
// memcpy — non-overlapping copy, CSR MEMCOPY + word-aligned fast path
// ---------------------------------------------------------------------------
void *memcpy(void *dest, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;

    // For tiny copies, just do bytes.
    if (n < 8) {
        while (n--)
            *d++ = *s++;
        return dest;
    }

    // Align destination to 4-byte boundary.
    size_t head = (4 - ((uintptr_t)d & 3)) & 3;
    n -= head;
    while (head--)
        *d++ = *s++;

    // If source is also aligned, use word copies (and CSR MEMCOPY when
    // both src+dst are 32-byte aligned).
    if (((uintptr_t)s & 3) == 0) {
        // CSR MEMCOPY requires 32-byte alignment on both src and dst.
        if (n >= 32 && (((uintptr_t)d | (uintptr_t)s) & 31) == 0) {
            while (n >= 32) {
                csr_memcopy32(d, s);
                d += 32;
                s += 32;
                n -= 32;
            }
        }

        uint32_t *dw = (uint32_t *)d;
        const uint32_t *sw = (const uint32_t *)s;

        // Remaining whole words.
        while (n >= 4) {
            *dw++ = *sw++;
            n -= 4;
        }

        d = (unsigned char *)dw;
        s = (const unsigned char *)sw;
    } else {
        // Source misaligned — use shift-merge technique.
        // Load aligned words from source and shift to reconstruct.
        uintptr_t sa = (uintptr_t)s & ~(uintptr_t)3;
        unsigned shift = ((uintptr_t)s & 3) * 8;  // 8, 16, or 24
        unsigned rshift = 32 - shift;
        const uint32_t *sw = (const uint32_t *)sa;
        uint32_t *dw = (uint32_t *)d;
        uint32_t prev = *sw++;

        while (n >= 16) {
            uint32_t a0 = sw[0];
            uint32_t a1 = sw[1];
            uint32_t a2 = sw[2];
            uint32_t a3 = sw[3];
            dw[0] = (prev >> shift) | (a0 << rshift);
            dw[1] = (a0 >> shift)   | (a1 << rshift);
            dw[2] = (a1 >> shift)   | (a2 << rshift);
            dw[3] = (a2 >> shift)   | (a3 << rshift);
            prev = a3;
            dw += 4;
            sw += 4;
            n -= 16;
        }

        while (n >= 4) {
            uint32_t cur = *sw++;
            *dw++ = (prev >> shift) | (cur << rshift);
            prev = cur;
            n -= 4;
        }

        d = (unsigned char *)dw;
        s = (const unsigned char *)sw - (rshift / 8);
    }

    // Tail bytes.
    while (n--)
        *d++ = *s++;

    return dest;
}

// ---------------------------------------------------------------------------
// memmove — handles overlapping regions
// ---------------------------------------------------------------------------
void *memmove(void *dest, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;

    // Non-overlapping or forward-safe: delegate to memcpy.
    if (d <= s || d >= s + n)
        return memcpy(dest, src, n);

    // Overlapping with dest > src: copy backward.
    d += n;
    s += n;

    // For tiny copies, just do bytes.
    if (n < 8) {
        while (n--)
            *--d = *--s;
        return dest;
    }

    // Align destination to 4-byte boundary (from the end).
    size_t tail = (uintptr_t)d & 3;
    n -= tail;
    while (tail--)
        *--d = *--s;

    // If source is also aligned, use word copies backward.
    if (((uintptr_t)s & 3) == 0) {
        uint32_t *dw = (uint32_t *)d;
        const uint32_t *sw = (const uint32_t *)s;

        // Unrolled: 4 words = 16 bytes per iteration.
        while (n >= 16) {
            uint32_t w3 = *--sw;
            uint32_t w2 = *--sw;
            uint32_t w1 = *--sw;
            uint32_t w0 = *--sw;
            *--dw = w3;
            *--dw = w2;
            *--dw = w1;
            *--dw = w0;
            n -= 16;
        }

        // Remaining whole words.
        while (n >= 4) {
            *--dw = *--sw;
            n -= 4;
        }

        d = (unsigned char *)dw;
        s = (const unsigned char *)sw;
    }

    // Remaining bytes.
    while (n--)
        *--d = *--s;

    return dest;
}

// 32-byte aligned zero buffer for CSR MEMCOPY-based bulk zeroing.
static const uint32_t __attribute__((aligned(32))) memset_zeros[8] = {0};

// ---------------------------------------------------------------------------
// memset — CSR MEMCOPY for zero-fill, word-at-a-time for other fills
// ---------------------------------------------------------------------------
void *memset(void *dest, int c, size_t n) {
    unsigned char *d = (unsigned char *)dest;
    unsigned char byte = (unsigned char)c;

    // For tiny fills, just do bytes.
    if (n < 8) {
        while (n--)
            *d++ = byte;
        return dest;
    }

    // Align destination to 4-byte boundary.
    size_t head = (4 - ((uintptr_t)d & 3)) & 3;
    n -= head;
    while (head--)
        *d++ = byte;

    // Zero-fill fast path: use CSR MEMCOPY from zero buffer (32 bytes/call).
    // Requires 32-byte alignment on dst (src is static and always aligned).
    if (byte == 0 && ((uintptr_t)d & 31) == 0) {
        while (n >= 32) {
            csr_memcopy32(d, memset_zeros);
            d += 32;
            n -= 32;
        }
    }

    // Replicate byte into a 32-bit word: 0xAB -> 0xABABABAB.
    uint32_t word = (uint32_t)byte;
    word |= word << 8;
    word |= word << 16;

    uint32_t *dw = (uint32_t *)d;

    // Unrolled: 4 words = 16 bytes per iteration.
    while (n >= 16) {
        dw[0] = word;
        dw[1] = word;
        dw[2] = word;
        dw[3] = word;
        dw += 4;
        n -= 16;
    }

    // Remaining whole words.
    while (n >= 4) {
        *dw++ = word;
        n -= 4;
    }

    // Tail bytes.
    d = (unsigned char *)dw;
    while (n--)
        *d++ = byte;

    return dest;
}

// ---------------------------------------------------------------------------
// memcmp — word-at-a-time comparison when both aligned
// ---------------------------------------------------------------------------
int memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;

    // If both pointers are 4-byte aligned, compare words first.
    if (n >= 4 && (((uintptr_t)pa | (uintptr_t)pb) & 3) == 0) {
        const uint32_t *wa = (const uint32_t *)pa;
        const uint32_t *wb = (const uint32_t *)pb;

        while (n >= 4) {
            if (*wa != *wb) {
                // Mismatch in this word — find which byte differs.
                pa = (const unsigned char *)wa;
                pb = (const unsigned char *)wb;
                for (int i = 0; i < 4; i++) {
                    if (pa[i] != pb[i])
                        return pa[i] - pb[i];
                }
            }
            wa++;
            wb++;
            n -= 4;
        }

        pa = (const unsigned char *)wa;
        pb = (const unsigned char *)wb;
    }

    while (n--) {
        if (*pa != *pb)
            return *pa - *pb;
        pa++;
        pb++;
    }
    return 0;
}
