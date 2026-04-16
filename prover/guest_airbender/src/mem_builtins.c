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

    // Fast-path hub for common aligned sizes.
    // Ordered by frequency: n==32 (90 sites), n==20 (31), n==64 (9), n==8 (5).
    if ((((uintptr_t)d | (uintptr_t)s) & 3) == 0) {
        uint32_t *dw = (uint32_t *)d;
        const uint32_t *sw = (const uint32_t *)s;

        if (__builtin_expect(n == 32, 1)) {
            dw[0] = sw[0]; dw[1] = sw[1]; dw[2] = sw[2]; dw[3] = sw[3];
            dw[4] = sw[4]; dw[5] = sw[5]; dw[6] = sw[6]; dw[7] = sw[7];
            return dest;
        }
        if (n == 20) {
            dw[0] = sw[0]; dw[1] = sw[1]; dw[2] = sw[2]; dw[3] = sw[3];
            dw[4] = sw[4];
            return dest;
        }
        if (n == 64) {
            dw[0]  = sw[0];  dw[1]  = sw[1];  dw[2]  = sw[2];  dw[3]  = sw[3];
            dw[4]  = sw[4];  dw[5]  = sw[5];  dw[6]  = sw[6];  dw[7]  = sw[7];
            dw[8]  = sw[8];  dw[9]  = sw[9];  dw[10] = sw[10]; dw[11] = sw[11];
            dw[12] = sw[12]; dw[13] = sw[13]; dw[14] = sw[14]; dw[15] = sw[15];
            return dest;
        }
        if (n == 8) {
            dw[0] = sw[0]; dw[1] = sw[1];
            return dest;
        }
        if (n == 4) {
            dw[0] = sw[0];
            return dest;
        }
        if (n == 16) {
            dw[0] = sw[0]; dw[1] = sw[1]; dw[2] = sw[2]; dw[3] = sw[3];
            return dest;
        }
        if (n == 48) {
            dw[0]  = sw[0];  dw[1]  = sw[1];  dw[2]  = sw[2];  dw[3]  = sw[3];
            dw[4]  = sw[4];  dw[5]  = sw[5];  dw[6]  = sw[6];  dw[7]  = sw[7];
            dw[8]  = sw[8];  dw[9]  = sw[9];  dw[10] = sw[10]; dw[11] = sw[11];
            return dest;
        }
        if (n == 96) {
            dw[0]  = sw[0];  dw[1]  = sw[1];  dw[2]  = sw[2];  dw[3]  = sw[3];
            dw[4]  = sw[4];  dw[5]  = sw[5];  dw[6]  = sw[6];  dw[7]  = sw[7];
            dw[8]  = sw[8];  dw[9]  = sw[9];  dw[10] = sw[10]; dw[11] = sw[11];
            dw[12] = sw[12]; dw[13] = sw[13]; dw[14] = sw[14]; dw[15] = sw[15];
            dw[16] = sw[16]; dw[17] = sw[17]; dw[18] = sw[18]; dw[19] = sw[19];
            dw[20] = sw[20]; dw[21] = sw[21]; dw[22] = sw[22]; dw[23] = sw[23];
            return dest;
        }
        // n==17: 4 words + 1 byte (13 sites, e.g. RLP nibble+prefix).
        if (n == 17) {
            dw[0] = sw[0]; dw[1] = sw[1]; dw[2] = sw[2]; dw[3] = sw[3];
            d[16] = s[16];
            return dest;
        }
        // n==12: 3 words (common for 96-bit fields).
        if (n == 12) {
            dw[0] = sw[0]; dw[1] = sw[1]; dw[2] = sw[2];
            return dest;
        }
        // n==24: 6 words.
        if (n == 24) {
            dw[0] = sw[0]; dw[1] = sw[1]; dw[2] = sw[2];
            dw[3] = sw[3]; dw[4] = sw[4]; dw[5] = sw[5];
            return dest;
        }
    }

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

    // If source is also aligned, use word copies (and CSR MEMCOPY when possible).
    if (((uintptr_t)s & 3) == 0) {
        uint32_t *dw = (uint32_t *)d;
        const uint32_t *sw = (const uint32_t *)s;

        // Advance to 32-byte alignment with word copies, then use CSR MEMCOPY.
        if (n >= 64) {
            // Align dst to 32-byte boundary with word stores.
            size_t to_align = (32 - ((uintptr_t)dw & 31)) & 31;
            if (to_align && ((uintptr_t)sw & 31) == ((uintptr_t)dw & 31)) {
                // Both have the same misalignment — aligning one aligns both.
                size_t words = to_align >> 2;
                for (size_t i = 0; i < words; i++)
                    dw[i] = sw[i];
                dw += words;
                sw += words;
                n -= to_align;
            }

            // Now use CSR MEMCOPY if both are 32-byte aligned.
            // Unrolled 4x: 128 bytes per iteration to reduce loop overhead.
            if ((((uintptr_t)dw | (uintptr_t)sw) & 31) == 0) {
                while (n >= 128) {
                    csr_memcopy32(dw,      sw);
                    csr_memcopy32(dw + 8,  sw + 8);
                    csr_memcopy32(dw + 16, sw + 16);
                    csr_memcopy32(dw + 24, sw + 24);
                    dw += 32;
                    sw += 32;
                    n -= 128;
                }
                while (n >= 32) {
                    csr_memcopy32(dw, sw);
                    dw += 8;
                    sw += 8;
                    n -= 32;
                }
            }
        } else if (n >= 32 && (((uintptr_t)dw | (uintptr_t)sw) & 31) == 0) {
            // Already 32-byte aligned — use CSR MEMCOPY directly.
            // Unrolled 4x for reduced loop overhead.
            while (n >= 128) {
                csr_memcopy32(dw,      sw);
                csr_memcopy32(dw + 8,  sw + 8);
                csr_memcopy32(dw + 16, sw + 16);
                csr_memcopy32(dw + 24, sw + 24);
                dw += 32;
                sw += 32;
                n -= 128;
            }
            while (n >= 32) {
                csr_memcopy32(dw, sw);
                dw += 8;
                sw += 8;
                n -= 32;
            }
        }

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

    // Inline fast paths for common aligned sizes — avoids overlap check + memcpy call.
    // Safe for both overlapping and non-overlapping when using word loads/stores
    // at non-overlapping offsets (which is the case for same-size small copies).
    if ((((uintptr_t)d | (uintptr_t)s) & 3) == 0) {
        uint32_t *dw = (uint32_t *)d;
        const uint32_t *sw = (const uint32_t *)s;
        if (__builtin_expect(n == 32, 1)) {
            // For 32-byte overlap-safe copy: read all first, then write.
            uint32_t t0=sw[0], t1=sw[1], t2=sw[2], t3=sw[3];
            uint32_t t4=sw[4], t5=sw[5], t6=sw[6], t7=sw[7];
            dw[0]=t0; dw[1]=t1; dw[2]=t2; dw[3]=t3;
            dw[4]=t4; dw[5]=t5; dw[6]=t6; dw[7]=t7;
            return dest;
        }
        if (n == 20) {
            uint32_t t0=sw[0], t1=sw[1], t2=sw[2], t3=sw[3], t4=sw[4];
            dw[0]=t0; dw[1]=t1; dw[2]=t2; dw[3]=t3; dw[4]=t4;
            return dest;
        }
        if (n == 4) {
            dw[0] = sw[0];
            return dest;
        }
        if (n == 8) {
            uint32_t t0=sw[0], t1=sw[1];
            dw[0]=t0; dw[1]=t1;
            return dest;
        }
        if (n == 16) {
            uint32_t t0=sw[0], t1=sw[1], t2=sw[2], t3=sw[3];
            dw[0]=t0; dw[1]=t1; dw[2]=t2; dw[3]=t3;
            return dest;
        }
        if (n == 64) {
            uint32_t t0=sw[0],  t1=sw[1],  t2=sw[2],  t3=sw[3];
            uint32_t t4=sw[4],  t5=sw[5],  t6=sw[6],  t7=sw[7];
            uint32_t t8=sw[8],  t9=sw[9],  ta=sw[10], tb=sw[11];
            uint32_t tc=sw[12], td=sw[13], te=sw[14], tf=sw[15];
            dw[0]=t0;  dw[1]=t1;  dw[2]=t2;  dw[3]=t3;
            dw[4]=t4;  dw[5]=t5;  dw[6]=t6;  dw[7]=t7;
            dw[8]=t8;  dw[9]=t9;  dw[10]=ta; dw[11]=tb;
            dw[12]=tc; dw[13]=td; dw[14]=te; dw[15]=tf;
            return dest;
        }
    }

    // Non-overlapping or forward-safe: delegate to memcpy (which has fast paths).
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

    // Fast zero-fill paths for common aligned sizes (skip alignment overhead).
    if (byte == 0 && (((uintptr_t)d) & 3) == 0) {
        uint32_t *dw = (uint32_t *)d;
        if (n == 8) {
            dw[0] = 0; dw[1] = 0;
            return dest;
        }
        if (n == 16) {
            dw[0] = 0; dw[1] = 0; dw[2] = 0; dw[3] = 0;
            return dest;
        }
        if (n == 32) {
            dw[0] = 0; dw[1] = 0; dw[2] = 0; dw[3] = 0;
            dw[4] = 0; dw[5] = 0; dw[6] = 0; dw[7] = 0;
            return dest;
        }
        if (n == 64) {
            dw[0]  = 0; dw[1]  = 0; dw[2]  = 0; dw[3]  = 0;
            dw[4]  = 0; dw[5]  = 0; dw[6]  = 0; dw[7]  = 0;
            dw[8]  = 0; dw[9]  = 0; dw[10] = 0; dw[11] = 0;
            dw[12] = 0; dw[13] = 0; dw[14] = 0; dw[15] = 0;
            return dest;
        }
        if (n == 4) {
            dw[0] = 0;
            return dest;
        }
        if (n == 24) {
            dw[0] = 0; dw[1] = 0; dw[2] = 0; dw[3] = 0; dw[4] = 0; dw[5] = 0;
            return dest;
        }
        // n==288: 9*32 bytes, 30 call sites (stack-array zeroing).
        // Use CSR MEMCOPY when 32-byte aligned for maximum throughput.
        if (n == 288 && (((uintptr_t)dw) & 31) == 0) {
            csr_memcopy32(dw,      memset_zeros);
            csr_memcopy32(dw + 8,  memset_zeros);
            csr_memcopy32(dw + 16, memset_zeros);
            csr_memcopy32(dw + 24, memset_zeros);
            csr_memcopy32(dw + 32, memset_zeros);
            csr_memcopy32(dw + 40, memset_zeros);
            csr_memcopy32(dw + 48, memset_zeros);
            csr_memcopy32(dw + 56, memset_zeros);
            csr_memcopy32(dw + 64, memset_zeros);
            return dest;
        }
        // n==96: 24 words (common for 3x bytes32).
        if (n == 96) {
            dw[0]  = 0; dw[1]  = 0; dw[2]  = 0; dw[3]  = 0;
            dw[4]  = 0; dw[5]  = 0; dw[6]  = 0; dw[7]  = 0;
            dw[8]  = 0; dw[9]  = 0; dw[10] = 0; dw[11] = 0;
            dw[12] = 0; dw[13] = 0; dw[14] = 0; dw[15] = 0;
            dw[16] = 0; dw[17] = 0; dw[18] = 0; dw[19] = 0;
            dw[20] = 0; dw[21] = 0; dw[22] = 0; dw[23] = 0;
            return dest;
        }
    }

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
    // Advance to 32-byte alignment with word stores, then use CSR MEMCOPY.
    if (byte == 0) {
        uint32_t *dw = (uint32_t *)d;

        // Align dst to 32-byte boundary with zero word stores.
        size_t to_align = (32 - ((uintptr_t)dw & 31)) & 31;
        size_t align_words = to_align >> 2;
        if (align_words && n >= to_align) {
            for (size_t i = 0; i < align_words; i++)
                dw[i] = 0;
            dw += align_words;
            n -= to_align;
        }

        // Now dst is 32-byte aligned — use CSR MEMCOPY from zero buffer.
        // Unrolled 4x: 128 bytes per iteration to reduce loop overhead.
        while (n >= 128) {
            csr_memcopy32(dw,      memset_zeros);
            csr_memcopy32(dw + 8,  memset_zeros);
            csr_memcopy32(dw + 16, memset_zeros);
            csr_memcopy32(dw + 24, memset_zeros);
            dw += 32;
            n -= 128;
        }
        while (n >= 32) {
            csr_memcopy32(dw, memset_zeros);
            dw += 8;
            n -= 32;
        }

        d = (unsigned char *)dw;
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

        // Fast path: n==32 (bytes32 comparison) — fully unrolled word compare.
        if (n == 32) {
            for (int i = 0; i < 8; i++) {
                if (wa[i] != wb[i]) {
                    pa = (const unsigned char *)&wa[i];
                    pb = (const unsigned char *)&wb[i];
                    for (int j = 0; j < 4; j++) {
                        if (pa[j] != pb[j])
                            return pa[j] - pb[j];
                    }
                }
            }
            return 0;
        }

        // Fast path: n==20 (address comparison).
        if (n == 20) {
            for (int i = 0; i < 5; i++) {
                if (wa[i] != wb[i]) {
                    pa = (const unsigned char *)&wa[i];
                    pb = (const unsigned char *)&wb[i];
                    for (int j = 0; j < 4; j++) {
                        if (pa[j] != pb[j])
                            return pa[j] - pb[j];
                    }
                }
            }
            return 0;
        }

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
