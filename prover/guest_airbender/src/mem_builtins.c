// Optimized memory builtins for rv32im (Airbender zkVM guest).
//
// Uses CSR MEMCOPY (0x7CA) for 32-byte aligned chunks when possible,
// falling back to word-aligned (uint32_t) loads/stores.
// Compiled with -fno-builtin -fno-tree-loop-distribute-patterns so GCC
// will NOT transform these back into library calls.

#include "stddef.h"
#include "stdint.h"

// Word accesses to bytes (any buffer the guest copies) go through this named may_alias type, so
// they are defined behaviour and -Wstrict-aliasing=1 accepts them.
typedef uint32_t __attribute__((may_alias)) w32;

// CSR MEMCOPY: copies 32 bytes from [x11] to [x10] in ~4 instructions.
// Both src and dst must be 4-byte aligned (32-byte alignment not required
// for correctness, but gives best performance).
#if defined(__riscv) && __riscv_xlen == 32
static inline __attribute__((always_inline))
void csr_memcopy32(void *dst, const void *src) {
    register uintptr_t a0 __asm__("x10") = (uintptr_t)dst;
    register uintptr_t a1 __asm__("x11") = (uintptr_t)src;
    register uint32_t  a2 __asm__("x12") = 0x80;
    __asm__ __volatile__("csrrw x0, 0x7CA, x0"
        : "+r"(a2) : "r"(a0), "r"(a1) : "memory");
}
#else
// Host unit tests (mem_builtins_test.cpp) compile this file for the host, with the four
// functions renamed, and supply the CSR as a function that checks the delegation's operand rules.
void csr_memcopy32(void *dst, const void *src);
#endif

// 32 bytes between any two addresses (3.5M calls per 200 mainnet blocks: hashes read out of
// witness RLP, whose alignment is arbitrary). The source words are read aligned and shifted
// together, the destination is written with byte stores up to its first word boundary, word
// stores to the last one and byte stores after. The generic stages below take 74..86 cycles for
// this shape, this about 45. Reads up to 3 bytes past src + 32, inside the same aligned word.
static inline __attribute__((always_inline))
void copy32_any(unsigned char *dst, const unsigned char *src) {
    const uintptr_t soff = (uintptr_t)src & 3;
    const w32 *sw = (const w32 *)(src - soff);
    const unsigned sh = (unsigned)soff * 8;
    uint32_t carry = sw[0];
    unsigned si = 1;
    // next_src: the next 4 source bytes as a word, at any source alignment.
#define NEXT_SRC(v)                                                   \
    do {                                                              \
        if (sh == 0) {                                                \
            v = carry;                                                \
            carry = sw[si++];                                         \
        } else {                                                      \
            uint32_t w1_ = sw[si++];                                  \
            v = (carry >> sh) | (w1_ << (32 - sh));                   \
            carry = w1_;                                              \
        }                                                             \
    } while (0)
    const uintptr_t doff = (uintptr_t)dst & 3;
    if (doff == 0) {
        w32 *dw = (w32 *)dst;
        for (int k = 0; k < 8; k++) {
            uint32_t v;
            NEXT_SRC(v);
            dw[k] = v;
        }
        return;
    }
    const unsigned lead = 4 - (unsigned)doff;
    uint32_t v;
    NEXT_SRC(v);
    for (unsigned k = 0; k < lead; k++) {
        dst[k] = (unsigned char)v;
        v >>= 8;
    }
    w32 *dw = (w32 *)(dst + lead);
    const unsigned keep = 32 - lead * 8;  // Bits of v (source bytes not yet stored) at its bottom.
    for (int k = 0; k < 7; k++) {
        uint32_t nx;
        NEXT_SRC(nx);
        dw[k] = v | (nx << keep);
        v = nx >> (32 - keep);
    }
    unsigned char *tail = dst + lead + 28;
    for (unsigned k = 0; k < 4 - lead; k++) {
        tail[k] = (unsigned char)v;
        v >>= 8;
    }
#undef NEXT_SRC
}

// ---------------------------------------------------------------------------
// memcpy — non-overlapping copy, CSR MEMCOPY + word-aligned fast path
// ---------------------------------------------------------------------------
// memcpy() itself only holds the short copies (word-aligned n <= 67 and n == 96 by a jump into a run
// of word copies, n == 32 at any alignment, n < 8 at unaligned addresses by bytes), with no CSR
// MEMCOPY in it: that instruction binds x10..x12, and with it in the same function GCC kept dest
// and src in other registers on every call. Everything else is memcpy_large().

// Copies words [0, words) of s to d, lowest first: memmove() forwards overlapping copies with
// d < s here, and a store ahead of a pending load would corrupt them. A jump into a run of
// loads and stores based at the end of the range.
#define COPY_WORDS_FWD(D, S, WORDS, MAXW)                                                  \
    do {                                                                                   \
        w32 *de_ = (w32 *)((uintptr_t)(D) + (WORDS) * 4 - (MAXW) * 4);                     \
        const w32 *se_ = (const w32 *)((uintptr_t)(S) + (WORDS) * 4 - (MAXW) * 4);         \
        switch (WORDS) {                                                                   \
        case 16: de_[(MAXW) - 16] = se_[(MAXW) - 16]; __attribute__((fallthrough));        \
        case 15: de_[(MAXW) - 15] = se_[(MAXW) - 15]; __attribute__((fallthrough));        \
        case 14: de_[(MAXW) - 14] = se_[(MAXW) - 14]; __attribute__((fallthrough));        \
        case 13: de_[(MAXW) - 13] = se_[(MAXW) - 13]; __attribute__((fallthrough));        \
        case 12: de_[(MAXW) - 12] = se_[(MAXW) - 12]; __attribute__((fallthrough));        \
        case 11: de_[(MAXW) - 11] = se_[(MAXW) - 11]; __attribute__((fallthrough));        \
        case 10: de_[(MAXW) - 10] = se_[(MAXW) - 10]; __attribute__((fallthrough));        \
        case 9: de_[(MAXW) - 9] = se_[(MAXW) - 9]; __attribute__((fallthrough));           \
        case 8: de_[(MAXW) - 8] = se_[(MAXW) - 8]; __attribute__((fallthrough));           \
        case 7: de_[(MAXW) - 7] = se_[(MAXW) - 7]; __attribute__((fallthrough));           \
        case 6: de_[(MAXW) - 6] = se_[(MAXW) - 6]; __attribute__((fallthrough));           \
        case 5: de_[(MAXW) - 5] = se_[(MAXW) - 5]; __attribute__((fallthrough));           \
        case 4: de_[(MAXW) - 4] = se_[(MAXW) - 4]; __attribute__((fallthrough));           \
        case 3: de_[(MAXW) - 3] = se_[(MAXW) - 3]; __attribute__((fallthrough));           \
        case 2: de_[(MAXW) - 2] = se_[(MAXW) - 2]; __attribute__((fallthrough));           \
        case 1: de_[(MAXW) - 1] = se_[(MAXW) - 1]; __attribute__((fallthrough));           \
        case 0: break;                                                                     \
        default: __builtin_unreachable();                                                  \
        }                                                                                  \
    } while (0)

// `chunks` (0..16) CSR MEMCOPY chunks, lowest first, by a jump into a run based at the end.
static inline __attribute__((always_inline))
void csr_chunks16(w32 *d, const w32 *s, size_t chunks) {
    // Integer arithmetic: for chunks < 16 the base lies before d, and the runs below only
    // reach back into [d, d + chunks * 32).
    unsigned char *de = (unsigned char *)((uintptr_t)d + chunks * 32 - 512);
    const unsigned char *se = (const unsigned char *)((uintptr_t)s + chunks * 32 - 512);
    switch (chunks) {
    case 16: csr_memcopy32(de + 0, se + 0); __attribute__((fallthrough));
    case 15: csr_memcopy32(de + 32, se + 32); __attribute__((fallthrough));
    case 14: csr_memcopy32(de + 64, se + 64); __attribute__((fallthrough));
    case 13: csr_memcopy32(de + 96, se + 96); __attribute__((fallthrough));
    case 12: csr_memcopy32(de + 128, se + 128); __attribute__((fallthrough));
    case 11: csr_memcopy32(de + 160, se + 160); __attribute__((fallthrough));
    case 10: csr_memcopy32(de + 192, se + 192); __attribute__((fallthrough));
    case 9: csr_memcopy32(de + 224, se + 224); __attribute__((fallthrough));
    case 8: csr_memcopy32(de + 256, se + 256); __attribute__((fallthrough));
    case 7: csr_memcopy32(de + 288, se + 288); __attribute__((fallthrough));
    case 6: csr_memcopy32(de + 320, se + 320); __attribute__((fallthrough));
    case 5: csr_memcopy32(de + 352, se + 352); __attribute__((fallthrough));
    case 4: csr_memcopy32(de + 384, se + 384); __attribute__((fallthrough));
    case 3: csr_memcopy32(de + 416, se + 416); __attribute__((fallthrough));
    case 2: csr_memcopy32(de + 448, se + 448); __attribute__((fallthrough));
    case 1: csr_memcopy32(de + 480, se + 480); __attribute__((fallthrough));
    case 0: break;
    default: __builtin_unreachable();
    }
}

// Both word-aligned, n > 67.
static inline __attribute__((always_inline)) void *memcpy_aligned_large(void *dest, const void *src, size_t n) {
    w32 *dw = (w32 *)dest;
    const w32 *sw = (const w32 *)src;
    if ((((uintptr_t)dw ^ (uintptr_t)sw) & 31) == 0) {
        // Same phase modulo 32: words up to the 32-byte boundary, CSR chunks, words, bytes.
        const size_t lead = (0u - (uintptr_t)dw) & 31;
        COPY_WORDS_FWD(dw, sw, lead >> 2, 7);
        dw = (w32 *)((uintptr_t)dw + lead);
        sw = (const w32 *)((uintptr_t)sw + lead);
        n -= lead;
        while (n >= 16 * 32) {
            csr_chunks16(dw, sw, 16);
            dw += 128;
            sw += 128;
            n -= 16 * 32;
        }
        csr_chunks16(dw, sw, n >> 5);
        dw = (w32 *)((uintptr_t)dw + (n & ~(size_t)31));
        sw = (const w32 *)((uintptr_t)sw + (n & ~(size_t)31));
        n &= 31;
        COPY_WORDS_FWD(dw, sw, n >> 2, 7);
        if (n & 3) {
            unsigned char *d = (unsigned char *)dw + (n & ~(size_t)3);
            const unsigned char *s = (const unsigned char *)sw + (n & ~(size_t)3);
            n &= 3;
            while (n--)
                *d++ = *s++;
        }
        return dest;
    }
    // Different phase: words, then bytes.
    while (n >= 32) {
        dw[0] = sw[0]; dw[1] = sw[1]; dw[2] = sw[2]; dw[3] = sw[3];
        dw[4] = sw[4]; dw[5] = sw[5]; dw[6] = sw[6]; dw[7] = sw[7];
        dw += 8;
        sw += 8;
        n -= 32;
    }
    COPY_WORDS_FWD(dw, sw, n >> 2, 7);
    if (n & 3) {
        unsigned char *d = (unsigned char *)dw + (n & ~(size_t)3);
        const unsigned char *s = (const unsigned char *)sw + (n & ~(size_t)3);
        n &= 3;
        while (n--)
            *d++ = *s++;
    }
    return dest;
}

// Defined at the end of the file (see the -fno-toplevel-reorder note in CMakeLists.txt): the
// memcpy() keeps its address (the later functions shift by the size change of memcpy and
// memcpy_large()), so the callers that reach it with jal still do.
static void *memcpy_large(void *dest, const void *src, size_t n) __attribute__((noinline));

void *memcpy(void *dest, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;

    if ((((uintptr_t)d | (uintptr_t)s) & 3) == 0) {
        w32 *dw = (w32 *)d;
        const w32 *sw = (const w32 *)s;
        if (__builtin_expect(n == 32, 1)) {
            dw[0] = sw[0]; dw[1] = sw[1]; dw[2] = sw[2]; dw[3] = sw[3];
            dw[4] = sw[4]; dw[5] = sw[5]; dw[6] = sw[6]; dw[7] = sw[7];
            return dest;
        }
        if ((n >> 2) <= 16) {
            COPY_WORDS_FWD(dw, sw, n >> 2, 16);
            if (n & 3) {
                d += n & ~(size_t)3;
                s += n & ~(size_t)3;
                switch (n & 3) {
                case 3: d[0] = s[0]; d[1] = s[1]; d[2] = s[2]; break;
                case 2: d[0] = s[0]; d[1] = s[1]; break;
                default: d[0] = s[0];
                }
            }
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
    } else if (n == 32) {
        copy32_any(d, s);
        return dest;
    } else if (n < 8) {
        while (n--)
            *d++ = *s++;
        return dest;
    }
    return memcpy_large(dest, src, n);
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
        w32 *dw = (w32 *)d;
        const w32 *sw = (const w32 *)s;
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
        w32 *dw = (w32 *)d;
        const w32 *sw = (const w32 *)s;

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
        w32 *dw = (w32 *)d;
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
        // Any other fill of up to 256 bytes: a jump into an unrolled run of word stores, then
        // the tail bytes. Most zero fills are struct value-initializations of 68 to 240 bytes
        // (evmc_message, Account, StorageValue, Transaction); the generic path below steers
        // such a fill through its 32-byte alignment, CSR and remainder stages for ~90 cycles,
        // this costs the stores plus about 10 instructions.
        if (n <= 256) {
            switch (n >> 2) {
        case 64: dw[63] = 0; __attribute__((fallthrough));
        case 63: dw[62] = 0; __attribute__((fallthrough));
        case 62: dw[61] = 0; __attribute__((fallthrough));
        case 61: dw[60] = 0; __attribute__((fallthrough));
        case 60: dw[59] = 0; __attribute__((fallthrough));
        case 59: dw[58] = 0; __attribute__((fallthrough));
        case 58: dw[57] = 0; __attribute__((fallthrough));
        case 57: dw[56] = 0; __attribute__((fallthrough));
        case 56: dw[55] = 0; __attribute__((fallthrough));
        case 55: dw[54] = 0; __attribute__((fallthrough));
        case 54: dw[53] = 0; __attribute__((fallthrough));
        case 53: dw[52] = 0; __attribute__((fallthrough));
        case 52: dw[51] = 0; __attribute__((fallthrough));
        case 51: dw[50] = 0; __attribute__((fallthrough));
        case 50: dw[49] = 0; __attribute__((fallthrough));
        case 49: dw[48] = 0; __attribute__((fallthrough));
        case 48: dw[47] = 0; __attribute__((fallthrough));
        case 47: dw[46] = 0; __attribute__((fallthrough));
        case 46: dw[45] = 0; __attribute__((fallthrough));
        case 45: dw[44] = 0; __attribute__((fallthrough));
        case 44: dw[43] = 0; __attribute__((fallthrough));
        case 43: dw[42] = 0; __attribute__((fallthrough));
        case 42: dw[41] = 0; __attribute__((fallthrough));
        case 41: dw[40] = 0; __attribute__((fallthrough));
        case 40: dw[39] = 0; __attribute__((fallthrough));
        case 39: dw[38] = 0; __attribute__((fallthrough));
        case 38: dw[37] = 0; __attribute__((fallthrough));
        case 37: dw[36] = 0; __attribute__((fallthrough));
        case 36: dw[35] = 0; __attribute__((fallthrough));
        case 35: dw[34] = 0; __attribute__((fallthrough));
        case 34: dw[33] = 0; __attribute__((fallthrough));
        case 33: dw[32] = 0; __attribute__((fallthrough));
        case 32: dw[31] = 0; __attribute__((fallthrough));
        case 31: dw[30] = 0; __attribute__((fallthrough));
        case 30: dw[29] = 0; __attribute__((fallthrough));
        case 29: dw[28] = 0; __attribute__((fallthrough));
        case 28: dw[27] = 0; __attribute__((fallthrough));
        case 27: dw[26] = 0; __attribute__((fallthrough));
        case 26: dw[25] = 0; __attribute__((fallthrough));
        case 25: dw[24] = 0; __attribute__((fallthrough));
        case 24: dw[23] = 0; __attribute__((fallthrough));
        case 23: dw[22] = 0; __attribute__((fallthrough));
        case 22: dw[21] = 0; __attribute__((fallthrough));
        case 21: dw[20] = 0; __attribute__((fallthrough));
        case 20: dw[19] = 0; __attribute__((fallthrough));
        case 19: dw[18] = 0; __attribute__((fallthrough));
        case 18: dw[17] = 0; __attribute__((fallthrough));
        case 17: dw[16] = 0; __attribute__((fallthrough));
        case 16: dw[15] = 0; __attribute__((fallthrough));
        case 15: dw[14] = 0; __attribute__((fallthrough));
        case 14: dw[13] = 0; __attribute__((fallthrough));
        case 13: dw[12] = 0; __attribute__((fallthrough));
        case 12: dw[11] = 0; __attribute__((fallthrough));
        case 11: dw[10] = 0; __attribute__((fallthrough));
        case 10: dw[9] = 0; __attribute__((fallthrough));
        case 9: dw[8] = 0; __attribute__((fallthrough));
        case 8: dw[7] = 0; __attribute__((fallthrough));
        case 7: dw[6] = 0; __attribute__((fallthrough));
        case 6: dw[5] = 0; __attribute__((fallthrough));
        case 5: dw[4] = 0; __attribute__((fallthrough));
        case 4: dw[3] = 0; __attribute__((fallthrough));
        case 3: dw[2] = 0; __attribute__((fallthrough));
        case 2: dw[1] = 0; __attribute__((fallthrough));
        case 1: dw[0] = 0; __attribute__((fallthrough));
        case 0: break;
            }
            d += n & ~(size_t)3;
            switch (n & 3) {
            case 3: d[2] = 0; __attribute__((fallthrough));
            case 2: d[1] = 0; __attribute__((fallthrough));
            case 1: d[0] = 0; __attribute__((fallthrough));
            case 0: break;
            }
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
        w32 *dw = (w32 *)d;

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

    w32 *dw = (w32 *)d;

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
        const w32 *wa = (const w32 *)pa;
        const w32 *wb = (const w32 *)pb;

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

// ---------------------------------------------------------------------------
// memcpy_large — the rest of memcpy
// ---------------------------------------------------------------------------
// Everything memcpy() does not copy inline: n >= 8, and either n > 67 at word alignment or not
// word-aligned. Out of line: the CSR MEMCOPY binds x10..x12, which in memcpy() itself had GCC keep
// dest and src in other registers on every call (two moves on entry, one on return).
static void *memcpy_large(void *dest, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    // A copy onto itself is a no-op: memmove() forwards one for an EVM MCOPY with equal
    // offsets, and GCC may emit one for a self-assignment. The CSR MEMCOPY paths below must
    // not see it, as the delegation requires x10 != x11.
    if (__builtin_expect(d == s, 0))
        return dest;
    if ((((uintptr_t)d | (uintptr_t)s) & 3) == 0)
        return memcpy_aligned_large(dest, src, n);
    // Align destination to 4-byte boundary.
    size_t head = (4 - ((uintptr_t)d & 3)) & 3;
    n -= head;
    while (head--)
        *d++ = *s++;

    // If source is also aligned, use word copies (and CSR MEMCOPY when possible).
    if (((uintptr_t)s & 3) == 0) {
        w32 *dw = (w32 *)d;
        const w32 *sw = (const w32 *)s;

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
        const w32 *sw = (const w32 *)sa;
        w32 *dw = (w32 *)d;
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
