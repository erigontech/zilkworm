// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Differential test of the guest's blst mul_mont_384 (a 768-bit product and a two-round
// reduction) against the single-round version it replaced, both compiled from the patch
// script's own text and run on an emulation of the BigInt delegation, plus an exact model of the
// Montgomery product. Compiled as C: it is the blst code, not C++.
//
// The domain is what the guest's callers pass: at least one operand below p (blst keeps every
// Fp value reduced, and raw 384-bit encodings are only multiplied by RR or by 1). Two operands
// near 2^384 are outside it and only counted: the new reduction drops the 769th bit.
#include "bigint_emu.h"
#include "blst_mont384_diff.h"

unsigned long mont384_emu_calls;
#define AIRBENDER_BIGINT_CSR 1
#include "base_block.inc"
#include "cand_block.inc"

static limb_t RP[12], RNP[12];
static void mp_mul(limb_t *r, const limb_t *a, int na, const limb_t *b, int nb)
{
    memset(r, 0, sizeof(limb_t) * (na + nb));
    for (int i = 0; i < na; i++) {
        llimb_t c = 0;
        for (int j = 0; j < nb; j++) { c += (llimb_t)a[i] * b[j] + r[i + j]; r[i + j] = (limb_t)c; c >>= 32; }
        r[i + nb] = (limb_t)c;
    }
}
static void ref_init(void)
{
    const char *hex = "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
    memset(RP, 0, sizeof RP);
    for (int i = 0; i < 96; i++) { int d = hex[95 - i]; d = d <= '9' ? d - '0' : d - 'a' + 10; RP[i / 8] |= (limb_t)d << (4 * (i % 8)); }
    limb_t x[12] = {1}, t[24], u[24];
    for (int it = 0; it < 10; it++) {
        mp_mul(t, RP, 12, x, 12);
        limb_t tm[12]; limb_t bw = 0;
        for (int i = 0; i < 12; i++) { llimb_t d = (llimb_t)(i == 0 ? 2 : 0) - t[i] - bw; tm[i] = (limb_t)d; bw = (limb_t)(d >> 63); }
        mp_mul(u, x, 12, tm, 12); memcpy(x, u, sizeof x);
    }
    limb_t bw = 0;
    for (int i = 0; i < 12; i++) { llimb_t d = (llimb_t)0 - x[i] - bw; RNP[i] = (limb_t)d; bw = (limb_t)(d >> 63); }
}
/* HEAD-equivalent exact model: q = (a*b + m*p)/2^384, one conditional subtraction, truncated to 384 bits */
static void ref_mont(limb_t ret[12], const limb_t a[12], const limb_t b[12], int *sub, int *tie)
{
    limb_t T[24], m[24], mp[25], U[26];
    mp_mul(T, a, 12, b, 12); mp_mul(m, T, 12, RNP, 12); mp_mul(mp, m, 12, RP, 12); mp[24] = 0;
    llimb_t c = 0;
    for (int i = 0; i < 25; i++) { c += (llimb_t)(i < 24 ? T[i] : 0) + mp[i]; U[i] = (limb_t)c; c >>= 32; }
    U[25] = (limb_t)c;
    for (int i = 0; i < 12; i++) if (U[i]) { fprintf(stderr, "ref: low half not zero\n"); abort(); }
    limb_t *q = U + 12; int ge = 1;
    for (int i = 13; i >= 0; i--) { limb_t pi = i < 12 ? RP[i] : 0; if (q[i] != pi) { ge = q[i] > pi; break; } }
    *sub = ge; *tie = (q[12] == 0 && q[13] == 0 && q[11] == RP[11]);
    if (ge) { limb_t bw = 0; for (int i = 0; i < 14; i++) { llimb_t d = (llimb_t)q[i] - (i < 12 ? RP[i] : 0) - bw; q[i] = (limb_t)d; bw = (limb_t)(d >> 63); } }
    memcpy(ret, q, 48);
}
static uint64_t rs = 0x9e3779b97f4a7c15ull;
static inline uint64_t rnd64(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static inline limb_t rnd32(void) { return (limb_t)(rnd64() >> 17); }
static int lt_p(const limb_t a[12]) { for (int i = 11; i >= 0; i--) if (a[i] != RP[i]) return a[i] < RP[i]; return 0; }
static void gen_reduced(limb_t a[12]) { do { for (int i = 0; i < 12; i++) a[i] = rnd32(); a[11] &= 0x1fffffff; } while (!lt_p(a)); }
static void gen_any(limb_t a[12]) { for (int i = 0; i < 12; i++) a[i] = rnd32(); }
static void gen_struct(limb_t a[12])
{
    for (int i = 0; i < 12; i++) {
        switch (rnd32() % 10) {
        case 0: a[i] = 0; break; case 1: a[i] = 0xffffffff; break; case 2: a[i] = RP[i]; break;
        case 3: a[i] = RP[i] + 1; break; case 4: a[i] = RP[i] - 1; break; case 5: a[i] = 1; break;
        case 6: a[i] = 0x80000000u; break; case 7: a[i] = RNP[i]; break; default: a[i] = rnd32();
        }
    }
    if (!lt_p(a) && (rnd32() & 1)) a[11] = RP[11] - 1 - (rnd32() & 0xff);
}
static void gen_tz(limb_t a[12], limb_t b[12])       /* a*b == 0 mod 2^k for k around 64..256 */
{
    int k = rnd32() % 300, ka = rnd32() % (k + 1), kb = k - ka;
    gen_reduced(a); gen_reduced(b);
    for (int i = 0; i < 12; i++) {
        int lo = 32 * i;
        if (lo + 32 <= ka) a[i] = 0; else if (lo < ka) a[i] &= ~((1u << (ka - lo)) - 1);
        if (lo + 32 <= kb) b[i] = 0; else if (lo < kb) b[i] &= ~((1u << (kb - lo)) - 1);
    }
}
static const limb_t RRc[12] = { 0x1c341746, 0xf4df1f34, 0x09d104f1, 0x0a76e6a6, 0x4c95b6d5, 0x8de5476c,
                                0x939d83c0, 0x67eb88a9, 0xb519952d, 0x9a793e85, 0x92cae3aa, 0x11988fe5 };

/* a*b*R^-1 = w mod p for a small w and a random b: a = w * R / b, by Fermat's inverse in the
 * Montgomery domain on the exact model. */
#define NSMALL 64
static limb_t SA[NSMALL][12], SB[NSMALL][12];
static void mont_mul_ref(limb_t r[12], const limb_t a[12], const limb_t b[12])
{
    int sub, tie;
    ref_mont(r, a, b, &sub, &tie);
}
static void gen_small_results(void)
{
    static const limb_t one[12] = {1};
    for (int k = 0; k < NSMALL; k++) {
        limb_t w[12] = {0}, wm[12], bm[12], acc[12], inv[12];
        int bits = k < 4 ? k : (int)(rnd32() % 385);   /* w = 0, 1, 2, 3, then any length */
        if (k >= 4) {
            for (int i = 0; i < 12; i++)
                w[i] = i * 32 + 32 <= bits ? rnd32() : i * 32 < bits ? rnd32() & ((1u << (bits - i * 32)) - 1) : 0;
            if (!lt_p(w)) w[11] = 0;
        } else w[0] = (limb_t)k;
        gen_reduced(SB[k]);
        mont_mul_ref(bm, SB[k], RRc);                  /* b * R */
        mont_mul_ref(acc, RRc, one);                   /* R mod p */
        limb_t e[12];                                  /* p - 2 */
        memcpy(e, RP, 48); e[0] -= 2;
        for (int i = 383; i >= 0; i--) {
            mont_mul_ref(acc, acc, acc);
            if ((e[i / 32] >> (i % 32)) & 1) mont_mul_ref(acc, acc, bm);
        }
        memcpy(inv, acc, 48);                          /* R / b */
        mont_mul_ref(wm, w, RRc);                      /* w * R */
        mont_mul_ref(SA[k], inv, wm);                  /* w * R / b */
    }
}

/* a*b = v mod 2^256 for a chosen v, with a, b below p: a odd, b = v / a mod 2^256 below, random above.
 * Round 1 of the reduction adds a carry into t1 exactly when the low 256 bits of the product are
 * not all zero, so v with a single bit or word set is what tells the zero test from a partial one. */
static void mul_lo256(limb_t r[8], const limb_t x[8], const limb_t y[8])
{
    limb_t t[16];
    mp_mul(t, x, 8, y, 8);
    memcpy(r, t, 32);
}
static void gen_lo256(limb_t a[12], limb_t b[12], const limb_t v[8])
{
    limb_t x[8] = {1}, t[8], tm[8];
    gen_reduced(a);
    a[0] |= 1;
    for (int it = 0; it < 8; it++) {            /* x = a^-1 mod 2^256 by Newton's iteration */
        mul_lo256(t, a, x);
        limb_t bw = 0;
        for (int i = 0; i < 8; i++) { llimb_t d = (llimb_t)(i == 0 ? 2 : 0) - t[i] - bw; tm[i] = (limb_t)d; bw = (limb_t)(d >> 63); }
        mul_lo256(t, x, tm);
        memcpy(x, t, 32);
    }
    gen_reduced(b);
    mul_lo256(b, v, x);                         /* writes b[0..7] only */
}
static unsigned long n_in, n_out, n_out_diff, n_sub, n_tie, n_c0z, n_tsmall;
static unsigned long base_min_csr, cand_max_csr, base_csr_sum, cand_csr_sum;
static int failed;
static char* fail_msg;
static size_t fail_cap;

static void dump(const char* tag, const limb_t* a, const limb_t* b)
{
    size_t n = (size_t)snprintf(fail_msg, fail_cap, "[%s] a=", tag);
    for (int i = 11; i >= 0 && n < fail_cap; i--) n += (size_t)snprintf(fail_msg + n, fail_cap - n, "%08x", a[i]);
    if (n < fail_cap) n += (size_t)snprintf(fail_msg + n, fail_cap - n, " b=");
    for (int i = 11; i >= 0 && n < fail_cap; i--) n += (size_t)snprintf(fail_msg + n, fail_cap - n, "%08x", b[i]);
    failed = 1;
}

static void check(const limb_t* a, const limb_t* b, const char* tag)
{
    limb_t want[12], h[12], c[12], t[12];
    int sub, tie;
    if (failed) return;
    ref_mont(want, a, b, &sub, &tie);
    unsigned long k0 = mont384_emu_calls;
    base_mul_mont_384(h, a, b, NULL, 0);
    unsigned long kb = mont384_emu_calls - k0;
    if (memcmp(h, want, 48)) { dump("base != model", a, b); return; }
    k0 = mont384_emu_calls;
    cand_mul_mont_384(c, a, b, NULL, 0);
    unsigned long kc = mont384_emu_calls - k0;
    if (!(lt_p(a) || lt_p(b))) { n_out++; n_out_diff += memcmp(c, h, 48) != 0; return; }
    n_in++; n_sub += (unsigned long)sub; n_tie += (unsigned long)tie;
    base_csr_sum += kb; cand_csr_sum += kc;
    if (kb < base_min_csr) base_min_csr = kb;
    if (kc > cand_max_csr) cand_max_csr = kc;
    {
        limb_t T[24];
        mp_mul(T, a, 12, b, 12);
        n_c0z += (T[0] | T[1]) == 0;
        int z = 1;
        for (int i = 0; i < 8; i++) z &= T[i] == 0;
        n_tsmall += (unsigned long)z;
    }
    if (memcmp(c, h, 48)) { dump(tag, a, b); return; }
    // ret may alias either operand
    memcpy(t, a, 48); cand_mul_mont_384(t, t, b, NULL, 0); if (memcmp(t, h, 48)) { dump("ret==a", a, b); return; }
    memcpy(t, b, 48); cand_mul_mont_384(t, a, t, NULL, 0); if (memcmp(t, h, 48)) { dump("ret==b", a, b); return; }
    if (lt_p(a)) {
        limb_t hs[12];
        base_sqr_mont_384(hs, a, NULL, 0);
        cand_sqr_mont_384(t, a, NULL, 0); if (memcmp(t, hs, 48)) { dump("sqr", a, a); return; }
        memcpy(t, a, 48); cand_mul_mont_384(t, t, t, NULL, 0); if (memcmp(t, hs, 48)) { dump("ret==a==b", a, a); return; }
    }
}

int blst_mont384_difftest(long n, unsigned long long seed, struct blst_mont384_stats* st, char* msg, size_t msg_cap)
{
    n_in = n_out = n_out_diff = n_sub = n_tie = n_c0z = n_tsmall = 0;
    base_min_csr = ~0ul; cand_max_csr = base_csr_sum = cand_csr_sum = 0;
    failed = 0; fail_msg = msg; fail_cap = msg_cap;
    if (msg_cap) msg[0] = 0;
    rs = 0x9e3779b97f4a7c15ull ^ (seed * 0x2545F4914F6CDD1Dull);
    ref_init();
    gen_small_results();
    for (int i = 0; i < 12; i++) if (RP[i] != base_bls_P[i] || RP[i] != cand_bls_P[i]) { snprintf(msg, msg_cap, "p mismatch"); return 1; }
    for (int i = 0; i < 8; i++) if (RNP[i] != cand_bls_np_lo[i] || RNP[i] != base_bls_np_lo[i]) { snprintf(msg, msg_cap, "np mismatch"); return 1; }
    static limb_t E[24][12];
    int ne = 0;
    memset(E[ne++], 0, 48);
    memset(E[ne], 0, 48); E[ne++][0] = 1;
    memset(E[ne], 0, 48); E[ne++][0] = 2;
    memcpy(E[ne], RP, 48); E[ne++][0] -= 1;
    memcpy(E[ne], RP, 48); E[ne++][0] -= 2;
    memset(E[ne++], 0xff, 48);
    memcpy(E[ne++], RP, 48);
    memset(E[ne], 0, 48); E[ne++][8] = 1;
    memset(E[ne], 0, 48); for (int i = 0; i < 8; i++) E[ne][i] = 0xffffffff; ne++;
    memset(E[ne], 0, 48); E[ne++][4] = 1;
    memset(E[ne], 0, 48); E[ne++][2] = 1;
    memcpy(E[ne++], RRc, 48);
    memset(E[ne], 0, 48); E[ne++][11] = RP[11];
    memset(E[ne], 0, 48); for (int i = 0; i < 11; i++) E[ne][i] = 0xffffffff; E[ne][11] = RP[11] - 1; ne++;
    memset(E[ne], 0, 48); E[ne][11] = 0x80000000u; ne++;
    for (int i = 0; i < ne; i++) for (int j = 0; j < ne; j++) check(E[i], E[j], "edge");
    limb_t a[12], b[12];
    for (int bit = 0; bit < 256 && !failed; bit++) {          // a*b = 2^bit, 2^256 - 2^bit, one word k * 2^32j
        limb_t v[8] = {0};
        v[bit / 32] = 1u << (bit % 32);
        gen_lo256(a, b, v); check(a, b, "lo256 bit"); check(b, a, "lo256 bit");
        limb_t w[8] = {0};
        w[bit / 32] = rnd32() | 1;
        gen_lo256(a, b, w); check(a, b, "lo256 word"); check(b, a, "lo256 word");
        limb_t u[8];
        for (int i = 0; i < 8; i++) u[i] = 0xffffffff;
        u[bit / 32] &= ~(1u << (bit % 32));
        gen_lo256(a, b, u); check(a, b, "lo256 ones"); check(b, a, "lo256 ones");
    }
    for (long it = 0; it < n && !failed; it++) {
        switch (it % 11) {
        case 0: case 1: gen_reduced(a); gen_reduced(b); check(a, b, "reduced"); break;
        case 2: gen_struct(a); gen_struct(b); check(a, b, "struct"); break;
        case 3: gen_tz(a, b); check(a, b, "tz"); break;
        case 4: gen_any(a); check(a, RRc, "any*RR"); check(RRc, a, "RR*any"); break;
        case 5: { gen_any(a); limb_t one[12] = {1}; check(a, one, "from_mont"); break; }
        case 6: gen_reduced(a); memcpy(b, a, 48); check(a, b, "sqr"); break;
        case 7: gen_reduced(a); gen_any(b); check(a, b, "red*any"); break;
        case 8: gen_reduced(a); a[11] = RP[11] - (rnd32() & 1); if (!lt_p(a)) a[10] = RP[10] - 1;
                gen_reduced(b); b[11] = RP[11] - (rnd32() & 3); if (!lt_p(b)) b[11] -= 4;
                check(a, b, "nearp"); break;
        case 9: gen_any(a); gen_any(b); check(a, b, "any*any"); break;
        case 10: {  // operands whose product is a small value: the quotient is want + p after
                    // the fast path, and its top word ties p's
            int k = (int)(rnd32() % NSMALL);
            check(SA[k], SB[k], "smallres");
            check(SB[k], SA[k], "smallres");
            break;
        }
        }
    }
    st->in_domain = n_in; st->out_of_domain = n_out; st->out_of_domain_diff = n_out_diff;
    st->sub_path = n_sub; st->top_word_ties = n_tie; st->t_low64_zero = n_c0z; st->t_low256_zero = n_tsmall;
    st->base_min_csr = base_min_csr; st->cand_max_csr = cand_max_csr;
    st->base_csr_sum = base_csr_sum; st->cand_csr_sum = cand_csr_sum;
    return failed;
}
