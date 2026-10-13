// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Differential test of the guest's fused cyclotomic squaring outputs (3*t - 2*a and 3*t + 2*a,
// formed with one CSR sum and one reduction) against the three modular operations of blst's
// original cyclotomic_sqr_fp12 and against an exact big-number model. Both versions are
// compiled from the patch script's own text (extract.py) and the CSR instruction runs on the
// emulation in bigint_emu.h. Compiled as C: it is the blst code, not C++.
//
// The domain is what the guest produces: t and a canonical (below p). The tests cover the whole
// function too, with sqr_fp4 replaced by a stub that hands out chosen t values.
#include "bigint_emu.h"
#include "blst_cyclotomic_diff.h"

typedef vec384x vec384fp2;
typedef vec384fp2 vec384fp4[2];
typedef vec384fp2 vec384fp6[3];
typedef vec384fp6 vec384fp12[2];

unsigned long emu_calls;
static unsigned long cov_reduce_calls, cov_reduce_taken, cov_q[5];

/* ---- big numbers: 16 little-endian 32-bit limbs ---- */
#define NB 16
typedef limb_t bn[NB];
static limb_t P[12];

static void bn_set12(bn r, const limb_t *x) { memset(r, 0, sizeof(bn)); memcpy(r, x, 48); }
static void bn_pow2(bn r, int bit) { memset(r, 0, sizeof(bn)); r[bit / 32] = 1u << (bit % 32); }
static int bn_cmp(const bn a, const bn b)
{
    for (int i = NB - 1; i >= 0; i--) if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    return 0;
}
static void bn_add(bn r, const bn a, const bn b)
{
    llimb_t c = 0;
    for (int i = 0; i < NB; i++) { c += (llimb_t)a[i] + b[i]; r[i] = (limb_t)c; c >>= 32; }
}
static void bn_sub(bn r, const bn a, const bn b)   /* a >= b */
{
    limb_t bw = 0;
    for (int i = 0; i < NB; i++) { llimb_t d = (llimb_t)a[i] - b[i] - bw; r[i] = (limb_t)d; bw = (limb_t)(d >> 63); }
}
static void bn_mulsmall(bn r, const bn a, limb_t k)
{
    llimb_t c = 0;
    for (int i = 0; i < NB; i++) { c += (llimb_t)a[i] * k; r[i] = (limb_t)c; c >>= 32; }
}
static limb_t bn_divsmall(bn r, const bn a, limb_t k)
{
    llimb_t rem = 0;
    for (int i = NB - 1; i >= 0; i--) { llimb_t cur = (rem << 32) | a[i]; r[i] = (limb_t)(cur / k); rem = cur % k; }
    return (limb_t)rem;
}
static void bn_from_i(bn r, long long v)   /* small signed offsets are applied by the caller */
{
    memset(r, 0, sizeof(bn)); r[0] = (limb_t)v;
}
static void bn_addi(bn r, const bn a, long long d)
{
    bn t; bn_from_i(t, d < 0 ? -d : d);
    if (d >= 0) bn_add(r, a, t);
    else if (bn_cmp(a, t) >= 0) bn_sub(r, a, t);
    else memset(r, 0xff, sizeof(bn));     /* below zero: callers drop it through the range test */
}
static int bn_lt_5p(const bn v)
{
    bn p5, pp; bn_set12(pp, P); bn_mulsmall(p5, pp, 5);
    return bn_cmp(v, p5) < 0;
}

/* modular operations on canonical values */
static void modadd(limb_t *r, const limb_t *x, const limb_t *y)
{
    bn a, b, s, pp; bn_set12(a, x); bn_set12(b, y); bn_set12(pp, P);
    bn_add(s, a, b);
    if (bn_cmp(s, pp) >= 0) bn_sub(s, s, pp);
    memcpy(r, s, 48);
}
static void modsub(limb_t *r, const limb_t *x, const limb_t *y)
{
    bn a, b, s, pp; bn_set12(a, x); bn_set12(b, y); bn_set12(pp, P);
    if (bn_cmp(a, b) >= 0) bn_sub(s, a, b);
    else { bn_add(s, a, pp); bn_sub(s, s, b); }
    memcpy(r, s, 48);
}
/* exact (3t -/+ 2a) mod p from big-number arithmetic alone */
static void model_lin(limb_t *out, const limb_t *t, const limb_t *a, int sub)
{
    bn bt, ba, pp, v, w;
    bn_set12(bt, t); bn_set12(ba, a); bn_set12(pp, P);
    bn_mulsmall(v, bt, 3);
    if (sub) bn_sub(w, pp, ba); else memcpy(w, ba, sizeof w);
    bn_mulsmall(w, w, 2);
    bn_add(v, v, w);
    while (bn_cmp(v, pp) >= 0) bn_sub(v, v, pp);
    memcpy(out, v, 48);
}
/* blst's chain: sub/add, add, add */
static void chain_lin(limb_t *out, const limb_t *t, const limb_t *a, int sub)
{
    limb_t s[12];
    if (sub) modsub(s, t, a); else modadd(s, t, a);
    modadd(s, s, s);
    modadd(out, s, t);
}

/* ---- stubs for what the blocks call ---- */
static void sub_fp2(vec384x ret, const vec384x a, const vec384x b)
{
    limb_t r[2][12];
    modsub(r[0], a[0], b[0]); modsub(r[1], a[1], b[1]);
    memcpy(ret, r, sizeof r);
}
static void add_fp2(vec384x ret, const vec384x a, const vec384x b)
{
    limb_t r[2][12];
    modadd(r[0], a[0], b[0]); modadd(r[1], a[1], b[1]);
    memcpy(ret, r, sizeof r);
}
static void mul_by_u_plus_1_fp2(vec384x ret, const vec384x a)
{
    limb_t r[2][12];
    modsub(r[0], a[0], a[1]); modadd(r[1], a[0], a[1]);
    memcpy(ret, r, sizeof r);
}
static limb_t inj[3][2][2][12];   /* the t values the next squaring gets, one fp4 per sqr_fp4 call */
static int inj_n;
static void sqr_fp4(vec384fp4 ret, const vec384x a0, const vec384x a1)
{
    memcpy(ret, inj[inj_n++], sizeof inj[0]);
}

#define AIRBENDER_BIGINT_CSR 1
#include "base_block.inc"
#include "cand_block.inc"

/* ---- generators ---- */
static uint64_t rs = 0x9e3779b97f4a7c15ull;
static inline uint64_t rnd64(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static inline limb_t rnd32(void) { return (limb_t)(rnd64() >> 17); }
static int lt_p(const limb_t a[12]) { for (int i = 11; i >= 0; i--) if (a[i] != P[i]) return a[i] < P[i]; return 0; }
static void gen_reduced(limb_t a[12]) { do { for (int i = 0; i < 12; i++) a[i] = rnd32(); a[11] &= 0x1fffffff; } while (!lt_p(a)); }
static void gen_small(limb_t a[12])      /* random bit length */
{
    int bits = rnd32() % 381;
    memset(a, 0, 48);
    for (int i = 0; i < 12; i++) a[i] = rnd32();
    for (int i = 0; i < 12; i++) {
        int lo = i * 32;
        if (lo >= bits) a[i] = 0;
        else if (lo + 32 > bits) a[i] &= (1u << (bits - lo)) - 1;
    }
    if (!lt_p(a)) memset(a, 0, 48);
}
static void gen_struct(limb_t a[12])
{
    for (int i = 0; i < 12; i++) {
        switch (rnd32() % 8) {
        case 0: a[i] = 0; break; case 1: a[i] = 0xffffffff; break; case 2: a[i] = P[i]; break;
        case 3: a[i] = P[i] + 1; break; case 4: a[i] = P[i] - 1; break; case 5: a[i] = 1; break;
        case 6: a[i] = 0x80000000u; break; default: a[i] = rnd32();
        }
    }
    if (!lt_p(a)) { memcpy(a, P, 48); a[0] -= 1 + (rnd32() & 3); }
}

#define NE 64
static limb_t E[NE][12];
static int ne;
static void add_edge(const bn v) { if (bn_cmp(v, (const limb_t[NB]){0}) < 0) return; limb_t x[12]; memcpy(x, v, 48); for (int i = 12; i < NB; i++) if (v[i]) return; if (lt_p(x) && ne < NE) memcpy(E[ne++], x, 48); }
static void build_edges(void)
{
    bn pp, v, one, two, z; bn_set12(pp, P); bn_from_i(one, 1); bn_from_i(two, 2); memset(z, 0, sizeof z);
    ne = 0;
    for (int d = 0; d < 4; d++) { bn_from_i(v, d); add_edge(v); }
    for (int d = 1; d <= 3; d++) { bn_addi(v, pp, -d); add_edge(v); }
    bn h; bn_divsmall(h, pp, 2); add_edge(h); bn_addi(v, h, 1); add_edge(v);
    for (int k = 1; k <= 2; k++) {
        bn kp; bn_mulsmall(kp, pp, k); bn_divsmall(v, kp, 3); add_edge(v); bn_addi(v, v, 1); add_edge(v); bn_addi(v, v, 1); add_edge(v);
    }
    static const int bits[] = {255, 256, 128, 64, 352, 380, 32, 96};
    for (unsigned i = 0; i < sizeof bits / sizeof *bits; i++) {
        bn_pow2(v, bits[i]); add_edge(v); bn_addi(v, v, 1); add_edge(v);
        bn_pow2(v, bits[i]); bn_addi(v, v, -1); add_edge(v);
    }
    /* p with its low 256 bits cleared, and with the top word one lower and the rest all ones */
    memset(v, 0, sizeof v); memcpy(v + 8, P + 8, 16); add_edge(v);
    memset(v, 0, sizeof v); memset(v, 0xff, 44); v[11] = P[11] - 1; add_edge(v);
    memset(v, 0, sizeof v); memset(v, 0xff, 32); add_edge(v);
    memset(v, 0, sizeof v); memset(v, 0xff, 32); v[8] = 1; add_edge(v);
    /* every word 0 or all ones, alternating */
    memset(v, 0, sizeof v); for (int i = 0; i < 11; i += 2) v[i] = 0xffffffff; add_edge(v);
    memset(v, 0, sizeof v); for (int i = 1; i < 11; i += 2) v[i] = 0xffffffff; add_edge(v);
}

/* ---- checks ---- */
static int failed;
static char *fail_msg;
static size_t fail_cap;
static unsigned long n_core, n_wrap, max_sub, max_add, max_wrap;

static void hex(char *dst, size_t cap, const limb_t *x)
{
    size_t n = 0;
    for (int i = 11; i >= 0 && n + 9 < cap; i--) n += (size_t)snprintf(dst + n, cap - n, "%08x", x[i]);
}
static void fail(const char *what, const limb_t *t, const limb_t *a, int sub)
{
    if (failed++) return;
    char ht[100] = "", ha[100] = "";
    hex(ht, sizeof ht, t); hex(ha, sizeof ha, a);
    snprintf(fail_msg, fail_cap, "%s (%s): t=%s a=%s", what, sub ? "3t-2a" : "3t+2a", ht, ha);
}

static void core(const limb_t *t, const limb_t *a, int sub)
{
    limb_t m[12], c[12], r[12], tc[12], ac[12];
    if (failed || !lt_p(t) || !lt_p(a)) return;
    n_core++;
    model_lin(m, t, a, sub);
    chain_lin(c, t, a, sub);
    if (memcmp(m, c, 48)) { fail("harness: model != blst chain", t, a, sub); return; }
    memcpy(tc, t, 48); memcpy(ac, a, 48);
    unsigned long before = emu_calls;
    if (sub) _cyc_3t_sub_2a(r, t, a); else _cyc_3t_add_2a(r, t, a);
    unsigned long k = emu_calls - before;
    if (sub) { if (k > max_sub) max_sub = k; } else if (k > max_add) max_add = k;
    if (memcmp(r, m, 48)) { fail("fused != model", t, a, sub); return; }
    if (memcmp(t, tc, 48) || memcmp(a, ac, 48)) { fail("inputs modified", t, a, sub); return; }
    memcpy(r, a, 48);   /* ret == a, as mul_n_sqr calls it */
    if (sub) _cyc_3t_sub_2a(r, t, r); else _cyc_3t_add_2a(r, t, r);
    if (memcmp(r, m, 48)) { fail("fused ret==a != model", t, a, sub); return; }
    memcpy(r, t, 48);
    if (sub) _cyc_3t_sub_2a(r, r, a); else _cyc_3t_add_2a(r, r, a);
    if (memcmp(r, m, 48)) { fail("fused ret==t != model", t, a, sub); return; }
}
static void core2(const limb_t *t, const limb_t *a) { core(t, a, 1); core(t, a, 0); }

/* a pair (t, a) whose pre-reduction value v is the given one: add: v = 3t + 2a, sub: v = 3t - 2a + 2p */
static void aim(const bn v, const limb_t *a, int sub)
{
    bn ba, pp, x, y, q; limb_t t[12];
    for (int i = NB - 1; i >= 0; i--) if (v[i] == 0xffffffff && i == NB - 1) return;   /* bn_addi underflow */
    bn_set12(ba, a); bn_set12(pp, P);
    if (!bn_lt_5p(v)) return;
    bn_mulsmall(y, ba, 2);
    if (sub) {
        bn p2; bn_mulsmall(p2, pp, 2);
        bn_add(x, v, y);
        if (bn_cmp(x, p2) < 0) return;
        bn_sub(x, x, p2);
    } else {
        if (bn_cmp(v, y) < 0) return;
        bn_sub(x, v, y);
    }
    if (bn_divsmall(q, x, 3)) return;
    if (bn_cmp(q, pp) >= 0) return;
    memcpy(t, q, 48);
    core(t, a, sub);
}
/* targets around the multiples of p, the quotient thresholds and the 2^256 split of v */
static void crafted(const limb_t *a)
{
    bn pp, v, w, t352; bn_set12(pp, P); bn_pow2(t352, 352);
    for (int sub = 0; sub < 2; sub++) {
        for (int k = 0; k <= 4; k++) {
            bn kp; bn_mulsmall(kp, pp, k);
            for (int d = -6; d <= 6; d++) { bn_addi(v, kp, d); aim(v, a, sub); }
            if (k >= 1) {   /* the smallest v whose top word reaches ceil(k*p / 2^352), and its neighbours */
                bn c; bn_add(c, kp, t352); bn_addi(c, c, -1);
                for (int i = 0; i < 11; i++) c[i] = 0;
                for (int d = -3; d <= 3; d++) { bn_addi(v, c, d); aim(v, a, sub); }
            }
            bn hi; memcpy(hi, kp, sizeof hi); for (int i = 0; i < 8; i++) hi[i] = 0;   /* (kp >> 256) << 256 */
            static const int ehi[] = {-1, 0, 1};
            for (unsigned e = 0; e < 3; e++) {
                bn h2; bn_pow2(w, 256); bn_mulsmall(w, w, 1);
                memcpy(h2, hi, sizeof h2);
                if (ehi[e] > 0) bn_add(h2, h2, w);
                if (ehi[e] < 0) { if (bn_cmp(h2, w) < 0) continue; bn_sub(h2, h2, w); }
                for (int pat = 0; pat < 8; pat++) {
                    memcpy(v, h2, sizeof v);
                    switch (pat) {
                    case 0: break;
                    case 1: v[0] = 1; break;
                    case 2: for (int i = 0; i < 8; i++) v[i] = 0xffffffff; break;
                    case 3: for (int i = 0; i < 8; i++) v[i] = 0xffffffff; v[0] = 0xfffffffe; break;
                    case 4: v[7] = 0x80000000u; break;
                    case 5: v[7] = 0x7fffffffu; for (int i = 0; i < 7; i++) v[i] = 0xffffffff; break;
                    case 6: for (int i = 0; i < 8; i++) v[i] = rnd32(); break;
                    default: v[rnd32() % 8] = 0xffffffff; break;
                    }
                    aim(v, a, sub);
                }
            }
        }
        /* carries of the CSR sums: v's low 256 bits wrap in the middle of the computation */
        for (int i = 0; i < 40; i++) {
            bn_set12(v, a); memset(v, 0, sizeof v);
            for (int j = 0; j < 8; j++) v[j] = (rnd32() & 1) ? 0xffffffff : rnd32();
            for (int j = 8; j < 12; j++) v[j] = rnd32();
            v[11] %= 0x68044000u;
            aim(v, a, sub);
        }
    }
}

static void wrap_check(const limb_t a[2][3][2][12], const limb_t t[3][2][2][12], const char *tag)
{
    limb_t rb[2][3][2][12], rn[2][3][2][12], ip[2][3][2][12];
    if (failed) return;
    n_wrap++;
    memcpy(inj, t, sizeof inj); inj_n = 0;
    base_cyclotomic_sqr_fp12(rb, a);
    memcpy(inj, t, sizeof inj); inj_n = 0;
    unsigned long before = emu_calls;
    cyclotomic_sqr_fp12(rn, a);
    unsigned long k = emu_calls - before;
    if (k > max_wrap) max_wrap = k;
    if (memcmp(rb, rn, sizeof rb)) { fail(tag, a[0][0][0], t[0][0][0], 1); return; }
    memcpy(ip, a, sizeof ip);
    memcpy(inj, t, sizeof inj); inj_n = 0;
    cyclotomic_sqr_fp12(ip, ip);
    if (memcmp(rb, ip, sizeof rb)) { fail("wrapper in place", a[0][0][0], t[0][0][0], 1); return; }
}
static void fill(limb_t *x, int n_fp, int mode)
{
    for (int i = 0; i < n_fp; i++) {
        limb_t *v = x + 12 * i;
        switch (mode) {
        case 0: gen_reduced(v); break;
        case 1: memset(v, 0, 48); break;
        case 2: memcpy(v, P, 48); v[0] -= 1; break;
        case 3: memcpy(v, E[rnd32() % ne], 48); break;
        case 4: gen_struct(v); break;
        default: gen_small(v); break;
        }
    }
}

int blst_cyc_difftest(long n, unsigned long long seed, struct blst_cyc_stats* st, char* msg, size_t msg_cap)
{
    static const char *hexp = "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
    memset(P, 0, sizeof P);
    for (int i = 0; i < 96; i++) { int d = hexp[95 - i]; d = d <= '9' ? d - '0' : d - 'a' + 10; P[i / 8] |= (limb_t)d << (4 * (i % 8)); }
    failed = 0; fail_msg = msg; fail_cap = msg_cap; if (msg_cap) msg[0] = 0;
    n_core = n_wrap = max_sub = max_add = max_wrap = 0;
    cov_reduce_calls = cov_reduce_taken = 0; memset(cov_q, 0, sizeof cov_q);
    rs = 0x9e3779b97f4a7c15ull ^ (seed * 0x2545F4914F6CDD1Dull);
    build_edges();

    /* the tables the block carries are k*p */
    for (int k = 1; k <= 4; k++) {
        bn pp, kp; bn_set12(pp, P); bn_mulsmall(kp, pp, k);
        for (int i = 0; i < 12; i++) {
            limb_t got = i < 8 ? _cyc_kp_lo[k][i] : _cyc_kp_hi[k][i - 8];
            if (kp[i] != got) { snprintf(msg, msg_cap, "table k*p wrong: k=%d limb %d", k, i); return 1; }
        }
        if (kp[12] || kp[13]) { snprintf(msg, msg_cap, "harness: k*p too wide"); return 1; }
    }

    for (int i = 0; i < ne && !failed; i++) for (int j = 0; j < ne; j++) core2(E[i], E[j]);
    for (int i = 0; i < ne && !failed; i++) { crafted(E[i]); }
    limb_t t[12], a[12];
    for (long it = 0; it < n && !failed; it++) {
        switch (it % 7) {
        case 0: gen_reduced(t); gen_reduced(a); core2(t, a); crafted(a); break;
        case 1: gen_struct(t); gen_struct(a); core2(t, a); crafted(a); break;
        case 2: gen_small(t); gen_small(a); core2(t, a); crafted(a); break;
        case 3: gen_reduced(t); memcpy(a, t, 48); core2(t, a); break;
        case 4: memcpy(t, E[rnd32() % ne], 48); gen_reduced(a); core2(t, a); core2(a, t); break;
        case 5: gen_reduced(a); crafted(a); break;
        default: gen_struct(a); memcpy(t, E[rnd32() % ne], 48); core2(t, a); crafted(a); break;
        }
    }

    /* the whole function: wiring of t and a to the twelve outputs, the u+1 twist, ret == a */
    {
        static limb_t wa[2][3][2][12], wt[3][2][2][12];
        for (int mode = 0; mode < 6 && !failed; mode++) {
            fill(&wa[0][0][0][0], 12, mode); fill(&wt[0][0][0][0], 12, mode);
            wrap_check(wa, wt, "wrapper uniform");
        }
        for (long it = 0; it < n / 8 + 200 && !failed; it++) {
            for (int i = 0; i < 12; i++) {
                fill(&wa[0][0][0][0] + 12 * i, 1, rnd32() % 6);
                fill(&wt[0][0][0][0] + 12 * i, 1, rnd32() % 6);
            }
            wrap_check(wa, wt, "wrapper mixed");
        }
    }

    st->core_cases = n_core; st->wrap_cases = n_wrap;
    st->reduce_calls = cov_reduce_calls; st->reduce_taken = cov_reduce_taken;
    for (int i = 0; i < 5; i++) st->q_hist[i] = cov_q[i];
    st->max_csr_sub = max_sub; st->max_csr_add = max_add; st->max_csr_wrap = max_wrap;
    return failed;
}
