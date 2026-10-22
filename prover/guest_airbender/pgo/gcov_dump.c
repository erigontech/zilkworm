/* Training-run hook for the instrumented (-fprofile-arcs -fprofile-info-section) guest: serializes every
 * instrumented TU's counters as a gcov-tool merge-stream (gcfn + gcda records) and prints it through the
 * QuasiUART as hex lines "GCD:<hex>". Compiled without instrumentation. */
#include <gcov.h>
#include <stddef.h>
#include <stdint.h>

extern const struct gcov_info *const __gcov_info_start[];
extern const struct gcov_info *const __gcov_info_end[];

static inline void csr_write_word(uint32_t v)
{
    __asm__ volatile("csrrw x0, 0x7C0, %0" ::"r"(v) : "memory");
}

/* Same framing as airbender::detail::uart_write_str. */
static void uart_bytes(const char *d, size_t len)
{
    csr_write_word(0xFFFFFFFFu);
    csr_write_word((uint32_t)((len + 3) / 4 + 1));
    csr_write_word((uint32_t)len);
    for (size_t i = 0; i < len; i += 4) {
        uint32_t w = 0;
        for (size_t j = 0; j < 4 && i + j < len; ++j)
            w |= (uint32_t)(uint8_t)d[i + j] << (8 * j);
        csr_write_word(w);
    }
}

static char line[4 + 8192];
static size_t pos;

static void flush_line(void)
{
    if (pos > 4)
        uart_bytes(line, pos);
    pos = 0;
}

static void put_hex(const void *data, unsigned n, void *arg)
{
    static const char hx[] = "0123456789abcdef";
    const uint8_t *p = (const uint8_t *)data;
    (void)arg;
    for (unsigned i = 0; i < n; ++i) {
        if (pos == 0) {
            line[0] = 'G'; line[1] = 'C'; line[2] = 'D'; line[3] = ':';
            pos = 4;
        }
        line[pos++] = hx[p[i] >> 4];
        line[pos++] = hx[p[i] & 15];
        if (pos >= sizeof line)
            flush_line();
    }
}

static void put_filename(const char *f, void *arg)
{
    __gcov_filename_to_gcfn(f, put_hex, arg);
}

/* Only TOPN value counters allocate; -fprofile-arcs has none. */
static void *no_alloc(unsigned length, void *arg)
{
    (void)length; (void)arg;
    return 0;
}

/* gcov_info lists __gcov_merge_add as the merge hook of the arc counters; the embedded dump only tests it for
 * non-null and never calls it, so a stub keeps libgcov's file-merging code (and its stdio) out of the image. */
void __gcov_merge_add(void *counters, unsigned n)
{
    (void)counters; (void)n;
}

void z6m_gcov_dump(void)
{
    for (const struct gcov_info *const *p = __gcov_info_start; p < __gcov_info_end; ++p)
        __gcov_info_to_gcda(*p, put_filename, put_hex, no_alloc, 0);
    flush_line();
    static const char done[] = "GCD-END";
    uart_bytes(done, sizeof done - 1);
}
