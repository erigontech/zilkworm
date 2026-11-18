/* Stubs for symbols the C++ runtime and stdlib need that bare-metal RISC-V lacks. */

#include <stdint.h>

/* __dso_handle only needs to exist for __cxa_atexit. */
void *__dso_handle = (void *)0;

/* math stubs – only used by std::to_chars / std::unordered_map internals */
double floor(double x)
{
    long long i = (long long)x;
    return (x < 0.0 && (double)i != x) ? (double)(i - 1) : (double)i;
}

/* Floating-point rounding-mode stubs (FE_TONEAREST = 0). */
int fegetround(void)
{
    return 0;
}

int fesetround(int round)
{
    (void)round;
    return 0;
}

/* Linker --wrap stubs that drop ~104KB of ryu float-to-string tables pulled in by printf %f/%g. */
struct _reent;
char *__wrap__dtoa_r(struct _reent *r, double d, int mode, int ndigits,
                     int *decpt, int *sign, char **rve)
{
    (void)r; (void)d; (void)mode; (void)ndigits;
    static char buf[] = "0";
    if (decpt) *decpt = 1;
    if (sign)  *sign  = 0;
    if (rve)   *rve   = buf + 1;
    return buf;
}

double __wrap__strtod_r(struct _reent *r, const char *s, char **end)
{
    (void)r;
    if (end) *end = (char *)s;
    return 0.0;
}
