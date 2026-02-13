/*
 * Stubs for symbols required by the C++ runtime and standard library
 * that aren't available in the bare-metal RISC-V environment.
 */

#include <stdint.h>

/* __dso_handle is used by __cxa_atexit for shared library support.
 * In a freestanding / static-only environment it just needs to exist. */
void *__dso_handle = (void *)0;

/* math stubs – only used by std::to_chars / std::unordered_map internals */
double floor(double x)
{
    /* Truncate toward negative infinity. */
    long long i = (long long)x;
    return (x < 0.0 && (double)i != x) ? (double)(i - 1) : (double)i;
}

/* Floating-point rounding-mode stubs (FE_TONEAREST = 0). */
int fegetround(void)
{
    return 0; /* FE_TONEAREST */
}

int fesetround(int round)
{
    (void)round;
    return 0; /* success */
}
