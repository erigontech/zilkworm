
#include <stdint.h>

#define WEAK   __attribute__((weak))
#define OPAQUE __attribute__((used,visibility("default")))

// --- 32-bit variants -------------------------------------------------

WEAK OPAQUE
int __atomic_fetch_add_4(volatile int *ptr, int val, int memorder)
{
    int old = *ptr;
    *ptr   += val;
    return old;
}

WEAK OPAQUE
int __atomic_fetch_sub_4(volatile int *ptr, int val, int memorder)
{
    int old = *ptr;
    *ptr   -= val;
    return old;
}

WEAK OPAQUE
int __atomic_compare_exchange_4(volatile int *ptr, int *expected,
                                int desired, int weak,
                                int success_mem, int failure_mem)
{
    if (*ptr == *expected) { *ptr = desired; return 1; }
    *expected = *ptr;
    return 0;
}

// You can add 8-byte versions if a warning appears:
//   __atomic_fetch_add_8, __atomic_compare_exchange_8, …