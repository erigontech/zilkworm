// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0


#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/reent.h>
static inline uint64_t rdcycle(void) {
  uint64_t v;
  __asm__ volatile ("rdcycle %0" : "=r"(v));
  return v;
}

#ifdef __cplusplus
extern "C" {
#endif
int _getentropy(void *buf, size_t len) {
  if (!buf) { errno = EFAULT; return -1; }
  uint8_t *p = (uint8_t*)buf;
  uint64_t x = rdcycle() ^ (rdcycle() << 13);
  // XorShift-ish mixer to fill the buffer
  for (size_t i = 0; i < len; ++i) {
    x ^= x << 7; x ^= x >> 9; x += 0x9E3779B97F4A7C15ULL;
    p[i] = (uint8_t)x;
  }
  return 0;
}

// Reentrant wrapper that newlib wants
int _getentropy_r(struct _reent *r, void *buf, size_t len) {
  int rc = _getentropy(buf, len);
  if (rc < 0 && r) r->_errno = errno;
  return rc;
}

#ifdef __cplusplus
}
#endif
