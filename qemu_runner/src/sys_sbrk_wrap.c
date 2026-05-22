// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/reent.h>

#include <stddef.h>
#include <stdalign.h>
enum { HEAP_ALIGN = _Alignof(max_align_t) };


extern char __heap_start;   // from linker
extern char __heap_end;     // from linker

static uintptr_t cur_brk = 0;

static inline uintptr_t align_up(uintptr_t p, size_t a) {
  return (p + (a - 1)) & ~(uintptr_t)(a - 1);
}

static inline void heap_init_once(void) {
  if (cur_brk == 0) {
    cur_brk = align_up((uintptr_t)&__heap_start, HEAP_ALIGN);
  }
}

void * __wrap__sbrk(ptrdiff_t incr) {
  heap_init_once();

  uintptr_t prev = cur_brk;
  uintptr_t next = prev + (uintptr_t)incr;

  if (next < (uintptr_t)&__heap_start || next > (uintptr_t)&__heap_end) {
    errno = ENOMEM;
    return (void *)-1;
  }

  cur_brk = next;
  return (void *)prev;
}

void * __wrap__sbrk_r(struct _reent *r, ptrdiff_t incr) {
  void *res = __wrap__sbrk(incr);
  if (res == (void*)-1 && r) r->_errno = errno;
  return res;
}