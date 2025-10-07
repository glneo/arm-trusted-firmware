/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) Timothy B. Terriberry (tterribe@xiph.org) 2001-2009 */
#define ILOG_IMPLEMENTATION
#include "ilog.h"
#include <limits.h>

/*
 * The fastest fallback strategy for platforms with fast multiplication appears
 *   to be based on de Bruijn sequences~\cite{LP98}.
 *   Tests confirmed this to be true even on an ARM11, where it is actually faster
 *   than using the native clz instruction.
 *   Define ILOG_NODEBRUIJN to use a simpler fallback on platforms where
 *   multiplication or table lookups are too expensive.
 *
 *   @UNPUBLISHED{LP98,
 *   author="Charles E. Leiserson and Harald Prokop",
 *   title="Using de {Bruijn} Sequences to Index a 1 in a Computer Word",
 *   month=Jun,
 *   year=1998,
 *   note="\url{http://supertech.csail.mit.edu/papers/debruijn.pdf}"
 *   }
 */
static __maybe_unused const uint8_t DEBRUIJN_IDX32[32] = {
	0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8,
	31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9
};

/* We always compile these in, in case someone takes address of function. */

int32_t ilog32(uint32_t _v)
{
	uint32_t v = _v;
	int32_t ret;

	ret = (int32_t)(v > 0U);
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v = (v >> 1)+1U;
	ret += (int32_t)DEBRUIJN_IDX32[(v*0x77CB531U >> 27)&0x1FU];
	return ret;
}
