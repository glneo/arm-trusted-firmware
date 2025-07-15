/* SPDX-License-Identifier: BSD-3-Clause */
#if !defined(_ilog_H)
#define _ilog_H (1)

#include <stdint.h>
#include <limits.h>
#include <cdefs.h>

#ifndef CONST_FUNCTION
#define CONST_FUNCTION __attribute__((const))
#endif

/**
 * ilog32 - Integer binary logarithm of a 32-bit value.
 * @_v: A 32-bit value.
 * Returns floor(log2(_v))+1, or 0 if _v==0.
 * This is the number of bits that would be required to represent _v in two's
 *  complement notation with all of the leading zeros stripped.
 * Note that many uses will resolve to the fast macro version instead.
 *
 * See Also:
 *	ilog32_nz(), ilog64()
 *
 * Example:
 *	// Rounds up to next power of 2 (if not a power of 2).
 *	static uint32_t round_up32(uint32_t i)
 *	{
 *		assert(i != 0);
 *		return 1U << ilog32(i-1);
 *	}
 */
int32_t ilog32(uint32_t _v) CONST_FUNCTION;

#endif /* _ilog_H */
