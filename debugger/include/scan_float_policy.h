// SPDX-License-Identifier: GPL-3.0-only

#pragma once

#include <stdint.h>
#include "protocol.h"

/* Shared client/server wire policy for Turbo float and double scans.
 * Value-type numbers are the published scan protocol encoding:
 * 8 = IEEE-754 binary32, 9 = IEEE-754 binary64. */
#define TS_FLOAT_VALUE_TYPE_F32 8u
#define TS_FLOAT_VALUE_TYPE_F64 9u
#define TS_FLOAT_DEFAULT_EXPONENTS 11u

static inline int ts_float_policy_is_float(uint8_t value_type) {
    return value_type == TS_FLOAT_VALUE_TYPE_F32 || value_type == TS_FLOAT_VALUE_TYPE_F64;
}

static inline uint32_t ts_float_policy_exponent_limit(uint32_t flags) {
    uint32_t limit = (flags & TS_FLOAT_EXPONENT_MASK) >> TS_FLOAT_EXPONENT_SHIFT;
    return limit ? limit : TS_FLOAT_DEFAULT_EXPONENTS;
}

/* Mirrors the clients' Simple predicate exactly. Positive zero is retained;
 * every other value must have an exponent within +/-limit of 1.0's exponent.
 * The 7-bit wire field bounds limit to 127. */
static inline int ts_float_policy_simple_value(uint32_t flags, uint8_t value_type,
                                               const void *value) {
    if (!(flags & TS_FLOAT_SIMPLE) || !ts_float_policy_is_float(value_type) || !value)
        return 1;

    uint32_t limit = ts_float_policy_exponent_limit(flags);
    if (value_type == TS_FLOAT_VALUE_TYPE_F32) {
        uint32_t bits;
        __builtin_memcpy(&bits, value, sizeof(bits));
        if (bits == 0u) return 1;
        uint32_t exponent = (bits >> 23) & 0xffu;
        uint32_t distance = exponent > 127u ? exponent - 127u : 127u - exponent;
        return distance <= limit;
    }

    uint64_t bits;
    __builtin_memcpy(&bits, value, sizeof(bits));
    if (bits == 0u) return 1;
    uint32_t exponent = (uint32_t)((bits >> 52) & 0x7ffu);
    uint32_t distance = exponent > 1023u ? exponent - 1023u : 1023u - exponent;
    return distance <= limit;
}

/* FloatExact in Phoenix/Cheater-NG means numeric IEEE equality, not a raw-bit
 * comparison: +0 equals -0 and NaN never equals NaN. Unaligned wire/memory
 * values are copied before conversion. */
static inline int ts_float_policy_exact_equal(uint8_t value_type,
                                              const void *memory_value,
                                              const void *scan_value) {
    if (!memory_value || !scan_value) return 0;
    if (value_type == TS_FLOAT_VALUE_TYPE_F32) {
        float memory_float, scan_float;
        __builtin_memcpy(&memory_float, memory_value, sizeof(memory_float));
        __builtin_memcpy(&scan_float, scan_value, sizeof(scan_float));
        return memory_float == scan_float;
    }
    if (value_type == TS_FLOAT_VALUE_TYPE_F64) {
        double memory_double, scan_double;
        __builtin_memcpy(&memory_double, memory_value, sizeof(memory_double));
        __builtin_memcpy(&scan_double, scan_value, sizeof(scan_double));
        return memory_double == scan_double;
    }
    return 0;
}
