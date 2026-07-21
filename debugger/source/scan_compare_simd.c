// SPDX-License-Identifier: GPL-3.0-only


#include "scan_turbo.h"
#include <immintrin.h>

static size_t elem_size(unsigned char vt) {
    switch (vt) {
        case 0: case 1: return 1;
        case 2: case 3: return 2;
        case 4: case 5: case 8: return 4;
        case 6: case 7: case 9: return 8;
        default: return 0;
    }
}

__attribute__((target("avx2")))
static size_t find_u32_avx2(const uint8_t *buf, size_t len, uint32_t target,
                            uint32_t *out, size_t max) {
    const uint32_t *p = (const uint32_t *)buf;
    size_t n = len / 4;
    size_t cnt = 0, i = 0;
    __m256i t = _mm256_set1_epi32((int)target);
    for (; i + 8 <= n; i += 8) {
        __m256i v  = _mm256_loadu_si256((const __m256i *)(p + i));
        __m256i eq = _mm256_cmpeq_epi32(v, t);
        int mask = _mm256_movemask_ps(_mm256_castsi256_ps(eq));
        if (mask) {
            for (int b = 0; b < 8; b++)
                if (mask & (1 << b)) { if (cnt < max) out[cnt] = (uint32_t)((i + b) * 4); cnt++; }
        }
    }
    for (; i < n; i++)
        if (p[i] == target) { if (cnt < max) out[cnt] = (uint32_t)(i * 4); cnt++; }
    return cnt;
}

static size_t find_scalar(unsigned char vt, const uint8_t *buf, size_t len,
                          const void *val, uint32_t step,
                          uint32_t *out, size_t max) {
    size_t esz = elem_size(vt);
    if (esz == 0 || step == 0 || len < esz) return 0;

    uint8_t  v8  = *(const uint8_t  *)val;
    uint16_t v16 = *(const uint16_t *)val;
    uint32_t v32 = *(const uint32_t *)val;
    uint64_t v64 = *(const uint64_t *)val;
    float    vf  = *(const float    *)val;
    double   vd  = *(const double   *)val;

    size_t cnt = 0;
    size_t end = len - esz;
    for (size_t off = 0; off <= end; off += step) {
        const uint8_t *m = buf + off;
        int eq = 0;
        switch (vt) {
            case 0: case 1: eq = (*(const uint8_t  *)m == v8);  break;
            case 2: case 3: eq = (*(const uint16_t *)m == v16); break;
            case 4: case 5: eq = (*(const uint32_t *)m == v32); break;
            case 6: case 7: eq = (*(const uint64_t *)m == v64); break;
            case 8:         eq = (*(const float    *)m == vf);  break;
            case 9:         eq = (*(const double   *)m == vd);  break;
            default:        return cnt;
        }
        if (eq) { if (cnt < max) out[cnt] = (uint32_t)off; cnt++; }
    }
    return cnt;
}

size_t scan_simd_find_exact(unsigned char valtype, const uint8_t *buf, size_t len,
                            const void *value, uint32_t step,
                            uint32_t *out_off, size_t max_out) {
    if (!buf || !value || !out_off) return 0;

    if ((valtype == 4 || valtype == 5) && step == 4)
        return find_u32_avx2(buf, len, *(const uint32_t *)value, out_off, max_out);
    return find_scalar(valtype, buf, len, value, step, out_off, max_out);
}

#define _SPC_BIN(P_LHS, P_RHS, OP)                                              \
    switch (valType) {                                                          \
    case 0: return *(const uint8_t  *)P_LHS OP *(const uint8_t  *)P_RHS;        \
    case 1: return *(const int8_t   *)P_LHS OP *(const int8_t   *)P_RHS;        \
    case 2: return *(const uint16_t *)P_LHS OP *(const uint16_t *)P_RHS;        \
    case 3: return *(const int16_t  *)P_LHS OP *(const int16_t  *)P_RHS;        \
    case 4: return *(const uint32_t *)P_LHS OP *(const uint32_t *)P_RHS;        \
    case 5: return *(const int32_t  *)P_LHS OP *(const int32_t  *)P_RHS;        \
    case 6: return *(const uint64_t *)P_LHS OP *(const uint64_t *)P_RHS;        \
    case 7: return *(const int64_t  *)P_LHS OP *(const int64_t  *)P_RHS;        \
    case 8: return *(const float    *)P_LHS OP *(const float    *)P_RHS;        \
    case 9: return *(const double   *)P_LHS OP *(const double   *)P_RHS;        \
    default: return 0;                                                          \
    }

#define _SPC_BY(P_MEM, P_BASE, P_DELTA, OP_BIN)                                 \
    switch (valType) {                                                          \
    case 0: return *(const uint8_t  *)P_MEM == (uint8_t )(*(const uint8_t  *)P_BASE OP_BIN *(const uint8_t  *)P_DELTA); \
    case 1: return *(const int8_t   *)P_MEM == (int8_t  )(*(const int8_t   *)P_BASE OP_BIN *(const int8_t   *)P_DELTA); \
    case 2: return *(const uint16_t *)P_MEM == (uint16_t)(*(const uint16_t *)P_BASE OP_BIN *(const uint16_t *)P_DELTA); \
    case 3: return *(const int16_t  *)P_MEM == (int16_t )(*(const int16_t  *)P_BASE OP_BIN *(const int16_t  *)P_DELTA); \
    case 4: return *(const uint32_t *)P_MEM == (*(const uint32_t *)P_BASE OP_BIN *(const uint32_t *)P_DELTA); \
    case 5: return *(const int32_t  *)P_MEM == (*(const int32_t  *)P_BASE OP_BIN *(const int32_t  *)P_DELTA); \
    case 6: return *(const uint64_t *)P_MEM == (*(const uint64_t *)P_BASE OP_BIN *(const uint64_t *)P_DELTA); \
    case 7: return *(const int64_t  *)P_MEM == (*(const int64_t  *)P_BASE OP_BIN *(const int64_t  *)P_DELTA); \
    case 8: return *(const float    *)P_MEM == (*(const float    *)P_BASE OP_BIN *(const float    *)P_DELTA); \
    case 9: { double delta_d = *(const double *)P_DELTA;                                                     \
              return *(const double *)P_MEM == (*(const double *)P_BASE OP_BIN delta_d); }                   \
    default: return 0;                                                          \
    }

int scan_point_turbo_supported(unsigned char cmpType, unsigned char valType) {
    if (valType > 9) return 0;
    switch (cmpType) {
        case 0:  return valType <= 7;
        case 5: case 6: case 7:
        case 8: case 9: case 10: return 1;
        default: return 0;
    }
}

int scan_point_compare(unsigned char cmpType, unsigned char valType,
                       const void *mem, const void *scan, const void *prev) {
    const void *pMem  = mem;
    const void *pScan = scan;
    const void *pPrev = prev;
    switch (cmpType) {
        case 0:  _SPC_BIN(pMem, pScan, ==)
        case 5:  _SPC_BIN(pMem, pPrev, >)
        case 6:  _SPC_BY (pMem, pPrev, pScan, +)
        case 7:  _SPC_BIN(pMem, pPrev, <)
        case 8:  _SPC_BY (pMem, pPrev, pScan, -)
        case 9:  _SPC_BIN(pMem, pPrev, !=)
        case 10: _SPC_BIN(pMem, pPrev, ==)
        default: return 0;
    }
}

#undef _SPC_BIN
#undef _SPC_BY
