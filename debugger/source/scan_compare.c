// SPDX-License-Identifier: GPL-3.0-only

#include "protocol.h"
#include "sdk_shim.h"
#include "proc.h"

uint64_t proc_scan_getSizeOfValueType(unsigned char valType) {
    static const uint64_t sizes[10] = { 1, 1, 2, 2, 4, 4, 8, 8, 4, 8 };
    if (valType > 9) return 0;
    return sizes[valType];
}

#include <float.h>

bool fuzzy_double_compare(double scanV, double memV, double tolerance) {
    if (scanV == memV) return true;

    double diff = (scanV - memV);
    if (diff < 0) diff = -diff;

    double abs_scan = scanV < 0 ? -scanV : scanV;
    double abs_mem  = memV  < 0 ? -memV  : memV;

    if (scanV == 0.0 || memV == 0.0) {
        return (DBL_MIN * tolerance) > diff;
    }
    double sum = abs_scan + abs_mem;
    if (DBL_MIN > sum) {
        return (DBL_MIN * tolerance) > diff;
    }
    return tolerance > (diff / sum);
}

bool fuzzy_float_compare(float scanV, float memV, float tolerance) {
    if (scanV == memV) return true;

    double diff_d = (double)(scanV - memV);
    if (diff_d < 0) diff_d = -diff_d;
    float diff = (float)diff_d;

    float abs_scan = scanV < 0 ? -scanV : scanV;
    float abs_mem  = memV  < 0 ? -memV  : memV;

    if (scanV == 0.0f || memV == 0.0f) {
        return (FLT_MIN * tolerance) > diff;
    }
    float sum = abs_scan + abs_mem;
    if (FLT_MIN > sum) {
        return (FLT_MIN * tolerance) > diff;
    }
    return tolerance > (diff / sum);
}

bool aob_match(uint64_t pattern_length,
               const uint8_t *pattern,
               const uint8_t *memory,
               uint64_t unused,
               const uint8_t *mask) {
    (void)unused;
    if (pattern_length == 0) return true;
    for (uint64_t i = 0; i < pattern_length; i++) {
        if (memory[i] != pattern[i]) {
            if (mask[i] == 1) return false;
        }
    }
    return true;
}

#define _PER_VALTYPE_BIN(P_LHS, P_RHS, OP)                                     \
    switch (valType) {                                                          \
    case 0: return *(const uint8_t  *)P_LHS OP *(const uint8_t  *)P_RHS;       \
    case 1: return *(const int8_t   *)P_LHS OP *(const int8_t   *)P_RHS;       \
    case 2: return *(const uint16_t *)P_LHS OP *(const uint16_t *)P_RHS;       \
    case 3: return *(const int16_t  *)P_LHS OP *(const int16_t  *)P_RHS;       \
    case 4: return *(const uint32_t *)P_LHS OP *(const uint32_t *)P_RHS;       \
    case 5: return *(const int32_t  *)P_LHS OP *(const int32_t  *)P_RHS;       \
    case 6: return *(const uint64_t *)P_LHS OP *(const uint64_t *)P_RHS;       \
    case 7: return *(const int64_t  *)P_LHS OP *(const int64_t  *)P_RHS;       \
    case 8: return *(const float    *)P_LHS OP *(const float    *)P_RHS;      \
    case 9: return *(const double   *)P_LHS OP *(const double   *)P_RHS;      \
    default: return false;                                                      \
    }

#define _PER_VALTYPE_BY(P_MEM, P_BASE, P_DELTA, OP_BIN)                        \
    switch (valType) {                                                          \
    case 0: return *(const uint8_t  *)P_MEM == (uint8_t )(*(const uint8_t  *)P_BASE OP_BIN *(const uint8_t  *)P_DELTA); \
    case 1: return *(const int8_t   *)P_MEM == (int8_t  )(*(const int8_t   *)P_BASE OP_BIN *(const int8_t   *)P_DELTA); \
    case 2: return *(const uint16_t *)P_MEM == (uint16_t)(*(const uint16_t *)P_BASE OP_BIN *(const uint16_t *)P_DELTA); \
    case 3: return *(const int16_t  *)P_MEM == (int16_t )(*(const int16_t  *)P_BASE OP_BIN *(const int16_t  *)P_DELTA); \
    case 4: return *(const uint32_t *)P_MEM == (*(const uint32_t *)P_BASE OP_BIN *(const uint32_t *)P_DELTA); \
    case 5: return *(const int32_t  *)P_MEM == (*(const int32_t  *)P_BASE  OP_BIN *(const int32_t  *)P_DELTA); \
    case 6: return *(const uint64_t *)P_MEM == (*(const uint64_t *)P_BASE OP_BIN *(const uint64_t *)P_DELTA); \
    case 7: return *(const int64_t  *)P_MEM == (*(const int64_t  *)P_BASE  OP_BIN *(const int64_t  *)P_DELTA); \
    case 8: return *(const float    *)P_MEM == (*(const float    *)P_BASE OP_BIN *(const float    *)P_DELTA); \
    case 9: {                                                                   \
                                                       \
        double delta_d = *(const double *)P_DELTA;                              \
        return *(const double *)P_MEM == (*(const double *)P_BASE OP_BIN delta_d); \
    }                                                                           \
    default: return false;                                                      \
    }

#define _BETWEEN_LEGACY(TY)                                                    \
    do {                                                                        \
        TY mv = *(const TY *)pMem;                                              \
        TY sv = *(const TY *)pScan;                                             \
        TY ev = *(const TY *)pExtra;                                            \
        if (ev > sv) return mv > sv && mv < ev;                                 \
        return mv < sv && mv > ev;                                              \
    } while (0)

bool proc_scan_legacy_compareValues(unsigned char cmpType, unsigned char valType,
                                    uint64_t valueLength,
                                    const void *scanValue,
                                    const void *memValue,
                                    const void *extraValue) {
    const unsigned char *pScan  = (const unsigned char *)scanValue;
    const unsigned char *pMem   = (const unsigned char *)memValue;
    const unsigned char *pExtra = (const unsigned char *)extraValue;

    if (cmpType >= 4 && cmpType <= 10 && pExtra == NULL) return false;

    switch (cmpType) {
    case 0: {
        if (valueLength <= 1) return false;
        for (uint64_t j = 0; j < valueLength - 1; j++) {
            if (pScan[j] != pMem[j]) return false;
        }
        return true;
    }
    case 1: {
        if (valType == 8) {
            float diff = *(const float *)pScan - *(const float *)pMem;
            return diff < 1.0f && diff > -1.0f;
        }
        if (valType == 9) {
            double diff = *(const double *)pScan - *(const double *)pMem;
            return diff < 1.0 && diff > -1.0;
        }
        return false;
    }
    case 2: _PER_VALTYPE_BIN(pMem, pScan, >)
    case 3: _PER_VALTYPE_BIN(pMem, pScan, <)
    case 4: {
        switch (valType) {
        case 0: _BETWEEN_LEGACY(uint8_t);
        case 1: _BETWEEN_LEGACY(int8_t);
        case 2: _BETWEEN_LEGACY(uint16_t);
        case 3: _BETWEEN_LEGACY(int16_t);
        case 4: _BETWEEN_LEGACY(uint32_t);
        case 5: _BETWEEN_LEGACY(int32_t);
        case 6: _BETWEEN_LEGACY(uint64_t);
        case 7: _BETWEEN_LEGACY(int64_t);
        case 8: _BETWEEN_LEGACY(float);
        case 9: _BETWEEN_LEGACY(double);
        default: return false;
        }
    }
    case 5: _PER_VALTYPE_BIN(pMem, pExtra, >)
    case 6: _PER_VALTYPE_BY(pMem, pExtra, pScan, +)
    case 7: _PER_VALTYPE_BIN(pMem, pExtra, <)
    case 8: _PER_VALTYPE_BY(pMem, pExtra, pScan, -)
    case 9: _PER_VALTYPE_BIN(pMem, pExtra, !=)
    case 10: _PER_VALTYPE_BIN(pMem, pExtra, ==)
    case 11:
    case 12:
        return true;
    default:
        return false;
    }
}

#undef _BETWEEN_LEGACY

#define _BETWEEN_ASYNC(TY)                                                     \
    do {                                                                        \
        TY mv = *(const TY *)pMem;                                              \
        TY sv = *(const TY *)pScan;                                             \
        TY ev = *(const TY *)pPrev;                                             \
        if (ev > sv) return mv >= sv && mv <= ev;                               \
        return mv <= sv && mv >= ev;                                            \
    } while (0)

bool proc_scan_compareValues(unsigned char cmpType, unsigned char valType,
                             uint64_t valueLength,
                             const void *scanValue,
                             const void *memValue,
                             const void *prevValue,
                             const void *mask) {
    const unsigned char *pScan = (const unsigned char *)scanValue;
    const unsigned char *pMem  = (const unsigned char *)memValue;
    const unsigned char *pPrev = (const unsigned char *)prevValue;
    const unsigned char *pMask = (const unsigned char *)mask;

    if (cmpType >= 4 && cmpType <= 10 && pPrev == NULL) return false;

    switch (cmpType) {
    case 0: {

        if (valType == 10) {
            if (valueLength == 0) return true;
            for (uint64_t j = 0; j < valueLength; j++) {
                if (pScan[j] != pMem[j]) {
                    if (pMask && pMask[j] == 1) return false;
                }
            }
            return true;
        }

        if (valType == 8) {
            uint32_t scanBits, memBits;
            memcpy(&scanBits, pScan, 4);
            if (scanBits == 0) {
                memcpy(&memBits, pMem, 4);
                return memBits == 0;
            }
            return fuzzy_float_compare(*(const float *)pScan, *(const float *)pMem,
                                       (float)1e-6);
        }

        if (valType == 9) {
            uint64_t scanBits, memBits;
            memcpy(&scanBits, pScan, 8);
            if (scanBits == 0) {
                memcpy(&memBits, pMem, 8);
                return memBits == 0;
            }
            return fuzzy_double_compare(*(const double *)pScan, *(const double *)pMem,
                                        1e-6);
        }

        if (valueLength == 0) return true;
        for (uint64_t j = 0; j < valueLength; j++) {
            if (pScan[j] != pMem[j]) return false;
        }
        return true;
    }
    case 1: {
        if (valType == 8) {
            float diff = *(const float *)pScan - *(const float *)pMem;
            return diff < 1.0f && diff > -1.0f;
        }
        if (valType == 9) {
            double diff = *(const double *)pScan - *(const double *)pMem;
            return diff < 1.0 && diff > -1.0;
        }
        return false;
    }
    case 2: _PER_VALTYPE_BIN(pMem, pScan, >)
    case 3: _PER_VALTYPE_BIN(pMem, pScan, <)
    case 4: {
        switch (valType) {
        case 0: _BETWEEN_ASYNC(uint8_t);
        case 1: _BETWEEN_ASYNC(int8_t);
        case 2: _BETWEEN_ASYNC(uint16_t);
        case 3: _BETWEEN_ASYNC(int16_t);
        case 4: _BETWEEN_ASYNC(uint32_t);
        case 5: _BETWEEN_ASYNC(int32_t);
        case 6: _BETWEEN_ASYNC(uint64_t);
        case 7: _BETWEEN_ASYNC(int64_t);
        case 8: _BETWEEN_ASYNC(float);
        case 9: _BETWEEN_ASYNC(double);
        default: return false;
        }
    }
    case 5: _PER_VALTYPE_BIN(pMem, pPrev, >)
    case 6: _PER_VALTYPE_BY(pMem, pPrev, pScan, +)
    case 7: _PER_VALTYPE_BIN(pMem, pPrev, <)
    case 8: _PER_VALTYPE_BY(pMem, pPrev, pScan, -)
    case 9: _PER_VALTYPE_BIN(pMem, pPrev, !=)
    case 10: _PER_VALTYPE_BIN(pMem, pPrev, ==)
    case 11: {
        switch (valType) {
        case 0:
        case 1: return *pMem != 0;
        case 2:
        case 3: return *(const uint16_t *)pMem != 0;
        case 4:
        case 5: return *(const uint32_t *)pMem != 0;
        case 6:
        case 7: return *(const uint64_t *)pMem != 0;
        case 8: return *(const float  *)pMem != 0.0f;
        case 9: return *(const double *)pMem != 0.0;
        default: return false;
        }
    }
    case 12: {
        switch (valType) {
        case 0: { uint8_t  mv = *pMem;                    if (mv == 0) return false; return mv <= *pScan; }
        case 1: { int8_t   mv = *(const int8_t   *)pMem;  if (mv == 0) return false;
                  return (uint64_t)(int64_t)mv <= (uint64_t)(int64_t)*(const int8_t *)pScan; }
        case 2: { uint16_t mv = *(const uint16_t *)pMem;  if (mv == 0) return false; return mv <= *(const uint16_t *)pScan; }
        case 3: { int16_t  mv = *(const int16_t  *)pMem;  if (mv == 0) return false;
                  return (uint64_t)(int64_t)mv <= (uint64_t)(int64_t)*(const int16_t *)pScan; }
        case 4: { uint32_t mv = *(const uint32_t *)pMem;  if (mv == 0) return false; return mv <= *(const uint32_t *)pScan; }
        case 5: { int32_t  mv = *(const int32_t  *)pMem;  if (mv == 0) return false;
                  return (uint64_t)(int64_t)mv <= (uint64_t)(int64_t)*(const int32_t *)pScan; }
        case 6: { uint64_t mv = *(const uint64_t *)pMem;  if (mv == 0) return false; return mv <= *(const uint64_t *)pScan; }
        case 7: { int64_t  mv = *(const int64_t  *)pMem;  if (mv == 0) return false;
                  return (uint64_t)mv <= (uint64_t)*(const int64_t *)pScan; }
        case 8: { float  mv = *(const float  *)pMem; if (mv == 0.0f) return false;
                  float abs_mv = mv < 0.0f ? -mv : mv;
                  return (double)abs_mv <= (double)*(const float *)pScan; }
        case 9: { double mv = *(const double *)pMem; if (mv == 0.0)  return false;
                  double abs_mv = mv < 0.0 ? -mv : mv;
                  return abs_mv <= *(const double *)pScan; }
        default: return false;
        }
    }
    default:
        return false;
    }
}

#undef _BETWEEN_ASYNC
#undef _PER_VALTYPE_BIN
#undef _PER_VALTYPE_BY

const uint8_t g_cmptype_needs_value   [16] = {1,1,1,1,1,0,1,0,1,0,0,0,1,0,0,0};
const uint8_t g_cmptype_needs_extra   [16] = {0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0};
const uint8_t g_cmptype_needs_previous[16] = {0,0,0,0,0,1,1,1,1,1,1,0,0,0,0,0};
