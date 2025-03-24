#pragma once
#include <cstdint>

struct NTRUParams {
    uint16_t N;  // Must be prime (e.g., 443, 761)
    uint16_t p = 3;  // Prime (changed from 2)
    uint16_t q;  // Must satisfy q ≥ 32*max_coeff + 1
    uint16_t df, dg, dr;

    // Recommended parameters from NTRU Prime
    static const NTRUParams EES443EP1;
};
