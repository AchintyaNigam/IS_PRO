#include "params.h"

// Define static parameter set
const NTRUParams NTRUParams::EES443EP1 = {
    .N = 443, .p = 3, .q = 2048,
    .df = 61, .dg = 20, .dr = 30
};
