#pragma once
#include "polynomial.h"

struct KeyPair {
    Polynomial f;     // Private key polynomial
    Polynomial fp_inv; // Inverse of f mod p
    Polynomial h;      // Public key polynomial
};
