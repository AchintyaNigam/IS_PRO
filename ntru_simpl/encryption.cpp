#include "encryption.h"
#include "polynomial.h"
#include "params.h"

Polynomial encrypt(const Polynomial& message, 
                  const Polynomial& public_key,
                  const NTRUParams& params) {
    // Generate random blinding polynomial
    Polynomial r = Polynomial::generate_sparse(params.N, params.dr);
    
    // Encrypt: e = r * h + m mod q
    Polynomial e = (r * public_key).mod(params.q);
    e = (e + message).mod(params.q);
    
    return e;
}
