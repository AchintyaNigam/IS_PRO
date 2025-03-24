#include "decryption.h"
#include "polynomial.h"
#include "params.h"
#include "keypair.h"

Polynomial decrypt(const Polynomial& ciphertext,
                  const KeyPair& keys,
                  const NTRUParams& params) {
    // Compute a = f * e mod q
    Polynomial a = (keys.f * ciphertext).mod(params.q);
    
    // Center lift coefficients
    a = a.center_lift(params.q);
    
    // Recover message: m = a * fp_inv mod p
    return (a * keys.fp_inv).mod(params.p);
}
