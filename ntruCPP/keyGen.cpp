#include "keyGen.h"
#include "keypair.h"
#include "polynomial.h"
#include "params.h"

#include <iostream>
#include <stdexcept>

#include <chrono>
#include <random>

KeyPair generate_keys(const NTRUParams& params) {
    constexpr int MAX_ATTEMPTS = 1000;  // Safety limit
    int attempts = 0;
    
    // Use better RNG
    std::random_device rd;
    std::mt19937_64 gen(rd());

    std::cout << "Generating keys for " << params.N << "-bit NTRU...\n";
    while(attempts++ < MAX_ATTEMPTS) {
        try {
            // Generate f = 1 + p*F (guarantees inverse mod p)
            std::cout << "Attempt #" << attempts << "\n";
            std::cout << "Generating f...\n";
            Polynomial F = Polynomial::generate_sparse(params.N, params.df/2);
            Polynomial f = (F * params.p) + Polynomial(1, params.N);
            
            std::cout << "Generating g...\n";
            // Generate g with exactly dg non-zero coefficients
            Polynomial g = Polynomial::generate_sparse(params.N, params.dg);
            
            std::cout << "Generating h...\n";
            // Compute inverses (will throw if unavailable)
            Polynomial fq_inv = f.inverse_mod_q(params.q);
            
            // Calculate public key h = p * fq_inv * g mod q
            Polynomial h = (fq_inv * g).mod(params.q);
            h = (h * params.p).mod(params.q);
            
            return {f, Polynomial(1, params.N), h};  // fp_inv = 1 (mod p)
        }
        catch(...) {} // Ignore inversion failures
    }
    
    throw std::runtime_error("Key generation failed after " + 
                            std::to_string(MAX_ATTEMPTS) + " attempts");
}


