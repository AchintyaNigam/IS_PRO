#include "polynomial.h"
#include "params.h"
#include "keyGen.h"
#include "encryption.h"
#include "decryption.h"
#include <iostream>
#include <vector>
#include <cassert>

// Helper function to convert string to polynomial
Polynomial string_to_poly(const std::string& msg, const NTRUParams& params) {
    std::vector<int16_t> coeffs(params.N, 0);
    size_t bit_pos = 0;
    
    for(char c : msg) {
        for(int i=0; i<8; ++i) {  // Process each bit
            if(bit_pos >= params.N) break;
            coeffs[bit_pos++] = (c >> (7-i)) & 0x1;
        }
    }
    return Polynomial(params.N, 2).mod(2);  // Ensure mod 2
}

// Helper to convert polynomial to string
std::string poly_to_string(const Polynomial& poly) {
    std::string result;
    uint8_t current_byte = 0;
    int bit_count = 0;
    
    for(auto coeff : poly.coefficients()) {
        current_byte = (current_byte << 1) | (coeff & 0x1);
        if(++bit_count == 8) {
            result += static_cast<char>(current_byte);
            current_byte = 0;
            bit_count = 0;
        }
    }
    
    // Handle remaining bits
    if(bit_count > 0) {
        current_byte <<= (8 - bit_count);
        result += static_cast<char>(current_byte);
    }
    return result;
}

int main() {
    // Use recommended post-quantum parameters
    const auto params = NTRUParams::EES443EP1;
    
    // Generate keys
    KeyPair keys = generate_keys(params);
    
    // Test message (must fit in N bits)
    const std::string original = "NTRU Test Message!";
    std::cout << "Original: " << original << "\n";
    
    // Convert to polynomial (mod 2)
    Polynomial message = string_to_poly(original, params);
    
    // Encrypt
    Polynomial ciphertext = encrypt(message, keys.h, params);
    
    // Decrypt
    Polynomial decrypted = decrypt(ciphertext, keys, params);
    std::string recovered = poly_to_string(decrypted);
    
    // Verification
    std::cout << "Recovered: " << recovered << "\n";
    
    // Sanity checks
    assert(message.coefficients().size() == params.N);
    assert(ciphertext.coefficients().size() == params.N);
    assert(original == recovered && "Decryption failed!");
    assert(message.coefficients() != ciphertext.coefficients() && "No encryption happened!");

    std::cout << "\nAll tests passed!\n";
    return 0;
}
