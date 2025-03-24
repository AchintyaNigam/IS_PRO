#pragma once
#include <vector>
#include <cstdint>
#include <utility>  // For std::pair
#include <algorithm> // For std::all_of

class Polynomial {
private:
    std::vector<int16_t> coeffs;
    uint16_t N;  // Polynomial degree
    
public:
    // Constructors
    Polynomial(uint16_t size, int mod = 0);
    Polynomial(uint16_t scalar, uint16_t size);
    
    // Arithmetic operations
    Polynomial operator+(const Polynomial& other) const;
    Polynomial operator-(const Polynomial& other) const;
    Polynomial operator*(const Polynomial& other) const;
    Polynomial operator-() const;
    
    // Modular arithmetic
    Polynomial mod(uint16_t q) const;
    Polynomial center_lift(uint16_t q) const;
    
    // Inverse operations
    Polynomial inverse_mod_prime(uint16_t p) const;
    Polynomial inverse_mod_q(uint16_t q) const;
    
    // Key generation helpers
    static Polynomial generate_sparse(uint16_t N, uint16_t df);
    static Polynomial constant(int16_t val, uint16_t p, uint16_t N);
    
    // Polynomial utilities
    bool is_zero() const;
    int degree() const;
    std::pair<Polynomial, Polynomial> divide(const Polynomial& divisor, uint16_t p) const;
    int16_t mod_inverse(int16_t a, uint16_t p) const;
    
    // Accessors
    const std::vector<int16_t>& coefficients() const { return coeffs; }
    uint16_t size() const { return N; }
    int16_t leading_coeff() const;
    
    // Friend operators for scalar operations
    friend Polynomial operator+(int scalar, const Polynomial& rhs);
    friend Polynomial operator-(int scalar, const Polynomial& rhs);
    friend Polynomial operator*(int scalar, const Polynomial& rhs);

    // Trim leading zeros
    Polynomial& trim();
};

