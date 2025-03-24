#include "polynomial.h"
#include <algorithm>
#include <numeric> // For gcd
#include <cassert>
#include <stdexcept>
#include <random>

// Constructor implementation
Polynomial::Polynomial(uint16_t size, int mod) 
    : N(size), coeffs(size) {
    if(mod != 0) {
        for(auto& c : coeffs) {
            c = rand() % mod;
        }
    }
}

Polynomial::Polynomial(uint16_t scalar, uint16_t size) : N(size) {
    coeffs = std::vector<int16_t>(N, 0);
    coeffs[0] = scalar;
}

Polynomial Polynomial::inverse_mod_prime(uint16_t p) const {
    const uint16_t N = this->N;
    
    // Create modulus polynomial x^N - 1 represented with N coefficients
    Polynomial mod_poly(N, 0);
    mod_poly.coeffs[0] = (-1 % p + p) % p;  // x^0 term: -1
    mod_poly.coeffs[0] = (mod_poly.coeffs[0] + 1) % p;  // x^N term (implicit via ring structure)

    Polynomial a = *this;
    Polynomial b = mod_poly;
    
    // Initialize Bezout coefficients
    Polynomial s0(Polynomial::constant(1, p, N));
    Polynomial s1(Polynomial::constant(0, p, N));

    while (!b.is_zero()) {
        // Polynomial division in Z_p[x]
        auto [quotient, remainder] = a.divide(b, p);
        
        // Update coefficients
        Polynomial temp = b;
        b = remainder;
        a = temp;

        temp = s1;
        s1 = s0 - quotient * s1;
        s0 = temp;
    }

    // Check if gcd is constant
    if (a.degree() != 0)
        throw std::runtime_error("No modular inverse exists");

    // Find inverse of constant term
    int16_t inv = 1;
    while ((a.coeffs[0] * inv) % p != 1) ++inv;

    // Final adjustment
    Polynomial inverse = (s0 * inv).mod(p).trim();
    
    // Reduce to degree < N
    Polynomial result(N, 0);
    for (size_t i=0; i<inverse.coeffs.size(); ++i) {
        result.coeffs[i % N] = (result.coeffs[i % N] + inverse.coeffs[i]) % p;
    }
    
    return result.mod(p);
}



Polynomial Polynomial::inverse_mod_q(uint16_t q) const {
    // Newton iteration method
    Polynomial f = *this;
    Polynomial g(1, 0); // Initial guess
    for(int i=0; i<10; ++i) { // Iterate until convergence
        g = (g * (2 - f*g)).mod(q);
    }
    return g;
}

// Sparse polynomial generation
Polynomial Polynomial::generate_sparse(uint16_t N, uint16_t df) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, N-1);
    
    Polynomial p(N);
    int count = 0;
    
    while(count < df) {
        int pos = dist(gen);
        if(p.coeffs[pos] == 0) {
            p.coeffs[pos] = 1;
            count++;
        }
    }
    return p;
}


// Modular reduction
Polynomial Polynomial::mod(uint16_t q) const {
    Polynomial result(*this);
    for(auto& c : result.coeffs) {
        c = (c % q + q) % q;
    }
    return result;
}

// Center lift
Polynomial Polynomial::center_lift(uint16_t q) const {
    Polynomial result(*this);
    for(auto& c : result.coeffs) {
        c = (c > q/2) ? c - q : c;
    }
    return result;
}

// Multiplication operator
Polynomial Polynomial::operator*(const Polynomial& other) const {
    // assert(N == other.N);
    Polynomial result(N);
    for(uint16_t i=0; i<N; ++i) {
        for(uint16_t j=0; j<N; ++j) {
            uint16_t k = (i + j) % N; // Cyclic convolution
            result.coeffs[k] += coeffs[i] * other.coeffs[j];
        }
    }
    return result;
}


// Division operator
std::pair<Polynomial, Polynomial> Polynomial::divide(const Polynomial& divisor, uint16_t p) const {
    Polynomial dividend = *this;
    Polynomial quotient(dividend.N, 0);
    
    while (dividend.degree() >= divisor.degree()) {
        int16_t lead_coeff = dividend.leading_coeff() * mod_inverse(divisor.leading_coeff(), p);
        int degree_diff = dividend.degree() - divisor.degree();
        
        Polynomial term(degree_diff + 1, 0);
        term.coeffs[degree_diff] = lead_coeff;
        
        quotient = quotient + term;
        dividend = dividend - term * divisor;
        dividend = dividend.mod(p);
    }
    
    return {quotient, dividend};
}

// Addition operator
Polynomial Polynomial::operator+(const Polynomial& other) const {
    Polynomial result(*this);
    for(uint16_t i=0; i<N; ++i) {
        result.coeffs[i] += other.coeffs[i];
    }
    return result;
}

// Subtraction operator
Polynomial Polynomial::operator-(const Polynomial& other) const {
    assert(N == other.N && "Polynomial degree mismatch");
    Polynomial result(N);
    for(uint16_t i=0; i<N; ++i) {
        result.coeffs[i] = coeffs[i] - other.coeffs[i];
    }
    return result;
}

// Non-member operator for integer - Polynomial
Polynomial operator-(int scalar, const Polynomial& rhs) {
    Polynomial lhs(scalar, rhs.N);  // Use rhs.N for size
    return lhs - rhs;
}

// Find modular inverse using Fermat's little theorem
int16_t Polynomial::mod_inverse(int16_t a, uint16_t p) const {
    a = (a % p + p) % p;
    int16_t result = 1;
    for (int exp = p-2; exp > 0; exp >>= 1) {
        if (exp & 1) result = (result * a) % p;
        a = (a * a) % p;
    }
    return result;
}

// Check if polynomial is zero
bool Polynomial::is_zero() const {
    return std::all_of(coeffs.begin(), coeffs.end(), 
                      [](int16_t c) { return c == 0; });
}

// Get polynomial degree
int Polynomial::degree() const {
    for (int i = coeffs.size()-1; i >= 0; --i)
        if (coeffs[i] != 0) return i;
    return -1;
}

// Create constant polynomial
Polynomial Polynomial::constant(int16_t val, uint16_t p, uint16_t N) {
    Polynomial poly(N, 0);
    poly.coeffs[0] = val % p;
    return poly;
}

// Trim implementation (remove trailing zeros beyond fixed degree N)
Polynomial& Polynomial::trim() {
    coeffs.resize(N, 0);  // Force resize to fixed degree N
    return *this;
}

// Leading coefficient implementation
int16_t Polynomial::leading_coeff() const {
    for(int i = N-1; i >= 0; --i) {
        if(coeffs[i] != 0) {
            return coeffs[i];
        }
    }
    return 0;  // Zero polynomial
}

