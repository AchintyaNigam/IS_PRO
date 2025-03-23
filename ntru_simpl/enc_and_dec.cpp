#include <random>
#include "polynomial.h"
// Simplified encryption
Polynomial encrypt(const Polynomial& message, const Polynomial& h, int degree) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(-1, 1);

    Polynomial r(degree);
    for (int i = 0; i <= degree; i++) {
        r.coefficients[i] = dis(gen);
    }

    Polynomial ciphertext = r * h + message;
    return ciphertext;
}

// Simplified decryption logic
Polynomial decrypt(const Polynomial& ciphertext, const Polynomial& f, const Polynomial& g, int degree, int p, int q) {
    // Compute a = f * e (mod q)
    Polynomial a = f * ciphertext;

    // Adjust coefficients of a to be within [-q/2, q/2]
    for (int i = 0; i <= degree; i++) {
        a.coefficients[i] = (a.coefficients[i] % q + q) % q;
        if (a.coefficients[i] > q / 2) {
            a.coefficients[i] -= q;
        }
    }

    // Compute b = a (mod p)
    Polynomial b(degree);
    for (int i = 0; i <= degree; i++) {
        b.coefficients[i] = a.coefficients[i] % p;
    }

    // The message m is b (mod p)
    return b;
}

