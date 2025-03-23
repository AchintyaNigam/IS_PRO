#include <random>
#include "polynomial.h"

// Simplified polynomial inversion using Extended Euclidean Algorithm
Polynomial inverse(const Polynomial& f, int q) {
    int degree = f.degree;
    Polynomial a = f, b = Polynomial(degree + 1); // b(x) = x^degree
    for (int i = 0; i <= degree; i++) {
        b.coefficients[i] = (i == degree) ? 1 : 0;
    }

    Polynomial x(0), y(0), u(1), v(0);

    while (b.coefficients[degree] != 0) {
        int quotient = a.coefficients[degree] / b.coefficients[degree];
        Polynomial temp = b;
        b = a - b * quotient;
        a = temp;

        Polynomial temp2 = x;
        x = y;
        y = temp2 - y * quotient;
    }

    // Normalize coefficients modulo q
    for (int i = 0; i <= degree; i++) {
        x.coefficients[i] = (x.coefficients[i] % q + q) % q;
    }

    return x;
}

// Compute h = f^{-1} * g (mod q)
Polynomial computeH(const Polynomial& f, const Polynomial& g, int q) {
    Polynomial fInv = inverse(f, q);
    Polynomial h = fInv * g;
    // Normalize coefficients of h modulo q
    for (int i = 0; i <= h.degree; i++) {
        h.coefficients[i] = (h.coefficients[i] % q + q) % q;
    }
    return h;
}

void generateKeys(Polynomial& f, Polynomial& g, Polynomial& h, int degree) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(-1, 1);

    f = Polynomial(degree);
    g = Polynomial(degree);
    h = Polynomial(degree);

    // Generate small coefficients for f and g
    for (int i = 0; i <= degree; i++) {
        f.coefficients[i] = dis(gen);
        g.coefficients[i] = dis(gen);
    }

    // Compute h = f^{-1} * g mod q
    h = computeH(f, g, 2048); // Example modulus
}

