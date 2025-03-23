#ifndef POLYNOMIAL_H
#define POLYNOMIAL_H

#include <iostream>
#include <vector>

class Polynomial
{
public:
    std::vector<int> coefficients;
    int degree;

    Polynomial(int degree) : degree(degree)
    {
        coefficients.resize(degree + 1, 0);
    }

    // Simple addition modulo q
    Polynomial operator+(const Polynomial &other) const
    {
        Polynomial result(degree);
        for (int i = 0; i <= degree; i++)
        {
            result.coefficients[i] = (coefficients[i] + other.coefficients[i]) % 2048; // Example modulus
        }
        return result;
    }

    // Simple multiplication modulo q
    Polynomial operator*(const Polynomial &other) const
    {
        Polynomial result(degree);
        for (int i = 0; i <= degree; i++)
        {
            for (int j = 0; j <= degree; j++)
            {
                if (i + j <= degree)
                {
                    result.coefficients[i + j] += coefficients[i] * other.coefficients[j];
                }
            }
        }
        for (int i = 0; i <= degree; i++)
        {
            result.coefficients[i] %= 2048; // Example modulus
        }
        return result;
    }

    // Define the - operator for Polynomial class
    Polynomial operator-(const Polynomial &other) const
    {
        Polynomial result(degree);
        for (int i = 0; i <= degree; i++)
        {
            result.coefficients[i] = coefficients[i] - other.coefficients[i];
        }
        return result;
    }

    void print() const
    {
        for (int i = degree; i >= 0; i--)
        {
            if (coefficients[i] != 0)
            {
                std::cout << coefficients[i] << "x^" << i << " + ";
            }
        }
        std::cout << "\n";
    }
};

#endif // POLYNOMIAL_H
