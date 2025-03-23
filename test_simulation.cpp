#include <iostream>
#include "./ntru_simpl/polynomial.h"
#include "./ntru_simpl/enc_and_dec.cpp"
#include "./ntru_simpl/key_gen.cpp"

int main() {
    int degree = 10; // Example degree
    int p = 3;       // Small modulus
    int q = 2048;    // Large modulus

    Polynomial f(degree), g(degree), h(degree), message(degree), ciphertext(degree);

    // Generate keys using the actual key generation function
    generateKeys(f, g, h, degree);

    // Set a simple message
    message.coefficients[0] = 1;

    // Encrypt using the actual encrypt function
    ciphertext = encrypt(message, h, degree);

    // Decrypt
    Polynomial decrypted = decrypt(ciphertext, f, g, degree, p, q);

    std::cout << "Decrypted message:\n";
    decrypted.print();

    return 0;
}
