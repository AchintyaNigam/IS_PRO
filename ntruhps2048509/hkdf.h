#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"
#include "cmov.h"
#include "crypto_hash_sha3256.h"
#include "kem.h"
#include "owcpa.h"
#include "params.h"
#include "rng.h"
#include "sample.h"

// Simple XOR-based encryption using the derived key
void xor_encrypt_decrypt(unsigned char *output, const unsigned char *input, 
                         size_t input_len, const unsigned char *key, size_t key_len) {
    for (size_t i = 0; i < input_len; i++) {
        output[i] = input[i] ^ key[i % key_len];
    }
}

void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int save_to_file(const char *filename, const unsigned char *data, size_t len) {
    FILE *f = fopen(filename, "wb");
    if (!f) {
        perror("Failed to open file for writing");
        return -1;
    }
    
    size_t written = fwrite(data, 1, len, f);
    fclose(f);
    
    if (written != len) {
        fprintf(stderr, "Failed to write all data to file\n");
        return -1;
    }
    
    return 0;
}

unsigned char *read_from_file(const char *filename, size_t *len) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        perror("Failed to open file for reading");
        return NULL;
    }
    
    // Get file size
    fseek(f, 0, SEEK_END);
    *len = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *data = (unsigned char*)malloc(*len);
    if (!data) {
        fclose(f);
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    
    size_t read_bytes = fread(data, 1, *len, f);
    fclose(f);
    
    if (read_bytes != *len) {
        free(data);
        fprintf(stderr, "Failed to read all data from file\n");
        return NULL;
    }
    
    return data;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage:\n");
        printf("  %s generate - Generate and save key pair\n", argv[0]);
        printf("  %s encrypt <input_file> <output_file> - Encrypt a file\n", argv[0]);
        printf("  %s decrypt <input_file> <output_file> - Decrypt a file\n", argv[0]);
        return 1;
    }

    // Generate key pair
    if (strcmp(argv[1], "generate") == 0) {
        unsigned char pk[NTRU_PUBLICKEYBYTES];
        unsigned char sk[NTRU_SECRETKEYBYTES];
        
        printf("Generating NTRU key pair...\n");
        crypto_kem_keypair(pk, sk);
        
        printf("Saving public key to 'public_key.bin'...\n");
        save_to_file("public_key.bin", pk, NTRU_PUBLICKEYBYTES);
        
        printf("Saving private key to 'private_key.bin'...\n");
        save_to_file("private_key.bin", sk, NTRU_SECRETKEYBYTES);
        
        printf("Key generation complete.\n");
        return 0;
    }
    
    // Encrypt file
    else if (strcmp(argv[1], "encrypt") == 0) {
        if (argc < 4) {
            printf("Error: Missing input or output file\n");
            return 1;
        }
        
        const char *input_file = argv[2];
        const char *output_file = argv[3];
        
        // Read public key
        size_t pk_len;
        unsigned char *pk = read_from_file("public_key.bin", &pk_len);
        if (!pk || pk_len != NTRU_PUBLICKEYBYTES) {
            fprintf(stderr, "Failed to read public key\n");
            free(pk);
            return 1;
        }
        
        // Read input file
        size_t input_len;
        unsigned char *input_data = read_from_file(input_file, &input_len);
        if (!input_data) {
            free(pk);
            return 1;
        }
        
        // Encapsulate key
        unsigned char ciphertext[NTRU_CIPHERTEXTBYTES];
        unsigned char shared_key[NTRU_SHAREDKEYBYTES];
        
        crypto_kem_enc(ciphertext, shared_key, pk);
        
        // Encrypt data with shared key
        unsigned char *encrypted_data = (unsigned char*)malloc(input_len);
        if (!encrypted_data) {
            fprintf(stderr, "Memory allocation failed\n");
            free(pk);
            free(input_data);
            return 1;
        }
        
        xor_encrypt_decrypt(encrypted_data, input_data, input_len, shared_key, NTRU_SHAREDKEYBYTES);
        
        // Create output buffer: [ciphertext][data_length][encrypted_data]
        size_t output_len = NTRU_CIPHERTEXTBYTES + sizeof(size_t) + input_len;
        unsigned char *output_data = (unsigned char*)malloc(output_len);
        if (!output_data) {
            fprintf(stderr, "Memory allocation failed\n");
            free(pk);
            free(input_data);
            free(encrypted_data);
            return 1;
        }
        
        // Copy ciphertext
        memcpy(output_data, ciphertext, NTRU_CIPHERTEXTBYTES);
        
        // Copy data length
        memcpy(output_data + NTRU_CIPHERTEXTBYTES, &input_len, sizeof(size_t));
        
        // Copy encrypted data
        memcpy(output_data + NTRU_CIPHERTEXTBYTES + sizeof(size_t), encrypted_data, input_len);
        
        // Save to output file
        save_to_file(output_file, output_data, output_len);
        
        printf("File encrypted successfully.\n");
        
        free(pk);
        free(input_data);
        free(encrypted_data);
        free(output_data);
        return 0;
    }
    
    // Decrypt file
    else if (strcmp(argv[1], "decrypt") == 0) {
        if (argc < 4) {
            printf("Error: Missing input or output file\n");
            return 1;
        }
        
        const char *input_file = argv[2];
        const char *output_file = argv[3];
        
        // Read private key
        size_t sk_len;
        unsigned char *sk = read_from_file("private_key.bin", &sk_len);
        if (!sk || sk_len != NTRU_SECRETKEYBYTES) {
            fprintf(stderr, "Failed to read private key\n");
            free(sk);
            return 1;
        }
        
        // Read encrypted file
        size_t encrypted_len;
        unsigned char *encrypted_data = read_from_file(input_file, &encrypted_len);
        if (!encrypted_data) {
            free(sk);
            return 1;
        }
        
        // Check if the file is large enough to contain the ciphertext and data length
        if (encrypted_len < NTRU_CIPHERTEXTBYTES + sizeof(size_t)) {
            fprintf(stderr, "Invalid encrypted file format\n");
            free(sk);
            free(encrypted_data);
            return 1;
        }
        
        // Extract ciphertext
        unsigned char ciphertext[NTRU_CIPHERTEXTBYTES];
        memcpy(ciphertext, encrypted_data, NTRU_CIPHERTEXTBYTES);
        
        // Extract original data length
        size_t original_len;
        memcpy(&original_len, encrypted_data + NTRU_CIPHERTEXTBYTES, sizeof(size_t));
        
        // Check if the file contains all the expected data
        if (encrypted_len != NTRU_CIPHERTEXTBYTES + sizeof(size_t) + original_len) {
            fprintf(stderr, "Invalid encrypted file format\n");
            free(sk);
            free(encrypted_data);
            return 1;
        }
        
        // Decrypt the key
        unsigned char shared_key[NTRU_SHAREDKEYBYTES];
        crypto_kem_dec(shared_key, ciphertext, sk);
        
        // Extract encrypted data
        unsigned char *encrypted_content = encrypted_data + NTRU_CIPHERTEXTBYTES + sizeof(size_t);
        
        // Decrypt the data
        unsigned char *decrypted_data = (unsigned char*)malloc(original_len);
        if (!decrypted_data) {
            fprintf(stderr, "Memory allocation failed\n");
            free(sk);
            free(encrypted_data);
            return 1;
        }
        
        xor_encrypt_decrypt(decrypted_data, encrypted_content, original_len, shared_key, NTRU_SHAREDKEYBYTES);
        
        // Save decrypted data
        save_to_file(output_file, decrypted_data, original_len);
        
        printf("File decrypted successfully.\n");
        
        free(sk);
        free(encrypted_data);
        free(decrypted_data);
        return 0;
    }
    
    else {
        printf("Unknown command: %s\n", argv[1]);
        return 1;
    }
}
