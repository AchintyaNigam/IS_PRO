#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define AES_KEY_LEN 32
#define NONCE_LEN 12
#define TAG_LEN 16
#define RATCHET_STEP_SIZE 32
    
#define ntru_hps2048509_length_public_key 699
#define ntru_hps2048509_length_secret_key 935
#define ntru_hps2048509_length_ciphertext 699

// Key state structure for the ratchet mechanism
typedef struct {
    uint8_t current_key[AES_KEY_LEN];
    uint32_t message_count;
    uint8_t chain_key[AES_KEY_LEN];
} ratchet_state;

// Initialize global ratchet state
ratchet_state sender_ratchet;
ratchet_state receiver_ratchet;

int hex2bin(const char *hex, uint8_t *bin, size_t bin_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != bin_len * 2) return 0;
    
    for (size_t i = 0; i < bin_len; i++) {
        if (sscanf(hex + 2*i, "%2hhx", &bin[i]) != 1) return 0;
    }
    return 1;
}

// Initialize the ratchet with the initial shared secret
void init_ratchet(ratchet_state *state, const uint8_t *shared_secret) {
    memcpy(state->current_key, shared_secret, AES_KEY_LEN);
    state->message_count = 0;
    
    // Initialize chain key by hashing the shared secret
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, shared_secret, AES_KEY_LEN);
    SHA256_Update(&sha256, "chain_key_init", 14); // Domain separation
    SHA256_Final(state->chain_key, &sha256);
}

// Advance the ratchet to generate a new encryption key
void advance_ratchet(ratchet_state *state) {
    // Update message count
    state->message_count++;
    
    // Generate new chain key by hashing the current one
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, state->chain_key, AES_KEY_LEN);
    SHA256_Update(&sha256, "next_chain_key", 14); // Domain separation
    SHA256_Final(state->chain_key, &sha256);
    
    // Generate new message key from the chain key
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, state->chain_key, AES_KEY_LEN);
    SHA256_Update(&sha256, "message_key", 11); // Domain separation
    SHA256_Final(state->current_key, &sha256);
}

int aes_encrypt(const uint8_t *key, const uint8_t *plaintext, size_t pt_len,
                uint8_t *ciphertext, uint8_t *nonce, uint8_t *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ret = 0;

    if (!RAND_bytes(nonce, NONCE_LEN)) {
        fprintf(stderr, "Nonce generation failed\n");
        goto err;
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce)) goto err;
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, pt_len)) goto err;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) goto err;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag)) goto err;

    ret = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int aes_decrypt(const uint8_t *key, const uint8_t *ciphertext, size_t ct_len,
                const uint8_t *nonce, const uint8_t *tag, uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ret = 0;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce)) goto err;
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ct_len)) goto err;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag)) goto err;
    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) goto err;

    ret = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

// Forward secrecy encryption function that updates ratchet after use
int fs_encrypt(const uint8_t *plaintext, size_t pt_len, uint8_t *ciphertext, 
               uint8_t *nonce, uint8_t *tag, uint32_t *msg_counter) {
    // First, encrypt with current key
    int result = aes_encrypt(sender_ratchet.current_key, plaintext, pt_len, ciphertext, nonce, tag);
    
    // Store current message count in output parameter
    *msg_counter = sender_ratchet.message_count;
    
    // Advance the ratchet after encryption (forward secrecy)
    if (result) {
        advance_ratchet(&sender_ratchet);
    }
    
    return result;
}

// Forward secrecy decryption function that updates ratchet to match sender
int fs_decrypt(const uint8_t *ciphertext, size_t ct_len, const uint8_t *nonce, 
               const uint8_t *tag, uint8_t *plaintext, uint32_t msg_counter) {
    // If received message counter is ahead of our counter, advance ratchet
    while (receiver_ratchet.message_count < msg_counter) {
        advance_ratchet(&receiver_ratchet);
    }
    
    // Decrypt using current key
    return aes_decrypt(receiver_ratchet.current_key, ciphertext, ct_len, nonce, tag, plaintext);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "r");
    if (!f) {
        perror("Failed to open input file");
        return 1;
    }

    uint8_t pk[ntru_hps2048509_length_public_key];
    uint8_t sk[ntru_hps2048509_length_secret_key];
    uint8_t ct[ntru_hps2048509_length_ciphertext];
    uint8_t ss_encap[AES_KEY_LEN];
    
    char line[4096];
    int fields_set = 0;

    while (fields_set < 4 && fgets(line, sizeof(line), f)) {
        char *key = strtok(line, "=");
        char *value = strtok(NULL, "\n");
        if (!key || !value) continue;

        if (strcmp(key, "pk") == 0) {
            if (!hex2bin(value, pk, sizeof(pk))) {
                fprintf(stderr, "Invalid public key\n");
                fclose(f);
                return 1;
            }
            fields_set++;
        } else if (strcmp(key, "sk") == 0) {
            if (!hex2bin(value, sk, sizeof(sk))) {
                fprintf(stderr, "Invalid secret key\n");
                fclose(f);
                return 1;
            }
            fields_set++;
        } else if (strcmp(key, "ct") == 0) {
            if (!hex2bin(value, ct, sizeof(ct))) {
                fprintf(stderr, "Invalid ciphertext\n");
                fclose(f);
                return 1;
            }
            fields_set++;
        } else if (strcmp(key, "ss") == 0) {
            if (!hex2bin(value, ss_encap, sizeof(ss_encap))) {
                fprintf(stderr, "Invalid shared secret\n");
                fclose(f);
                return 1;
            }
            fields_set++;
        }
    }
    fclose(f);

    // Initialize ratchet states with the NTRU shared secret
    init_ratchet(&sender_ratchet, ss_encap);
    init_ratchet(&receiver_ratchet, ss_encap);

    // Demonstrate forward secrecy with multiple messages
    const char *messages[] = {
        "Message 1: Siva Shanmugam is good teacher",
        "Message 2: Post-quantum cryptography is important",
        "Message 3: Forward secrecy protects previous communications"
    };
    const int num_messages = 3;
    
    printf("\n=== Post-Quantum Forward Secrecy Demo ===\n");
    
    for (int i = 0; i < num_messages; i++) {
        size_t pt_len = strlen(messages[i]);
        uint8_t ciphertext[pt_len], decrypted[pt_len + 1];
        uint8_t nonce[NONCE_LEN], tag[TAG_LEN];
        uint32_t msg_counter;
        
        decrypted[pt_len] = '\0'; // Null-terminate decrypted message

        printf("\n--- Message %d ---\n", i+1);
        
        // Encrypt with forward secrecy
        if (!fs_encrypt((uint8_t *)messages[i], pt_len, ciphertext, nonce, tag, &msg_counter)) {
            fprintf(stderr, "Encryption failed\n");
            return 1;
        }

        printf("Original: %s\n", messages[i]);
        printf("Encrypted (hex): ");
        for (size_t j = 0; j < pt_len; j++) {
            printf("%02X", ciphertext[j]);
        }
        printf("\nMessage counter: %u\n", msg_counter);
        
        // Decrypt with forward secrecy
        if (!fs_decrypt(ciphertext, pt_len, nonce, tag, decrypted, msg_counter)) {
            fprintf(stderr, "Decryption failed\n");
            return 1;
        }

        printf("Decrypted: %s\n", decrypted);
        
        // Show current key state (normally this would be secret)
        printf("Sender key state (hex): ");
        for (size_t j = 0; j < AES_KEY_LEN; j++) {
            printf("%02X", sender_ratchet.current_key[j]);
        }
        printf("\n");
    }
    
    printf("\n=== Key Compromise Simulation ===\n");
    printf("If an attacker compromises the current key, they still cannot decrypt previous messages\n");
    printf("Current sender key (hex): ");
    for (size_t i = 0; i < AES_KEY_LEN; i++) {
        printf("%02X", sender_ratchet.current_key[i]);
    }
    printf("\n");
    
    return 0;
}