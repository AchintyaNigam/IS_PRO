#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define AES_KEY_LEN 32
#define NONCE_LEN 12
#define TAG_LEN 16

#define ntru_hps2048509_length_public_key 699
#define ntru_hps2048509_length_secret_key 935
#define ntru_hps2048509_length_ciphertext 699

int hex2bin(const char *hex, uint8_t *bin, size_t bin_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != bin_len * 2) return 0;
    
    for (size_t i = 0; i < bin_len; i++) {
        if (sscanf(hex + 2*i, "%2hhx", &bin[i]) != 1) return 0;
    }
    return 1;
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

    const char *plaintext = "Siva Shanmugam is good teacher";
    size_t pt_len = strlen(plaintext);
    uint8_t ciphertext[pt_len], decrypted[pt_len + 1];
    uint8_t nonce[NONCE_LEN], tag[TAG_LEN];
    
    decrypted[pt_len] = '\0'; // Null-terminate decrypted message

    if (!aes_encrypt(ss_encap, (uint8_t *)plaintext, pt_len, ciphertext, nonce, tag)) {
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }

    if (!aes_decrypt(ss_encap, ciphertext, pt_len, nonce, tag, decrypted)) {
        fprintf(stderr, "Decryption failed\n");
        return 1;
    }

    printf("\nPlaintext: %s\n", plaintext);
    printf("Ciphertext (hex): ");
    for (size_t i = 0; i < pt_len; i++) {
        printf("%02X", ciphertext[i]);
    }
    printf("\nDecrypted: %s\n", decrypted);

    return 0;
}
