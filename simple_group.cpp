#include <iostream>
#include <vector>
#include <string>
#include <map>

// Include NTRU headers
#include "./libntru/src/ntru.h"

class SimpleGroup {
public:
    SimpleGroup() {
        members = {"Alice", "Bob", "Charlie"};
        
        // Generate NTRU keys for each member
        for(auto& member : members) {
            NtruEncKeyPair kp;
            NtruEncParams params = NTRU_DEFAULT_PARAMS_128_BITS;
            NtruRandContext rand_ctx;
            NtruRandGen rng_def = NTRU_RNG_DEFAULT;
            
            if (ntru_rand_init(&rand_ctx, &rng_def) != NTRU_SUCCESS) {
                std::cerr << "Failed to initialize RNG.\n";
                return;
            }
            
            if (ntru_gen_key_pair(&params, &kp, &rand_ctx) != NTRU_SUCCESS) {
                std::cerr << "Failed to generate key pair.\n";
                return;
            }
            
            ntru_keys[member] = kp;
        }
    }

    void sendMessage(const std::string& sender, const std::string& message) {
        // Combined MLS+NTRU encryption
        std::vector<uint8_t> ciphertext = encryptMessage(sender, message);
        
        // Broadcast to group
        for(auto& member : members) {
            if(member != sender) {
                std::string decrypted = decryptMessage(member, ciphertext);
                std::cout << member << " received: " << decrypted << "\n";
            }
        }
    }

private:
    std::vector<std::string> members;
    std::map<std::string, NtruEncKeyPair> ntru_keys;
    
    std::vector<uint8_t> encryptMessage(const std::string& sender, const std::string& msg) {
        // MLS layer encryption (example placeholder)
        auto mls_encrypted = std::vector<uint8_t>(msg.begin(), msg.end());
        
        // NTRU post-quantum layer
        NtruEncKeyPair& kp = ntru_keys[sender];
        uint8_t ntru_ciphertext[ntru_enc_len(&NTRU_DEFAULT_PARAMS_128_BITS)];
        if (ntru_encrypt((uint8_t*)msg.data(), msg.size(), &kp.pub, &NTRU_DEFAULT_PARAMS_128_BITS, NULL, ntru_ciphertext) != NTRU_SUCCESS) {
            std::cerr << "NTRU encryption failed.\n";
            return {};
        }
        
        // Combine both encryptions
        std::vector<uint8_t> combined(mls_encrypted.begin(), mls_encrypted.end());
        combined.insert(combined.end(), ntru_ciphertext, ntru_ciphertext+ntru_enc_len(&NTRU_DEFAULT_PARAMS_128_BITS));
        
        return combined;
    }
    
    std::string decryptMessage(const std::string& receiver, const std::vector<uint8_t>& ciphertext) {
        // Split combined ciphertext
        auto mls_part = std::vector<uint8_t>(ciphertext.begin(), ciphertext.begin()+ciphertext.size()-ntru_enc_len(&NTRU_DEFAULT_PARAMS_128_BITS));
        auto ntru_part = std::vector<uint8_t>(ciphertext.end()-ntru_enc_len(&NTRU_DEFAULT_PARAMS_128_BITS), ciphertext.end());
        
        // MLS decryption (example placeholder)
        std::string decrypted(mls_part.begin(), mls_part.end());
        
        // NTRU verification
        NtruEncKeyPair& kp = ntru_keys[receiver];
        uint8_t ntru_decrypted[ntru_max_msg_len(&NTRU_DEFAULT_PARAMS_128_BITS)];
        uint16_t dec_len;
        if (ntru_decrypt(ntru_part.data(), &kp, &NTRU_DEFAULT_PARAMS_128_BITS, ntru_decrypted, &dec_len) != NTRU_SUCCESS) {
            std::cerr << "NTRU decryption failed.\n";
            return "";
        }
        
        return std::string((char*)ntru_decrypted, dec_len);
    }
};

// int main() {
//     SimpleGroup group;
//     group.sendMessage("Alice", "Hello Group!");
//     return 0;
// }
