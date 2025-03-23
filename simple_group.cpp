#include <mls/core.h>
#include <ntru_crypto.h>

class SimpleGroup {
public:
    SimpleGroup() {
        // Initialize 3 members: Alice, Bob, Charlie
        members = {"Alice", "Bob", "Charlie"};
        
        // Generate NTRU keys for each member
        for(auto& member : members) {
            ntru_keys[member] = new NTRU_Key();
            ntru_create_key(128, &ntru_keys[member]);
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
    std::map<std::string, NTRU_Key*> ntru_keys;
    
    std::vector<uint8_t> encryptMessage(const std::string& sender, const std::string& msg) {
        // MLS layer encryption
        auto mls_encrypted = mls::encrypt(msg.data(), msg.size());
        
        // NTRU post-quantum layer
        uint8_t ntru_ciphertext[1000];
        ntru_encrypt(msg.data(), msg.size(), ntru_keys[sender], ntru_ciphertext);
        
        // Combine both encryptions
        std::vector<uint8_t> combined(mls_encrypted.begin(), mls_encrypted.end());
        combined.insert(combined.end(), ntru_ciphertext, ntru_ciphertext+1000);
        
        return combined;
    }
    
    std::string decryptMessage(const std::string& receiver, const std::vector<uint8_t>& ciphertext) {
        // Split combined ciphertext
        auto mls_part = std::vector<uint8_t>(ciphertext.begin(), ciphertext.begin()+ciphertext.size()-1000);
        auto ntru_part = std::vector<uint8_t>(ciphertext.end()-1000, ciphertext.end());
        
        // MLS decryption
        std::string decrypted = mls::decrypt(mls_part.data(), mls_part.size());
        
        // NTRU verification
        uint8_t ntru_decrypted[1000];
        ntru_decrypt(ntru_part.data(), ntru_part.size(), ntru_keys[receiver], ntru_decrypted);
        
        return decrypted;
    }
};
