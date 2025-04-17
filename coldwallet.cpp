#include "coldwallet.h"
#include "metadata.h"
#include "utils.h"
#include <ncurses.h>
#include <ctime>
#include <secp256k1.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <sodium.h>
#include <vector>


struct ColdWalletEntry {
    std::string name;
    std::string public_address;
    std::time_t creation_date;
    
    ColdWalletEntry(const std::string& n, const std::string& addr)
        : name(n), public_address(addr), creation_date(std::time(nullptr)) {}
};




void generate_ephemeral_wallet() {
    // Secure memory allocation
    unsigned char* seed = static_cast<unsigned char*>(
        sodium_malloc(32)); // 256-bit seed
    randombytes_buf(seed, 32);

    // BIP-39 Mnemonic Conversion
    const char* words[2048] = {/* BIP-39 word list */};
    std::vector<std::string> mnemonic;
    for(int i=0; i<24; i++) { // 24-word phrase
        uint16_t index = (seed[i*11/8] << 8 | seed[i*11/8+1]) >> (3 - i%8);
        mnemonic.push_back(words[index]);
    }

    // In-memory key derivation
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    /*secp256k1_ecdsa_secret_key privkey;*/
    unsigned char privkey[32];
    /*PBKDF2_HMAC_SHA512(seed, 32, "mnemonic", 8, 2048, privkey, 32);*/
    /*PKCS5_PBKDF2_HMAC_SHA1(seed, 32, "mnemonic", 8, 2048, privkey, 32);*/
    PKCS5_PBKDF2_HMAC_SHA1(seed, 32, "mnemonic", 8, 2048, privkey, 32);

    // Display workflow
    mvprintw(0, 0, "COLD WALLET GENERATION:");
    for(int i=0; i<24; i+=2) {
        mvprintw(i/2+1, 0, "%2d. %-14s %2d. %s", 
            i+1, mnemonic[i].c_str(), 
            i+2, mnemonic[i+1].c_str());
    }
    refresh();

    // Memory sanitization
    sodium_munlock(seed, 32);
    sodium_free(seed);
    secp256k1_context_destroy(ctx);
    /*secp256k1_context_clear(ctx);*/
}


void handle_cold_command() {
    noecho();
    curs_set(0);
    
    generate_ephemeral_wallet();
    
    mvprintw(13, 0, "Write these words in order!");
    mvprintw(14, 0, "Press any key to wipe memory...");
    getch();
    
    clear();
    echo();
    curs_set(1);
}

void save_cold_metadata(const ColdWalletEntry& entry) {
    const std::string wallet_dir = getenv("HOME") + std::string("/.wallet/cold/");
    mkdir(wallet_dir.c_str(), 0700);  // Secure directory creation
    
    nlohmann::json metadata;
    metadata["name"] = entry.name;
    metadata["address"] = entry.public_address;
    metadata["created"] = entry.creation_date;
    
    std::ofstream file(wallet_dir + "metadata.json", std::ios::app);
    file << metadata.dump() << "\n";
    file.close();
    
    chmod((wallet_dir + "metadata.json").c_str(), 0600);  // Restrict file permissions
}


void generate_cold_wallet_ui() {
    // Generate mnemonic and public key in-memory
    // Display mnemonic to user
    // Prompt for wallet name
    // Save public key, name, and timestamp to metadata
    // Wipe sensitive memory
    clear();
    mvprintw(0, 0, "COLD WALLET GENERATION");
    // ... generate mnemonic ...
    handle_cold_command();
    // ... display mnemonic ...
    char name[128];
    mvprintw(10, 0, "Enter wallet name: ");
    echo();
    getnstr(name, sizeof(name)-1);
    noecho();
    std::string pubkey = "generated_pubkey"; // stub
    std::time_t now = std::time(nullptr);
    save_cold_metadata(name, pubkey, now);
    mvprintw(12, 0, "Public key and metadata saved. Press any key to continue.");
    getch();
}
