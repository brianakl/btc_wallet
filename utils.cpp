#include "utils.h"
#include <cstdlib>
#include <string>
/*#include <dirent.h>*/
#include <sys/stat.h>
#include <sys/types.h>


std::string generate_public_address() {
    // Use secp256k1 to generate address
    return "stub_public_address";
}

std::string encrypt_private_key(const std::string& privkey, const std::string& passphrase) {
    // Use OpenSSL to encrypt privkey
    return "stub_encrypted_privkey";
}

double fetch_balance_online(const std::string& address) {
    // Use cURL to fetch balance from blockchain API
    return 0.0;
}

std::string get_wallets_file() {
    std::string dir = std::string(getenv("HOME")) + "/.wallet/";
    mkdir(dir.c_str(), 0700);
    return dir + "wallets.json";
}


