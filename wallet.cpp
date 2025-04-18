#include "wallet.h"
#include "utils.h"
/*#include "json/json.hpp"*/
#include "json.hpp"
#include <fstream>
#include <ctime>

WalletManager::WalletManager() {
    load_wallets();
}

void WalletManager::create_new_wallet(const std::string& passphrase, const std::string& name) {
    // Generate keypair, encrypt private key, create Wallet struct
    // Use utility functions from utils.cpp
    Wallet wallet;
    wallet.name = name;
    wallet.public_address = generate_public_address(); // stub
    wallet.encrypted_private_key = encrypt_private_key("privkey", passphrase); // stub
    wallet.creation_date = std::time(nullptr);
    save_wallet(wallet);
    wallets.push_back(wallet);
}

double WalletManager::get_balance(const std::string& address) {
    return fetch_balance_online(address); // stub in utils.cpp
}

void WalletManager::load_wallets() {
    // Load wallets from ~/.wallet/wallets.json
    wallets.clear();
    std::ifstream file(get_wallets_file());
    if (!file) return;
    nlohmann::json arr;
    file >> arr;
    for (auto& obj : arr) {
        Wallet w;
        w.name = obj["name"];
        w.public_address = obj["public_address"];
        w.encrypted_private_key = obj["encrypted_private_key"];
        w.creation_date = obj["creation_date"];
        wallets.push_back(w);
    }
}

void WalletManager::save_wallet(const Wallet& wallet) {
    // Append wallet to wallets.json
    std::vector<Wallet> all_wallets = wallets;
    all_wallets.push_back(wallet);
    /*nlohmann::json arr = nlohmann::json::array();*/
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& w : all_wallets) {
        arr.push_back({
            {"name", w.name},
            {"public_address", w.public_address},
            {"encrypted_private_key", w.encrypted_private_key},
            {"creation_date", w.creation_date}
        });
    }
    std::ofstream file(get_wallets_file());
    file << arr.dump(4);
}

const std::vector<Wallet>& WalletManager::get_wallets() const {
    return wallets;
}

