#pragma once
#include <string>
#include <vector>
#include <ctime>

struct Wallet {
    std::string name;
    std::string public_address;
    std::string encrypted_private_key;
    std::time_t creation_date;
};

class WalletManager {
public:
    WalletManager();
    void create_new_wallet(const std::string& passphrase, const std::string& name);
    double get_balance(const std::string& address);
    void load_wallets();
    void save_wallet(const Wallet& wallet);
    const std::vector<Wallet>& get_wallets() const;
private:
    std::vector<Wallet> wallets;
};

