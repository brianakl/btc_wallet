#pragma once
#include <string>

std::string generate_public_address(const std::string& passphrase);
std::string encrypt_private_key(const std::string& privkey, const std::string& passphrase);
double fetch_balance_online(const std::string& address);
std::string get_wallets_file();

