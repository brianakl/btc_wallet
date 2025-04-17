#pragma once
#include <string>


struct ColdWalletEntry {
    std::string name;
    std::string public_address;
    std::time_t creation_date;
    
    ColdWalletEntry(const std::string& n, const std::string& addr)
        : name(n), public_address(addr), creation_date(std::time(nullptr)) {}
};

void generate_cold_wallet_ui();
void handle_cold_command();
void save_cold_metadata(const ColdWalletEntry& entry) ;
void save_cold_metadata(const ColdWalletEntry& entry) ;
