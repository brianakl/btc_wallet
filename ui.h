#pragma once
#include "wallet.h"

class VimInterface {
public:
    VimInterface(WalletManager& wm);
    void run();
private:
    WalletManager& walletManager;
    void handle_command(const std::string& cmd);
    void draw_ui();
    void process_input();
    int selected_row;
    bool in_details;
    void draw_wallet();
    void handle_wallet_page();
    void process_wallet_input();
};

