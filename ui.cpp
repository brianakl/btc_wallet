#include "ui.h"
#include "coldwallet.h"
#include <ncurses.h>
#include <iostream>

VimInterface::VimInterface(WalletManager& wm) : walletManager(wm) {}

void VimInterface::run() {
    initscr();
    noecho();
    cbreak();
    keypad(stdscr, TRUE);

    bool running = true;
    while (running) {
        draw_ui();
        process_input();
        // Set running=false to exit
    }

    endwin();
}

void VimInterface::draw_ui() {
    // Draw wallet list, details, etc.
    clear();
    mvprintw(0, 0, "Bitcoin Wallet - Vim Navigation (j/k/h/l, : for command)");
    // ... draw wallets ...
    refresh();
}

void VimInterface::process_input() {
    int ch = getch();
    if (ch == ':') {
        echo();
        char cmd[256];
        mvprintw(1, 0, ":");
        getnstr(cmd, sizeof(cmd)-1);
        handle_command(cmd);
        noecho();
    }
    // Handle j/k/h/l navigation here
}

void VimInterface::handle_command(const std::string& cmd) {
    if (cmd == "q") {
        endwin();
        exit(0);
    } else if (cmd == "new") {
        // Prompt for passphrase and wallet name, then create
        // ...
    } else if (cmd == "cold") {
        generate_cold_wallet_ui();
    }
    // Add other commands as needed
}

