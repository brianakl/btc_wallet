#include "ui.h"
#include "coldwallet.h"
#include <ncurses.h>
#include <iostream>

/*VimInterface::VimInterface(WalletManager& wm) : walletManager(wm) {}*/

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

/*void VimInterface::draw_ui() {*/
/*    // Draw wallet list, details, etc.*/
/*    clear();*/
/*    mvprintw(0, 0, "Bitcoin Wallet - Vim Navigation (j/k/h/l, : for command)");*/
/*    // ... draw wallets ...*/
/*    refresh();*/
/*}*/

/*void VimInterface::process_input() {*/
/*    int ch = getch();*/
/*    if (ch == ':') {*/
/*        echo();*/
/*        char cmd[256];*/
/*        mvprintw(1, 0, ":");*/
/*        getnstr(cmd, sizeof(cmd)-1);*/
/*        handle_command(cmd);*/
/*        noecho();*/
/*    }*/
/*    // Handle j/k/h/l navigation here*/
/*}*/

/*void VimInterface::handle_command(const std::string& cmd) {*/
/*    if (cmd == "q") {*/
/*        endwin();*/
/*        exit(0);*/
/*    } else if (cmd == "new") {*/
/*        // Prompt for passphrase and wallet name, then create*/
/*        // ...*/
/*    } else if (cmd == "cold") {*/
/*        generate_cold_wallet_ui();*/
/*    }*/
/*    // Add other commands as needed*/
/*}*/


#include "ui.h"
#include <ncurses.h>
#include <vector>
#include <string>
#include <cstring>
#include <iomanip>
#include <sstream>

extern void generate_cold_wallet_ui(); // from coldwallet.cpp

VimInterface::VimInterface(WalletManager& wm)
    : walletManager(wm), selected_row(0), in_details(false) {}

void VimInterface::draw_ui() {
    clear();
    int row = 0;
    mvprintw(row++, 0, "Bitcoin Wallet - Vim Navigation (j/k/h/l, : for command, q to quit)");

    // Draw wallet list
    mvprintw(row++, 0, "Wallets:");
    const auto& wallets = walletManager.get_wallets();
    int list_height = std::min((int)wallets.size(), LINES - 8);

    for (int i = 0; i < list_height; ++i) {
        if (i == selected_row && !in_details) attron(A_REVERSE);
        mvprintw(row + i, 2, "%d. %s", i + 1, wallets[i].name.c_str());
        if (i == selected_row && !in_details) attroff(A_REVERSE);
    }

    // Draw details panel
    int details_col = 30;
    mvprintw(2, details_col, "Details:");
    if (!wallets.empty() && size_t(selected_row) < wallets.size()) {
        const auto& w = wallets[selected_row];
        if (in_details) attron(A_REVERSE);
        mvprintw(3, details_col, "Name: %s", w.name.c_str());
        mvprintw(4, details_col, "Address: %s", w.public_address.c_str());
        mvprintw(5, details_col, "Created: %s", ctime(&w.creation_date));
        double bal = walletManager.get_balance(w.public_address);
        mvprintw(6, details_col, "Balance: %.8f BTC", bal);
        if (in_details) attroff(A_REVERSE);
    }

    refresh();
}

void VimInterface::process_input() {
    int ch = getch();
    const auto& wallets = walletManager.get_wallets();
    int wallet_count = wallets.size();

    if (ch == ':') {
        echo();
        char cmd[256];
        move(LINES - 2, 0);
        clrtoeol();
        mvprintw(LINES - 2, 0, ":");
        getnstr(cmd, sizeof(cmd) - 1);
        handle_command(std::string(cmd));
        noecho();
    } else if (ch == 'j') {
        if (!in_details && selected_row < wallet_count - 1) ++selected_row;
    } else if (ch == 'k') {
        if (!in_details && selected_row > 0) --selected_row;
    } else if (ch == 'h') {
        in_details = false;
    } else if (ch == 'l') {
        in_details = true;
    }
}

void VimInterface::handle_command(const std::string& cmd) {
    if (cmd == "q") {
        endwin();
        exit(0);
    } else if (cmd == "new") {
        // Prompt for passphrase and wallet name, then create
        echo();
        char pass1[256], pass2[256], name[256];
        move(LINES - 4, 0); clrtoeol();
        mvprintw(LINES - 4, 0, "Enter passphrase: ");
        getnstr(pass1, sizeof(pass1) - 1);

        move(LINES - 3, 0); clrtoeol();
        mvprintw(LINES - 3, 0, "Confirm passphrase: ");
        getnstr(pass2, sizeof(pass2) - 1);

        if (strcmp(pass1, pass2) != 0) {
            move(LINES - 2, 0); clrtoeol();
            mvprintw(LINES - 2, 0, "Passphrases do not match! Press any key.");
            getch();
            noecho();
            return;
        }

        move(LINES - 2, 0); clrtoeol();
        mvprintw(LINES - 2, 0, "Enter wallet name: ");
        getnstr(name, sizeof(name) - 1);

        walletManager.create_new_wallet(std::string(pass1), std::string(name));
        move(LINES - 2, 0); clrtoeol();
        mvprintw(LINES - 2, 0, "Wallet created! Press any key.");
        getch();
        noecho();
    } else if (cmd == "cold") {
        generate_cold_wallet_ui();
    } else if (cmd == "refresh"){
        
    } else if (cmd == "help") {
        echo();

    } 

    // Add other commands as needed
}

