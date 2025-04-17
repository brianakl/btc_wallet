#include <iostream>
#include "wallet.h"
#include "ui.h"
#include "coldwallet.h"
#include <unistd.h>
#include <cstdlib>
#include <sodium.h>

int main() {
    // Require sudo for security
    if (geteuid() != 0 || std::getenv("SUDO_USER") == nullptr) {
        std::cerr << "Error: This application must be run with sudo\n";
        std::cerr << "Usage: sudo ./bitcoinwallet\n";
        return EXIT_FAILURE;
    }

    if (sodium_init() < 0) {
        // panic! the library couldn't be initialized
        return 1;
    }

    // Initialize wallet manager and UI
    WalletManager walletManager;
    VimInterface ui(walletManager);

    // Start main interface loop
    ui.run();

    return EXIT_SUCCESS;
}

