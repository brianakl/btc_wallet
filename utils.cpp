#include "utils.h"
#include <cstdlib>
#include <string>
/*#include <dirent.h>*/
#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <secp256k1.h>
#include <random>
#include <vector>
#include <string>
#include <cstring>

// Base58 alphabet
const char* BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Helper: Base58 encoding
std::string base58_encode(const std::vector<unsigned char>& input) {
    std::vector<unsigned char> bytes = input;
    std::string result;
    unsigned int zeros = 0;
    while (zeros < bytes.size() && bytes[zeros] == 0) ++zeros;
    std::vector<unsigned char> b58((bytes.size() - zeros) * 138 / 100 + 1);
    size_t length = 0;
    for (size_t i = zeros; i < bytes.size(); ++i) {
        int carry = bytes[i];
        size_t j = 0;
        for (auto it = b58.rbegin(); (carry != 0 || j < length) && it != b58.rend(); ++it, ++j) {
            carry += 256 * (*it);
            *it = carry % 58;
            carry /= 58;
        }
        length = j;
    }
    auto it = b58.begin() + (b58.size() - length);
    while (it != b58.end() && *it == 0) ++it;
    for (size_t i = 0; i < zeros; ++i) result += '1';
    while (it != b58.end()) result += BASE58_ALPHABET[*it++];
    return result;
}

std::string generate_public_address() {
    // Generate a random private key
    std::random_device rd;
    std::vector<unsigned char> privkey(32);
    for (auto& b : privkey) b = rd();

    // Create secp256k1 context
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privkey.data())) {
        secp256k1_context_destroy(ctx);
        return "";
    }

    // Serialize as compressed pubkey
    unsigned char pubkey_serialized[33];
    size_t pubkey_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, pubkey_serialized, &pubkey_len, &pubkey, SECP256K1_EC_COMPRESSED);
    secp256k1_context_destroy(ctx);

    // SHA256
    unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
    SHA256(pubkey_serialized, pubkey_len, sha256_digest);

    // RIPEMD160
    unsigned char ripemd160_digest_buff[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160(sha256_digest, SHA256_DIGEST_LENGTH, ripemd160_digest_buff);
    /*RIPEMD160(sha256_digest, SHA256_DIGEST_LENGTH);*/
    /*memcpy(ripemd160_digest_buff, digest.data(), digest.size());*/

    // Prepend version byte (0x00 for mainnet)
    std::vector<unsigned char> versioned_payload(1 + RIPEMD160_DIGEST_LENGTH);
    versioned_payload[0] = 0x00;
    std::copy(ripemd160_digest_buff, ripemd160_digest_buff + RIPEMD160_DIGEST_LENGTH, versioned_payload.begin() + 1);

    // Double SHA256 for checksum
    unsigned char checksum_full[SHA256_DIGEST_LENGTH];
    SHA256(versioned_payload.data(), versioned_payload.size(), checksum_full);
    SHA256(checksum_full, SHA256_DIGEST_LENGTH, checksum_full);

    // Append first 4 bytes as checksum
    versioned_payload.insert(versioned_payload.end(), checksum_full, checksum_full + 4);

    // Base58Check encode
    return base58_encode(versioned_payload);
}


#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <vector>
#include <string>
#include <cstring>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <openssl/bio.h>
#include <openssl/buffer.h>

// Helper: Base64 encode
std::string base64_encode(const unsigned char* data, size_t len) {
    BIO* bmem = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data, len);
    BIO_flush(b64);
    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string result(bptr->data, bptr->length);
    BIO_free_all(b64);
    return result;
}

std::string encrypt_private_key(const std::string& privkey, const std::string& passphrase) {
    // Derive key from passphrase (SHA256)
    unsigned char key[32];
    SHA256(reinterpret_cast<const unsigned char*>(passphrase.data()), passphrase.size(), key);

    // Generate random IV
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));

    // Pad privkey to AES block size
    std::vector<unsigned char> padded(privkey.begin(), privkey.end());
    size_t pad_len = AES_BLOCK_SIZE - (padded.size() % AES_BLOCK_SIZE);
    padded.insert(padded.end(), pad_len, static_cast<unsigned char>(pad_len));

    // Encrypt
    std::vector<unsigned char> ciphertext(padded.size());
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, padded.data(), padded.size());
    int total_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    total_len += len;
    EVP_CIPHER_CTX_free(ctx);

    // Concatenate IV + ciphertext
    std::vector<unsigned char> out(iv, iv + sizeof(iv));
    out.insert(out.end(), ciphertext.begin(), ciphertext.begin() + total_len);

    // Base64 encode
    return base64_encode(out.data(), out.size());
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


