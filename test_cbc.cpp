#include <iostream>
#include <vector>
#include <iomanip>
#include <cstdint>
#include "aesplusplus.h"

static void printHex(const std::vector<uint8_t>& v) {
    for (uint8_t b : v) std::cout << std::hex << std::setw(2) << std::setfill('0') << int(b);
}

int main() {
    auto result = aes_ni_supported();   
    std::cout << "AES-NI supported: " << (result ? "Yes" : "No") << std::endl << std::endl;
    
    // Test CBC with different key sizes
    std::vector<uint8_t> plaintext = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff  // 32 bytes for CBC
    };
    
    std::vector<uint8_t> iv = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    // Test AES-128 CBC
    std::cout << "=== AES-128 CBC Test ===" << std::endl;
    std::vector<uint8_t> key128 = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    try {
        AESEncryption aes128(key128);
        auto cipher = aes128.encryptCBC(plaintext, iv);
        auto decrypted = aes128.decryptCBC(cipher, iv);
        
        std::cout << "Original:   "; printHex(plaintext); std::cout << std::endl;
        std::cout << "Decrypted:  "; printHex(decrypted); std::cout << std::endl;
        
        if (plaintext == decrypted) {
            std::cout << "PASS" << std::endl;
        } else {
            std::cout << "FAIL" << std::endl;
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }

    // Test AES-192 CBC
    std::cout << "\n=== AES-192 CBC Test ===" << std::endl;
    std::vector<uint8_t> key192 = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17
    };
    try {
        AESEncryption aes192(key192);
        auto cipher = aes192.encryptCBC(plaintext, iv);
        auto decrypted = aes192.decryptCBC(cipher, iv);
        
        std::cout << "Original:   "; printHex(plaintext); std::cout << std::endl;
        std::cout << "Decrypted:  "; printHex(decrypted); std::cout << std::endl;
        
        if (plaintext == decrypted) {
            std::cout << "PASS" << std::endl;
        } else {
            std::cout << "FAIL" << std::endl;
            return 2;
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 2;
    }

    // Test AES-256 CBC
    std::cout << "\n=== AES-256 CBC Test ===" << std::endl;
    std::vector<uint8_t> key256 = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    try {
        AESEncryption aes256(key256);
        auto cipher = aes256.encryptCBC(plaintext, iv);
        auto decrypted = aes256.decryptCBC(cipher, iv);
        
        std::cout << "Original:   "; printHex(plaintext); std::cout << std::endl;
        std::cout << "Decrypted:  "; printHex(decrypted); std::cout << std::endl;
        
        if (plaintext == decrypted) {
            std::cout << "PASS" << std::endl;
        } else {
            std::cout << "FAIL" << std::endl;
            return 3;
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 3;
    }

    std::cout << "\nAll CBC tests passed!" << std::endl;
    return 0;
}
