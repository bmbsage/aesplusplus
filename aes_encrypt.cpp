#include <iostream>
#include <vector>
#include <iomanip>
#include <cstdint>
#include "aesplusplus.h"


static void printHex(const std::vector<uint8_t>& v) {
    for (uint8_t b : v) std::cout << std::hex << std::setw(2) << std::setfill('0') << int(b);
}

int main() {

    auto result=aes_ni_supported();   
    std::cout << "AES-NI supported: " << (result ? "Yes" : "No") << std::endl << std::endl;
    
    // NIST AES-128 test vector
    std::cout << "=== AES-128 Test (NIST vector) ===" << std::endl;
    std::vector<uint8_t> key128 = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    std::vector<uint8_t> plaintext128 = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    std::vector<uint8_t> expected128 = {
        0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
    };

    try {
        AESEncryption aes128(key128);
        auto cipher128 = aes128.encryptECB(plaintext128);

        std::cout << "Ciphertext: "; printHex(cipher128); std::cout << std::dec << std::endl;
        std::cout << "Expected:   "; printHex(expected128); std::cout << std::dec << std::endl;

        if (cipher128 == expected128) {
            std::cout << "Encrypt: PASS" << std::endl;
        } else {
            std::cout << "Encrypt: FAIL" << std::endl;
            return 2;
        }

        auto plain128_dec = aes128.decryptECB(cipher128);
        if (plain128_dec == plaintext128) {
            std::cout << "Decrypt: PASS" << std::endl << std::endl;
        } else {
            std::cout << "Decrypt: FAIL" << std::endl;
            return 3;
        }
    } catch (const std::exception& e) {
        std::cerr << "AES-128 Exception: " << e.what() << std::endl;
        return 4;
    }

    // AES-192 round-trip test
    std::cout << "=== AES-192 Test (Round-trip) ===" << std::endl;
    std::vector<uint8_t> key192 = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17
    };
    std::vector<uint8_t> plaintext192 = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };

    try {
        AESEncryption aes192(key192);
        auto cipher192 = aes192.encryptECB(plaintext192);
        auto dec192 = aes192.decryptECB(cipher192);

        std::cout << "Original:   "; printHex(plaintext192); std::cout << std::endl;
        std::cout << "After RoundTrip: "; printHex(dec192); std::cout << std::dec << std::endl;

        if (dec192 == plaintext192) {
            std::cout << "Encrypt/Decrypt: PASS" << std::endl << std::endl;
        } else {
            std::cout << "Encrypt/Decrypt: FAIL" << std::endl;
            return 5;
        }
    } catch (const std::exception& e) {
        std::cerr << "AES-192 Exception: " << e.what() << std::endl;
        return 6;
    }

    // AES-256 round-trip test
    std::cout << "=== AES-256 Test (Round-trip) ===" << std::endl;
    std::vector<uint8_t> key256 = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    std::vector<uint8_t> plaintext256 = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    std::string plainstr("welcome to AES--");

    try {
        AESEncryption aes256(key256);
        auto cipher256 = aes256.encryptECB(plaintext256);
        auto dec256 = aes256.decryptECB(cipher256);

        std::cout << "Original:   "; printHex(plaintext256); std::cout << std::endl;
        std::cout << "After RoundTrip: "; printHex(dec256); std::cout << std::dec << std::endl;

        if (dec256 == plaintext256) {
            std::cout << "Encrypt/Decrypt: PASS" << std::endl << std::endl;
        } else {
            std::cout << "Encrypt/Decrypt: FAIL" << std::endl;
            return 7;
        }
    } catch (const std::exception& e) {
        std::cerr << "AES-256 Exception: " << e.what() << std::endl;
        return 8;
    }

  std::cout << "=== AES-String  encryptString, decryptString Test ===" << std::endl;
     try {
        AESEncryption aesString(key128);
        auto cipherString = aesString.encryptString(plainstr);
        auto decString = aesString.decryptString(cipherString);

         std::cout << "Original:   "; std::cout << plainstr << std::endl;
         std::cout << "Plaintext String: " << cipherString << std::endl;
         std::cout << "Ciphertext String (hex): "; printHex(std::vector<uint8_t>(cipherString.begin(), cipherString.end())); std::cout << std::dec << std::endl;
         std::cout << "Decrypted String: " << decString << std::endl;

         if (decString == plainstr) {
             std::cout << "Encrypt/Decrypt String: PASS" << std::endl << std::endl;
         } else {
             std::cout << "Encrypt/Decrypt String: FAIL" << std::endl;
             return 9;
         }
    

        if (decString == plainstr) {
            std::cout << "Encrypt/Decrypt: PASS" << std::endl << std::endl;
        } else {
            std::cout << "Encrypt/Decrypt: FAIL" << std::endl;
            return 7;
        }
    } catch (const std::exception& e) {
        std::cerr << "AES-String Exception: " << e.what() << std::endl;
        return 9;
    }

    std::cout << "All tests passed!" << std::endl;
    return 0;
}


