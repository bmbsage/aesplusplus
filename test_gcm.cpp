#include <iostream>
#include <vector>
#include <iomanip>
#include <cstdint>
#include "aesplusplus.h"

static void printHex(const std::vector<uint8_t>& v, size_t limit = 0) {
    size_t len = (limit > 0) ? std::min(limit, v.size()) : v.size();
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << int(v[i]);
    }
    if (limit > 0 && v.size() > limit) std::cout << "...";
}

int main() {
    auto result = aes_ni_supported();   
    std::cout << "AES-NI supported: " << (result ? "Yes" : "No") << std::endl << std::endl;
    
    // Test GCM with different key sizes
    std::vector<uint8_t> plaintext = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    
    std::vector<uint8_t> iv = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b
    };
    
    std::vector<uint8_t> aad = {
        0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef
    };
    
    size_t tagLen = 16;

    // Test AES-128 GCM
    std::cout << "=== AES-128 GCM Test ===" << std::endl;
    std::vector<uint8_t> key128 = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    try {
        AESEncryption aes128(key128);
        auto encResult = aes128.encryptGCM(plaintext, iv, aad, tagLen);
        
        std::cout << "Plaintext:  "; printHex(plaintext); std::cout << " (len=" << plaintext.size() << ")" << std::endl;
        std::cout << "Ciphertext+Tag: "; printHex(encResult, 32); std::cout << " (len=" << encResult.size() << ")" << std::endl;
        
        auto decrypted = aes128.decryptGCM(encResult, iv, aad, tagLen);
        std::cout << "Decrypted:  "; printHex(decrypted); std::cout << " (len=" << decrypted.size() << ")" << std::dec << std::endl;
        
        if (plaintext == decrypted) {
            std::cout << "PASS" << std::endl;
        } else {
            std::cout << "FAIL - Decrypted payload doesn't match plaintext" << std::endl;
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }

    // Test AES-192 GCM
    std::cout << "\n=== AES-192 GCM Test ===" << std::endl;
    std::vector<uint8_t> key192 = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17
    };
    try {
        AESEncryption aes192(key192);
        auto encResult = aes192.encryptGCM(plaintext, iv, aad, tagLen);
        
        std::cout << "Plaintext:  "; printHex(plaintext); std::cout << " (len=" << plaintext.size() << ")" << std::endl;
        std::cout << "Ciphertext+Tag: "; printHex(encResult, 32); std::cout << " (len=" << encResult.size() << ")" << std::endl;
        
        auto decrypted = aes192.decryptGCM(encResult, iv, aad, tagLen);
        std::cout << "Decrypted:  "; printHex(decrypted); std::cout << " (len=" << decrypted.size() << ")" << std::dec << std::endl;
        
        if (plaintext == decrypted) {
            std::cout << "PASS" << std::endl;
        } else {
            std::cout << "FAIL - Decrypted payload doesn't match plaintext" << std::endl;
            return 2;
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 2;
    }

    // Test AES-256 GCM
    std::cout << "\n=== AES-256 GCM Test ===" << std::endl;
    std::vector<uint8_t> key256 = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    try {
        AESEncryption aes256(key256);
        auto encResult = aes256.encryptGCM(plaintext, iv, aad, tagLen);
        
        std::cout << "Plaintext:  "; printHex(plaintext); std::cout << " (len=" << plaintext.size() << ")" << std::endl;
        std::cout << "Ciphertext+Tag: "; printHex(encResult, 32); std::cout << " (len=" << encResult.size() << ")" << std::endl;
        
        auto decrypted = aes256.decryptGCM(encResult, iv, aad, tagLen);
        std::cout << "Decrypted:  "; printHex(decrypted); std::cout << " (len=" << decrypted.size() << ")" << std::dec << std::endl;
        
        if (plaintext == decrypted) {
            std::cout << "PASS" << std::endl;
        } else {
            std::cout << "FAIL - Decrypted payload doesn't match plaintext" << std::endl;
            return 3;
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 3;
    }

    // Test authentication failure detection
    std::cout << "\n=== Authentication Failure Test (AES-128) ===" << std::endl;
    try {
        AESEncryption aes128(key128);
        auto encResult = aes128.encryptGCM(plaintext, iv, aad, tagLen);
        
        // Corrupt the tag by modifying last byte
        encResult[encResult.size() - 1] ^= 0xFF;
        
        try {
            auto decrypted = aes128.decryptGCM(encResult, iv, aad, tagLen);
            std::cout << "FAIL - Authentication should have failed but didn't" << std::endl;
            return 4;
        } catch (const std::runtime_error& e) {
            std::cout << "Authentication check caught tampered tag: " << e.what() << std::endl;
            std::cout << "PASS" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 4;
    }

    std::cout << "\nAll GCM tests passed!" << std::endl;
    return 0;
}
