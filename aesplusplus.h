#ifndef AESPLUSPLUS_H
#define AESPLUSPLUS_H

#include <vector>
#include <cstdint>
#include <string>
#include <stdexcept>
#include <array>
#include <immintrin.h>
#include <cpuid.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

// Query for AES-NI at runtime
static bool aes_ni_supported(void);


/* AES-128 constants */

static const uint8_t sbox[256] = {
    /* 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F */
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };
static const uint8_t inv_sbox[256] = {
    0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
    0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
    0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
    0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
    0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
    0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
    0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
    0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
    0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
    0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
    0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
    0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
    0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
    0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
    0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
    0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};



enum AESMode { ECB, CBC, CTR, GCM };

class AESEncryption {
public:
    // Constructor with 128, 192, or 256-bit key
    explicit AESEncryption(const std::vector<uint8_t>& key);

    // PKCS#7 padding (pads to nearest 16-byte boundary; always pads if already multiple of 16)
    static std::vector<uint8_t> pad(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> unpad(const std::vector<uint8_t>& data);
    
    // Encrypt plaintext (must be multiple of 16 bytes)
    std::vector<uint8_t> encryptECB(const std::vector<uint8_t>& plaintext);
    
    // Decrypt ciphertext
    std::vector<uint8_t> decryptECB(const std::vector<uint8_t>& ciphertext);
    
    // Convenience functions for strings
    std::string encryptString(const std::string& plaintext,AESMode mode = AESMode::ECB, const std::vector<uint8_t>* iv = nullptr);
    std::string decryptString(const std::string& ciphertext,AESMode mode = AESMode::ECB, const std::vector<uint8_t>* iv = nullptr);

    // Encrypt/decrypt in CBC mode (plaintext/ciphertext length must be multiple of 16)
    std::vector<uint8_t> encryptCBC(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& iv);
    std::vector<uint8_t> decryptCBC(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& iv);

    // CTR mode (supports arbitrary input length)
    std::vector<uint8_t> encryptCTR(const std::vector<uint8_t>& data, const std::vector<uint8_t>& iv);
    std::vector<uint8_t> decryptCTR(const std::vector<uint8_t>& data, const std::vector<uint8_t>& iv);

        // GCM (returns ciphertext||tag; decrypt throws on auth failure)
    std::vector<uint8_t> encryptGCM(const std::vector<uint8_t>& plaintext,
                                    const std::vector<uint8_t>& iv,
                                    const std::vector<uint8_t>& aad,
                                    size_t tagLen = 16);
    std::vector<uint8_t> decryptGCM(const std::vector<uint8_t>& ciphertext_and_tag,
                                    const std::vector<uint8_t>& iv,
                                    const std::vector<uint8_t>& aad,
                                    size_t tagLen = 16);

    inline void Set_useAESNI(bool use) { use_aesni = use; } 
    
private:
    std::vector<uint8_t> key;
    int rounds;
    // expanded round keys stored as bytes: (rounds+1)*16
    std::vector<uint8_t> expandedKey;
    // AES-NI accelerated round keys (only used when available and for AES-128)
    bool use_aesni = false;
    std::vector<__m128i> aesni_enc_rounds;
    std::vector<__m128i> aesni_dec_rounds;
    // per-round 4-byte words for key schedule (no longer used)

    void keyExpansion();
    void setupAESNIKeys128();
    void setupAESNIKeys192();
    void setupAESNIKeys256();
    void aesniEncryptBlock(const uint8_t* in, uint8_t* out) const;
    void aesniDecryptBlock(const uint8_t* in, uint8_t* out) const;
    void subBytes(std::vector<uint8_t>& state);
    void shiftRows(std::vector<uint8_t>& state);
    void mixColumns(std::vector<uint8_t>& state);
    void addRoundKey(std::vector<uint8_t>& state, int round);

    // inverse transforms for decryption
    void invSubBytes(std::vector<uint8_t>& state);
    void invShiftRows(std::vector<uint8_t>& state);
    void invMixColumns(std::vector<uint8_t>& state);
};




AESEncryption::AESEncryption(const std::vector<uint8_t>& key) : key(key) {
    if (key.size() == 16) {
        rounds = 10; // AES-128
    } else if (key.size() == 24) {
        rounds = 12; // AES-192
    } else if (key.size() == 32) {
        rounds = 14; // AES-256
    } else {
        throw std::invalid_argument("Key must be 128, 192, or 256 bits");
    }
    keyExpansion();
    // If AES-NI is available, prepare hardware round keys for any key size
    if (aes_ni_supported()) {
        use_aesni = true;
        if (key.size() == 16) setupAESNIKeys128();
        else if (key.size() == 24) setupAESNIKeys192();
        else if (key.size() == 32) setupAESNIKeys256();
    } else {
        use_aesni = false;
    }
}

void AESEncryption::keyExpansion()
{
const uint32_t rcon[11] = {0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
                          0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};
    const int Nb = 4;
    const int Nk = static_cast<int>(key.size()) / 4;
    const int Nr = rounds;
    const int words = Nb * (Nr + 1);

    std::vector<uint32_t> w(words);

    for (int i = 0; i < Nk; ++i) {
        w[i] = (uint32_t(key[4*i]) << 24) | (uint32_t(key[4*i+1]) << 16) |
               (uint32_t(key[4*i+2]) << 8) | uint32_t(key[4*i+3]);
    }

    auto rotWord = [](uint32_t x) -> uint32_t { return (x << 8) | (x >> 24); };
    auto subWord = [](uint32_t x) -> uint32_t {
        return (uint32_t(sbox[(x >> 24) & 0xff]) << 24) |
               (uint32_t(sbox[(x >> 16) & 0xff]) << 16) |
               (uint32_t(sbox[(x >> 8) & 0xff]) << 8) |
               uint32_t(sbox[x & 0xff]);
    };

    for (int i = Nk; i < words; ++i) {
        uint32_t temp = w[i - 1];
        if (i % Nk == 0) {
      temp = subWord(rotWord(temp)) ^ rcon[i / Nk];
        } else if (Nk > 6 && (i % Nk) == 4) {
            temp = subWord(temp);
        }
        w[i] = w[i - Nk] ^ temp;
    }

    expandedKey.assign(words * 4, 0);
    for (int i = 0; i < words; ++i) {
        expandedKey[4*i + 0] = (w[i] >> 24) & 0xff;
        expandedKey[4*i + 1] = (w[i] >> 16) & 0xff;
        expandedKey[4*i + 2] = (w[i] >> 8) & 0xff;
        expandedKey[4*i + 3] = w[i] & 0xff;
    }
}
// AES-NI helpers (AES-128 only)
static inline __m128i aes128_key_expansion_step(__m128i temp1, __m128i temp2) {
    temp2 = _mm_shuffle_epi32(temp2, _MM_SHUFFLE(3,3,3,3));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, temp2);
    return temp1;
}

void AESEncryption::setupAESNIKeys128() {
    // Only for 128-bit key
    aesni_enc_rounds.clear(); aesni_dec_rounds.clear();
    aesni_enc_rounds.resize(11);
    aesni_dec_rounds.resize(11);

    __m128i temp1 = _mm_loadu_si128((const __m128i*)key.data());
    aesni_enc_rounds[0] = temp1;

    temp1 = aes128_key_expansion_step(temp1, _mm_aeskeygenassist_si128(temp1, 0x01));
    aesni_enc_rounds[1] = temp1;
    temp1 = aes128_key_expansion_step(temp1, _mm_aeskeygenassist_si128(temp1, 0x02));
    aesni_enc_rounds[2] = temp1;
    temp1 = aes128_key_expansion_step(temp1, _mm_aeskeygenassist_si128(temp1, 0x04));
    aesni_enc_rounds[3] = temp1;
    temp1 = aes128_key_expansion_step(temp1, _mm_aeskeygenassist_si128(temp1, 0x08));
    aesni_enc_rounds[4] = temp1;
    temp1 = aes128_key_expansion_step(temp1, _mm_aeskeygenassist_si128(temp1, 0x10));
    aesni_enc_rounds[5] = temp1;
    temp1 = aes128_key_expansion_step(temp1, _mm_aeskeygenassist_si128(temp1, 0x20));
    aesni_enc_rounds[6] = temp1;
    temp1 = aes128_key_expansion_step(temp1, _mm_aeskeygenassist_si128(temp1, 0x40));
    aesni_enc_rounds[7] = temp1;
    temp1 = aes128_key_expansion_step(temp1, _mm_aeskeygenassist_si128(temp1, 0x80));
    aesni_enc_rounds[8] = temp1;
    temp1 = aes128_key_expansion_step(temp1, _mm_aeskeygenassist_si128(temp1, 0x1B));
    aesni_enc_rounds[9] = temp1;
    temp1 = aes128_key_expansion_step(temp1, _mm_aeskeygenassist_si128(temp1, 0x36));
    aesni_enc_rounds[10] = temp1;

    // Prepare decryption round keys
    aesni_dec_rounds[0] = aesni_enc_rounds[10];
    aesni_dec_rounds[10] = aesni_enc_rounds[0];
    for (int i = 1; i < 10; ++i) {
        aesni_dec_rounds[i] = _mm_aesimc_si128(aesni_enc_rounds[10 - i]);
    }
}

void AESEncryption::setupAESNIKeys192() {
    // AES-192: 12 rounds (13 round keys stored in expandedKey)
    aesni_enc_rounds.clear(); aesni_dec_rounds.clear();
    aesni_enc_rounds.resize(13);
    aesni_dec_rounds.resize(13);

    // Load round keys from expandedKey (software-expanded)
    for (int r = 0; r <= 12; ++r) {
        aesni_enc_rounds[r] = _mm_loadu_si128((const __m128i*)(expandedKey.data() + r * 16));
    }

    // Prepare decryption round keys (InvMixColumns + reorder)
    aesni_dec_rounds[0] = aesni_enc_rounds[12];
    aesni_dec_rounds[12] = aesni_enc_rounds[0];
    for (int i = 1; i < 12; ++i) {
        aesni_dec_rounds[i] = _mm_aesimc_si128(aesni_enc_rounds[12 - i]);
    }
}

void AESEncryption::setupAESNIKeys256() {
    // AES-256: 14 rounds (15 round keys stored in expandedKey)
    aesni_enc_rounds.clear(); aesni_dec_rounds.clear();
    aesni_enc_rounds.resize(15);
    aesni_dec_rounds.resize(15);

    // Load round keys from expandedKey (software-expanded)
    for (int r = 0; r <= 14; ++r) {
        aesni_enc_rounds[r] = _mm_loadu_si128((const __m128i*)(expandedKey.data() + r * 16));
    }

    // Prepare decryption round keys (InvMixColumns + reorder)
    aesni_dec_rounds[0] = aesni_enc_rounds[14];
    aesni_dec_rounds[14] = aesni_enc_rounds[0];
    for (int i = 1; i < 14; ++i) {
        aesni_dec_rounds[i] = _mm_aesimc_si128(aesni_enc_rounds[14 - i]);
    }
}

void AESEncryption::aesniEncryptBlock(const uint8_t* in, uint8_t* out) const {
    __m128i m = _mm_loadu_si128((const __m128i*)in);
    m = _mm_xor_si128(m, aesni_enc_rounds[0]);
    for (int r = 1; r < rounds; ++r) m = _mm_aesenc_si128(m, aesni_enc_rounds[r]);
    m = _mm_aesenclast_si128(m, aesni_enc_rounds[rounds]);
    _mm_storeu_si128((__m128i*)out, m);
}

void AESEncryption::aesniDecryptBlock(const uint8_t* in, uint8_t* out) const {
    __m128i m = _mm_loadu_si128((const __m128i*)in);
    m = _mm_xor_si128(m, aesni_dec_rounds[0]);
    for (int r = 1; r < rounds; ++r) m = _mm_aesdec_si128(m, aesni_dec_rounds[r]);
    m = _mm_aesdeclast_si128(m, aesni_dec_rounds[rounds]);
    _mm_storeu_si128((__m128i*)out, m);
}

void AESEncryption::subBytes(std::vector<uint8_t>& state) {
    // Implement SubBytes transformation using the AES S-box
    // This is a placeholder and should be implemented according to the AES specification
    for (size_t i = 0; i < state.size(); i++) {
        state[i] = sbox[state[i]];
    }
}

void AESEncryption::shiftRows(std::vector<uint8_t>& state) {
    // Implement ShiftRows transformation
    // This is a placeholder and should be implemented according to the AES specification
    std::vector<uint8_t> temp(state.size());
    temp[0] = state[0];
    temp[1] = state[5];
    temp[2] = state[10];
    temp[3] = state[15];
    
    temp[4] = state[4];
    temp[5] = state[9];
    temp[6] = state[14];
    temp[7] = state[3];
    
    temp[8] = state[8];
    temp[9] = state[13];
    temp[10] = state[2];
    temp[11] = state[7];
    
    temp[12] = state[12];
    temp[13] = state[1];
    temp[14] = state[6];
    temp[15] = state[11];

    for (size_t i = 0; i < state.size(); i++) {
        state[i] = temp[i];
    }
}

void AESEncryption::mixColumns(std::vector<uint8_t>& state) {
    auto xtime = [](uint8_t x) -> uint8_t { return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00)); };
    for (int c = 0; c < 4; ++c) {
        int i = c * 4;
        uint8_t a0 = state[i+0];
        uint8_t a1 = state[i+1];
        uint8_t a2 = state[i+2];
        uint8_t a3 = state[i+3];
        uint8_t t = a0 ^ a1 ^ a2 ^ a3;
        uint8_t u = a0;
        state[i+0] ^= t ^ xtime(a0 ^ a1);
        state[i+1] ^= t ^ xtime(a1 ^ a2);
        state[i+2] ^= t ^ xtime(a2 ^ a3);
        state[i+3] ^= t ^ xtime(a3 ^ u);
    }
}

void AESEncryption::addRoundKey(std::vector<uint8_t>& state, int round) {
    int base = round * 16;
    for (int i = 0; i < 16; ++i) state[i] ^= expandedKey[base + i];
}

std::vector<uint8_t> AESEncryption::encryptECB(const std::vector<uint8_t>& plaintext) {
    if (plaintext.size() % 16 != 0) {
        throw std::invalid_argument("Plaintext must be a multiple of 16 bytes");
    }
    std::vector<uint8_t> ciphertext(plaintext.size());
    for (size_t off = 0; off < plaintext.size(); off += 16) {
        if (use_aesni) {
            aesniEncryptBlock(&plaintext[off], &ciphertext[off]);
            continue;
        }

        std::vector<uint8_t> state(16);
        for (int i = 0; i < 16; ++i) state[i] = plaintext[off + i];

        addRoundKey(state, 0);
        for (int round = 1; round < rounds; ++round) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, round);
        }
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, rounds);

        for (int i = 0; i < 16; ++i) ciphertext[off + i] = state[i];
    }
    return ciphertext;
}

std::vector<uint8_t> AESEncryption::decryptECB(const std::vector<uint8_t>& ciphertext) {
    if (ciphertext.size() % 16 != 0) {
        throw std::invalid_argument("Ciphertext must be a multiple of 16 bytes");
    }
    std::vector<uint8_t> plaintext(ciphertext.size());

    auto gf_mul = [](uint8_t a, uint8_t b) -> uint8_t {
        uint8_t res = 0;
        uint8_t t = a;
        for (int i = 0; i < 8; ++i) {
            if (b & 1) res ^= t;
            bool hi = (t & 0x80) != 0;
            t = (uint8_t)(t << 1);
            if (hi) t ^= 0x1b;
            b >>= 1;
        }
        return res;
    };

    for (size_t off = 0; off < ciphertext.size(); off += 16) {
        if (use_aesni) {
            aesniDecryptBlock(&ciphertext[off], &plaintext[off]);
            continue;
        }

        std::vector<uint8_t> state(16);
        for (int i = 0; i < 16; ++i) state[i] = ciphertext[off + i];

        addRoundKey(state, rounds);
        for (int round = rounds - 1; round > 0; --round) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, round);
            // invMixColumns
            for (int c = 0; c < 4; ++c) {
                int i = c * 4;
                uint8_t a0 = state[i+0];
                uint8_t a1 = state[i+1];
                uint8_t a2 = state[i+2];
                uint8_t a3 = state[i+3];
                state[i+0] = (uint8_t)(gf_mul(a0,0x0e) ^ gf_mul(a1,0x0b) ^ gf_mul(a2,0x0d) ^ gf_mul(a3,0x09));
                state[i+1] = (uint8_t)(gf_mul(a0,0x09) ^ gf_mul(a1,0x0e) ^ gf_mul(a2,0x0b) ^ gf_mul(a3,0x0d));
                state[i+2] = (uint8_t)(gf_mul(a0,0x0d) ^ gf_mul(a1,0x09) ^ gf_mul(a2,0x0e) ^ gf_mul(a3,0x0b));
                state[i+3] = (uint8_t)(gf_mul(a0,0x0b) ^ gf_mul(a1,0x0d) ^ gf_mul(a2,0x09) ^ gf_mul(a3,0x0e));
            }
        }
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, 0);

        for (int i = 0; i < 16; ++i) plaintext[off + i] = state[i];
    }

    return plaintext;
}

std::vector<uint8_t> AESEncryption::encryptCBC(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& iv) {
    if (iv.size() != 16) throw std::invalid_argument("IV must be 16 bytes");
    if (plaintext.size() % 16 != 0) throw std::invalid_argument("Plaintext must be a multiple of 16 bytes");
    std::vector<uint8_t> ciphertext(plaintext.size());
    std::vector<uint8_t> prev(iv.begin(), iv.end());

    for (size_t off = 0; off < plaintext.size(); off += 16) {
        // XOR plaintext with previous ciphertext block
        uint8_t block[16];
        for (int i = 0; i < 16; ++i) block[i] = plaintext[off + i] ^ prev[i];
        
        // Encrypt using AES-NI if available, otherwise software
        if (use_aesni) {
            aesniEncryptBlock(block, &ciphertext[off]);
        } else {
            auto out = encryptECB(std::vector<uint8_t>(block, block + 16));
            for (int i = 0; i < 16; ++i) ciphertext[off + i] = out[i];
        }
        
        // Update previous for next iteration
        for (int i = 0; i < 16; ++i) prev[i] = ciphertext[off + i];
    }
    return ciphertext;
}

std::vector<uint8_t> AESEncryption::decryptCBC(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& iv) {
    if (iv.size() != 16) throw std::invalid_argument("IV must be 16 bytes");
    if (ciphertext.size() % 16 != 0) throw std::invalid_argument("Ciphertext must be a multiple of 16 bytes");
    std::vector<uint8_t> plaintext(ciphertext.size());
    uint8_t prev[16];
    for (int i = 0; i < 16; ++i) prev[i] = iv[i];

    for (size_t off = 0; off < ciphertext.size(); off += 16) {
        uint8_t decrypted[16];
        
        // Decrypt using AES-NI if available, otherwise software
        if (use_aesni) {
            aesniDecryptBlock(&ciphertext[off], decrypted);
        } else {
            std::vector<uint8_t> block(ciphertext.begin() + off, ciphertext.begin() + off + 16);
            auto dec = decryptECB(block);
            for (int i = 0; i < 16; ++i) decrypted[i] = dec[i];
        }
        
        // XOR with previous ciphertext block and store plaintext
        for (int i = 0; i < 16; ++i) {
            plaintext[off + i] = decrypted[i] ^ prev[i];
            prev[i] = ciphertext[off + i];  // Save for next iteration
        }
    }
    return plaintext;
}


static void increment_counter(std::vector<uint8_t>& counter) {
    for (int i = 15; i >= 0; --i) {
        if (++counter[i] != 0) break;
    }
}

std::vector<uint8_t> AESEncryption::encryptCTR(const std::vector<uint8_t>& data, const std::vector<uint8_t>& iv) {
    if (iv.size() != 16) throw std::invalid_argument("IV must be 16 bytes");
    std::vector<uint8_t> out(data.size());
    uint8_t counter[16];
    for (int i = 0; i < 16; ++i) counter[i] = iv[i];

    for (size_t off = 0; off < data.size(); ) {
        uint8_t keystream[16];
        
        // Encrypt counter block using AES-NI if available
        if (use_aesni) {
            aesniEncryptBlock(counter, keystream);
        } else {
            auto ks = encryptECB(std::vector<uint8_t>(counter, counter + 16));
            for (int i = 0; i < 16; ++i) keystream[i] = ks[i];
        }
        
        // XOR with plaintext
        size_t chunk = std::min<size_t>(16, data.size() - off);
        for (size_t i = 0; i < chunk; ++i) out[off + i] = data[off + i] ^ keystream[i];
        off += chunk;
        
        // Increment counter (big-endian)
        for (int i = 15; i >= 0; --i) {
            if (++counter[i] != 0) break;
        }
    }
    return out;
}

std::vector<uint8_t> AESEncryption::decryptCTR(const std::vector<uint8_t>& data, const std::vector<uint8_t>& iv) {
    // CTR encryption and decryption are identical
    return encryptCTR(data, iv);
}


static inline void xor_block(std::array<uint8_t,16>& dst, const std::array<uint8_t,16>& a) {
    for (int i=0;i<16;++i) dst[i] ^= a[i];
}

static inline std::array<uint8_t,16> vec16_from_ptr(const uint8_t *p) {
    std::array<uint8_t,16> r;
    for (int i=0;i<16;++i) r[i] = p[i];
    return r;
}

static inline void to_u64be(const std::array<uint8_t,16>& b, uint64_t &hi, uint64_t &lo) {
    hi = 0; lo = 0;
    for (int i = 0; i < 8; ++i) hi = (hi << 8) | b[i];
    for (int i = 8; i < 16; ++i) lo = (lo << 8) | b[i];
}
static inline std::array<uint8_t,16> from_u64be(uint64_t hi, uint64_t lo) {
    std::array<uint8_t,16> r;
    for (int i = 7; i >= 0; --i) { r[i] = hi & 0xff; hi >>= 8; }
    for (int i = 15; i >= 8; --i) { r[i] = lo & 0xff; lo >>= 8; }
    return r;
}

// Carry-less multiply in GF(2^128) per GCM (right-to-left method)
static inline std::array<uint8_t,16> ghash_mul(const std::array<uint8_t,16>& X, const std::array<uint8_t,16>& Y) {
    uint64_t xh, xl, yh, yl;
    to_u64be(X, xh, xl);
    to_u64be(Y, yh, yl);

    uint64_t Zh = 0, Zl = 0;
    uint64_t Vh = yh, Vl = yl;

    for (int i = 0; i < 128; ++i) {
        // test MSB of X (bit 127-i)
        bool bit;
        if (i < 64) bit = (xh & (1ULL << (63 - i))) != 0;
        else bit = (xl & (1ULL << (63 - (i-64)))) != 0;
        if (bit) { Zh ^= Vh; Zl ^= Vl; }
        // V = V >> 1; if (LSB prior == 1) V ^= R
        bool lsb = (Vl & 1) != 0;
        // shift right whole 128-bit V
        Vl = (Vh << 63) | (Vl >> 1);
        Vh = (Vh >> 1);
        if (lsb) {
            // XOR with R = 0xe1 << 120 == (0xe100000000000000ULL, 0x0ULL)
            Vh ^= 0xe100000000000000ULL;
        }
    }

    return from_u64be(Zh, Zl);
}

static inline std::array<uint8_t,16> ghash(const std::array<uint8_t,16>& H,
                                           const std::vector<uint8_t>& aad,
                                           const std::vector<uint8_t>& cipher) {
    std::array<uint8_t,16> Y{};
    // process aad blocks
    size_t off = 0;
    while (off + 16 <= aad.size()) {
        std::array<uint8_t,16> block;
        for (int i=0;i<16;++i) block[i] = aad[off+i];
        xor_block(Y, block);
        Y = ghash_mul(Y, H);
        off += 16;
    }
    if (off < aad.size()) {
        std::array<uint8_t,16> block{};
        for (size_t i=0;i<aad.size()-off;++i) block[i] = aad[off + i];
        xor_block(Y, block);
        Y = ghash_mul(Y, H);
    }
    // process ciphertext blocks
    off = 0;
    while (off + 16 <= cipher.size()) {
        std::array<uint8_t,16> block;
        for (int i=0;i<16;++i) block[i] = cipher[off+i];
        xor_block(Y, block);
        Y = ghash_mul(Y, H);
        off += 16;
    }
    if (off < cipher.size()) {
        std::array<uint8_t,16> block{};
        for (size_t i=0;i<cipher.size()-off;++i) block[i] = cipher[off + i];
        xor_block(Y, block);
        Y = ghash_mul(Y, H);
    }
    // length block: 64-bit lengths in bits, big-endian
    uint64_t aad_bits = static_cast<uint64_t>(aad.size()) * 8ULL;
    uint64_t cipher_bits = static_cast<uint64_t>(cipher.size()) * 8ULL;
    std::array<uint8_t,16> len_block{};
    for (int i=0;i<8;++i) len_block[7-i] = (uint8_t)((aad_bits >> (8*i)) & 0xff);
    for (int i=0;i<8;++i) len_block[15-i] = (uint8_t)((cipher_bits >> (8*i)) & 0xff);
    xor_block(Y, len_block);
    Y = ghash_mul(Y, H);
    return Y;
}

static inline bool ct_equal(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) return false;
    uint8_t x = 0;
    for (size_t i=0;i<a.size();++i) x |= a[i] ^ b[i];
    return x == 0;
}

std::vector<uint8_t> AESEncryption::encryptGCM(const std::vector<uint8_t>& plaintext,
                                               const std::vector<uint8_t>& iv,
                                               const std::vector<uint8_t>& aad,
                                               size_t tagLen) {
    if (tagLen == 0 || tagLen > 16) throw std::invalid_argument("tagLen must be 1..16");
    // H = E(K, 0^128)
    uint8_t zero16[16] = {0};
    uint8_t H_bytes[16];
    
    if (use_aesni) {
        aesniEncryptBlock(zero16, H_bytes);
    } else {
        auto Hvec = encryptECB(std::vector<uint8_t>(zero16, zero16 + 16));
        for (int i = 0; i < 16; ++i) H_bytes[i] = Hvec[i];
    }
    
    std::array<uint8_t,16> H;
    for (int i=0;i<16;++i) H[i] = H_bytes[i];

    // J0:
    std::array<uint8_t,16> J0{};
    if (iv.size() == 12) {
        for (int i=0;i<12;++i) J0[i] = iv[i];
        J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;
    } else {
        // J0 = GHASH(H, {}, iv)
        auto g = ghash(H, std::vector<uint8_t>{}, iv);
        J0 = g;
    }

    // ciphertext = CTR-enc starting with inc32(J0) (i.e., increment last 32 bits)
    std::vector<uint8_t> counter(16);
    for (int i=0;i<16;++i) counter[i] = J0[i];
    // increment counter
    increment_counter(counter);

    std::vector<uint8_t> ciphertext = encryptCTR(plaintext, counter);

    // Compute auth tag: S = GHASH(H, aad, ciphertext); tag = E(K, J0) xor S
    std::array<uint8_t,16> S = ghash(H, aad, ciphertext);
    
    uint8_t E_J0_bytes[16];
    if (use_aesni) {
        aesniEncryptBlock((const uint8_t*)J0.data(), E_J0_bytes);
    } else {
        auto E_J0 = encryptECB(std::vector<uint8_t>(J0.begin(), J0.end()));
        for (int i = 0; i < 16; ++i) E_J0_bytes[i] = E_J0[i];
    }
    
    std::vector<uint8_t> tag(16);
    for (int i=0;i<16;++i) tag[i] = E_J0_bytes[i] ^ S[i];
    tag.resize(tagLen);

    // return ciphertext || tag
    std::vector<uint8_t> out;
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    out.insert(out.end(), tag.begin(), tag.end());
    return out;
}

std::vector<uint8_t> AESEncryption::decryptGCM(const std::vector<uint8_t>& ciphertext_and_tag,
                                               const std::vector<uint8_t>& iv,
                                               const std::vector<uint8_t>& aad,
                                               size_t tagLen) {
    if (tagLen == 0 || tagLen > 16) throw std::invalid_argument("tagLen must be 1..16");
    if (ciphertext_and_tag.size() < tagLen) throw std::invalid_argument("Input too short");

    size_t clen = ciphertext_and_tag.size() - tagLen;
    std::vector<uint8_t> ciphertext(ciphertext_and_tag.begin(), ciphertext_and_tag.begin() + clen);
    std::vector<uint8_t> recv_tag(ciphertext_and_tag.begin() + clen, ciphertext_and_tag.end());

    // H = E(K, 0^128)
    uint8_t zero16[16] = {0};
    uint8_t H_bytes[16];
    
    if (use_aesni) {
        aesniEncryptBlock(zero16, H_bytes);
    } else {
        auto Hvec = encryptECB(std::vector<uint8_t>(zero16, zero16 + 16));
        for (int i = 0; i < 16; ++i) H_bytes[i] = Hvec[i];
    }
    
    std::array<uint8_t,16> H;
    for (int i=0;i<16;++i) H[i] = H_bytes[i];

    // J0:
    std::array<uint8_t,16> J0{};
    if (iv.size() == 12) {
        for (int i=0;i<12;++i) J0[i] = iv[i];
        J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;
    } else {
        auto g = ghash(H, std::vector<uint8_t>{}, iv);
        J0 = g;
    }

    // counter = inc32(J0)
    std::vector<uint8_t> counter(16);
    for (int i=0;i<16;++i) counter[i] = J0[i];
    increment_counter(counter);

    // Decrypt (CTR)
    std::vector<uint8_t> plaintext = encryptCTR(ciphertext, counter);

    // Compute expected tag
    std::array<uint8_t,16> S = ghash(H, aad, ciphertext);
    
    uint8_t E_J0_bytes[16];
    if (use_aesni) {
        aesniEncryptBlock((const uint8_t*)J0.data(), E_J0_bytes);
    } else {
        auto E_J0 = encryptECB(std::vector<uint8_t>(J0.begin(), J0.end()));
        for (int i = 0; i < 16; ++i) E_J0_bytes[i] = E_J0[i];
    }
    
    std::vector<uint8_t> expect_tag(16);
    for (int i=0;i<16;++i) expect_tag[i] = E_J0_bytes[i] ^ S[i];
    expect_tag.resize(tagLen);

    if (!ct_equal(expect_tag, recv_tag)) throw std::runtime_error("GCM authentication failed");

    return plaintext;
}


void AESEncryption::invSubBytes(std::vector<uint8_t>& state) {
    for (size_t i = 0; i < state.size(); ++i) state[i] = inv_sbox[state[i]];
}

void AESEncryption::invShiftRows(std::vector<uint8_t>& state) {
    std::vector<uint8_t> tmp(16);
    tmp[0] = state[0]; tmp[1] = state[13]; tmp[2] = state[10]; tmp[3] = state[7];
    tmp[4] = state[4]; tmp[5] = state[1]; tmp[6] = state[14]; tmp[7] = state[11];
    tmp[8] = state[8]; tmp[9] = state[5]; tmp[10] = state[2]; tmp[11] = state[15];
    tmp[12] = state[12]; tmp[13] = state[9]; tmp[14] = state[6]; tmp[15] = state[3];
    for (int i = 0; i < 16; ++i) state[i] = tmp[i];
}

void AESEncryption::invMixColumns(std::vector<uint8_t>& state) {
    auto gf_mul = [](uint8_t a, uint8_t b) -> uint8_t {
        uint8_t res = 0;
        uint8_t t = a;
        for (int i = 0; i < 8; ++i) {
            if (b & 1) res ^= t;
            bool hi = (t & 0x80) != 0;
            t = (uint8_t)(t << 1);
            if (hi) t ^= 0x1b;
            b >>= 1;
        }
        return res;
    };
    for (int c = 0; c < 4; ++c) {
        int i = c * 4;
        uint8_t a0 = state[i+0];
        uint8_t a1 = state[i+1];
        uint8_t a2 = state[i+2];
        uint8_t a3 = state[i+3];
        state[i+0] = (uint8_t)(gf_mul(a0,0x0e) ^ gf_mul(a1,0x0b) ^ gf_mul(a2,0x0d) ^ gf_mul(a3,0x09));
        state[i+1] = (uint8_t)(gf_mul(a0,0x09) ^ gf_mul(a1,0x0e) ^ gf_mul(a2,0x0b) ^ gf_mul(a3,0x0d));
        state[i+2] = (uint8_t)(gf_mul(a0,0x0d) ^ gf_mul(a1,0x09) ^ gf_mul(a2,0x0e) ^ gf_mul(a3,0x0b));
        state[i+3] = (uint8_t)(gf_mul(a0,0x0b) ^ gf_mul(a1,0x0d) ^ gf_mul(a2,0x09) ^ gf_mul(a3,0x0e));
    }
}

std::string AESEncryption::encryptString(const std::string& plaintext,AESMode mode, const std::vector<uint8_t>* iv) {
    
    if (mode == AESMode::CBC || mode == AESMode::CTR) {
        if (!iv) throw std::invalid_argument("IV is required for CBC and CTR modes");
        if (iv->size() != 16) throw std::invalid_argument("IV must be 16 bytes");
    }
    std::vector<uint8_t> plainBytes(plaintext.begin(), plaintext.end());
    plainBytes = pad(plainBytes);  // Pad to multiple of 16 bytes if necessary
    std::vector<uint8_t> cipherBytes;
    switch(mode) {
        case AESMode::ECB:
            cipherBytes = encryptECB(plainBytes);
            break;
        case AESMode::CBC:
            cipherBytes = encryptCBC(plainBytes, *iv);
            break;
        case AESMode::CTR:
            cipherBytes = encryptCTR(plainBytes, *iv);
            break;
        case AESMode::GCM:
            throw std::invalid_argument("encryptString does not support GCM mode");
    }
    return std::string(cipherBytes.begin(), cipherBytes.end());
}   

std::string AESEncryption::decryptString(const std::string& ciphertext,AESMode mode, const std::vector<uint8_t>* iv) {

        if (mode == AESMode::CBC || mode == AESMode::CTR) {
        if (!iv) throw std::invalid_argument("IV is required for CBC and CTR modes");
        if (iv->size() != 16) throw std::invalid_argument("IV must be 16 bytes");
    }
    std::vector<uint8_t> cipherBytes(ciphertext.begin(), ciphertext.end());
    std::vector<uint8_t> plainBytes;
    switch(mode) {
        case AESMode::ECB:
            plainBytes = decryptECB(cipherBytes);
            break;
        case AESMode::CBC:
            plainBytes = decryptCBC(cipherBytes, *iv);
            break;
        case AESMode::CTR:
            plainBytes = decryptCTR(cipherBytes, *iv);
            break;
        case AESMode::GCM:
            throw std::invalid_argument("decryptString does not support GCM mode");
    }
    plainBytes = unpad(plainBytes);  // Pad to multiple of 16 bytes if necessary
    return std::string(plainBytes.begin(), plainBytes.end());
}   

std::vector<uint8_t> AESEncryption::pad(const std::vector<uint8_t>& data) {
    size_t pad_len = 16 - (data.size() % 16);
    std::vector<uint8_t> padded(data);
    padded.insert(padded.end(), pad_len, static_cast<uint8_t>(pad_len));
    return padded;
}

std::vector<uint8_t> AESEncryption::unpad(const std::vector<uint8_t>& data) {
    if (data.empty()) throw std::invalid_argument("Cannot unpad empty data");
    uint8_t pad_len = data.back();
    if (pad_len == 0 || pad_len > 16) throw std::invalid_argument("Invalid padding");
    if (data.size() < pad_len) throw std::invalid_argument("Invalid padding length");
    
    // Verify all padding bytes match
    for (size_t i = data.size() - pad_len; i < data.size(); ++i) {
        if (data[i] != pad_len) throw std::invalid_argument("Invalid padding");
    }
    
    return std::vector<uint8_t>(data.begin(), data.end() - pad_len);
}


static bool aes_ni_supported(void) {
    unsigned int eax, ebx, ecx, edx;
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx))
        return false;
    return (ecx & bit_AES) != 0;  // AES-NI bit
}

#endif // AESPLUSPLUS_H