```markdown
A single .h file that implements AES encryption 128, 192, 256, ECB, CBC, CTR, and GCM.

**Usage Examples**

A few short examples showing common usage of the `AESEncryption` class.

- **ECB (block-aligned)**: encrypt/decrypt a single 16-byte block

```cpp
#include "aesplusplus.h"
#include <vector>
#include <iostream>

int main() {
    std::vector<uint8_t> key = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    std::vector<uint8_t> plain = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    AESEncryption aes(key);
    auto cipher = aes.encryptECB(plain);
    auto recovered = aes.decryptECB(cipher);
    std::cout << (recovered == plain ? "OK\n" : "Mismatch\n");
}
```

- **String convenience (PKCS#7 padding, ECB by default)**

```cpp
AESEncryption aes(key);
std::string ct = aes.encryptString("hello world"); // returns raw bytes in a std::string
std::string pt = aes.decryptString(ct);
```

- **CTR (stream, arbitrary length)**

```cpp
std::vector<uint8_t> iv = { /* 16 bytes IV */ 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
auto ct = aes.encryptCTR(std::vector<uint8_t>{/* data */}, iv);
auto pt = aes.decryptCTR(ct, iv);
```

- **GCM (authenticated encryption)**

```cpp
auto out = aes.encryptGCM(plaintext_bytes, iv12bytes, aad_bytes, 16); // returns ciphertext||tag
auto plain = aes.decryptGCM(out, iv12bytes, aad_bytes, 16); // throws on bad tag
```

```
