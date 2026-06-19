#pragma once
#include <Arduino.h>

namespace WMBus {
namespace Crypto {

class AES {
public:
    static constexpr uint8_t RK_SIZE = 176;

    static void keyExpansion(const uint8_t* key, uint8_t* rk);
    static void encryptBlock(const uint8_t* in, uint8_t* out, const uint8_t* rk);
    static void decryptBlock(const uint8_t* in, uint8_t* out, const uint8_t* rk);
    static void cbcDecrypt(const uint8_t* key, const uint8_t* iv,
                           const uint8_t* in, uint8_t* out, uint8_t len);
    static void cmac16(const uint8_t* key, const uint8_t* msg, uint8_t* mac);
};

} // namespace Crypto
} // namespace WMBus
