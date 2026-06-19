#pragma once
#include <Arduino.h>

namespace WMBus {
namespace Crypto {

// EN 13757-4 CRC-16: poly 0x3D65, init 0x0000, output XOR 0xFFFF
class CRC {
public:
    static uint16_t compute(const uint8_t* data, uint8_t len);
    // Returns true when the 2 bytes after data[0..dataLen-1] match the computed CRC
    static bool     check(const uint8_t* block, uint8_t dataLen);
};

} // namespace Crypto
} // namespace WMBus
