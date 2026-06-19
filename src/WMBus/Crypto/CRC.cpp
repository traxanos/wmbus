#include "CRC.h"

namespace WMBus {
namespace Crypto {

uint16_t CRC::compute(const uint8_t* data, uint8_t len) {
    uint16_t crc = 0x0000;
    for (uint8_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (uint8_t b = 0; b < 8; b++)
            crc = (crc & 0x8000) ? (crc << 1) ^ 0x3D65 : (crc << 1);
    }
    return ~crc;
}

bool CRC::check(const uint8_t* block, uint8_t dataLen) {
    if (dataLen < 2) return false;
    uint16_t computed = compute(block, dataLen);
    uint16_t stored   = ((uint16_t)block[dataLen] << 8) | block[dataLen + 1];
    return computed == stored;
}

} // namespace Crypto
} // namespace WMBus
