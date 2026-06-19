#pragma once
#include <Arduino.h>

namespace WMBus {
namespace Crypto {

// AES-128 key registry — maps meter IDs to keys for auto-decryption.
// One instance owns its own key table; decryption itself lives on
// Frame::decrypt(key).
class Decrypt {
public:
    static constexpr uint8_t MAX_KEYS = 8;

    void           setKey(uint32_t meterId, const uint8_t key[16]);
    void           removeKey(uint32_t meterId);
    const uint8_t* getKey(uint32_t meterId) const;  // nullptr if not registered

private:
    struct KeyEntry {
        uint32_t meterId = 0;
        uint8_t  key[16] = {};
        bool     used    = false;
    };
    KeyEntry _keyStore[MAX_KEYS]{};
};

} // namespace Crypto
} // namespace WMBus
