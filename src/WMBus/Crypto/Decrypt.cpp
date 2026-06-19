#include "Decrypt.h"

namespace WMBus {
namespace Crypto {

void Decrypt::setKey(uint32_t meterId, const uint8_t key[16]) {
    for (auto& e : _keyStore) {
        if (e.used && e.meterId == meterId) { memcpy(e.key, key, 16); return; }
    }
    for (auto& e : _keyStore) {
        if (!e.used) { e.meterId = meterId; e.used = true; memcpy(e.key, key, 16); return; }
    }
    // Key store full — overwrite first slot
    _keyStore[0].meterId = meterId; _keyStore[0].used = true; memcpy(_keyStore[0].key, key, 16);
}

void Decrypt::removeKey(uint32_t meterId) {
    for (auto& e : _keyStore) {
        if (e.used && e.meterId == meterId) { e.used = false; memset(e.key, 0, 16); return; }
    }
}

const uint8_t* Decrypt::getKey(uint32_t meterId) const {
    for (const auto& e : _keyStore) {
        if (e.used && e.meterId == meterId) return e.key;
    }
    return nullptr;
}

} // namespace Crypto
} // namespace WMBus
