#include "Frame.h"
#include "Crypto/AES.h"

namespace WMBus {

// ── 3of6 decode (T1 mode) ─────────────────────────────────────────────────
//
// EN 13757-4 Table A.1 — each nibble maps to a 6-bit symbol with exactly 3 set bits.

static const uint8_t DECODE_TABLE[64] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x00-0x07
    0xFF, 0xFF, 0xFF, 0x03, 0xFF, 0x01, 0x02, 0xFF, // 0x08-0x0F
    0xFF, 0xFF, 0xFF, 0x07, 0xFF, 0xFF, 0x00, 0xFF, // 0x10-0x17
    0xFF, 0x05, 0x06, 0xFF, 0x04, 0xFF, 0xFF, 0xFF, // 0x18-0x1F
    0xFF, 0xFF, 0xFF, 0x0B, 0xFF, 0x09, 0x0A, 0xFF, // 0x20-0x27
    0xFF, 0x0F, 0xFF, 0xFF, 0x08, 0xFF, 0xFF, 0xFF, // 0x28-0x2F
    0xFF, 0x0D, 0x0E, 0xFF, 0x0C, 0xFF, 0xFF, 0xFF, // 0x30-0x37
    // ^ EN 13757-4 Table A.1: symbol 0x32→E, 0x34→C (were swapped → C/E corruption)
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x38-0x3F
};

uint16_t Frame::decode3of6(const uint8_t* raw, uint16_t rawLen, uint8_t* out, uint16_t outMax) {
    uint16_t outIdx    = 0;
    uint32_t bitBuf    = 0;
    uint8_t  bitsInBuf = 0;

    for (uint16_t i = 0; i < rawLen && outIdx < outMax; i++) {
        bitBuf = (bitBuf << 8) | raw[i];
        bitsInBuf += 8;

        while (bitsInBuf >= 12 && outIdx < outMax) {
            bitsInBuf -= 12;
            uint8_t sym_hi = (bitBuf >> (bitsInBuf + 6)) & 0x3F;
            uint8_t sym_lo = (bitBuf >>  bitsInBuf)      & 0x3F;

            uint8_t hi = DECODE_TABLE[sym_hi];
            uint8_t lo = DECODE_TABLE[sym_lo];
            if (hi == 0xFF || lo == 0xFF) return outIdx;

            out[outIdx++] = (hi << 4) | lo;
        }
    }
    return outIdx;
}

// ── Manchester decode (S1 mode) ───────────────────────────────────────────
//
// EN 13757-4 S-mode is Manchester coded (TI table): each 4-bit Manchester
// nibble carries 2 data bits — 0xA→00, 0x9→01, 0x6→10, 0x5→11; every other
// value is an invalid Manchester symbol (RF bit error). Two encoded bytes
// (16 chips) therefore yield one decoded data byte. The CC1101 is configured
// WITHOUT hardware Manchester (MDMCFG2 bit3 = 0), so it delivers the raw chip
// stream and we decode here — mirroring the software 3of6 path used for T1.

static const uint8_t MANCH_TABLE[16] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x03, 0x02, 0xFF,
    0xFF, 0x01, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

uint16_t Frame::decodeManchester(const uint8_t* raw, uint16_t rawLen,
                                 uint8_t* out, uint16_t outMax) {
    uint16_t outIdx = 0;
    for (uint16_t i = 0; i + 1 < rawLen && outIdx < outMax; i += 2) {
        uint8_t n3 = MANCH_TABLE[(raw[i]     >> 4) & 0x0F];
        uint8_t n2 = MANCH_TABLE[ raw[i]            & 0x0F];
        uint8_t n1 = MANCH_TABLE[(raw[i + 1] >> 4) & 0x0F];
        uint8_t n0 = MANCH_TABLE[ raw[i + 1]        & 0x0F];
        if (n3 == 0xFF || n2 == 0xFF || n1 == 0xFF || n0 == 0xFF)
            return outIdx;
        out[outIdx++] = (uint8_t)((n3 << 6) | (n2 << 4) | (n1 << 2) | n0);
    }
    return outIdx;
}

// ── CRC strip ─────────────────────────────────────────────────────────────
// Block 1: 10 data bytes + 2 CRC; subsequent blocks: ≤16 data + 2 CRC each.

uint16_t Frame::stripCRC(const uint8_t* in, uint16_t inLen, uint8_t* out, uint16_t outMax) {
    if (inLen < 1 || outMax == 0) return 0;

    if (inLen < 10) {
        uint16_t n = (inLen < outMax) ? inLen : outMax;
        memcpy(out, in, n);
        return n;
    }
    uint16_t n = (10u < outMax) ? 10u : outMax;
    memcpy(out, in, n);
    uint16_t outLen = n;

    uint8_t  L        = in[0];
    uint8_t  dataLeft = (L >= 9u) ? (uint8_t)(L - 9u) : 0u;
    uint16_t src      = 12;

    while (src < inLen && outLen < outMax && dataLeft > 0) {
        uint8_t  blockData = (dataLeft >= 16u) ? 16u : dataLeft;
        uint16_t available = inLen - src;

        if (available >= blockData + 2u) {
            uint16_t toCopy = (blockData < (outMax - outLen))
                              ? blockData : (outMax - outLen);
            memcpy(out + outLen, in + src, toCopy);
            outLen   += toCopy;
            src      += blockData + 2u;
            dataLeft -= blockData;
        } else {
            uint16_t toCopy = (available < (outMax - outLen))
                              ? available : (outMax - outLen);
            memcpy(out + outLen, in + src, toCopy);
            outLen += toCopy;
            break;
        }
    }
    return outLen;
}

// ── TPL (Transport Presentation Layer) header parser ──────────────────────
// Reads AccessNo, Status, config bytes and computes payloadOffset.
// tpl_pos is the byte index of CI=0x7A in buf.

void Frame::parseTpl(const uint8_t* buf, uint16_t len,
                     uint8_t tpl_pos, Frame& f, uint8_t& payloadOffset) {
    if (tpl_pos + 4 >= len) return;
    f._accessNo   = buf[tpl_pos + 1];
    f._status     = buf[tpl_pos + 2];
    f._cfgLo      = buf[tpl_pos + 3];
    uint8_t cfgHi = buf[tpl_pos + 4];

    // OMS / EN 13757-7 configuration word (16-bit LE = cfgHi<<8 | cfgLo):
    //   security mode      = bits 8-12  → cfgHi & 0x1f
    //   num encrypted blks = bits 4-7   → high nibble of cfgLo
    // Mode 7 keeps its own detection (cfgHi & 0x07 == 7) and 3-byte config.
    f._encMode = (cfgHi & 0x07) == 7 ? 7 : (cfgHi & 0x1f);

    uint8_t cfgBytes;
    f._encBlocks = (f._cfgLo & 0xF0) >> 4;
    cfgBytes     = (f._encMode == 7) ? 3 : 2;
    payloadOffset = tpl_pos + 3 + cfgBytes;
}

// ── Factory ───────────────────────────────────────────────────────────────

Frame Frame::parse(const uint8_t* buf, uint16_t len) {
    Frame f{};
    if (len < MIN_FRAME_BYTES) return f;

    // L-field declares the full (CRC-stripped) frame length = L + 1. Comparing
    // it to len lets complete() detect a truncated telegram (see Frame.h).
    f._lField      = buf[OFF_L];
    f._receivedLen = len;

    f._vendor[0] = buf[OFF_M];
    f._vendor[1] = buf[OFF_M + 1];

    f._meterId = ((uint32_t)buf[OFF_ID + 3] << 24) |
                 ((uint32_t)buf[OFF_ID + 2] << 16) |
                 ((uint32_t)buf[OFF_ID + 1] <<  8) |
                  (uint32_t)buf[OFF_ID];

    f._version = buf[OFF_VER];
    f._devType = buf[OFF_DEV];
    f._ci      = buf[OFF_CI];

    uint8_t payloadOffset = 0;

    if (f._ci == CI_VARIABLE_SHORT && len >= OFF_DATA + 4) {
        parseTpl(buf, len, OFF_CI, f, payloadOffset);

    } else if (f._ci == CI_ELL_I || f._ci == CI_ELL_I_BITERR) {
        // ELL-I: CC + ACC at OFF_DATA, then AFL CI
        uint8_t p = OFF_DATA + 2;
        if (p >= len) { f._valid = true; return f; }

        if (buf[p] == CI_AFL && p + 1 < len) {
            uint8_t afl_len     = buf[p + 1];
            uint8_t afl_content = p + 2;

            if (afl_content + 2 <= len) {
                uint16_t fcl = (uint16_t)buf[afl_content] |
                               ((uint16_t)buf[afl_content + 1] << 8);
                uint8_t off = afl_content + 2;
                if ((fcl & 0x2000) && off < len) off++;
                if ((fcl & 0x0800) && off + 4 <= len) {
                    memcpy(f._mcr, buf + off, 4);
                    off += 4;
                }
            }

            uint8_t tpl_pos = p + 2 + afl_len;
            if (tpl_pos < len && buf[tpl_pos] == CI_VARIABLE_SHORT)
                parseTpl(buf, len, tpl_pos, f, payloadOffset);
        }

    } else if (f._ci == CI_ELL_II) {
        // ELL-II: CC(1) + ACC(1) + SN(4) + CRC(2) = 8 bytes, then application CI
        uint8_t app_ci_pos = OFF_CI + 9;
        if (app_ci_pos >= len) { f._valid = true; return f; }

        if (buf[app_ci_pos] == CI_VARIABLE_SHORT)
            parseTpl(buf, len, app_ci_pos, f, payloadOffset);
        else if (buf[app_ci_pos] == CI_VARIABLE_NOHEADER && app_ci_pos + 1 < len)
            payloadOffset = app_ci_pos + 1;
    }

    // Copy payload (ciphertext or plaintext) into the Frame
    if (payloadOffset > 0 && payloadOffset < len) {
        uint16_t payloadLen = len - payloadOffset;
        uint16_t toCopy = (payloadLen < sizeof(f._payload))
                          ? payloadLen : (uint16_t)sizeof(f._payload);
        memcpy(f._payload, buf + payloadOffset, toCopy);
        f._payloadLen = toCopy;
    }

    f._valid = true;
    return f;
}

// ── Decryption ────────────────────────────────────────────────────────────

bool Frame::decrypt(const uint8_t* key) {
    if (!key || !_valid || _encMode == ENC_NONE || _encBlocks == 0) return false;

    uint8_t toDecrypt = (uint8_t)(_encBlocks * 16u);
    if (toDecrypt > _payloadLen) return false;

    uint8_t tmp[MAX_PAYLOAD];

    switch (_encMode) {
        case ENC_AES: {
            // Mode 5 — AES-128-CBC with frame-derived IV (EN 13757-3 §9, OMS):
            //   IV = M(2) | ID(4 LE) | version | devType | accessNo × 8
            uint8_t iv[16];
            iv[0]  = _vendor[0];
            iv[1]  = _vendor[1];
            iv[2]  = (_meterId >>  0) & 0xFF;
            iv[3]  = (_meterId >>  8) & 0xFF;
            iv[4]  = (_meterId >> 16) & 0xFF;
            iv[5]  = (_meterId >> 24) & 0xFF;
            iv[6]  = _version;
            iv[7]  = _devType;
            for (uint8_t i = 8; i < 16; i++) iv[i] = _accessNo;
            Crypto::AES::cbcDecrypt(key, iv, _payload, tmp, toDecrypt);
            break;
        }
        case ENC_OMS_AES: {
            // Mode 7 — Kenc = AES-CMAC(masterKey, 0x00 || MCR[4] || meterID[4 LE] || 0x07×7)
            uint8_t kdfInput[16];
            kdfInput[0] = 0x00;
            memcpy(kdfInput + 1, _mcr, 4);
            kdfInput[5] = (_meterId >>  0) & 0xFF;
            kdfInput[6] = (_meterId >>  8) & 0xFF;
            kdfInput[7] = (_meterId >> 16) & 0xFF;
            kdfInput[8] = (_meterId >> 24) & 0xFF;
            memset(kdfInput + 9, 0x07, 7);

            uint8_t kenc[16];
            Crypto::AES::cmac16(key, kdfInput, kenc);

            const uint8_t iv0[16] = {};
            Crypto::AES::cbcDecrypt(kenc, iv0, _payload, tmp, toDecrypt);
            break;
        }
        default:
            return false;
    }

    memcpy(_payload, tmp, toDecrypt);
    _decrypted = (_payload[0] == 0x2F && _payload[1] == 0x2F);
    return _decrypted;
}

const char* Frame::vendorStr() const {
    static char buf[4];
    uint16_t w = ((uint16_t)_vendor[1] << 8) | _vendor[0];
    buf[0] = (char)(((w >> 10) & 0x1F) + 'A' - 1);
    buf[1] = (char)(((w >>  5) & 0x1F) + 'A' - 1);
    buf[2] = (char)(((w >>  0) & 0x1F) + 'A' - 1);
    buf[3] = '\0';
    return buf;
}

} // namespace WMBus
