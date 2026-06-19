#pragma once
#include <Arduino.h>

namespace WMBus {

// Receive mode (also used by WMBus.h API)
enum class Mode : uint8_t {
    T1C1B = 0,  // combined: T1 PHY (sync 0x543D), auto-detect 3of6 (T1) or raw+CRC (C1B)
    T1    = 1,  // 3of6 encoded, sync 0x543D
    C1A   = 2,  // raw bytes,    sync 0x54CD (Frame A)
    C1B   = 3,  // raw bytes,    sync 0x543D (Frame B) — same PHY as C1A, B-format
    S1    = 4,  // raw bytes,    sync 0x7696, longer preamble
};

// Parsed wMBus frame.  Holds header metadata, payload (ciphertext or plaintext),
// and RSSI/mode annotations added by the WMBus layer.
class Frame {
public:
    // ── Byte offsets in a decoded, CRC-stripped frame ─────────────────────
    static constexpr uint8_t OFF_L    = 0;
    static constexpr uint8_t OFF_C    = 1;
    static constexpr uint8_t OFF_M    = 2;
    static constexpr uint8_t OFF_ID   = 4;
    static constexpr uint8_t OFF_VER  = 8;
    static constexpr uint8_t OFF_DEV  = 9;
    static constexpr uint8_t OFF_CI   = 10;
    static constexpr uint8_t OFF_DATA = 11;
    static constexpr uint8_t MIN_FRAME_BYTES = 11;

    // Max ciphertext/plaintext bytes. Sized to cover the largest possible stripped
    // frame (L=0xFF → 256 decoded bytes minus 11-byte header = 245 data bytes).
    static constexpr uint16_t MAX_PAYLOAD = 256;

    // ── CI field values ───────────────────────────────────────────────────
    static constexpr uint8_t CI_VARIABLE_SHORT = 0x7A;
    static constexpr uint8_t CI_VARIABLE_NOHEADER = 0x78; // no TPL header, payload follows directly
    static constexpr uint8_t CI_ELL_I          = 0x8C;
    static constexpr uint8_t CI_ELL_I_BITERR   = 0x8E;  // our CC1101 flips bit 1
    static constexpr uint8_t CI_ELL_II         = 0x8D;  // ELL-II: CC+ACC+SN(4)+CRC(2) after CI
    static constexpr uint8_t CI_AFL            = 0x90;

    // ── Encryption mode in config word ────────────────────────────────────
    static constexpr uint8_t ENC_NONE    = 0;
    static constexpr uint8_t ENC_AES     = 5;   // EN 13757-3 AES-CBC, CI=0x7A
    static constexpr uint8_t ENC_OMS_AES = 7;   // OMS Security Profile B

    // ── Static decode pipeline ────────────────────────────────────────────
    // T1 mode: decode 3-of-6 symbols. Returns decoded length, 0 on error.
    static uint16_t decode3of6(const uint8_t* raw, uint16_t rawLen,
                                uint8_t* out, uint16_t outMax);
    // S1 mode: Manchester decode (2 encoded bytes → 1 data byte, EN 13757-4 /
    // TI manchester table). Stops on the first invalid Manchester nibble and
    // returns the bytes decoded so far. After decoding, an S-mode frame is a
    // Frame A (with per-block CRCs) — identical to C1A from stripCRC() onward.
    static uint16_t decodeManchester(const uint8_t* raw, uint16_t rawLen,
                                     uint8_t* out, uint16_t outMax);
    // Remove per-block CRC bytes from a decoded stream.
    static uint16_t stripCRC(const uint8_t* in, uint16_t inLen,
                              uint8_t* out, uint16_t outMax);

    // ── Factory ───────────────────────────────────────────────────────────
    // Build a Frame from a decoded, CRC-stripped buffer.
    // The payload (ciphertext or plaintext) is copied into the Frame.
    static Frame parse(const uint8_t* stripped, uint16_t len);

    // ── Accessors ─────────────────────────────────────────────────────────
    bool     valid()      const { return _valid; }
    bool     encrypted()  const { return _encMode != ENC_NONE && _encBlocks > 0; }
    bool     decrypted()  const { return _decrypted; }

    uint32_t       meterId()   const { return _meterId; }
    const uint8_t* vendor()    const { return _vendor; }
    const char*    vendorStr() const;   // Returns 3-char vendor code (e.g., "DME")
    uint8_t        version()   const { return _version; }
    uint8_t        devType()   const { return _devType; }
    uint8_t        ci()        const { return _ci; }
    uint8_t        accessNo()  const { return _accessNo; }
    uint8_t        status()    const { return _status; }
    uint8_t        encMode()   const { return _encMode; }
    uint8_t        encBlocks() const { return _encBlocks; }
    const uint8_t* mcr()       const { return _mcr; }

    const uint8_t* payload()    const { return _payload; }
    uint16_t       payloadLen() const { return _payloadLen; }

    uint8_t  rssi()    const { return _rssi; }
    int8_t   rssiDbm() const { return _rssiDbm; }
    Mode     rxMode()  const { return _rxMode; }

    // Per-block EN 13757-4 CRC result for the raw frame this was decoded from.
    // crcOk() == true means every block's CRC matched → the bytes are clean.
    uint8_t  badBlocks()   const { return _badBlocks; }
    uint8_t  totalBlocks() const { return _totalBlocks; }
    bool     crcOk()       const { return _totalBlocks > 0 && _badBlocks == 0; }

    // Telegram completeness. The L-field (byte 0, inside the CRC-clean block 1)
    // declares the full frame length, so a short receivedLen() means the frame
    // was truncated — the 3of6 decode aborted on a bad symbol (RF bit error) or
    // the FIFO drain was cut short. The bytes we DID get are still CRC-clean, but
    // the telegram is incomplete: when complete() == false the encryption and
    // payload fields are partial and must NOT be trusted (e.g. encMode()==0 then
    // means "TPL header not reached", not "unencrypted").
    uint16_t expectedLen() const { return _lField ? (uint16_t)(_lField + 1u) : 0u; }
    uint16_t receivedLen() const { return _receivedLen; }
    bool     complete()    const { return _lField > 0 && _receivedLen > _lField; }

    // ── Decryption ────────────────────────────────────────────────────────
    // Decrypts the stored payload in-place using the given 16-byte key.
    // Mode is inferred from encMode() (5 = EN 13757-3, 7 = OMS Profile B).
    // Returns true when decryption succeeds and the result starts with 0x2F 0x2F.
    // Passing nullptr returns false immediately.
    bool decrypt(const uint8_t* key);

    // ── Set by WMBus layer after construction ─────────────────────────────
    void setRssi(uint8_t raw, int8_t dbm)   { _rssi = raw; _rssiDbm = dbm; }
    void setRxMode(Mode mode)                { _rxMode = mode; }
    void setCrc(uint8_t bad, uint8_t total)  { _badBlocks = bad; _totalBlocks = total; }


private:
    bool     _valid      = false;
    bool     _decrypted  = false;

    uint8_t  _vendor[2]  = {};
    uint32_t _meterId    = 0;
    uint8_t  _version    = 0;
    uint8_t  _devType    = 0;
    uint8_t  _ci         = 0;
    uint8_t  _accessNo   = 0;
    uint8_t  _status     = 0;
    uint8_t  _cfgLo      = 0;   // first config byte (used in mode 5 IV)
    uint8_t  _encMode    = 0;
    uint8_t  _encBlocks  = 0;
    uint8_t  _mcr[4]     = {};  // AFL message counter (mode 7 KDF input)

    uint8_t  _payload[MAX_PAYLOAD] = {};
    uint16_t _payloadLen  = 0;

    uint8_t  _rssi    = 0;
    int8_t   _rssiDbm = 0;
    Mode     _rxMode  = Mode::T1;

    uint8_t  _badBlocks   = 0;
    uint8_t  _totalBlocks = 0;

    uint8_t  _lField      = 0;   // L-field: declared bytes after L (excl L & CRC)
    uint16_t _receivedLen = 0;   // stripped bytes actually parsed into this Frame

    static void parseTpl(const uint8_t* buf, uint16_t len,
                         uint8_t tpl_pos, Frame& f, uint8_t& payloadOffset);
};

} // namespace WMBus
