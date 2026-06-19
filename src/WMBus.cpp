#include "WMBus.h"
#include "WMBus/Radio/CC1101.h"
#include "WMBus/Crypto/CRC.h"
#include <SPI.h>
#include <stdarg.h>

namespace WMBus {

// ── File-local constants ─────────────────────────────────────────────────────
namespace {

// T1 infinite-mode FIFO accumulation.
//
// GDO0 RISING (sync word) → starts a 50 ms accumulation window.
// Expected raw size is computed from the L-field (3of6-peeked after ≥2 bytes).
constexpr uint16_t T1_DRAIN_MS   = 50;   // frame ≈ 41 ms at 32 kbaud

// C1 infinite-mode FIFO accumulation (Frame A and Frame B, same strategy as T1).
//
// GDO0 RISING (sync word) → starts a 30 ms accumulation window.
// C1 runs at ~100 kbaud; a max-size Frame A (192 raw bytes) takes ≈15 ms.
constexpr uint16_t C1A_DRAIN_MS = 30;

// S1 infinite-mode FIFO accumulation. S-mode runs at only 32.73 kBaud and is
// Manchester coded (2 raw bytes per data byte), so a full frame is ~2× the
// bytes of C1 at ~1/3 the rate → much longer on air. A 105-byte L-field frame
// is ~240 raw bytes ≈ 59 ms; allow headroom.
constexpr uint16_t S1_DRAIN_MS = 80;

// Expected raw Frame A size (with inter-block CRCs) for a given L-field value.
// Frame B is shorter but this is the upper bound — we use it as the drain target.
// Returns uint16_t: a max frame (L=0xFF) is 290 bytes, which does not fit in a
// uint8_t. For S1 the caller doubles this (Manchester), so the wider type also
// keeps the doubled target correct before it is clamped to MAX_RAW_FRAME.
static uint16_t c1ExpectedRaw(uint8_t L) {
    uint8_t  dataRem   = (L >= 9u) ? (uint8_t)(L - 9u) : 0u;
    uint8_t  numBlocks = (uint8_t)((dataRem + 15u) / 16u);
    uint16_t total     = 12u + dataRem + 2u * numBlocks;
    return (total < Radio::MAX_RAW_FRAME) ? total : Radio::MAX_RAW_FRAME;
}

// C-mode (C1/C1B) frames sometimes arrive with the 2-byte sync word still ahead
// of the L-field in the FIFO (Frame B 0x543D, Frame A 0x54CD), depending on where
// the CC1101 locked onto the preamble — some chips strip it, some leave it in.
// Return the offset of a CRC-valid block 1: 0 (no prefix) or 2 (sync prefix), or
// 0xFF if no valid block 1 is present in the leading bytes.
static uint8_t c1Block1Offset(const uint8_t* b, uint16_t n) {
    if (n >= 12u && Crypto::CRC::check(b, 10)) return 0u;
    if (n >= 14u && b[0] == 0x54 && (b[1] == 0x3D || b[1] == 0xCD) &&
        Crypto::CRC::check(b + 2, 10)) return 2u;
    return 0xFFu;
}


// C1B / Frame Format B helpers.
//
// Important: this is NOT a meter-specific workaround.  It follows the generic
// frame layout summarized in EN 13757-4 application notes:
//   - sync 0x543D may be present before the L-field,
//   - after sync removal, byte 0 is L,
//   - for Frame B the L-field includes the following bytes INCLUDING CRC bytes,
//   - the first 10 bytes are L, C, M-field and A-field,
//   - CI follows at byte 10,
//   - CRC(s) are at the end of the following data block(s).
//
// Therefore C1B must NOT be validated with the Frame-A block-1 CRC rule
// (CRC over decoded[0..9] at decoded[10..11]); decoded[10] is the CI-field.
static bool c1ASyncPrefix(const uint8_t* b, uint16_t n) {
    return n >= 2u && b[0] == 0x54 && b[1] == 0xCD;
}

static bool c1BSyncPrefix(const uint8_t* b, uint16_t n) {
    return n >= 2u && b[0] == 0x54 && b[1] == 0x3D;
}

// Raw C1B length after optional sync removal: L-field byte plus L following
// bytes.  This is needed because infinite FIFO drain can collect a few bytes
// behind the actual telegram.
static uint16_t c1BExpectedRaw(uint8_t L) {
    uint16_t total = 1u + (uint16_t)L;
    return (total < Radio::MAX_RAW_FRAME) ? total : Radio::MAX_RAW_FRAME;
}

// Validate and strip CRCs from C1B / Frame Format B into the same CRC-free
// representation that Frame::parse() expects: L C M A CI DATA...
//
// Format B short case, L <= 127:
//   [0..9]       L C M A
//   [10..N-3]    CI + data
//   [N-2..N-1]   CRC over [10..N-3]
//
// Format B long case, L >= 129:
//   [0..9]       L C M A
//   [10..125]    CI + first data part, 116 bytes
//   [126..127]   CRC over [10..125]
//   [128..N-3]   optional data part
//   [N-2..N-1]   CRC over [128..N-3]
//
// L=128 is structurally impossible for this block split and is rejected.
static bool c1BStripCRC(const uint8_t* in, uint16_t inLen,
                        uint8_t* out, uint16_t outMax,
                        uint16_t& outLen, uint8_t& crcBlocks) {
    outLen    = 0;
    crcBlocks = 0;

    if (!in || !out || inLen < 13u || outMax < 11u) return false;

    const uint8_t  L        = in[0];
    const uint16_t expected = c1BExpectedRaw(L);
    if (expected < 13u || expected > inLen) return false;

    // Work only on the telegram length declared by the L-field. Bytes after
    // that are FIFO over-read and must not be part of CRC calculation.
    inLen = expected;

    // Frame Format B, short frame:
    //   [0..N-3]    L C M A CI DATA
    //   [N-2..N-1]  CRC over [0..N-3]
    //
    // Important: byte 10 is CI, not a Frame-A block-1 CRC byte. Therefore the
    // CRC check starts at the L-field and spans the complete CRC-protected
    // block. This keeps CI in its normative position and is not meter-specific.
    if (L <= 127u) {
        const uint16_t dataLen = inLen - 2u;       // data covered by final CRC
        if (dataLen > 255u) return false;          // CRC::check length is uint8_t
        if (!Crypto::CRC::check(in, (uint8_t)dataLen)) return false;

        if (dataLen > outMax) return false;
        memcpy(out, in, dataLen);
        if (out[0] < 2u) return false;
        out[0] = (uint8_t)(L - 2u);                // remove one CRC pair from L
        outLen    = dataLen;
        crcBlocks = 1u;
        return true;
    }

    // Frame Format B, long frame:
    //   First block:  126 data bytes [0..125] + CRC [126..127]
    //   Optional:     remaining data [128..N-3] + CRC [N-2..N-1]
    //
    // Public summaries describe two CRC fields for long Format-B telegrams.
    // Keep this generic: no check for meter-id, manufacturer or CI value.
    if (L < 129u) return false;                    // no room for a second CRC pair

    const uint16_t firstDataLen = 126u;
    const uint16_t secondDataLen = inLen - 128u - 2u;

    if (firstDataLen > 255u || secondDataLen > 255u) return false;
    if (!Crypto::CRC::check(in, (uint8_t)firstDataLen)) return false;
    if (!Crypto::CRC::check(in + 128u, (uint8_t)secondDataLen)) return false;

    const uint16_t len = firstDataLen + secondDataLen;
    if (len > outMax) return false;

    memcpy(out, in, firstDataLen);
    if (secondDataLen > 0u)
        memcpy(out + firstDataLen, in + 128u, secondDataLen);

    if (L < 4u) return false;
    out[0] = (uint8_t)(L - 4u);                    // remove two CRC pairs from L
    outLen    = len;
    crcBlocks = 2u;
    return true;
}


// CC1101 RSSI register → dBm (datasheet conversion).
int8_t rssiToDbm(uint8_t raw) {
    int16_t r = (raw >= 128) ? (int16_t)(raw - 256) : (int16_t)raw;
    return (int8_t)(r / 2 - 74);
}

} // anonymous namespace

// On ESP32/ESP8266 the ISR must live in IRAM: if it fires while the flash cache
// is busy (e.g. during a flash read), a non-IRAM handler crashes the chip.
// RP2040/AVR don't need this; the macro is empty there.
#if defined(ARDUINO_ARCH_ESP32) || defined(ARDUINO_ARCH_ESP8266)
  #define WMBUS_ISR_ATTR IRAM_ATTR
#else
  #define WMBUS_ISR_ATTR
#endif

// ── ISR ──────────────────────────────────────────────────────────────────────
// attachInterrupt() wants a plain function pointer, so a static trampoline
// forwards to the active instance. Minimal work: only set a flag — SPI is not
// safe in an ISR on RP2040/arduino-pico. The FIFO read happens in loop().

Receiver* Receiver::s_isrTarget = nullptr;

void WMBUS_ISR_ATTR Receiver::isrTrampoline() {
    Receiver* self = s_isrTarget;
    if (self) {
        self->_pktReady = true;
        self->_isrCount = self->_isrCount + 1;
    }
}

// ── Construction / lifecycle ─────────────────────────────────────────────────

void Receiver::begin(Radio::CC1101& radio) {
    _radio = &radio;

    // The radio is already configured and receiving (radio.begin() applied the
    // mode + startRx). We only wire up the GDO0 interrupt with the edge that
    // matches the radio's mode — we do NOT re-apply the register config, so any
    // tuning the caller set on the radio (gain/bandwidth/offset) stays intact.
    pinMode(_radio->gdo0Pin(), INPUT);
    attachIsr(_radio->mode());

#if defined(ARDUINO_ARCH_ESP32) || defined(ARDUINO_ARCH_RP2040)
  #if defined(ARDUINO_ARCH_RP2040)
    mutex_init(&_rp2040Mux);
  #endif
    startDrainTimer();
#endif
}

void Receiver::setKey(uint32_t meterId, const uint8_t key[16]) {
    _keys.setKey(meterId, key);
}


void Receiver::removeKey(uint32_t meterId) {
    _keys.removeKey(meterId);
}

bool Receiver::available() const {
    return _ringCount > 0;
}

Frame Receiver::read() {
    Frame f    = _ring[_ringHead];
    _ringHead  = (_ringHead + 1) % RING_SIZE;
    _ringCount--;
    return f;
}

uint32_t Receiver::packetCount() const {
    return _isrCount;
}

void Receiver::end() {
#if defined(ARDUINO_ARCH_ESP32) || defined(ARDUINO_ARCH_RP2040)
    stopDrainTimer();
#endif
    if (_radio && _isrAttached) {
        detachInterrupt(digitalPinToInterrupt(_radio->gdo0Pin()));
        _radio->strobe(Radio::STROBE_SIDLE);
    }
    _isrAttached = false;
    s_isrTarget  = nullptr;
    _pktReady    = false;
    _callback    = nullptr;
}

uint32_t Receiver::dropCount() const {
#if defined(ARDUINO_ARCH_ESP32) || defined(ARDUINO_ARCH_RP2040)
    return _dropCount;
#else
    return 0;
#endif
}

uint32_t Receiver::drainCount() const {
    return _drainCount;
}

void Receiver::setCallback(FrameCallback cb) {
    _callback = std::move(cb);
}

void Receiver::setLogger(LogCallback cb) {
    _logCb = std::move(cb);
}

void Receiver::logf(const char* fmt, ...) {
    if (!_logCb) return;
    char buf[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    _logCb(buf);
}

void Receiver::setDebug(bool enable) {
    _debug = enable;
}

// (Re-)attach the GDO0 interrupt with RISING edge for all modes.
// All modes now use infinite packet mode (PKTCTRL0=0x02): GDO0 asserts on sync
// word detection (RISING) and Receiver::loop() drains the FIFO mid-reception.
void Receiver::attachIsr(Mode mode) {
    (void)mode;
    s_isrTarget = this;
    attachInterrupt(digitalPinToInterrupt(_radio->gdo0Pin()), isrTrampoline, RISING);
    _isrAttached = true;
}

void Receiver::setMode(Mode mode) {
#if defined(ARDUINO_ARCH_ESP32) || defined(ARDUINO_ARCH_RP2040)
    // Pause the background drain so its SPI traffic cannot interleave with the
    // multi-register radio reconfiguration below.
    stopDrainTimer();
  #if defined(ARDUINO_ARCH_RP2040)
    mutex_enter_blocking(&_rp2040Mux);
    _rawReady = false;
    mutex_exit(&_rp2040Mux);
  #else
    _rawReady = false;
  #endif
#endif
    if (_isrAttached) detachInterrupt(digitalPinToInterrupt(_radio->gdo0Pin()));
    _pktReady         = false;
    _accum.len        = 0;
    _drainDeadline    = 0;

    _radio->setMode(mode);
    attachIsr(mode);

#if defined(ARDUINO_ARCH_ESP32) || defined(ARDUINO_ARCH_RP2040)
    startDrainTimer();
#endif
}

// ── Frame decode + push to ring ──────────────────────────────────────────────

void Receiver::processRawFrame(const uint8_t* raw, uint16_t rawLen,
                               uint8_t rssiRaw, Mode rxMode,
                               int8_t freqEst, uint8_t lqi, bool overflow) {
    // Single processing path. Debug logging is interleaved and gated on `dbg`;
    // the decode/CRC/strip/parse/decrypt steps run identically with or without it.
    const bool dbg = _debug && _logCb;
    char buf[96];

    auto hexDump = [&]() {
        if (!dbg) return;
        _logCb("  Hex:");
        for (uint16_t off = 0; off < rawLen; off += 32) {
            char hex[70];
            int  n = snprintf(hex, sizeof(hex), "    ");
            for (uint16_t i = off; i < rawLen && i < off + 32; i++)
                n += snprintf(hex + n, sizeof(hex) - n, "%02X", raw[i]);
            _logCb(hex);
        }
    };

    // Remember explicit C-mode sync prefixes from the raw FIFO.  In pure C1B
    // mode false sync / noise captures otherwise get reported as "C1B BAD"
    // endlessly.  A real no-prefix C1B frame is still accepted if the Format-B
    // CRC check below passes.
    const bool rawHasC1BSync = c1BSyncPrefix(raw, rawLen);
    const bool rawHasC1ASync = c1ASyncPrefix(raw, rawLen);

    // In pure C1B mode, a 0x54CD prefix is explicitly a C1A frame.  Do not feed
    // it into the C1B Format-B CRC path and then complain that it is BAD-C1B.
    if (rxMode == Mode::C1B && rawHasC1ASync) {
        if (dbg) _logCb("C1B drop: received C1A sync 0x54CD");
        return;
    }

    // ── Decode (T1: 3of6, C1/S1: raw copy) ─────────────────────────────────
    // Static so the two ~512-byte work buffers stay off the stack. Safe because
    // processRawFrame only ever runs in the main context (loop()/consumeRaw()),
    // never reentrant and never from the drain timer.
    static uint8_t decoded[Radio::MAX_RAW_FRAME];
    uint16_t decodedLen;
    if (rxMode == Mode::T1 || rxMode == Mode::T1C1B) {
        decodedLen = Frame::decode3of6(raw, rawLen, decoded, sizeof(decoded));
        // Combined T1+C1B: T1 and C1B share sync 0x543D. A 3of6 decode of a raw
        // C1B stream effectively never reaches 12 bytes (24 consecutive valid
        // symbols ≈ 4^-24), so a short result + valid raw block-1 CRC reliably
        // identifies a C1B Frame-B telegram. Relabel rxMode to what was decoded.
        if (rxMode == Mode::T1C1B) {
            // Combined T1+C1B: Mode T and Mode C Frame B can both be seen around
            // the 0x543D pattern.  If the raw FIFO starts with a C-mode sync word,
            // route it as raw C immediately; 0x54 is not a valid 3of6 symbol start.
            if (c1BSyncPrefix(raw, rawLen)) {
                uint8_t off = 2u;
                decodedLen = (uint16_t)(rawLen - off);
                if (decodedLen > sizeof(decoded)) decodedLen = (uint16_t)sizeof(decoded);
                memcpy(decoded, raw + off, decodedLen);
                rxMode = Mode::C1B;
            } else if (c1ASyncPrefix(raw, rawLen)) {
                uint8_t off = 2u;
                decodedLen = (uint16_t)(rawLen - off);
                if (decodedLen > sizeof(decoded)) decodedLen = (uint16_t)sizeof(decoded);
                memcpy(decoded, raw + off, decodedLen);
                rxMode = Mode::C1A;
            } else if (decodedLen >= 12) {
                rxMode = Mode::T1;                       // decoded as a T1 telegram
            } else {
                // 3of6 failed → try a raw C-mode frame without sync prefix.
                // In T1+C1B the CC1101 may strip the 0x543D sync. Then a valid
                // C1B telegram starts directly with the L-field, e.g. 6B 44 ...
                // The old fallback used c1Block1Offset(), which is a Frame-A
                // block-CRC test and can never validate Format-B where byte 10 is CI.
                // Therefore first probe the no-prefix buffer with the generic
                // Format-B CRC stripper. This is structural/CRC based, not
                // meter-id/vendor/CI based.
                static uint8_t probeC1B[Radio::MAX_RAW_FRAME];
                uint16_t probeLen = 0;
                uint8_t  probeBlocks = 0;
                if (c1BStripCRC(raw, rawLen, probeC1B, sizeof(probeC1B), probeLen, probeBlocks)) {
                    decodedLen = rawLen;
                    if (decodedLen > sizeof(decoded)) decodedLen = (uint16_t)sizeof(decoded);
                    memcpy(decoded, raw, decodedLen);
                    rxMode = Mode::C1B;
                } else {
                    uint8_t off = c1Block1Offset(raw, rawLen);
                    if (off != 0xFFu) {
                        decodedLen = (uint16_t)(rawLen - off);
                        if (decodedLen > sizeof(decoded)) decodedLen = (uint16_t)sizeof(decoded);
                        memcpy(decoded, raw + off, decodedLen);
                        rxMode = (off == 2u && raw[1] == 0xCD) ? Mode::C1A : Mode::C1B;
                    } else {
                        rxMode = Mode::T1;               // neither — report as T1 attempt
                    }
                }
            }
        }
    } else if (rxMode == Mode::S1) {
        decodedLen = Frame::decodeManchester(raw, rawLen, decoded, sizeof(decoded));
    } else {
        // C1 (Frame A, sync 0x54CD) and C1B (Frame B, sync 0x543D): raw bytes.
        // Skip a leading sync word if the chip left it in the FIFO.  Do not use
        // the Frame-A block-1 CRC rule to decide C1B: for Frame B decoded[10] is
        // the CI-field, not a CRC byte.
        uint8_t off = 0u;
        if (c1BSyncPrefix(raw, rawLen) || c1ASyncPrefix(raw, rawLen)) {
            off = 2u;
        } else if (rxMode == Mode::C1A) {
            uint8_t crcOff = c1Block1Offset(raw, rawLen);
            if (crcOff != 0xFFu) off = crcOff;
        }
        decodedLen = (uint16_t)(rawLen - off);
        if (decodedLen > sizeof(decoded)) decodedLen = (uint16_t)sizeof(decoded);
        memcpy(decoded, raw + off, decodedLen);
    }

    // C1/C1B frames need isFrameB (from the CRC section below) to label the mode
    // as C1A vs C1B. Buffer the decode line and defer the header until then.
    bool isFrameB = false;
    char decodeLine[96] = {};
    auto logHeader = [&]() {
        if (!dbg) return;
        const char* ms;
        if      (rxMode == Mode::T1)  ms = "T1";
        else if (rxMode == Mode::S1)  ms = "S1";
        else if (rxMode == Mode::C1B) ms = "C1B";
        else                          ms = isFrameB ? "C1B" : "C1A";
        snprintf(buf, sizeof(buf), "Received Frame: Mode=%s Bytes=%u RSSI=%ddBm FreqEst=%d LQI=%u%s",
            ms, (unsigned)rawLen, rssiToDbm(rssiRaw), freqEst, lqi,
            overflow ? " OVERFLOW" : "");
        _logCb(buf);
        if (decodeLine[0]) _logCb(decodeLine);
    };
    if (dbg) {
        snprintf(decodeLine, sizeof(decodeLine), "  Decode: Length=%u Status=%s",
            (unsigned)decodedLen,
            (rxMode != Mode::T1) ? "OK" : (decodedLen > 0 ? "OK" : "FAILED"));
    }
    if (decodedLen < 12) { logHeader(); hexDump(); return; }

    // ── Per-block CRC check + C1/S1 Frame-B detection ──────────────────────
    uint8_t badBlocks = 0, totalBlocks = 0;

    // For C1B we strip here already because Format B has a different CRC
    // placement than Format A.  The generic strip block below will simply copy
    // this prepared buffer.
    static uint8_t c1bStripped[Radio::MAX_RAW_FRAME];
    uint16_t c1bStrippedLen = 0;
    uint8_t  c1bCrcBlocks   = 0;
    bool     c1bPrepared    = false;

    {
        uint8_t L = decoded[0];

        if (rxMode == Mode::C1B) {
            uint16_t expected = c1BExpectedRaw(L);
            if (expected >= 13u && expected <= decodedLen)
                decodedLen = expected;       // discard FIFO over-read before CRC

            if (!c1BStripCRC(decoded, decodedLen,
                             c1bStripped, sizeof(c1bStripped),
                             c1bStrippedLen, c1bCrcBlocks)) {
                // If there was no explicit 0x543D prefix, this is usually just a
                // pure-C1B false trigger / noise capture.  Drop it quietly so
                // C1B-only mode stays usable.  Explicit 0x543D frames are still
                // logged as BAD-C1B because those are the interesting failures.
                if (!rawHasC1BSync) {
                    if (dbg) _logCb("C1B drop: false trigger / no valid Format-B CRC");
                    return;
                }
                logHeader();
                if (dbg) _logCb("  CRC: Status=BAD-C1B");
                hexDump();
                return;
            }

            isFrameB     = true;
            badBlocks    = 0;
            totalBlocks  = c1bCrcBlocks;
            c1bPrepared  = true;
        } else {
            if (!Crypto::CRC::check(decoded, 10)) {   // block-1 CRC failed → discard
                logHeader();
                if (dbg) _logCb("  CRC: Status=BAD");
                hexDump();
                return;
            }
            totalBlocks = 1;
            uint16_t src      = 12;
            uint8_t  dataLeft = (L >= 9u) ? (uint8_t)(L - 9u) : 0u;
            while (src + 2 < decodedLen && dataLeft > 0) {
                uint8_t blockData = (dataLeft >= 16u) ? 16u : dataLeft;
                if (src + blockData + 2u > decodedLen) break;
                if (!Crypto::CRC::check(decoded + src, blockData)) badBlocks++;
                totalBlocks++;
                src      += blockData + 2u;
                dataLeft -= blockData;
            }
            // Frame B fallback for existing non-C1B code paths.
            if (badBlocks > 0 && rxMode != Mode::T1 && decodedLen >= 14 &&
                Crypto::CRC::check(decoded + 12, (uint8_t)(decodedLen - 14))) {
                isFrameB    = true;
                badBlocks   = 0;
                totalBlocks = 1;
            }
        }
    }
    _lastBadBlocks   = badBlocks;
    _lastTotalBlocks = totalBlocks;
    logHeader();
    if (dbg) {
        snprintf(buf, sizeof(buf), "  CRC: Status=%s",
            (badBlocks == 0) ? "OK" : "BAD");
        _logCb(buf);
    }

    // ── Strip inter-block CRCs ────────────────────────────────────────────
    static uint8_t stripped[Radio::MAX_RAW_FRAME];
    uint16_t strippedLen;
    if (c1bPrepared) {
        strippedLen = c1bStrippedLen;
        if (strippedLen > sizeof(stripped)) strippedLen = sizeof(stripped);
        memcpy(stripped, c1bStripped, strippedLen);
    } else if (isFrameB) {
        uint16_t remLen = (decodedLen >= 14u) ? (decodedLen - 14u) : 0u;
        strippedLen = 10u + remLen;
        if (strippedLen > sizeof(stripped)) strippedLen = sizeof(stripped);
        memcpy(stripped, decoded, 10u);
        if (remLen > 0u)
            memcpy(stripped + 10u, decoded + 12u, remLen);
    } else {
        strippedLen = Frame::stripCRC(decoded, decodedLen, stripped, sizeof(stripped));
    }

    // ── Parse ─────────────────────────────────────────────────────────────
    Frame frame = (strippedLen >= Frame::MIN_FRAME_BYTES)
                  ? Frame::parse(stripped, strippedLen) : Frame{};
    if (dbg) {
        if (strippedLen >= Frame::MIN_FRAME_BYTES && frame.valid())
            snprintf(buf, sizeof(buf), "  Parse: Status=OK MeterId=%08X Type=0x%02X",
                (unsigned)frame.meterId(), frame.devType());
        else
            snprintf(buf, sizeof(buf), "  Parse: Status=%s",
                (strippedLen < Frame::MIN_FRAME_BYTES) ? "STRIP-FAIL" : "PARSE-FAIL");
        _logCb(buf);
    }
    if (strippedLen < Frame::MIN_FRAME_BYTES || !frame.valid()) { hexDump(); return; }

    frame.setRssi(rssiRaw, rssiToDbm(rssiRaw));
    frame.setRxMode(rxMode);
    frame.setCrc(badBlocks, totalBlocks);

    // ── Decrypt ───────────────────────────────────────────────────────────
    if (frame.encrypted()) {
        const uint8_t* key = _keys.getKey(frame.meterId());
        if (key) frame.decrypt(key);
        if (dbg) {
            if (key)
                snprintf(buf, sizeof(buf), "  Encryption: Mode=%u Status=%s",
                    frame.encMode(), frame.decrypted() ? "OK" : "FAILED");
            else
                snprintf(buf, sizeof(buf), "  Encryption: Mode=%u Status=MISSING-KEY",
                    frame.encMode());
            _logCb(buf);
        }
    } else if (dbg) {
        _logCb("  Encryption: Status=NONE");
    }

    // ── Parse DIF/VIF records ─────────────────────────────────────────────
    DataRecord records[MAX_DATA_RECORDS];
    uint8_t recordCount = 0;
    if ((frame.decrypted() || !frame.encrypted()) && frame.payloadLen() > 0)
        recordCount = parseRecords(frame.payload(), (uint8_t)frame.payloadLen(),
                                   records, MAX_DATA_RECORDS);
    if (dbg) {
        snprintf(buf, sizeof(buf), "  Payload: Records=%u Status=%s", recordCount,
            (frame.decrypted() || !frame.encrypted()) ? "OK" : "DECRYPT-FAILED");
        _logCb(buf);
        hexDump();
    }

    // ── Push to ring buffer (drop if full) + fire callback for every frame ─
    if (_ringCount < RING_SIZE) {
        _ring[_ringTail] = frame;
        _ringTail = (_ringTail + 1) % RING_SIZE;
        _ringCount++;
    }
    if (_callback)
        _callback(frame, records, recordCount);
}

// ── FIFO drain ───────────────────────────────────────────────────────────────

// One FIFO accumulation step for the current mode (T1 or C1/S1). On finalize
// _accum holds the raw bytes with metadata and true is returned. Pure radio/SPI
// — no decode/decrypt/callback, safe to call from the ESP32 drain timer.
bool Receiver::pumpRaw() {
    Mode localMode = _radio->mode();

    // RISING edge (sync word detected) → start a fresh accumulation window.
    if (_pktReady) {
        noInterrupts();
        _pktReady = false;
        interrupts();
        _accum.len     = 0;
        _drainDeadline = millis() + ((localMode == Mode::T1 ||
                                      localMode == Mode::T1C1B) ? T1_DRAIN_MS
                                  :  (localMode == Mode::S1) ? S1_DRAIN_MS
                                  :                            C1A_DRAIN_MS);
    }

    if (_drainDeadline == 0) return false;

    // Synchronous FIFO poll. Leave ≥1 byte in the FIFO during active RX (CC1101
    // erratum SWRZ020); read avail-1 only.
    uint8_t rxb       = _radio->readStatusReg(Radio::SREG_RXBYTES);
    bool fifoOverflow = (rxb & 0x80) != 0;
    if (!fifoOverflow) {
        // Once in RXFIFO_OVERFLOW the chip ignores SRX until SFRX — bail out and
        // let the finalise block below issue SIDLE+SFRX+SRX.
        uint8_t  avail  = rxb & 0x7F;
        uint8_t  toRead = avail > 1u ? (uint8_t)(avail - 1u) : 0u;
        uint16_t space  = (uint16_t)(sizeof(_accum.buf) - _accum.len);
        if (toRead > space) toRead = (uint8_t)space;
        if (toRead > 0)
            _accum.len += _radio->readFifo(_accum.buf + _accum.len, toRead);
    }

    // C1/C1B early abort: once block-1 (10 data + 2 CRC) is in, check its CRC.
    // Fail → not a valid wMBus frame, discard (also catches false sync triggers).
    // Both C-mode frame formats share the same 10-data + 2-CRC block 1, so the
    // check is valid for C1B too. S1 is excluded: its raw bytes are still
    // Manchester-coded here, so a CRC over them is meaningless — S-mode relies on
    // the target/timeout below and the post-decode block-1 CRC in processRawFrame.
    if (localMode == Mode::C1A) {
        // A leading sync word (0x54CD) shifts block 1 to offset 2, so we
        // need 14 bytes to rule it out. Abort only when no valid Frame-A block 1
        // exists at offset 0 or 2 (also catches false sync triggers).
        bool syncPrefix = (_accum.len >= 2 && _accum.buf[0] == 0x54 && _accum.buf[1] == 0xCD);
        uint16_t need = syncPrefix ? 14u : 12u;
        if (_accum.len >= need && c1Block1Offset(_accum.buf, _accum.len) == 0xFFu) {
            if (_debug && _logCb) {
                char abortBuf[96];
                int  n = snprintf(abortBuf, sizeof(abortBuf),
                    "C1A early-abort: block-1 CRC bad (L=0x%02X) buf=", _accum.buf[0]);
                for (uint8_t i = 0; i < 14 && i < _accum.len; i++)
                    n += snprintf(abortBuf + n, sizeof(abortBuf) - n, "%02X", _accum.buf[i]);
                _logCb(abortBuf);
            }
            _radio->startRx();
            _drainDeadline = 0;
            _accum.len     = 0;
            return false;
        }
    }

    // Compute expected raw-frame size to exit early when we have enough bytes.
    // T1: once we have ≥2 raw bytes, 3of6-peek the L-field (first decoded byte).
    // T1C1B: 3of6-peek; if it fails the stream is a raw C1B frame, peek L directly.
    // S1: Manchester-peek the L-field (2 raw bytes → 1), raw = 2× Frame-A bytes.
    // C1 (Frame A and B): L-field is the first raw byte directly.
    uint16_t target;
    if (localMode == Mode::T1 || localMode == Mode::T1C1B) {
        if (_accum.len >= 2) {
            uint8_t L = 0;
            if (Frame::decode3of6(_accum.buf, 2, &L, 1) > 0) {
                uint8_t  dataRem   = (L >= 9u) ? (uint8_t)(L - 9u) : 0u;
                uint8_t  numBlocks = (uint8_t)((dataRem + 15u) / 16u);
                uint16_t withCRC   = 12u + dataRem + 2u * numBlocks;
                target = (uint16_t)(withCRC * 3u / 2u);
                if (target > Radio::MAX_RAW_FRAME) target = Radio::MAX_RAW_FRAME;
            } else if (localMode == Mode::T1C1B) {
                // 3of6 peek invalid → raw C-mode frame. Skip a leading sync word
                // (0x543D/0x54CD) if present; the L-field follows it.
                uint8_t off = (_accum.len >= 3 && _accum.buf[0] == 0x54 &&
                               (_accum.buf[1] == 0x3D || _accum.buf[1] == 0xCD)) ? 2u : 0u;
                // If sync is present we know whether this is C1B or C1A.
                // If sync is absent in T1+C1B, prefer the C1B L-field length:
                // Format-B frames may arrive without 0x543D in the FIFO. The
                // Format-B CRC probe in processRawFrame() will later decide if
                // this was really C1B; noise just gets discarded.
                target = (uint16_t)(off + (((off == 2u && _accum.buf[1] == 0x3D) || off == 0u)
                                        ? c1BExpectedRaw(_accum.buf[off])
                                        : c1ExpectedRaw(_accum.buf[off])));
            } else {
                target = Radio::MAX_RAW_FRAME;
            }
        } else {
            target = Radio::MAX_RAW_FRAME;
        }
    } else if (localMode == Mode::S1) {
        if (_accum.len >= 2) {
            uint8_t L = 0;
            Frame::decodeManchester(_accum.buf, 2, &L, 1);
            uint16_t target32 = (uint16_t)(2u * c1ExpectedRaw(L));
            target = (target32 > Radio::MAX_RAW_FRAME) ? Radio::MAX_RAW_FRAME : target32;
        } else {
            target = Radio::MAX_RAW_FRAME;
        }
    } else {
        // C1/C1B: L-field is the first raw byte, after an optional sync word.
        uint8_t off = (_accum.len >= 2 && _accum.buf[0] == 0x54 &&
                       (_accum.buf[1] == 0x3D || _accum.buf[1] == 0xCD)) ? 2u : 0u;
        target = (_accum.len > off)
               ? (uint16_t)(off + ((localMode == Mode::C1B || (off == 2u && _accum.buf[1] == 0x3D))
                                ? c1BExpectedRaw(_accum.buf[off])
                                : c1ExpectedRaw(_accum.buf[off])))
               : Radio::MAX_RAW_FRAME;
    }

    bool enough  = (_accum.len >= target);
    bool timeout = fifoOverflow || ((int32_t)(millis() - _drainDeadline) >= 0);
    if (!(enough || timeout)) return false;

    // Finalise: stop radio, drain remaining bytes (safe after SIDLE).
    _radio->strobe(Radio::STROBE_SIDLE);
    uint8_t  rxb2    = _radio->readStatusReg(Radio::SREG_RXBYTES);
    bool     overflow = (rxb2 & 0x80) != 0;
    uint8_t  avail2  = rxb2 & 0x7F;
    uint16_t space2  = (uint16_t)(sizeof(_accum.buf) - _accum.len);
    uint8_t  toRead2 = (avail2 < space2) ? avail2 : (uint8_t)space2;
    if (toRead2 > 0)
        _accum.len += _radio->readFifo(_accum.buf + _accum.len, toRead2);

    _accum.rssi     = _radio->readRSSI();
    _accum.freqEst  = (int8_t)_radio->readStatusReg(Radio::SREG_FREQEST);
    _accum.lqi      = _radio->readStatusReg(Radio::SREG_LQI) & 0x7F;
    _accum.overflow = overflow;
    _accum.mode     = localMode;
    _radio->startRx();
    _drainDeadline  = 0;
    return true;
}

// ── Main loop ────────────────────────────────────────────────────────────────

void Receiver::loop() {
#if defined(ARDUINO_ARCH_ESP32) || defined(ARDUINO_ARCH_RP2040)
    // FIFO drain runs in a background context (esp_timer / Core1); here we only
    // process a finished raw frame in the main context (decode/decrypt/callback).
    consumeRaw();
#else
    // Other platforms: drain the FIFO synchronously in loop().
    if (!pumpRaw()) return;

    uint16_t minLen = (_accum.mode == Mode::T1 || _accum.mode == Mode::T1C1B) ? 20u
                    : (_accum.mode == Mode::S1) ? 40u   // Manchester: 2 raw bytes per decoded byte
                    :                             12u;
    if (_accum.len >= minLen)
        processRawFrame(_accum.buf, _accum.len, _accum.rssi, _accum.mode,
                        _accum.freqEst, _accum.lqi, _accum.overflow);

#endif
}

#if defined(ARDUINO_ARCH_ESP32)

// ── ESP32 background drain ────────────────────────────────────────────────────

void Receiver::drainTimerTramp(void* arg) {
    static_cast<Receiver*>(arg)->drainTick();
}

void Receiver::startDrainTimer() {
    if (_drainTimer) return;
    const esp_timer_create_args_t args = {
        .callback              = &Receiver::drainTimerTramp,
        .arg                   = this,
        .dispatch_method       = ESP_TIMER_TASK,
        .name                  = "wmbus_drain",
        .skip_unhandled_events = true,
    };
    if (esp_timer_create(&args, &_drainTimer) == ESP_OK)
        esp_timer_start_periodic(_drainTimer, 3000);  // 3 ms
}

void Receiver::stopDrainTimer() {
    if (!_drainTimer) return;
    esp_timer_stop(_drainTimer);
    esp_timer_delete(_drainTimer);
    _drainTimer = nullptr;
}

// Runs in the esp_timer task (high priority, NOT an ISR → SPI is allowed).
// Collects RAW bytes only and hands a finished frame to loop() via _hand.
// Never decodes or fires the callback (those need the main context).
void Receiver::drainTick() {
    if (!_radio) return;
    _drainCount++;
    if (!pumpRaw()) return;

    uint16_t minLen = (_accum.mode == Mode::T1 || _accum.mode == Mode::T1C1B) ? 20u
                    : (_accum.mode == Mode::S1) ? 40u   // Manchester: 2 raw bytes per decoded byte
                    :                             12u;
    if (_accum.len < minLen) return;

    portENTER_CRITICAL(&_rawMux);
    if (_rawReady) _dropCount++;   // previous frame not consumed yet → overwrite
    _hand     = _accum;
    _rawReady = true;
    portEXIT_CRITICAL(&_rawMux);
}

// Runs in loop() (main context). Decodes/decrypts/fires the callback for a frame
// the drain timer finished. Copies the capture out under the lock first so a
// concurrent drainTick() cannot corrupt it mid-decode.
void Receiver::consumeRaw() {
    RawCapture cap;
    bool       ready = false;

    portENTER_CRITICAL(&_rawMux);
    if (_rawReady) {
        ready     = true;
        cap       = _hand;
        _rawReady = false;
    }
    portEXIT_CRITICAL(&_rawMux);

    if (ready)
        processRawFrame(cap.buf, cap.len, cap.rssi, cap.mode, cap.freqEst, cap.lqi, cap.overflow);
}

#endif // ARDUINO_ARCH_ESP32

#if defined(ARDUINO_ARCH_RP2040)

// ── RP2040 hardware-timer drain ──────────────────────────────────────────────
//
// A pico-sdk repeating_timer fires every 3 ms as an alarm IRQ on Core0.
// drainTick() runs there: raw FIFO bytes only, never decode/decrypt/callback.
// consumeRaw() runs in loop() on Core0; noInterrupts()/interrupts() protect
// the one-flag + one-struct handoff (no mutex needed — same core).

bool Receiver::drainTimerTramp(struct repeating_timer *t) {
    Receiver* self = s_isrTarget;
    if (self) self->drainTick();
    return true;  // keep firing
}

void Receiver::startDrainTimer() {
    if (_drainTimerRunning) return;
    // Negative delay = time between *starts* (not between end-and-next-start).
    add_repeating_timer_us(-3000, drainTimerTramp, nullptr, &_drainTimer);
    _drainTimerRunning = true;
}

void Receiver::stopDrainTimer() {
    if (!_drainTimerRunning) return;
    cancel_repeating_timer(&_drainTimer);
    _drainTimerRunning = false;
}

// Runs in the alarm-IRQ context every 3 ms. SPI is safe: the CC1101 SPI is
// exclusive to wmbus; consumeRaw() in loop() never touches SPI.
// Uses mutex_try_enter() so that if loop() currently holds the mutex the IRQ
// returns immediately without deadlocking or stalling other interrupts.
// The internal spin-lock inside mutex_try_enter disables IRQs for only ~4
// instructions — negligible impact on other interrupt handlers.
void Receiver::drainTick() {
    if (!_radio) return;
    _drainCount++;
    if (!pumpRaw()) return;

    uint16_t minLen = (_accum.mode == Mode::T1 || _accum.mode == Mode::T1C1B) ? 20u
                    : (_accum.mode == Mode::S1) ? 40u   // Manchester: 2 raw bytes per decoded byte
                    :                             12u;
    if (_accum.len < minLen) return;

    if (mutex_try_enter(&_rp2040Mux, nullptr)) {
        if (_rawReady) _dropCount++;
        _hand     = _accum;
        _rawReady = true;
        mutex_exit(&_rp2040Mux);
    } else {
        _dropCount++;   // loop() is copying; skip — next tick will deliver a frame
    }
}

// Runs in loop() (Core0). Copies the frame under the mutex so drainTick()
// cannot overwrite _hand mid-copy. Uses mutex_try_enter() too: if the timer
// IRQ is mid-copy we simply pick the frame up on the next loop() — frames are
// seconds apart, loop() runs every few ms, so nothing is lost. decode/decrypt/
// callback run outside the mutex so the IRQ is never blocked during heavy work.
void Receiver::consumeRaw() {
    RawCapture cap;
    bool       ready = false;

    if (mutex_try_enter(&_rp2040Mux, nullptr)) {
        if (_rawReady) {
            cap       = _hand;
            _rawReady = false;
            ready     = true;
        }
        mutex_exit(&_rp2040Mux);
    }

    if (ready)
        processRawFrame(cap.buf, cap.len, cap.rssi, cap.mode, cap.freqEst, cap.lqi, cap.overflow);
}

#endif // ARDUINO_ARCH_RP2040

// ── Stateless utility helpers ────────────────────────────────────────────────

const char* modeName(Mode mode) {
    switch (mode) {
        case Mode::T1:    return "T1";
        case Mode::C1A:   return "C1A";
        case Mode::C1B:   return "C1B";
        case Mode::T1C1B: return "T1+C1B";
        case Mode::S1:    return "S1";
        default:          return "?";
    }
}

const char* devTypeName(uint8_t devType) {
    switch (devType) {
        case 0x00: return "Other";
        case 0x01: return "Oil";
        case 0x02: return "Electricity";
        case 0x03: return "Gas";
        case 0x04: return "Heat";
        case 0x05: return "Steam";
        case 0x06: return "Hot water";
        case 0x07: return "Water";
        case 0x08: return "Heat cost allocator";
        case 0x09: return "Compressed air";
        case 0x0A: return "Cooling (return)";
        case 0x0B: return "Cooling (flow)";
        case 0x0C: return "Heat (flow)";
        case 0x0D: return "Heat/cooling";
        case 0x0E: return "Bus/system";
        case 0x0F: return "Unknown medium";
        case 0x15: return "Hot water (>=90C)";
        case 0x16: return "Cold water";
        case 0x17: return "Dual water";
        case 0x18: return "Pressure";
        case 0x19: return "A/D converter";
        default:   return "Unknown";
    }
}

// Decodes the 2-byte M-field into the 3-character manufacturer string (A..Z).
// out must point to a buffer of at least 4 bytes; the string is NUL-terminated.
void decodeVendor(const uint8_t vendor[2], char out[4]) {
    uint16_t w = ((uint16_t)vendor[1] << 8) | vendor[0];
    out[0] = (char)(((w >> 10) & 0x1F) + 'A' - 1);
    out[1] = (char)(((w >>  5) & 0x1F) + 'A' - 1);
    out[2] = (char)(((w >>  0) & 0x1F) + 'A' - 1);
    out[3] = '\0';
}

} // namespace WMBus
