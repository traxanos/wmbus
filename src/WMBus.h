#pragma once
#include "WMBus/Frame.h"            // defines WMBus::Mode and WMBus::Frame
#include "WMBus/DataRecord.h"       // DIF/VIF parsed data records
#include "WMBus/Crypto/Decrypt.h"   // per-instance AES key store
#include "WMBus/Radio/CC1101.h"     // MAX_RAW_FRAME for the accumulation buffer
#include <SPI.h>
#include <functional>
#if defined(ARDUINO_ARCH_ESP32)
  #include <esp_timer.h>
#elif defined(ARDUINO_ARCH_RP2040)
  #include <pico/time.h>
  #include <pico/mutex.h>
#endif

// Platform note: the CC1101 FIFO is drained with synchronous SPI polling.
//
//  - ESP8266, bare AVR, …: the drain runs in Receiver::loop(), which must be
//    called often enough that the 64-byte FIFO (~15 ms of T1 air) never fills.
//  - ESP32: the Arduino loopTask is preempted by higher-priority RTOS tasks
//    (WiFi/Ethernet/system) for >15 ms, which would overflow the FIFO mid-frame.
//    The drain runs in a high-priority esp_timer; decode/decrypt/callback happen
//    in loop() (main context). Call drainTick() from the timer.
//  - RP2040: the OpenKNX main loop can exceed 15 ms when multiple modules run.
//    The drain runs on Core1 via drainTick(); loop() on Core0 only decodes.
//    Call drainTick() from loop1() and ensure setup1() completes before loop1()
//    can reach drainTick() (the _radioReady guard in MBusModule handles this).

namespace WMBus {

// Callback invoked once per parsed frame (after auto-decrypt, if applicable).
// records/count are only valid during the callback; copy what you need.
using FrameCallback = std::function<void(const Frame& frame,
                                         const DataRecord* records,
                                         uint8_t count)>;

// Logging callback: receives a single NUL-terminated, newline-free message.
// Register via Receiver::setLogger(). Without a logger, the library is silent.
using LogCallback = std::function<void(const char* msg)>;

// ── Receiver ────────────────────────────────────────────────────────────────
//
// Owns one CC1101 on a given SPI bus and the state for receiving wMBus frames.
//
// Single-radio note: the GDO0 interrupt routes through a static trampoline
// (attachInterrupt needs a plain function pointer), so only the most recently
// begin()-ed Receiver instance services interrupts. One instance per program.
class Receiver {
public:
    Receiver() = default;

    // Bind to an already-begin()ed radio, attach the GDO0 interrupt, and start
    // servicing it. Call once from setup(), after radio.begin().
    //   radio : the CC1101 to service (must outlive the Receiver). The Receiver
    //           reads radio.gdo0Pin() and radio.mode() to wire the interrupt and
    //           pick the decode path.
    void begin(Radio::CC1101& radio);

    // Register / drop an AES-128 key for a specific meter (16 bytes).
    void setKey(uint32_t meterId, const uint8_t key[16]);
    void removeKey(uint32_t meterId);

    // true when at least one parsed frame is waiting in the ring buffer.
    bool available() const;

    // Returns the next frame from the ring buffer.
    // Call only when available() == true.
    Frame read();

    // Change receive mode at runtime (re-applies CC1101 config + re-wires the
    // GDO0 interrupt edge).
    void setMode(Mode mode);

    // Must be called frequently from Arduino loop() to process incoming data.
    void loop();

    // Total number of GDO0 interrupts seen (= sync words detected by CC1101).
    // If this stays 0, the CC1101 hears nothing on the air.
    uint32_t packetCount() const;

    // Stop receiving: detach the GDO0 interrupt and strobe the radio to IDLE.
    // Call from destructor or before re-using the radio on another Receiver.
    void end();

    // Register a callback invoked once per parsed frame with decoded data records.
    // Replaces any previously registered callback. Pass nullptr to clear.
    // When debug is enabled, the raw bytes are printed BEFORE the callback fires.
    void setCallback(FrameCallback cb);

    // Register a logging callback. The library forwards all diagnostic output
    // (raw frame dumps, CRC results, rate-scan progress) to this callback as
    // NUL-terminated, newline-free strings. Pass nullptr to silence the library.
    // The callback is called from loop() (main context, not ISR).
    void setLogger(LogCallback cb);

    // When enabled, loop() emits one compact raw-bytes line per telegram via the
    // logger before the callback fires. Without a registered logger, setDebug has
    // no visible effect. Use only for short diagnostic sessions (170-byte hex dump
    // at 115200 baud takes ~44 ms and may starve the FIFO if a new sync arrives
    // while the logger is running).
    void setDebug(bool enable);
    bool isDebug() const { return _debug; }

    // Number of raw frames dropped because loop() did not consume the previous
    // one before the next finished (ESP32 background-drain handoff). Stays 0 in
    // normal operation — frames are seconds apart, loop() consumes in ms.
    uint32_t dropCount() const;

    // Number of times the background drain body ran (esp_timer / RP2040 timer).
    // If this barely advances while packetCount() climbs, the drain timer is
    // being starved → FIFO overflows → frames break up. 0 on synchronous targets.
    uint32_t drainCount() const;

private:
    // GDO0 ISR: a static trampoline forwards to the active instance. SPI is not
    // safe in an ISR on RP2040/arduino-pico, so it only sets a flag; the FIFO
    // read happens in loop().
    static void isrTrampoline();
    static Receiver* s_isrTarget;

    // Decode a raw capture, CRC-check, parse, auto-decrypt, push to the ring.
    // freqEst/lqi/overflow are CC1101 diagnostics printed in debug mode.
    void processRawFrame(const uint8_t* raw, uint16_t rawLen,
                         uint8_t rssiRaw, Mode rxMode,
                         int8_t freqEst = 0, uint8_t lqi = 0, bool overflow = false);

    // (Re-)attach the GDO0 interrupt with the edge that matches a mode.
    void attachIsr(Mode mode);

    // One FIFO accumulation step (T1 or C1/S1, per _radio->mode()). On finalize
    // _accum holds the raw bytes with metadata; returns true. Pure radio/SPI
    // work — no decode/decrypt/callback, safe to call from the ESP32 drain timer.
    // Used by loop() on other platforms and by drainTick() on ESP32.
    bool pumpRaw();

    // ── Configuration ─────────────────────────────────────────────────────
    Radio::CC1101* _radio = nullptr;

    // ── ISR / debug ───────────────────────────────────────────────────────
    volatile bool     _pktReady   = false;
    volatile uint32_t _isrCount   = 0;
    bool              _debug      = false;
    bool              _isrAttached = false;
    LogCallback       _logCb;

    // Format + forward a diagnostic message to _logCb (no-op if _logCb is null).
    void logf(const char* fmt, ...) __attribute__((format(printf, 2, 3)));

    // ── Raw frame capture (accumulation + optional handoff) ───────────────
    // All raw bytes and metadata for one received frame, from first FIFO byte
    // to finalization. pumpRaw() writes here; on ESP32 drainTick() copies this
    // under a mutex into _hand for consumption in loop().
    struct RawCapture {
        uint8_t  buf[Radio::MAX_RAW_FRAME] = {};
        uint16_t len      = 0;
        Mode     mode     = Mode::T1;
        uint8_t  rssi     = 0;
        int8_t   freqEst  = 0;
        uint8_t  lqi      = 0;
        bool     overflow = false;
    };

    RawCapture _accum;                    // written by pumpRaw() / drainTick()
    uint32_t   _drainDeadline = 0;        // millis() deadline for current frame (0 = idle)

#if defined(ARDUINO_ARCH_ESP32)
    // ── ESP32 background drain ────────────────────────────────────────────
    // A high-priority esp_timer runs pumpRaw() (all radio/SPI) so the drain is
    // not starved by RTOS preemption of the Arduino loopTask. On finalize the
    // raw frame is handed off to loop() via _hand; decode/decrypt/callback
    // run there (main context), never in the timer.
    void startDrainTimer();
    void stopDrainTimer();
    void drainTick();                       // timer body (esp_timer task context)
    static void drainTimerTramp(void* arg);
    void consumeRaw();                      // loop() side: process handed-off frame

    esp_timer_handle_t _drainTimer = nullptr;
    portMUX_TYPE       _rawMux     = portMUX_INITIALIZER_UNLOCKED;
    volatile bool      _rawReady   = false;
    RawCapture         _hand;              // written by drainTick(), read by consumeRaw()
    uint32_t           _dropCount  = 0;

#elif defined(ARDUINO_ARCH_RP2040)
    // ── RP2040 hardware-timer drain ──────────────────────────────────────
    // A pico-sdk repeating_timer fires every 3 ms (alarm IRQ on Core0) and
    // calls drainTick() to drain the CC1101 FIFO. decode/decrypt/callback
    // happen in loop() via consumeRaw(). Both run on Core0 so noInterrupts()
    // / interrupts() suffice for the flag + copy handoff — no mutex needed.
    void startDrainTimer();
    void stopDrainTimer();
    void drainTick();                        // alarm-IRQ body
    static bool drainTimerTramp(struct repeating_timer *t);
    void consumeRaw();                       // loop() side: process handed-off frame

    struct repeating_timer _drainTimer;
    bool               _drainTimerRunning = false;
    mutex_t            _rp2040Mux;         // guards _hand + _rawReady; init in begin()
    volatile bool      _rawReady          = false;
    RawCapture         _hand;
    volatile uint32_t  _dropCount         = 0;
#endif

    // Diagnostics: how many times the background drain body executed.
    uint32_t _drainCount = 0;

    // Last frame's per-block CRC result (set by processRawFrame)
    uint8_t  _lastBadBlocks   = 0;
    uint8_t  _lastTotalBlocks = 0;

    // ── Decoded-frame ring buffer ─────────────────────────────────────────
    static constexpr uint8_t RING_SIZE = 4;
    Frame   _ring[RING_SIZE];
    uint8_t _ringHead  = 0;
    uint8_t _ringTail  = 0;
    uint8_t _ringCount = 0;

    // ── Per-instance AES key store ────────────────────────────────────────
    Crypto::Decrypt _keys;

    // ── Callback ──────────────────────────────────────────────────────────
    FrameCallback _callback;
};

// ── Stateless utility helpers ───────────────────────────────────────────────

// Returns a short ASCII label for the receive mode: "T1", "C1A", "C1B", "S1".
const char* modeName(Mode mode);

// Returns a human-readable label for an EN 13757-3 device type byte.
// e.g. 0x07 → "Water", 0x02 → "Electricity". Unrecognised values → "Unknown".
const char* devTypeName(uint8_t devType);

// Decodes the 2-byte M-field into the 3-character manufacturer string (A..Z).
// out must point to a buffer of at least 4 bytes; the string is NUL-terminated.
void decodeVendor(const uint8_t vendor[2], char out[4]);

} // namespace WMBus
