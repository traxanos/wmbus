#pragma once
#include <Arduino.h>
#include <SPI.h>
#include "../Frame.h"   // WMBus::Mode

namespace WMBus {
namespace Radio {

// ── Configuration registers ───────────────────────────────────────────────
constexpr uint8_t REG_IOCFG2   = 0x00;
constexpr uint8_t REG_IOCFG1   = 0x01;
constexpr uint8_t REG_IOCFG0   = 0x02;
constexpr uint8_t REG_FIFOTHR  = 0x03;
constexpr uint8_t REG_SYNC1    = 0x04;
constexpr uint8_t REG_SYNC0    = 0x05;
constexpr uint8_t REG_PKTLEN   = 0x06;
constexpr uint8_t REG_PKTCTRL1 = 0x07;
constexpr uint8_t REG_PKTCTRL0 = 0x08;
constexpr uint8_t REG_CHANNR   = 0x0A;
constexpr uint8_t REG_FSCTRL1  = 0x0B;
constexpr uint8_t REG_FSCTRL0  = 0x0C;
constexpr uint8_t REG_FREQ2    = 0x0D;
constexpr uint8_t REG_FREQ1    = 0x0E;
constexpr uint8_t REG_FREQ0    = 0x0F;
constexpr uint8_t REG_MDMCFG4  = 0x10;
constexpr uint8_t REG_MDMCFG3  = 0x11;
constexpr uint8_t REG_MDMCFG2  = 0x12;
constexpr uint8_t REG_MDMCFG1  = 0x13;
constexpr uint8_t REG_MDMCFG0  = 0x14;
constexpr uint8_t REG_DEVIATN  = 0x15;
constexpr uint8_t REG_MCSM2    = 0x16;
constexpr uint8_t REG_MCSM1    = 0x17;
constexpr uint8_t REG_MCSM0    = 0x18;
constexpr uint8_t REG_FOCCFG   = 0x19;
constexpr uint8_t REG_BSCFG    = 0x1A;
constexpr uint8_t REG_AGCCTRL2 = 0x1B;
constexpr uint8_t REG_AGCCTRL1 = 0x1C;
constexpr uint8_t REG_AGCCTRL0 = 0x1D;
constexpr uint8_t REG_WORCTRL  = 0x20;
constexpr uint8_t REG_FREND1   = 0x21;
constexpr uint8_t REG_FREND0   = 0x22;
constexpr uint8_t REG_FSCAL3   = 0x23;
constexpr uint8_t REG_FSCAL2   = 0x24;
constexpr uint8_t REG_FSCAL1   = 0x25;
constexpr uint8_t REG_FSCAL0   = 0x26;
constexpr uint8_t REG_TEST2    = 0x2C;
constexpr uint8_t REG_TEST1    = 0x2D;
constexpr uint8_t REG_TEST0    = 0x2E;

// ── Status registers (read with burst flag) ───────────────────────────────
constexpr uint8_t SREG_PARTNUM  = 0x30;
constexpr uint8_t SREG_VERSION  = 0x31;  // expected: 0x14
constexpr uint8_t SREG_FREQEST  = 0x32;  // estimated frequency offset (signed, ~1.59 kHz/LSB @ 325 kHz BW)
constexpr uint8_t SREG_LQI      = 0x33;  // link quality (lower 7 bits; bit7 = CRC_OK)
constexpr uint8_t SREG_RSSI     = 0x34;
constexpr uint8_t SREG_MARCSTATE= 0x35;
constexpr uint8_t SREG_RXBYTES  = 0x3B;

// ── Strobe commands ───────────────────────────────────────────────────────
constexpr uint8_t STROBE_SRES   = 0x30;
constexpr uint8_t STROBE_SRX    = 0x34;
constexpr uint8_t STROBE_SIDLE  = 0x36;
constexpr uint8_t STROBE_SFRX   = 0x3A;
constexpr uint8_t STROBE_SNOP   = 0x3D;

// ── FIFO ──────────────────────────────────────────────────────────────────
constexpr uint8_t RXFIFO        = 0x3F;

// ── SPI access flags ──────────────────────────────────────────────────────
constexpr uint8_t READ_SINGLE   = 0x80;
constexpr uint8_t READ_BURST    = 0xC0;
constexpr uint8_t WRITE_BURST   = 0x40;

// ── Expected chip version ─────────────────────────────────────────────────
constexpr uint8_t EXPECTED_VERSION = 0x14;

// ── Maximum raw FIFO bytes per receive ───────────────────────────────────
// Worst-case raw (on-air) bytes for a max frame (L=0xFF → 290 Frame-A bytes
// incl. inter-block CRCs):
//   T1: ×1.5 (3of6)      = 435 raw
//   C1:  ×1   (raw)      = 290 raw  (Frame A; Frame B is smaller)
//   S1: ×2   (Manchester)= 580 raw   ← the binding case
// 580 is exactly the S-mode maximum. The pumpRaw() space-clamp prevents any
// overflow; bytes past the 580-byte frame are only postamble and not needed.
// Sizes the two accumulation buffers and the two static decode buffers.
constexpr uint16_t MAX_RAW_FRAME = 580;

// One register/value pair in a configuration table.
struct RegVal { uint8_t reg; uint8_t val; };

// ── CC1101 transceiver ─────────────────────────────────────────────────────
//
// Drives one CC1101 on a given SPI bus: its chip-select / GDO0 pins, the SPI
// bus, the optional bus pin assignments, and the currently configured wMBus
// mode. All configuration is passed to begin() — the (empty) constructor touches
// no hardware, so a global instance is safe to declare before setup() runs.
//
// The class does NOT manage the GDO0 interrupt; that belongs to the Receiver,
// which reads gdo0Pin() and mode() to wire it up.
// Receiver gain — pre-shifted AGCCTRL2 bits [7:3]:
// [7:6] MAX_DVGA_GAIN + [5:3] MAX_LNA_GAIN. Lower = less sensitive front-end,
// so the receiver physically hears less (weak noise / distant meters drop out).
enum class Gain : uint8_t {
    High   = 0x00,  // most sensitive = keep the mode table's tuned AGCCTRL2 (no override)
    Medium = 0x18,  // LNA  -7.4 dB
    Low    = 0x30,  // LNA -14.6 dB
    Min    = 0xF0,  // 3 top DVGA steps off + LNA -14.6 dB (deafest)
};

enum class Bandwidth : uint8_t {
    Wide   = 0x5,  // 325 kHz (default) — accepts signals up to ~160 kHz off-channel
    Medium = 0x8,  // 203 kHz
    Narrow = 0xA,  // 135 kHz — rejects signals >67 kHz off-channel
};

class CC1101 {
public:
    CC1101() = default;

    // Apply the mode's register set and start RX.
    // Call once from setup(), after the SPI bus has been configured and started
    // by the application. Returns false if the VERSION register is unreadable
    // (wiring or power fault).
    //   csPin / gdo0Pin : chip-select and GDO0 (sync/packet) GPIOs.
    //   spi             : already-initialised SPI bus (caller owns begin/end).
    //   mode            : wMBus receive mode (T1, C1A, C1B, or S1).
    bool begin(uint8_t csPin, uint8_t gdo0Pin, SPIClass& spi = SPI,
               Mode mode = Mode::T1);

    // Adjust LNA gain (write takes effect immediately).
    // High = full sensitivity; Low = ~15 dB less, filters out distant meters.
    void setGain(Gain g);

    // Adjust channel bandwidth (write takes effect immediately).
    // Narrow rejects signals that are significantly off the wMBus center frequency.
    void setBandwidth(Bandwidth bw);

    // Set a static frequency offset (FSCTRL0), signed, ~1.59 kHz per LSB @ 26 MHz.
    // Use to re-center RX on a meter whose FREQEST is consistently non-zero, so
    // off-channel interferers fall outside a Narrow bandwidth. Takes effect at once.
    void setFrequencyOffset(int8_t lsb);

    // Preamble quality threshold (PKTCTRL1 bits [7:5], 0–7).
    // The CC1101 counts 0xAA preamble transitions before accepting a sync word.
    // Higher values reject more false sync detections from noise; 4 is a good
    // starting point. 0 = disabled (default). Takes effect at once.
    void setPreambleQuality(uint8_t pqt);

    // Re-apply a mode's register set and restart RX. Stores the new mode.
    void setMode(Mode mode);

    // The mode this radio is currently configured for.
    Mode    mode()    const { return _mode; }
    uint8_t gdo0Pin() const { return _gdo0Pin; }

    // Diagnostics. VERSION is commonly 0x14 (0x04/0x07/0x17 are also genuine).
    // PARTNUM is 0x00 on a real CC1101.
    uint8_t chipVersion();
    uint8_t partNumber();

    // ── Low-level register / FIFO access (used by the Receiver) ───────────
    void    reset();
    void    writeReg(uint8_t reg, uint8_t val);
    uint8_t readReg(uint8_t reg);
    uint8_t readStatusReg(uint8_t reg);
    void    strobe(uint8_t cmd);
    uint8_t readFifo(uint8_t* buf, uint8_t maxLen);
    void    startRx();
    uint8_t readRSSI();

private:
    void applyMode(Mode mode);
    void applyConfig(const RegVal* table, uint8_t count);
    // Re-apply the stored gain/bandwidth/offset overrides on top of the mode's
    // register table. Called at the end of applyMode() so the tuning survives
    // every mode switch instead of being reset to the table defaults.
    void applyTuning();

    uint8_t   _csPin   = 0;
    uint8_t   _gdo0Pin = 0;
    SPIClass* _spi     = nullptr;
    Mode      _mode    = Mode::T1;

    // User tuning overrides (0xFF = leave the mode table's default).
    int8_t    _freqOffset = 0;     // FSCTRL0
    uint8_t   _gain       = 0xFF;  // AGCCTRL2 bits [7:3] (DVGA + LNA)
    uint8_t   _chanbw     = 0xFF;  // MDMCFG4  bits [7:4]
    uint8_t   _pqt        = 0xFF;  // PKTCTRL1 bits [7:5] (preamble quality threshold)
};

} // namespace Radio
} // namespace WMBus
