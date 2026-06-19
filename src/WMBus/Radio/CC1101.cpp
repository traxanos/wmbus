#include "CC1101.h"

namespace WMBus {
namespace Radio {

// ── Register tables for each wMBus mode ──────────────────────────────────
//
// All modes: 868.95 MHz, 32.768 kbps, 2-FSK, ±47 kHz deviation.
// Differences are sync word and packet length mode.
//
// Register values cross-referenced from:
//   - SzczepanLeon/wMbus-gateway (CC1101 configs)
//   - TI CC1101 datasheet (SWRS061H)
//   - EN 13757-4 physical layer spec

// GDO0 = 0x06: asserts when sync word detected, deasserts when packet complete
// (0x46 is wrong: bit6 = TEMP_SENSOR_ENABLE which overrides the signal config)
constexpr uint8_t GDO0_PKT_SYNC = 0x06;

static const RegVal T1_CONFIG[] = {
    {REG_IOCFG0,   GDO0_PKT_SYNC},
    {REG_FIFOTHR,  0x47},           // RX FIFO threshold 48 bytes
    {REG_PKTCTRL1, 0x00},           // no address check, no status appended
    {REG_PKTCTRL0, 0x02},           // infinite packet length (FIFO drained mid-packet)
    {REG_CHANNR,   0x00},
    {REG_FSCTRL1,  0x08},
    {REG_FSCTRL0,  0x00},           // no static freq offset — like culfw. FOCCFG
                                    // (0x2E) auto-compensates each board's crystal
                                    // offset, which keeps RX board-independent.
                                    // (A hardcoded +37 LSB here was tuned to one
                                    // old board and de-tuned every other crystal.)
    // ── RF/demod registers: proven culfw T-mode values (tmode_rf_settings.h) ──
    // Aligned to the reference that receives this meter without bit errors.
    {REG_FREQ2,    0x21},           // 868.9497 MHz
    {REG_FREQ1,    0x6B},
    {REG_FREQ0,    0xD0},
    {REG_MDMCFG4,  0x5C},           // BW 325 kHz, DRATE_E=12  → ~103 kBaud
    {REG_MDMCFG3,  0x04},           // DRATE_M=4  (culfw deliberately oversamples)
    {REG_MDMCFG2,  0x06},           // 2-FSK, no Manchester, 16/16 sync word
    {REG_MDMCFG1,  0x22},           // 4 preamble bytes, no FEC
    {REG_MDMCFG0,  0xF8},
    {REG_DEVIATN,  0x44},           // ±38 kHz (culfw T-mode value; 0x47 was wrong)
    {REG_MCSM2,    0x07},
    {REG_MCSM1,    0x00},           // after RX → IDLE
    {REG_MCSM0,    0x18},           // calibrate from IDLE → RX
    {REG_FOCCFG,   0x2E},           // freq offset compensation (culfw)
    {REG_BSCFG,    0xBF},           // bit sync / clock recovery (culfw)
    {REG_AGCCTRL2, 0x43},
    {REG_AGCCTRL1, 0x09},
    {REG_AGCCTRL0, 0xB5},
    {REG_WORCTRL,  0xFB},
    {REG_FREND1,   0xB6},
    {REG_FREND0,   0x10},
    {REG_FSCAL3,   0xEA},
    {REG_FSCAL2,   0x2A},
    {REG_FSCAL1,   0x00},
    {REG_FSCAL0,   0x1F},
    {REG_TEST2,    0x81},
    {REG_TEST1,    0x35},
    {REG_TEST0,    0x09},
    {REG_SYNC1,    0x54},           // T1 sync word: 0x543D
    {REG_SYNC0,    0x3D},
};

// C1A mode: same radio params, different sync word, infinite packet length.
// (no 3of6 encoding → first byte IS the L-field)
// PKTCTRL0=0x02 (infinite) so Receiver::loop() can drain the 64-byte FIFO
// mid-reception, exactly like T1. Frames are 170–192 raw bytes — well beyond
// the FIFO capacity if we wait for end-of-packet with variable-length mode.
static const RegVal C1A_CONFIG[] = {
    {REG_IOCFG0,   GDO0_PKT_SYNC},
    {REG_FIFOTHR,  0x47},
    {REG_PKTCTRL1, 0x00},
    {REG_PKTCTRL0, 0x02},           // infinite packet length (FIFO drained mid-packet)
    {REG_CHANNR,   0x00},
    {REG_FSCTRL1,  0x08},
    {REG_FSCTRL0,  0x00},
    // ── RF/demod: C-mode PHY (100 kBaud raw, ±47 kHz deviation) ─────────────
    // Data rate differs from T1 (100 vs 103 kBaud); all other timing registers
    // use the culfw-proven T1 values — same frequency band, same CC1101 clock,
    // valid at both rates.  Key: BSCFG=0xBF (max clock-recovery pre-lock gains)
    // and AGCCTRL1=0x09 (freeze AGC after sync) are critical for the 2-byte
    // C-mode preamble (vs T1's 4 bytes) — without them the first bytes after
    // sync have elevated BER.
    {REG_FREQ2,    0x21},           // 868.9528 MHz
    {REG_FREQ1,    0x6B},
    {REG_FREQ0,    0xD8},
    {REG_MDMCFG4,  0x5B},           // BW 325 kHz, DRATE_E=11  → ~100 kBaud
    {REG_MDMCFG3,  0xF8},           // DRATE_M=248
    {REG_MDMCFG2,  0x06},           // 2-FSK, no Manchester, 16/16 sync word
    {REG_MDMCFG1,  0x02},           // 2 preamble bytes (C-mode), no FEC
    {REG_MDMCFG0,  0xF8},
    {REG_DEVIATN,  0x47},           // ±47.6 kHz (C-mode spec; T1 uses ±38 kHz)
    {REG_MCSM2,    0x07},
    {REG_MCSM1,    0x00},           // after RX → IDLE
    {REG_MCSM0,    0x18},           // calibrate from IDLE → RX
    {REG_FOCCFG,   0x2E},           // freq offset compensation (culfw)
    {REG_BSCFG,    0xBF},           // bit sync / clock recovery (culfw — max gains)
    {REG_AGCCTRL2, 0x43},           // (culfw)
    {REG_AGCCTRL1, 0x09},           // freeze AGC after sync word (culfw)
    {REG_AGCCTRL0, 0xB5},           // (culfw)
    {REG_WORCTRL,  0xFB},
    {REG_FREND1,   0xB6},           // (culfw)
    {REG_FREND0,   0x10},
    {REG_FSCAL3,   0xEA},           // (culfw)
    {REG_FSCAL2,   0x2A},           // (culfw)
    {REG_FSCAL1,   0x00},           // (culfw)
    {REG_FSCAL0,   0x1F},           // (culfw)
    {REG_TEST2,    0x81},
    {REG_TEST1,    0x35},
    {REG_TEST0,    0x09},
    {REG_SYNC1,    0x54},           // C1A sync word: 0x54CD (EN 13757-4)
    {REG_SYNC0,    0xCD},
};

// C1B mode: identical PHY to C1A (868.95 MHz, 100 kBaud, ±47 kHz, raw bytes) but
// the sync word is 0x543D — the Frame-B variant of C-mode (EN 13757-4 §7.2).
// C1A (0x54CD) and C1B (0x543D) cannot be heard simultaneously (one sync-word
// register), so a meter that transmits C-mode Frame B needs this dedicated mode.
// Note: 0x543D is also T1's sync word; the raw-vs-3of6 decode is selected by the
// receive mode, not the sync word, so C1B always treats the bytes as raw C-mode.
static const RegVal C1B_CONFIG[] = {
    {REG_IOCFG0,   GDO0_PKT_SYNC},
    {REG_FIFOTHR,  0x47},
    {REG_PKTCTRL1, 0x00},
    {REG_PKTCTRL0, 0x02},           // infinite packet length (FIFO drained mid-packet)
    {REG_CHANNR,   0x00},
    {REG_FSCTRL1,  0x08},
    {REG_FSCTRL0,  0x00},
    // ── RF/demod: identical PHY to C1A, only sync word differs ───────────────
    {REG_FREQ2,    0x21},           // 868.9528 MHz
    {REG_FREQ1,    0x6B},
    {REG_FREQ0,    0xD8},
    {REG_MDMCFG4,  0x5B},           // BW 325 kHz, DRATE_E=11  → ~100 kBaud
    {REG_MDMCFG3,  0xF8},           // DRATE_M=248
    {REG_MDMCFG2,  0x06},           // 2-FSK, no Manchester, 16/16 sync word
    {REG_MDMCFG1,  0x02},           // 2 preamble bytes (C-mode), no FEC
    {REG_MDMCFG0,  0xF8},
    {REG_DEVIATN,  0x47},           // ±47.6 kHz (C-mode spec)
    {REG_MCSM2,    0x07},
    {REG_MCSM1,    0x00},           // after RX → IDLE
    {REG_MCSM0,    0x18},           // calibrate from IDLE → RX
    {REG_FOCCFG,   0x2E},           // freq offset compensation (culfw)
    {REG_BSCFG,    0xBF},           // bit sync / clock recovery (culfw — max gains)
    {REG_AGCCTRL2, 0x43},           // (culfw)
    {REG_AGCCTRL1, 0x09},           // freeze AGC after sync word (culfw)
    {REG_AGCCTRL0, 0xB5},           // (culfw)
    {REG_WORCTRL,  0xFB},
    {REG_FREND1,   0xB6},           // (culfw)
    {REG_FREND0,   0x10},
    {REG_FSCAL3,   0xEA},           // (culfw)
    {REG_FSCAL2,   0x2A},           // (culfw)
    {REG_FSCAL1,   0x00},           // (culfw)
    {REG_FSCAL0,   0x1F},           // (culfw)
    {REG_TEST2,    0x81},
    {REG_TEST1,    0x35},
    {REG_TEST0,    0x09},
    {REG_SYNC1,    0x54},           // C1 Frame B sync word: 0x543D (EN 13757-4 §7.2)
    {REG_SYNC0,    0x3D},
};

// S1 mode (EN 13757-4 stationary): a genuinely different PHY from T1/C1 —
// 868.30 MHz (NOT 868.95), 32.73 kBaud, Manchester coded. RF/demod values are
// the proven culfw S-mode set (smode_rf_settings.h, TI SmartRF base):
//   868.299866 MHz, 32.73 kBaud, RX BW 270 kHz, deviation 47 kHz,
//   2-FSK, NO hardware Manchester (MDMCFG2=0x06) → Manchester is decoded in
//   software (Frame::decodeManchester), exactly like 3of6 for T1.
// We keep our own packet handling (PKTCTRL0=0x02 infinite + RXBYTES drain)
// instead of culfw's fixed-length scheme, so only the PHY registers change.
static const RegVal S1_CONFIG[] = {
    {REG_IOCFG0,   GDO0_PKT_SYNC},
    {REG_FIFOTHR,  0x47},
    {REG_PKTCTRL1, 0x00},
    {REG_PKTCTRL0, 0x02},           // infinite packet length (FIFO drained mid-packet)
    {REG_CHANNR,   0x00},
    {REG_FSCTRL1,  0x08},
    {REG_FSCTRL0,  0x00},
    {REG_FREQ2,    0x21},           // 868.2999 MHz (S-mode carrier)
    {REG_FREQ1,    0x65},
    {REG_FREQ0,    0x6A},
    {REG_MDMCFG4,  0x6A},           // RX BW 270 kHz, DRATE_E=10
    {REG_MDMCFG3,  0x4A},           // DRATE_M=74  → 32.73 kBaud
    {REG_MDMCFG2,  0x06},           // 2-FSK, no Manchester, 16/16 sync
    {REG_MDMCFG1,  0x22},           // 4 preamble bytes
    {REG_MDMCFG0,  0xF8},
    {REG_DEVIATN,  0x47},           // ±47 kHz
    {REG_MCSM2,    0x07},
    {REG_MCSM1,    0x00},           // after RX → IDLE
    {REG_MCSM0,    0x18},
    {REG_FOCCFG,   0x2E},           // freq offset compensation (culfw)
    {REG_BSCFG,    0x6D},           // bit sync / clock recovery (culfw)
    {REG_AGCCTRL2, 0x04},
    {REG_AGCCTRL1, 0x09},
    {REG_AGCCTRL0, 0xB2},
    {REG_WORCTRL,  0xFB},
    {REG_FREND1,   0xB6},
    {REG_FREND0,   0x10},
    {REG_FSCAL3,   0xEA},
    {REG_FSCAL2,   0x2A},
    {REG_FSCAL1,   0x00},
    {REG_FSCAL0,   0x1F},
    {REG_TEST2,    0x81},
    {REG_TEST1,    0x35},
    {REG_TEST0,    0x09},
    {REG_SYNC1,    0x76},           // S1 sync word: 0x7696
    {REG_SYNC0,    0x96},
};

static constexpr uint8_t T1_SIZE  = sizeof(T1_CONFIG)  / sizeof(RegVal);
static constexpr uint8_t C1A_SIZE  = sizeof(C1A_CONFIG)  / sizeof(RegVal);
static constexpr uint8_t C1B_SIZE = sizeof(C1B_CONFIG) / sizeof(RegVal);
static constexpr uint8_t S1_SIZE  = sizeof(S1_CONFIG)  / sizeof(RegVal);

static SPISettings spiSettings(4000000, MSBFIRST, SPI_MODE0);

// ── Initialisation ────────────────────────────────────────────────────────

bool CC1101::begin(uint8_t csPin, uint8_t gdo0Pin, SPIClass& spi, Mode mode) {
    _csPin   = csPin;
    _gdo0Pin = gdo0Pin;
    _spi     = &spi;

    pinMode(_csPin, OUTPUT);
    digitalWrite(_csPin, HIGH);

    reset();

    // VERSION (0x31) is batch-dependent: 0x14 is most common, but 0x04, 0x07
    // and 0x17 are also genuine CC1101 lots. Only 0x00 (no MISO / chip dead)
    // and 0xFF (bus stuck high) are real faults — treat any other stable value
    // as "chip present, SPI works". PARTNUM (0x30) == 0x00 confirms a real part.
    uint8_t ver = readStatusReg(SREG_VERSION);
    bool ok = (ver != 0x00 && ver != 0xFF);

    applyMode(mode);
    startRx();
    return ok;
}

// ── Mode ──────────────────────────────────────────────────────────────────

void CC1101::applyMode(Mode mode) {
    switch (mode) {
        case Mode::C1A: applyConfig(C1A_CONFIG,  C1A_SIZE);  break;
        case Mode::C1B: applyConfig(C1B_CONFIG, C1B_SIZE); break;
        case Mode::S1:  applyConfig(S1_CONFIG,  S1_SIZE);  break;
        case Mode::T1C1B:   // combined T1+C1B uses the T1 PHY (sync 0x543D), auto-detect in decode
        case Mode::T1:
        default:        applyConfig(T1_CONFIG,  T1_SIZE);  break;
    }
    _mode = mode;
    applyTuning();   // re-apply user overrides on top of the mode defaults
}

void CC1101::applyTuning() {
    if (_freqOffset != 0)
        writeReg(REG_FSCTRL0, (uint8_t)_freqOffset);
    if (_gain != 0xFF)   // AGCCTRL2 [7:3] = DVGA+LNA, preserve MAGN_TARGET [2:0]
        writeReg(REG_AGCCTRL2, (readReg(REG_AGCCTRL2) & 0x07) | (_gain & 0xF8));
    if (_chanbw != 0xFF)
        writeReg(REG_MDMCFG4, (readReg(REG_MDMCFG4) & 0x0F) | (_chanbw << 4));
    if (_pqt != 0xFF)
        writeReg(REG_PKTCTRL1, (readReg(REG_PKTCTRL1) & 0x1F) | (_pqt << 5));
}

void CC1101::setMode(Mode mode) {
    strobe(STROBE_SIDLE);
    applyMode(mode);
    startRx();
}

void CC1101::setGain(Gain g) {
    if (g == Gain::High) {
        // High = maximum sensitivity = the mode table's tuned AGCCTRL2 value
        // (e.g. T1's culfw 0x43). Clear the override and re-apply the mode so the
        // proven register value is restored instead of being zeroed out.
        _gain = 0xFF;
        setMode(_mode);     // re-applies table + remaining (bw/pqt/freq) overrides
        return;
    }
    _gain = (uint8_t)g;
    strobe(STROBE_SIDLE);   // write modem/AGC regs in IDLE, then restart RX
    applyTuning();
    startRx();
}

void CC1101::setBandwidth(Bandwidth bw) {
    _chanbw = (uint8_t)bw;
    strobe(STROBE_SIDLE);
    applyTuning();
    startRx();
}

void CC1101::setFrequencyOffset(int8_t lsb) {
    _freqOffset = lsb;
    strobe(STROBE_SIDLE);
    applyTuning();
    startRx();
}

void CC1101::setPreambleQuality(uint8_t pqt) {
    _pqt = pqt & 0x07;
    strobe(STROBE_SIDLE);
    applyTuning();
    startRx();
}

// ── Diagnostics ─────────────────────────────────────────────────────────────

uint8_t CC1101::chipVersion() { return readStatusReg(SREG_VERSION); }
uint8_t CC1101::partNumber()  { return readStatusReg(SREG_PARTNUM); }

// ── Low-level register / FIFO access ─────────────────────────────────────────

void CC1101::reset() {
    digitalWrite(_csPin, LOW);
    delayMicroseconds(10);
    digitalWrite(_csPin, HIGH);
    delayMicroseconds(40);
    strobe(STROBE_SRES);
    delay(1);
}

void CC1101::writeReg(uint8_t reg, uint8_t val) {
    _spi->beginTransaction(spiSettings);
    digitalWrite(_csPin, LOW);
    _spi->transfer(reg);
    _spi->transfer(val);
    digitalWrite(_csPin, HIGH);
    _spi->endTransaction();
}

uint8_t CC1101::readReg(uint8_t reg) {
    _spi->beginTransaction(spiSettings);
    digitalWrite(_csPin, LOW);
    _spi->transfer(reg | READ_SINGLE);
    uint8_t val = _spi->transfer(0x00);
    digitalWrite(_csPin, HIGH);
    _spi->endTransaction();
    return val;
}

uint8_t CC1101::readStatusReg(uint8_t reg) {
    _spi->beginTransaction(spiSettings);
    digitalWrite(_csPin, LOW);
    _spi->transfer(reg | READ_BURST);
    uint8_t val = _spi->transfer(0x00);
    digitalWrite(_csPin, HIGH);
    _spi->endTransaction();
    return val;
}

void CC1101::strobe(uint8_t cmd) {
    _spi->beginTransaction(spiSettings);
    digitalWrite(_csPin, LOW);
    _spi->transfer(cmd);
    digitalWrite(_csPin, HIGH);
    _spi->endTransaction();
}

uint8_t CC1101::readFifo(uint8_t* buf, uint8_t maxLen) {
    uint8_t avail = readStatusReg(SREG_RXBYTES) & 0x7F;
    if (avail == 0) return 0;
    uint8_t n = (avail < maxLen) ? avail : maxLen;

    _spi->beginTransaction(spiSettings);
    digitalWrite(_csPin, LOW);
    _spi->transfer(RXFIFO | READ_BURST);
    for (uint8_t i = 0; i < n; i++) buf[i] = _spi->transfer(0x00);
    digitalWrite(_csPin, HIGH);
    _spi->endTransaction();
    return n;
}

void CC1101::applyConfig(const RegVal* table, uint8_t count) {
    for (uint8_t i = 0; i < count; i++) writeReg(table[i].reg, table[i].val);
}

void CC1101::startRx() {
    strobe(STROBE_SIDLE);
    strobe(STROBE_SFRX);
    strobe(STROBE_SRX);
}

uint8_t CC1101::readRSSI() {
    return readStatusReg(SREG_RSSI);
}

} // namespace Radio
} // namespace WMBus
