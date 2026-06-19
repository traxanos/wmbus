# WMBus

Arduino library for receiving **Wireless M-Bus** telegrams via a **CC1101** RF module.
Targets any Arduino-compatible platform: ESP32, ESP8266, Raspberry Pi Pico / Pico 2 (RP2040/RP2350), and others.

Receives T1/C1/S1 telegrams from water, gas, heat, and electricity meters (C1 supports Frame A and Frame B). Decrypts them automatically and parses all DIF/VIF data records into typed structures.

**Supported encryption:**
- **EN 13757-3 Mode 5** — AES-128-CBC with frame-derived IV (simple CI=0x7A frames)
- **OMS Security Mode 7** — AES-CMAC key derivation + AES-128-CBC (ELL+AFL+TPL layered frames)

All crypto is self-contained — no external library dependency.

## Hardware

Connect a CC1101 breakout board to any available SPI bus:

| CC1101 pin | Signal  |
|-----------|---------|
| VCC       | 3.3 V   |
| GND       | GND     |
| MOSI      | SPI MOSI|
| SCK       | SPI SCK |
| MISO      | SPI MISO|
| CSN       | any GPIO (csPin) |
| GDO0      | any interrupt-capable GPIO (gdo0Pin) |
| GDO2      | unused  |

## Installation

Copy `lib/wmbus/` into your project's `lib/` folder (PlatformIO), or install via the Arduino Library Manager.

Supported frameworks: `arduino` (any platform). No extra library dependencies.

## Quick start

```cpp
#include <Arduino.h>
#include <SPI.h>
#include <WMBus.h>

const uint8_t METER_KEY[16] = { 0x09, 0x2D, 0x7E, /* ... 13 more bytes ... */ };
constexpr uint32_t METER_ID = 0x64095861;

WMBus::Radio::CC1101 radio;
WMBus::Receiver      wmbus;

void onFrame(const WMBus::Frame& frame,
             const WMBus::DataRecord* records, uint8_t count) {
    if (!frame.complete() || frame.badBlocks() > 0 || (frame.encrypted() && !frame.decrypted()))
        return;

    Serial.printf("[%08lX] %s\n", (unsigned long)frame.meterId(), frame.vendorStr());
    for (uint8_t i = 0; i < count; i++) {
        const WMBus::DataRecord& r = records[i];
        if (r.quantity != WMBus::Quantity::Unknown)
            Serial.printf("  %-20s : %g %s\n", r.prettyName(), r.value(), r.unitStr());
    }
}

void setup() {
    Serial.begin(115200);

#if defined(ARDUINO_ARCH_RP2040)
    SPI.setRX(16); SPI.setTX(19); SPI.setSCK(18);
#endif
    SPI.begin();

    radio.begin(17 /*CS*/, 20 /*GDO0*/, SPI, WMBus::Mode::T1);
    wmbus.setKey(METER_ID, METER_KEY);
    wmbus.setCallback(onFrame);
    wmbus.begin(radio);
}

void loop() {
    wmbus.loop();
}
```

## API

### CC1101 class

```cpp
WMBus::Radio::CC1101 radio;

// Initialise CC1101 and start receiving. Call once from setup() after SPI.begin().
bool radio.begin(uint8_t csPin, uint8_t gdo0Pin,
                 SPIClass& spi = SPI, WMBus::Mode mode = Mode::T1);

void radio.setMode(WMBus::Mode mode);  // switch mode at runtime
uint8_t radio.chipVersion();           // VERSION register (expect 0x14)
uint8_t radio.partNumber();            // PARTNUM (genuine CC1101: 0x00)
```

### Receiver class

```cpp
WMBus::Receiver wmbus;

// Bind to an already-begin()ed radio. Call once from setup() after radio.begin().
void wmbus.begin(WMBus::Radio::CC1101& radio);

// Register/unregister an AES master key for a meter (16 bytes).
void wmbus.setKey(uint32_t meterId, const uint8_t key[16]);
void wmbus.removeKey(uint32_t meterId);

// Register a callback invoked once per parsed frame.
void wmbus.setCallback(WMBus::FrameCallback cb);

// Drive the receive state machine. Must be called continuously from Arduino loop().
void wmbus.loop();

// Diagnostics
uint32_t wmbus.packetCount();           // total sync words detected since begin()
void     wmbus.setMode(WMBus::Mode mode);

// Logging — the library never writes to Serial directly. Register a logger to
// receive diagnostic strings (raw dumps, CRC results, scan progress); without
// one the library is silent. setDebug() enables a verbose block per telegram,
// emitted through the logger.
void wmbus.setLogger(WMBus::LogCallback cb);  // e.g. [](const char* m){ Serial.println(m); }
void wmbus.setDebug(bool enable);
```

### Callback

```cpp
using FrameCallback = std::function<void(const WMBus::Frame& frame,
                                         const WMBus::DataRecord* records,
                                         uint8_t count)>;

wmbus.setCallback([](const WMBus::Frame& frame,
                     const WMBus::DataRecord* records, uint8_t count) {
    if (!frame.complete() || frame.badBlocks() > 0 || (frame.encrypted() && !frame.decrypted()))
        return;

    for (uint8_t i = 0; i < count; i++) {
        if (records[i].quantity == WMBus::Quantity::Volume) {
            float volume = records[i].value();
            // publish to MQTT, update display, etc.
        }
    }
});
```

### Frame class

```cpp
class WMBus::Frame {
public:
    uint32_t        meterId()    const;  // BCD-decoded meter ID
    const uint8_t*  vendor()     const;  // raw M-field (2 bytes)
    const char*     vendorStr()  const;  // 3-char string, e.g. "DME"
    uint8_t         version()    const;
    uint8_t         devType()    const;  // 0x07=Water, 0x03=Gas, etc.
    uint8_t         accessNo()   const;
    uint8_t         status()     const;

    uint8_t   encMode()    const;  // 0=none, 5=Mode 5, 7=OMS Mode 7
    uint8_t   encBlocks()  const;
    bool      encrypted()  const;
    bool      decrypted()  const;

    const uint8_t* payload()    const;
    uint16_t       payloadLen() const;

    uint8_t   badBlocks()   const;
    uint8_t   totalBlocks() const;
    bool      crcOk()       const;

    uint16_t  expectedLen() const;
    uint16_t  receivedLen() const;
    bool      complete()    const;

    int8_t      rssiDbm()  const;
    WMBus::Mode rxMode()   const;
};
```

### DataRecord — parsed M-Bus records

```cpp
struct WMBus::DataRecord {
    WMBus::Quantity quantity;   // Volume, VolumeFlow, Energy, Power, temps, …
    WMBus::Function function;   // Instantaneous, Maximum, Minimum, ErrorState
    uint8_t  storage;           // 0 = current, 1+ = historical
    uint8_t  tariff;

    int32_t  rawValue;
    int8_t   exponent;          // actual = rawValue × 10^exponent
    float    value() const;

    uint8_t  day, month; uint16_t year;
    uint8_t  hour, minute;
    bool     hasTime;

    const char* prettyName() const;  // "Water volume", "Flow temperature", …
    const char* unitStr()    const;  // "m3", "m3/h", "C", "W", …
};

enum class WMBus::Quantity : uint8_t {
    Unknown, Volume, VolumeFlow, Energy, Power,
    FlowTemperature, ReturnTemperature, ExternalTemperature,
    TemperatureDifference, Pressure,
    OnTime, OperatingTime, Date, DateTime
};

enum class WMBus::Function : uint8_t {
    Instantaneous = 0, Maximum = 1, Minimum = 2, ErrorState = 3
};
```

### Utility functions

```cpp
void        WMBus::decodeVendor(const uint8_t vendor[2], char out[4]);
const char* WMBus::modeName(WMBus::Mode mode);       // "T1", "C1A", "C1B", "S1"
const char* WMBus::devTypeName(uint8_t devType);     // "Water", "Gas", …
```

### Receive modes

| Mode   | Sync word | Encoding | Use case |
|--------|-----------|----------|----------|
| T1     | 0x543D    | 3of6     | Most European water/gas/heat meters |
| C1A    | 0x54CD    | raw      | Compact frame meters (Frame A) |
| C1B    | 0x543D    | raw      | Compact frame meters (Frame B, e.g. some heat meters) |
| T1C1B  | 0x543D    | auto     | Combined T1 + C1B (same carrier and sync word) |
| S1     | 0x7696    | raw      | Stationary meters (24-byte preamble) |

## Decryption details

### Mode 5 (EN 13757-3)

Used by devices with a simple `CI=0x7A` short header:

```
IV = mfr[0..1] | ID[0..3] | version | devType | accessNo×8
decrypt = AES-128-CBC(registeredKey, IV, ciphertext)
```

### Mode 7 (OMS Security Mode 7, Profile B)

Used by devices with ELL-I (`CI=0x8C`) + AFL (`CI=0x90`) + TPL (`CI=0x7A`) layering:

```
MCR  = 4-byte message counter from AFL layer
Kenc = AES-CMAC(masterKey, 0x00 | MCR | meterID[LE] | 0x07×7)
decrypt = AES-128-CBC(Kenc, IV=0×16, ciphertext)
```

The registered key is the **master key**. `Kenc` is derived per-message from the MCR counter embedded in each frame.

## Known issues / hardware notes

- **Cheap CC1101 breakout boards:** May have slight RF drift. If frames come in truncated at -70 to -75 dBm but work fine on a tuned CUL stick, check antenna coupling and SMA connector contact.
- **CC1101 FIFO erratum SWRZ020:** Reading the last byte in the FIFO while the radio is still writing corrupts it. During active T1 reception the library always leaves ≥1 byte unread; final drain happens only after strobing SIDLE.

## Acknowledgements

Thanks to [@mf583](https://github.com/mf583) for extensive real-world testing and validation across multiple meter types and modes.
