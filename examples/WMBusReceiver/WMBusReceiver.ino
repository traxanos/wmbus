// WMBusReceiver — minimal wMBus example for copy-paste use
//
// Wiring (RP2040 Pico SPI0):
//   CC1101 VCC  → 3V3    (pin 36)
//   CC1101 GND  → GND    (pin 38)
//   CC1101 MOSI → GPIO19 (pin 25)
//   CC1101 SCK  → GPIO18 (pin 24)
//   CC1101 MISO → GPIO16 (pin 21)
//   CC1101 CSN  → GPIO17 (pin 22)
//   CC1101 GDO0 → GPIO20 (pin 26)

#include <WMBus.h>

WMBus::Radio::CC1101 radio;
WMBus::Receiver      wmbus;

// ── Meter credentials — replace with your meter's ID and AES key ──────────
constexpr uint32_t METER_ID     = 0x12345678;
const uint8_t      METER_KEY[16] = {
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
};

void onFrame(const WMBus::Frame& frame,
             const WMBus::DataRecord* records, uint8_t count) {

    if (!frame.complete() || frame.badBlocks() > 0
        || (frame.encrypted() && !frame.decrypted()))
        return;

    Serial.printf("[%08lX] %s", (unsigned long)frame.meterId(),
                  WMBus::devTypeName(frame.devType()));

    for (uint8_t i = 0; i < count; i++) {
        const WMBus::DataRecord& r = records[i];
        if (r.storage  != 0)                               continue;
        if (r.function != WMBus::Function::Instantaneous)  continue;
        if (r.quantity == WMBus::Quantity::Unknown)         continue;
        if (r.quantity == WMBus::Quantity::Date
         || r.quantity == WMBus::Quantity::DateTime)        continue;
        bool isTemp = (r.quantity == WMBus::Quantity::FlowTemperature   ||
                       r.quantity == WMBus::Quantity::ReturnTemperature  ||
                       r.quantity == WMBus::Quantity::ExternalTemperature);
        Serial.printf(" - %.*f %s", isTemp ? 1 : 3, r.value(), r.unitStr());
    }
    Serial.println();
}

void setup() {
    Serial.begin(115200);

    // Configure SPI bus (RP2040 Pico pin assignment shown; adapt for your board)
    SPI.setRX(16); SPI.setTX(19); SPI.setSCK(18);
    SPI.begin();

    if (!radio.begin(17, 20, SPI, WMBus::Mode::T1C1B)) {
        Serial.println("CC1101 not found");
        while (true);
    }

    wmbus.setKey(METER_ID, METER_KEY);
    wmbus.begin(radio);
    wmbus.setCallback(onFrame);

    // Optional: enable verbose per-telegram logging to Serial.
    // Remove these two lines in production.
    wmbus.setLogger([](const char* msg){ Serial.println(msg); });
    wmbus.setDebug(true);

    Serial.println("Ready");
}

void loop() {
    wmbus.loop();
}
