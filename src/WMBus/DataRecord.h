#pragma once
#include <Arduino.h>

namespace WMBus {

// Physical quantity the record describes (EN 13757-3 VIF table)
enum class Quantity : uint8_t {
    Unknown,
    Volume,               // m³
    VolumeFlow,           // m³/h
    Energy,               // Wh
    Power,                // W
    FlowTemperature,      // °C
    ReturnTemperature,    // °C
    ExternalTemperature,      // °C
    TemperatureDifference,    // K
    Pressure,                 // bar
    OnTime,               // seconds (raw value; see unitStr)
    OperatingTime,        // seconds (raw value; see unitStr)
    Date,                 // type G: day/month/year only
    DateTime,             // type F: + hour/minute
};

// DIF function field
enum class Function : uint8_t {
    Instantaneous = 0,
    Maximum       = 1,
    Minimum       = 2,
    ErrorState    = 3,
};

// One parsed DIF/VIF data record.
//
// Numeric value: actual_value = rawValue × 10^exponent.
// For Date/DateTime: use the day/month/year/hour/minute fields.
//
// Example — Volume record:
//   quantity = Volume, rawValue = 747743, exponent = -3
//   → 747.743 m³  (call value() to get the float)
struct DataRecord {
    Quantity  quantity = Quantity::Unknown;
    Function  function = Function::Instantaneous;
    uint8_t   storage  = 0;   // 0 = current period, 1+ = historical
    uint8_t   tariff   = 0;

    int32_t   rawValue = 0;
    int8_t    exponent = 0;

    uint8_t   dif      = 0;   // raw DIF byte (low nibble = data-field length code)
    uint8_t   vif      = 0;   // raw VIF byte

    // Date / DateTime fields (quantity == Date or DateTime)
    uint8_t   day     = 0;
    uint8_t   month   = 0;
    uint16_t  year    = 0;
    uint8_t   hour    = 0;
    uint8_t   minute  = 0;
    bool      hasTime = false;

    float       value()       const;
    const char* unitStr()     const;
    const char* quantityStr() const;  // technical: "Volume", "FlowTemp", …
    const char* prettyName()  const;  // human:     "Water volume", "Flow temperature", …
    const char* functionStr() const;
};

constexpr uint8_t MAX_DATA_RECORDS = 20;

// Parse DIF/VIF data records from a decrypted wMBus payload.
// Leading 0x2F fill bytes are skipped automatically.
// Returns the number of records parsed (≤ maxOut).
// Works for water, gas, heat, electricity meters — any standard VIF set.
uint8_t parseRecords(const uint8_t* payload, uint8_t payloadLen,
                     DataRecord* out, uint8_t maxOut);

} // namespace WMBus
