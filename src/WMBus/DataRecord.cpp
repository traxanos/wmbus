#include "DataRecord.h"

namespace WMBus {

// ── Helpers ──────────────────────────────────────────────────────────────────

float DataRecord::value() const {
    float v = (float)rawValue;
    if (exponent > 0) {
        for (int8_t i = 0; i < exponent;  i++) v *= 10.0f;
    } else {
        for (int8_t i = 0; i < -exponent; i++) v /= 10.0f;
    }
    return v;
}

const char* DataRecord::unitStr() const {
    switch (quantity) {
        case Quantity::Volume:              return "m3";
        case Quantity::VolumeFlow:          return "m3/h";
        case Quantity::Energy:              return "Wh";
        case Quantity::Power:               return "W";
        case Quantity::FlowTemperature:     return "C";
        case Quantity::ReturnTemperature:   return "C";
        case Quantity::ExternalTemperature:   return "C";
        case Quantity::TemperatureDifference: return "K";
        case Quantity::Pressure:              return "bar";
        case Quantity::OnTime:              return "s";
        case Quantity::OperatingTime:       return "s";
        default:                            return "";
    }
}

const char* DataRecord::quantityStr() const {
    switch (quantity) {
        case Quantity::Volume:              return "Volume";
        case Quantity::VolumeFlow:          return "VolumeFlow";
        case Quantity::Energy:              return "Energy";
        case Quantity::Power:               return "Power";
        case Quantity::FlowTemperature:     return "FlowTemp";
        case Quantity::ReturnTemperature:   return "ReturnTemp";
        case Quantity::ExternalTemperature:   return "ExtTemp";
        case Quantity::TemperatureDifference: return "TempDiff";
        case Quantity::Pressure:              return "Pressure";
        case Quantity::OnTime:              return "OnTime";
        case Quantity::OperatingTime:       return "OpTime";
        case Quantity::Date:                return "Date";
        case Quantity::DateTime:            return "DateTime";
        default:                            return "Unknown";
    }
}

const char* DataRecord::prettyName() const {
    switch (quantity) {
        case Quantity::Volume:              return "Water volume";
        case Quantity::VolumeFlow:          return "Flow rate";
        case Quantity::Energy:              return "Energy";
        case Quantity::Power:               return "Power";
        case Quantity::FlowTemperature:     return "Flow temperature";
        case Quantity::ReturnTemperature:   return "Return temperature";
        case Quantity::ExternalTemperature:   return "External temperature";
        case Quantity::TemperatureDifference: return "Temperature difference";
        case Quantity::Pressure:              return "Pressure";
        case Quantity::OnTime:              return "On time";
        case Quantity::OperatingTime:       return "Operating time";
        case Quantity::Date:                return "Meter date";
        case Quantity::DateTime:            return "Meter timestamp";
        default:                            return quantityStr();
    }
}

const char* DataRecord::functionStr() const {
    switch (function) {
        case Function::Instantaneous: return "inst";
        case Function::Maximum:       return "max";
        case Function::Minimum:       return "min";
        case Function::ErrorState:    return "err";
        default:                      return "?";
    }
}

// ── DIF/VIF parser internals ─────────────────────────────────────────────────

// Data byte count for DIF data field (bits 3:0), index 0..15.
// 0xD (variable) and 0xF (special) return 0 → caller skips the record.
static const uint8_t DATA_LEN[16] = {0,1,2,3,4,4,6,8,0,1,2,3,4,0,6,0};

// Decode N bytes of little-endian BCD (2 digits per byte) → int32.
// EN 13757-3 §6.3: a 0xF in the most-significant nibble marks a negative value.
// Meters sign small/decreasing readings this way (e.g. a residual flow of
// -0.003 m³/h just after a tap closes). Treating that 0xF as a digit would
// inflate the result by 15·10^(2N-1) — e.g. a flow of 0.003 reads as 1500.003.
static int32_t decodeBCD(const uint8_t* b, uint8_t n) {
    bool negative = (n > 0) && (((b[n - 1] >> 4) & 0x0F) == 0x0F);

    int32_t v = 0, mult = 1;
    for (uint8_t i = 0; i < n; i++) {
        v += (b[i] & 0x0F) * mult;        mult *= 10;
        uint8_t hi = (b[i] >> 4) & 0x0F;
        if (!(negative && i == n - 1))    // skip the sign nibble, not a digit
            v += hi * mult;
        mult *= 10;
    }
    return negative ? -v : v;
}

// Decode N bytes of little-endian signed integer (1–4 bytes) → int32.
static int32_t decodeInt(const uint8_t* b, uint8_t n) {
    int32_t v = 0;
    for (uint8_t i = 0; i < n && i < 4; i++)
        v |= ((int32_t)b[i] << (8 * i));
    // Sign-extend
    if (n < 4 && n > 0 && (b[n - 1] & 0x80))
        for (uint8_t i = n; i < 4; i++) v |= (int32_t)(0xFF) << (8 * i);
    return v;
}

// EN 13757-3 Type G date: 2 bytes LE
//   byte0 [4:0]=day  [7:5]=year[2:0]
//   byte1 [3:0]=month  [7:4]=year[6:3]
static void decodeTypeG(const uint8_t* b,
                         uint8_t& day, uint8_t& month, uint16_t& year) {
    day   = b[0] & 0x1F;
    month = b[1] & 0x0F;
    uint16_t y = ((uint16_t)(b[0] >> 5) & 0x07)
               | (((uint16_t)(b[1] >> 4) & 0x0F) << 3);
    year  = 2000u + y;
}

// EN 13757-3 Type F date+time: 4 bytes LE
//   byte0 [5:0]=minute
//   byte1 [4:0]=hour
//   byte2 [4:0]=day   [7:5]=year[2:0]
//   byte3 [3:0]=month [7:4]=year[6:3]
static void decodeTypeF(const uint8_t* b, uint8_t& minute, uint8_t& hour,
                         uint8_t& day, uint8_t& month, uint16_t& year) {
    minute = b[0] & 0x3F;
    hour   = b[1] & 0x1F;
    day    = b[2] & 0x1F;
    month  = b[3] & 0x0F;
    uint16_t y = ((uint16_t)(b[2] >> 5) & 0x07)
               | (((uint16_t)(b[3] >> 4) & 0x0F) << 3);
    year   = 2000u + y;
}

// ── Public parser ─────────────────────────────────────────────────────────────

uint8_t parseRecords(const uint8_t* payload, uint8_t len,
                     DataRecord* out, uint8_t maxOut) {
    if (!payload || !out || maxOut == 0) return 0;

    uint8_t pos   = 0;
    uint8_t count = 0;

    // Skip leading fill bytes (0x2F = decryption-check padding)
    while (pos < len && payload[pos] == 0x2F) pos++;

    while (pos < len && count < maxOut) {

        // ── DIF ──────────────────────────────────────────────────────────
        uint8_t dif0 = payload[pos++];

        if (dif0 == 0x0F || dif0 == 0x1F) break;   // manufacturer-specific, stop
        if (dif0 == 0x2F) continue;                  // fill, skip

        DataRecord rec{};
        rec.dif       = dif0;
        rec.function  = (Function)((dif0 >> 5) & 0x03);
        uint8_t dataField = dif0 & 0x0F;
        uint8_t storage   = (dif0 >> 4) & 0x01;     // storage bit 0 from DIF

        // ── DIFEs ────────────────────────────────────────────────────────
        // Storage number: DIF[4] is bit 0; each DIFE's bits [5:4] contribute
        // the next 2 bits (EN 13757-3 §6.4.1).
        uint8_t prev = dif0;
        uint8_t difeShift = 1;
        while ((prev & 0x80) && pos < len) {
            uint8_t dife = payload[pos++];
            storage   |= (uint8_t)(((dife >> 4) & 0x03) << difeShift);
            rec.tariff |= (uint8_t)(((dife >> 2) & 0x03) << (difeShift - 1));
            difeShift += 2;
            prev = dife;
        }
        rec.storage = storage;

        if (pos >= len) break;

        // ── VIF ──────────────────────────────────────────────────────────
        uint8_t vif = payload[pos++];
        rec.vif = vif;

        // When VIF bit7 is set an extension byte (VIFE) follows.
        // Consume all VIFE bytes — we mark these as Unknown quantity.
        bool hasVife = (vif & 0x80) != 0;
        uint8_t vife = 0;
        if (hasVife && pos < len) {
            vife = payload[pos++];
            // Consume chained VIFEs (each with bit7=1)
            while ((vife & 0x80) && pos < len) vife = payload[pos++];
        }
        uint8_t vifBase = vif & 0x7F;

        // ── Data bytes ───────────────────────────────────────────────────
        uint8_t dlen = DATA_LEN[dataField];
        if (dataField == 0x0D || dataField == 0x0F) {
            // variable / special: give up on this record and the rest,
            // length field would need its own parsing
            break;
        }
        if (pos + dlen > len) break;
        const uint8_t* data = payload + pos;
        pos += dlen;

        if (dataField == 0x00) continue;  // DIF says "no data", skip

        // Decode raw value
        bool isBCD = (dataField >= 0x09 && dataField <= 0x0E);
        if (isBCD) {
            rec.rawValue = decodeBCD(data, dlen);
        } else {
            rec.rawValue = decodeInt(data, dlen);
        }

        // ── VIF → quantity + exponent ────────────────────────────────────
        if (!hasVife) {
            if (vifBase <= 0x07) {
                // Energy Wh, 10^(n-3)
                rec.quantity = Quantity::Energy;
                rec.exponent = (int8_t)(vifBase) - 3;
            } else if (vifBase <= 0x0F) {
                // Energy J, 10^(n-0)
                rec.quantity = Quantity::Energy;
                rec.exponent = (int8_t)(vifBase & 0x07);
            } else if (vifBase <= 0x17) {
                // Volume m³, 10^(n-6)
                rec.quantity = Quantity::Volume;
                rec.exponent = (int8_t)(vifBase & 0x07) - 6;
            } else if (vifBase >= 0x20 && vifBase <= 0x23) {
                // On time: raw = seconds/minutes/hours/days
                rec.quantity = Quantity::OnTime;
                rec.exponent = 0;
            } else if (vifBase >= 0x24 && vifBase <= 0x27) {
                rec.quantity = Quantity::OperatingTime;
                rec.exponent = 0;
            } else if (vifBase >= 0x28 && vifBase <= 0x2F) {
                // Power W, 10^(n-3)
                rec.quantity = Quantity::Power;
                rec.exponent = (int8_t)(vifBase & 0x07) - 3;
            } else if (vifBase >= 0x38 && vifBase <= 0x3F) {
                // Volume flow m³/h, 10^(n-6)
                rec.quantity = Quantity::VolumeFlow;
                rec.exponent = (int8_t)(vifBase & 0x07) - 6;
            } else if (vifBase >= 0x58 && vifBase <= 0x5B) {
                // Flow temperature °C, 10^(n-3)
                rec.quantity = Quantity::FlowTemperature;
                rec.exponent = (int8_t)(vifBase & 0x03) - 3;
            } else if (vifBase >= 0x5C && vifBase <= 0x5F) {
                // Return temperature °C, 10^(n-3)
                rec.quantity = Quantity::ReturnTemperature;
                rec.exponent = (int8_t)(vifBase & 0x03) - 3;
            } else if (vifBase >= 0x60 && vifBase <= 0x63) {
                // Temperature difference K, 10^(n-3)
                rec.quantity = Quantity::TemperatureDifference;
                rec.exponent = (int8_t)(vifBase & 0x03) - 3;
            } else if (vifBase >= 0x64 && vifBase <= 0x67) {
                // External temperature °C, 10^(n-3)
                rec.quantity = Quantity::ExternalTemperature;
                rec.exponent = (int8_t)(vifBase & 0x03) - 3;
            } else if (vifBase >= 0x68 && vifBase <= 0x6B) {
                // Pressure bar, 10^(n-3)
                rec.quantity = Quantity::Pressure;
                rec.exponent = (int8_t)(vifBase & 0x03) - 3;
            } else if (vifBase == 0x6C) {
                // Date (Type G)
                rec.quantity = Quantity::Date;
                rec.hasTime  = false;
                if (dlen >= 2) decodeTypeG(data, rec.day, rec.month, rec.year);
            } else if (vifBase == 0x6D) {
                // Date+Time (Type F)
                rec.quantity = Quantity::DateTime;
                rec.hasTime  = true;
                if (dlen >= 4)
                    decodeTypeF(data, rec.minute, rec.hour,
                                rec.day, rec.month, rec.year);
            }
            // All other VIF values → Quantity::Unknown, rawValue preserved
        }
        // VIFE records (hasVife=true) remain Quantity::Unknown with rawValue set

        out[count++] = rec;
    }

    return count;
}

} // namespace WMBus
