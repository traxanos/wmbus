# WMBus Library

Arduino library for receiving Wireless M-Bus telegrams via CC1101 RF module.
Targets any Arduino-compatible platform (ESP32, ESP8266, RP2040/RP2350, …).

## Library layout

```
src/
  WMBus.h / .cpp            Public API: Receiver class, callbacks (namespace WMBus::)
  WMBus/
    Frame.h / .cpp          3of6 decoder, frame parser, decryption
    DataRecord.h / .cpp     DIF/VIF data record parser (EN 13757-3)
    Crypto/
      AES.h / .cpp          AES-128-CBC + AES-CMAC encryption/key derivation
      CRC.h / .cpp          EN 13757-4 CRC-16 validation
      Decrypt.h / .cpp      Per-instance AES key store
    Radio/
      CC1101.h / .cpp       CC1101 SPI driver, register tables
examples/
  WMBusReceiver/
    WMBusReceiver.ino       Minimal Arduino IDE example
README.md                   User-facing docs: wiring, quick start, full API reference
AGENTS.md                   This file: contributor/agent notes, constraints, internals
CLAUDE.md                   Claude Code entry point — just @-includes AGENTS.md
library.properties          Arduino Library Manager metadata
library.json                PlatformIO library metadata
.gitignore                  Build-artifact ignores
```

## Critical constraints — do not violate

- **No SPI inside ISR.** arduino-pico SPI uses internal mutexes; calling it from an interrupt causes a deadlock or hang. The ISR (`isrTrampoline`) only sets a flag. All SPI happens in `Receiver::loop()`.
- **GDO0_PKT_SYNC = 0x06**, not `0x46`. Bit 6 of IOCFG0 is TEMP_SENSOR_ENABLE; setting it overrides the signal config and empties the FIFO.
- **Status registers need READ_BURST (0xC0).** `SREG_RXBYTES`, `SREG_MARCSTATE`, `SREG_VERSION`, `SREG_RSSI` all require `reg | 0xC0`, not `reg | 0x80`.
- **Read FIFO before `startRx()`.** `startRx()` sends SFRX (flush RX FIFO), so debug prints and `readFifo()` must happen before it.
- **T1 mode: infinite packet mode (PKTCTRL0=0x02).** GDO0 RISING edge (sync word detect) starts a 50 ms accumulation window. Target: ~170 raw bytes → ~113 decoded → full ELL+AFL+TPL frame including 4×16 encrypted blocks. On all platforms, `Receiver::loop()` polls RXBYTES synchronously.
- **CC1101 FIFO erratum SWRZ020.** During active RX, always read `avail−1` bytes, never drain fully. Only read all remaining bytes after strobing SIDLE. The synchronous drain path enforces this. When the overflow bit (RXBYTES bit 7) is set, immediately abort to the finalise path — do not loop-print the error.
- **Single Receiver instance per program.** The GDO0 ISR is a static trampoline (`isrTrampoline`) that routes to a single global `s_isrTarget`. Only one `Receiver` at a time can service interrupts.

## Callback mechanism

A registered callback fires immediately after a frame is parsed and (if applicable) auto-decrypted:

```cpp
void Receiver::setCallback(std::function<void(const Frame&, const DataRecord*, uint8_t)> cb);
```

The callback receives:
- The fully parsed `Frame` (with all header fields, encryption status, CRC status)
- An array of `DataRecord` (parsed DIF/VIF records from the decrypted payload, if applicable)
- The count of valid records

The pointers are only valid during the callback; copy what you need.

The callback fires for **every** frame, even incomplete or failed ones. The caller must check `frame.complete()`, `frame.badBlocks()`, and `frame.decrypted()` to filter by status.

## Frame completeness (L-field validation)

The L-field (byte 0, in the CRC-clean block 1) declares the full frame length. `Frame::complete()` compares it against the actual received length:

- `expectedLen()` = L-field + 1
- `receivedLen()` = decoded bytes actually received
- `complete()` = true iff `receivedLen >= expectedLen`

When `complete() == false`, the 3of6 decode aborted on an invalid symbol (RF bit error) or the FIFO was cut short. The bytes received are CRC-clean (block 1 passed), but later blocks are missing — do not trust `encMode()` or any payload field.

## Key implementation details

### T1 3of6 decode
Each decoded nibble is transmitted as a 6-bit symbol (EN 13757-4, Table A.1). The decode table maps 6-bit symbols → nibbles; `0xFF` = invalid. `decode3of6()` stops on the first invalid symbol and returns partial output.

### Decryption — Mode 5 and Mode 7

Both modes are fully self-contained (no external Crypto library dependency).

**Mode 5 (EN 13757-3, CI=0x7A simple frame):**
- IV = mfr[0..1] ‖ ID[0..3] ‖ version ‖ devType ‖ accessNo × 8  (OMS §9 mode-5 IV)
- AES-128-CBC(key, IV, ciphertext)
- Verified byte-exact against real DWZ waterstarm + EFE sensostar telegrams.
- Config word (16-bit LE = cfgHi<<8 | cfgLo): `encMode = cfgHi & 0x1F` (bits 8-12) == 5;
  `encBlocks = (cfgLo & 0xF0) >> 4` (high nibble, bits 4-7) — same field as mode 7.
  Real meters: waterstarm cfgHi=0x25, sensostar cfgHi=0x05, both cfgLo=0x90 (9 blocks).

**Mode 7 (OMS Security Mode 7, ELL+AFL+TPL layered frame):**
- Key derivation: `Kenc = AES-CMAC(masterKey, 0x00 ‖ MCR[4B] ‖ meterID[4B LE] ‖ 0x07×7)`
- AES-128-CBC(Kenc, IV=0×16, ciphertext)
- MCR (4-byte message counter) is extracted from the AFL layer
- `encMode = cfgHi & 0x07` == 7; `encBlocks = (cfgLo & 0xF0) >> 4` (high nibble)
- Config word is 3 bytes (not 2)

Decryption success indicator for both: `payload[0]==0x2F && payload[1]==0x2F`.

### DIF/VIF data record parser

The decrypted payload (after stripping the 0x2F fill bytes) contains a stream of DIF/VIF records per EN 13757-3. `parseRecords()` parses them into typed `DataRecord` structures:

```cpp
uint8_t parseRecords(const uint8_t* payload, uint8_t payloadLen,
                     DataRecord* out, uint8_t maxOut);
```

Supports:
- **Volume** (VIF 0x10–0x17): m³ with exponent
- **Energy** (VIF 0x00–0x0F): Wh or J
- **Power** (VIF 0x28–0x2F): W
- **VolumeFlow** (VIF 0x38–0x3F): m³/h
- **Temperatures** (VIF 0x58–0x67): °C (flow, return, external, pressure)
- **On/Operating time** (VIF 0x20–0x27): seconds/minutes/hours/days
- **Date (Type G)** (VIF 0x6C): day/month/year
- **DateTime (Type F)** (VIF 0x6D): + hour/minute
- **Storage numbers** (DIF bit 4 + DIFE bits): current (0) and historical records (1+)
- **Tariff numbers** (DIFE bits)
- **Function field** (DIF bits 7:5): instantaneous (0), max (1), min (2), error (3)

Exponent is derived from VIF bits, so `actual_value = rawValue × 10^exponent`. The helper `DataRecord::value()` computes the float. `DataRecord::prettyName()` returns a human-readable label (e.g. `"Water volume"`, `"Flow temperature"`).

Records with VIFE (extended VIF) are parsed but marked as `Quantity::Unknown` (the extended table is large; common types are handled).

Decoder stops on variable-length (DIF 0x0D) or manufacturer-specific (DIF 0x0F) records.

### wMBus frame layouts (post-decode, after CRC strip)

**Simple frame (CI=0x7A):**
```
[0]     L-Field
[1]     C-Field
[2-3]   M-Field (manufacturer, 2-char encoded)
[4-7]   ID-Field (BCD little-endian)
[8]     Version
[9]     Device type
[10]    CI=0x7A (variable short header)
[11]    Access No
[12]    Status
[13]    cfgLo  (encBlocks in bits[7:4] — high nibble)
[14]    cfgHi  (encMode in bits[4:0], i.e. cfgHi & 0x1F)
[15+]   Encrypted payload
```

**Layered frame (ELL-I + AFL + TPL, e.g. OMS Mode 7):**
```
[0-9]   Link layer (same as above)
[10]    CI=0x8C  ELL-I (or 0x8E with CC1101 bit error, treated identically)
[11]    CC (communication control)
[12]    ACC (access counter)
[13]    CI=0x90  AFL (Auth+Fragmentation Layer)
[14]    AFL length (bytes that follow, e.g. 0x0F = 15)
[15-16] FCL (frame control, LE): bit 0x2000=MCL present, bit 0x0800=MCR present
[17]    MCL (optional, 1 byte)
[18-21] MCR (optional, 4 bytes — message counter, used for Kenc derivation)
[22-29] MAC (8 bytes)
[30]    CI=0x7A  TPL short header
[31]    Access No
[32]    Status
[33]    cfgLo  (encBlocks in bits[7:4] for mode 7)
[34]    cfgHi  (encMode in bits[2:0] for mode 7)
[35]    cfgByte3 (3rd config byte, mode 7 only)
[36+]   Encrypted payload (4 blocks × 16 = 64 bytes)
```

CI=0x8C/0x8D/0x8E/0x8F are Extended Link Layer (ELL-I..IV), **not** short headers.
Some CC1101 chips deterministically flip bit 1 of the CI byte (0x8C→0x8E); both values are handled identically.

**ELL-II (CI=0x8D) — e.g. Kamstrup Multical21:**
```
[0-9]   Link layer (same as above)
[10]    CI=0x8D  ELL-II
[11]    CC (communication control)
[12]    ACC (access counter)
[13-16] SN (4-byte session number)
[17-18] CRC (2-byte ELL CRC, already stripped from raw blocks — kept here as-is)
[19]    Application CI:
          0x7A → parseTpl() (short header with config/enc bytes follows)
          0x78 → no TPL header, DIF/VIF payload follows directly (no encryption)
[20+]   Application data (DIF/VIF records when app CI = 0x78)
```
The ELL CRC at [17-18] is part of the ELL-II protocol header; it survives `stripCRC()` since it sits inside a data block, not at a block boundary. Frame::parse() skips it by jumping directly to `OFF_CI + 9`.

## Logger und Debug-Ausgabe

Die Library schreibt **niemals direkt auf Serial**. Alle Diagnose-Ausgaben gehen über einen optionalen Logger-Callback:

```cpp
wmbus.setLogger([](const char* msg){ Serial.println(msg); });
```

Ohne registrierten Logger ist die Library vollständig still (geeignet für Fremdsysteme mit eigenem Logging-Framework).

`setDebug(true)` schaltet ausführliche Ausgaben pro Telegramm ein. Ohne Logger hat das keine Wirkung.

```
// Logger + debug=true: ein strukturierter Block pro Telegramm (via Logger,
// VOR dem Callback). Jede Zeile ist ein eigener Logger-Aufruf:
Received Frame: Mode=T1 Bytes=170 RSSI=-62dBm FreqEst=10 LQI=37
  Decode: Length=113 Status=OK
  CRC: Status=OK
  Parse: Status=OK MeterId=61854485 Type=0x07
  Encryption: Mode=5 Status=OK
  Payload: Records=4 Status=OK
  Hex:
    68B7448561...
// Das Mode-Label unterscheidet C1A (Frame A) und C1B (Frame B):
//   "Received Frame: Mode=C1A ..."  bzw.  "Mode=C1B ..."
```

Die anwendungsseitigen Ausgaben (Vendor/Type/Status/Werte) stammen aus dem Callback im Anwendungscode (siehe `examples/WMBusReceiver`) — nicht aus der Library.

## Modes

| Mode   | Sync    | Encoding       | PKTCTRL0              | GDO0 edge |
|--------|---------|----------------|-----------------------|-----------|
| T1     | 0x543D  | 3of6           | 0x02 (infinite, ~170B)        | RISING  |
| C1A    | 0x54CD  | raw            | 0x02 (infinite, ~192B)        | RISING  |
| C1B    | 0x543D  | raw            | 0x02 (infinite, ~192B)        | RISING  |
| T1C1B  | 0x543D  | 3of6 / raw     | 0x02 (infinite)               | RISING  |
| S1     | 0x7696  | Manchester (SW)| 0x02 (infinite, ~240B)        | RISING  |

All modes use our infinite-packet-mode FIFO drain. T1 and C1 (Frame A and Frame B) all share the
868.95 MHz carrier (T1 ~103 kBaud, C1 ~100 kBaud); **S1 is a different PHY:
868.30 MHz, 32.73 kBaud, Manchester coded** (culfw S-mode register set,
`smode_rf_settings.h`). The CC1101 runs without hardware Manchester
(MDMCFG2=0x06); `Frame::decodeManchester()` decodes 2 raw bytes → 1 data byte in
software (TI table: 0xA→00, 0x9→01, 0x6→10, 0x5→11), exactly like `decode3of6()`
for T1. After Manchester decode an S-mode telegram is a Frame A (per-block CRCs)
— identical to C1A from `stripCRC()` onward. Because the raw stream is
Manchester-coded, the C1A block-1-CRC early-abort in `pumpRaw()` is skipped for
S1, and the drain target is `2× c1ExpectedRaw(L)` (L peeked by
Manchester-decoding the first 2 raw bytes).

**C1A vs C1B.** C-mode has two frame formats with *different sync words*: Frame A
uses 0x54CD (`Mode::C1A`), Frame B uses 0x543D (`Mode::C1B`). The CC1101 has a
single sync-word register, so the two cannot be received simultaneously — a
Frame-B meter (e.g. some EFE/Engelmann heat meters) needs `Mode::C1B`. Both C1A
and C1B share identical RF/demod registers (raw bytes, 100 kBaud, ±47 kHz); only
SYNC1/SYNC0 differ. The block-1 CRC early-abort in `pumpRaw()` applies to C1A
(Frame A) **only** — C1B skips it because Frame B has no block-1 CRC. Drain
targets differ: C1A uses `c1ExpectedRaw()` (Frame A size with inter-block CRCs);
C1B uses `c1BExpectedRaw()` (= 1 + L). Note that 0x543D is also T1's sync word,
but the raw-vs-3of6 decode is chosen by the *receive mode*, not the sync word.

**T1C1B (combined).** Because T1 and C1B share sync 0x543D and the same carrier,
a single mode can receive both. `Mode::T1C1B` uses the T1 PHY (T1 register set,
sync 0x543D) and auto-detects per frame in `processRawFrame()`: if the raw FIFO
starts with the C-mode sync prefix 0x543D, the frame is routed as raw C1B
immediately (no 3of6 attempt). Without a sync prefix, 3of6 decode is tried; if
that yields ≥12 bytes the telegram is T1. Otherwise, `c1BStripCRC()` is probed
on the raw buffer — if it passes, the frame is C1B; if not, the legacy
`c1Block1Offset()` fallback is tried for Frame A. The block-1 CRC early-abort is
**not** applied in T1C1B. Drain target: 3of6-peek for T1; `c1BExpectedRaw()` for
C1B (either by sync prefix or no-prefix fallback). Trade-off: T1C1B receives C1B
at T1's oversampling rate (~103 kBaud vs the meter's 100 kBaud), slightly less
sensitive for weak C1B signals than the dedicated `C1B` mode. C1A (0x54CD) is
**not** covered — different sync word.

## C1A/C1B/S1 Frame Formats

**Frame A** (EN 13757-4 §7.1): 10 data + 2 CRC (block 1), then 16 data + 2 CRC per subsequent block. `stripCRC()` removes inter-block CRCs. Example: L=0xA9 → 192 raw bytes → 170 stripped bytes.

**Frame B** (EN 13757-4 §7.2): **No inter-block CRCs.** CI sits at byte 10 directly after the link-layer header (L, C, M-field, A-field) — there is no block-1 CRC between the header and CI. The L-field in Frame B counts all following bytes *including* the trailing CRC(s), so total raw size = 1 + L bytes.

- **Short frame (L ≤ 127):** one 2-byte trailing CRC covers bytes [0..L-2] (the entire frame). After CRC strip: CI is at stripped[10], L is decremented by 2.
- **Long frame (L ≥ 129):** first block = bytes [0..125] + CRC [126..127]; second block = bytes [128..L-2] + CRC [L-1..L]. After CRC strip: two CRC pairs removed, L decremented by 4.
- **L = 128** is structurally invalid (no room for second CRC pair) and is rejected.

`c1BStripCRC()` in `WMBus.cpp` validates and strips these CRCs into the CRC-free layout that `Frame::parse()` expects. Detection: sync prefix 0x543D identifies a C1B frame; no block-1 CRC check is performed (Frame B has none). False triggers without a valid trailing CRC are silently discarded. Debug: the frame is labelled `Mode=C1B`.

## Commit conventions

- Commit messages are **always written in English** (subject + body).
- **No `Co-Authored-By` trailer** in commits.
