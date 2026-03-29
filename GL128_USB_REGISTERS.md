# Plustek OpticFilm 8200i (GL128) USB Register Map

Reverse-engineered by diffing USB captures at 3200 DPI and 7200 DPI.

## Protocol

Register writes use vendor control transfers to endpoint 0x00 with format:

    40 04 83 00 00 00 <payload_len_u16_le> <reg:val pairs...>

Each payload consists of sequential (register_address, value) byte pairs.
Multiple registers can be written in a single transfer (up to 64 payload bytes).

Status reads use endpoint 0x80:

    C0 0C 8E 00 <addr> 00 01 00  → reads 1 byte, 0x55 = ready

## Register Blocks

Registers are written in four large blocks during scan setup (phases init/scan_cmd),
covering ranges 0x01-0x1F, 0x24-0x5B, 0x5C-0x86, and 0x87-0xBF.

## DPI-Related Registers

Derived from comparing capture3200.pcap vs capture7200.pcap.
Registers not listed here were identical between both captures.

### Motor / Timing

| Reg  | 3200 DPI | 7200 DPI | Description |
|------|----------|----------|-------------|
| 0x06 | 0x18 (24) | 0xF0 (240) | **Motor step timing.** 10x increase at 7200 suggests per-line settling time. Higher value = slower motor = finer spatial resolution. |
| 0x0B | 0x6C (108) | 0x4C (76) | **Line exposure / integration time.** Lower at 7200 — possibly compensating for multi-pass accumulation. |

### Scan Geometry

| Reg  | 3200 DPI | 7200 DPI | Description |
|------|----------|----------|-------------|
| 0x1C:0x1D | 0x0000 (0) | 0x2080 (8320) | **Scan start offset** (16-bit BE). Nonzero at 7200 suggests sub-pixel alignment shift for multi-pass. |
| 0x1E:0x1F | 0x1000 (4096) | 0x2000 (8192) | **Scan line count or area height** (16-bit BE). Exactly 2x at 7200 DPI — consistent with doubling vertical resolution. |
| 0x7E:0x7F | 0x2AF8 (11000) | 0x36B0 (14000) | **Total motor travel / line target** (16-bit BE). Scales roughly with DPI ratio. |

### CCD Configuration

| Reg  | 3200 DPI | 7200 DPI | Description |
|------|----------|----------|-------------|
| 0x3B | 0xFF | 0x01 | **CCD binning / mode flag.** 0xFF at 3200 (native optical, full binning), 0x01 at 7200 (unbinned or multi-sample). |
| 0x70 | 0x01 | 0x0A | **CCD phase R** (or line interleave step). Sequential 1-4 at native res; 10-13 at 7200 suggests multi-pass offset pattern. |
| 0x71 | 0x02 | 0x0B | **CCD phase G.** |
| 0x72 | 0x03 | 0x0C | **CCD phase B.** |
| 0x73 | 0x04 | 0x0D | **CCD phase (4th channel or timing).** |

### Analog / Gain

| Reg  | 3200 DPI | 7200 DPI | Description |
|------|----------|----------|-------------|
| 0x52 | 0x07 | 0x0B | **Analog gain or offset, channel 1.** Higher at 7200 — compensating for shorter integration. |
| 0x53 | 0x09 | 0x0D | **Analog gain or offset, channel 2.** |
| 0x54 | 0x0B | 0x0F | **Analog gain or offset, channel 3.** |

## Unchanged Registers (notable)

These registers are the same at both resolutions and likely control fixed parameters:

| Reg  | Value | Likely Function |
|------|-------|-----------------|
| 0x01 | 0x22 | Device mode / color depth (48-bit RGB) |
| 0x02 | 0x78 (120) | Possibly max pixel clock or CCD width config |
| 0x03 | 0x20 (32) | Scan mode (also written repeatedly as a "go" trigger) |
| 0x04 | 0x02 | Channel count or scan direction |
| 0x05 | 0x48 (72) | Line buffer size or DMA config |
| 0x15:0x16 | 0x8027 | CCD total pixel count (might encode 10272 = 2x5184 with padding) |
| 0x24 | 0x1A (26) | Lamp or LED control |
| 0x30 | 0x6F (111) | Shading correction config |

## Scan Phases

1. **INIT** — USB enumeration, configuration, basic register setup
2. **SCAN_CMD** — Full register programming (the four large blocks above), gamma tables, shading data
3. **DATA** — Bulk reads on EP 0x81. Preamble (~14.5 MB calibration), then image data
4. **CLEANUP** — Post-scan register reset, motor park

## Image Parameters

| Parameter | 3200 DPI | 7200 DPI (estimated) |
|-----------|----------|----------------------|
| Pixel width | 5184 | ~11664 |
| Pixel height | 6959 | ~15659 |
| Bytes/pixel | 6 (48-bit RGB) | 6 (48-bit RGB) |
| Line bytes | 31104 | ~69984 |
| Preamble | ~14.5 MB | TBD |

## Notes

- The GL128 chip has no public datasheet. All register meanings are inferred.
- 3200 DPI appears to be the native optical resolution (CCD phases 1,2,3,4 = simple sequential).
- 7200 DPI is likely achieved via multi-pass or sub-pixel shifting (CCD phases 10,11,12,13 = offset pattern).
- Register 0x03 is written multiple times with values 0x20 and 0x30 between phases — likely a command/trigger register (start scan, flush, etc).
- The captures were taken from SilverFast running under Windows.
