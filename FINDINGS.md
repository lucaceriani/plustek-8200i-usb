# Plustek OpticFilm 8200i USB Capture — Image Extraction

## Goal
Extract the scanned image from USB packet captures (pcap files) of a Plustek OpticFilm 8200i
scanner (vendor=0x07b3, product=0x1825, chip=GL128) performing scans via SilverFast on Windows.

## Files
- `capture3200.pcap` — 224MB, classic pcap (linktype 249 = USBPcap), 3200 DPI scan
- `capture7200.pcap` — 470MB, classic pcap, 7200 DPI scan
- `scan3200.tif` — reference TIFF from SilverFast, 3600 x 5184 x 3 uint16 (48-bit RGB)
- `scan7200.tif` — reference TIFF from SilverFast, 7200 x 10368 x 3 uint16 (48-bit RGB)
- `raw_bulk_in_7200.data` — pre-extracted bulk IN payload (491,129,328 bytes)
- `extract_improved.py` — working extraction script for both resolutions
- `output_7200.tif` — extracted image, matches scan7200.tif (R corr=0.997, G=0.995, B=0.994)
- `output_3200.tif` — extracted image, matches scan3200.tif (R corr=0.996, G=0.994, B=0.993)

## Summary

Image extraction is **fully working** for both 7200 and 3200 DPI. Both outputs match their
SilverFast references with >0.99 per-channel correlation and near-identical per-channel means.

Three CCD/readout quirks had to be solved:

1. **CCD dual-amplifier column reordering** — the sensor reads out through two amplifiers,
   each producing its segment in reverse column order. Split point differs per resolution.
2. **Tri-linear CCD line offset** — the R, G, B sensor rows are physically separated on
   the CCD, requiring per-channel Y shifts (7200: +0/+24/+48, 3200: +0/+12/+24).
3. **No flat-field correction** — SilverFast's TIFF stores raw sensor uint16 values with
   no dark/white normalization and no gamma.

At 3200 DPI, the scanner additionally sends each scan line **twice** (consecutive pairs);
the odd lines match the reference.

## Pcap Parsing

- Files are classic pcap format (magic `d4c3b2a1`), NOT pcapng
- Linktype 249 = USBPcap (Windows capture)
- USBPcap header: 27+ bytes, fields at known offsets
- Device 2 is the scanner; Device 1 is hub/host (interrupt only)
- All image data comes via **bulk IN** transfers from device 2, endpoint 0x81
- No special libraries needed — parse with `struct` directly

## Raw Data Format (7200 DPI)

### Line Width
Each raw line is **32754 uint16 = 65508 bytes = 10918 pixels x 3 channels**.

Determined via row-to-row correlation: width 32754 gave corr=0.9963 (clear winner).

### Pixel Format
Within each raw line, the data is **pixel-interleaved RGB**:
```
R[0] G[0] B[0] R[1] G[1] B[1] ... R[N-1] G[N-1] B[N-1]
```
where N = 10918 (full CCD width).

### CCD Column Reordering (Dual-Amplifier Reversed Readout)

The CCD has two readout amplifiers that each produce their segment in **reverse** column order.
The raw-to-output column mapping is:

| Output (TIFF) columns | Raw columns     | Direction |
|------------------------|-----------------|-----------|
| 0 — 2092               | 2092 — 0        | reversed  |
| 2093 — 10367           | 10917 — 2643    | reversed  |

Raw columns 2093–2642 (550 pixels) are the CCD border that falls outside the output crop.
This accounts for the full difference between CCD width (10918) and TIFF width (10368):
550 = 10918 − 10368.

The mapping formulas:
```
output col 0–2092:     raw_col = 2092 − output_col
output col 2093–10367: raw_col = 13010 − output_col
```

This was discovered by cross-correlating individual column signals between the raw data
and the reference TIFF. Per-column correlations are >0.99 once the mapping is applied.

### CCD Tri-Linear Line Offset

The R, G, B CCD sensor rows are physically separated. As the carriage moves, each color
row captures a different Y position at any given moment. The offsets (determined by
cross-correlating per-channel row-mean profiles against the reference):

| Channel | Line offset (relative to R) | Correlation with ref |
|---------|----------------------------|---------------------|
| R       | +0                         | 0.9988              |
| G       | +24                        | 0.9983              |
| B       | +48                        | 0.9984              |

To reconstruct output row Y:
- R comes from raw line Y + 248
- G comes from raw line Y + 272  (248 + 24)
- B comes from raw line Y + 296  (248 + 48)

where 248 is the Y offset aligning raw line 248 to output row 0 (ref row 0).

### Data Phases

The bulk IN stream has 7497 raw lines total:

| Lines (approx) | Phase | Description |
|----------------|-------|-------------|
| 0–2            | CAL   | Bright calibration (lamp warmup) |
| 2–100          | DARK  | Dark reference (mean ~1017) |
| 100–200        | WHITE | White/lamp calibration (mean ~40749) |
| 200–300        | WHITE | Continued white cal (mean ~23640) |
| 300–400        | DARK  | Second dark reference (mean ~454) |
| 400–450        | RAMP  | Motor ramp-up |
| 248–7447       | IMAGE | The 7200 output lines (includes dark border + ramp at edges) |
| 7448–7497      | DARK  | End dark / motor stop |

The "image" region includes dark film-border rows at both ends (rows 0–200 and 7000–7200
of the output have means ~430–460, matching the unexposed film border).

### Output Format

SilverFast's reference TIFF stores **raw sensor uint16 values** — no flat-field correction,
no gamma, no white balance. The channel means reflect the natural CCD spectral response
through the film:

| Channel | Mean  | Max    |
|---------|-------|--------|
| R       | 9030  | ~27000 |
| G       | 4169  | ~14000 |
| B       | 2655  | ~8000  |

R is strongest because the CCD has highest sensitivity in red and typical color film
transmits more red light.

## Extraction Algorithm

```python
raw = np.frombuffer(data, dtype='<u2')
lines = raw[:n * 32754].reshape(n, 32754)

# 1. CCD column reordering
col_map[0:2093]     = 2092 - np.arange(2093)           # left segment reversed
col_map[2093:10368] = 13010 - np.arange(2093, 10368)   # right segment reversed

# 2. CCD line offset + channel extraction
R = lines[248:248+7200,  0::3][:, col_map]
G = lines[272:272+7200,  1::3][:, col_map]
B = lines[296:296+7200,  2::3][:, col_map]

# 3. Stack and save (raw uint16, no correction needed)
result = np.stack([R, G, B], axis=2)  # shape (7200, 10368, 3), dtype uint16
```

See `extract_improved.py` for the complete working implementation.

## Verification

| Metric | Value |
|--------|-------|
| Output dimensions | 7200 x 10368 x 3 (exact match) |
| R correlation | 0.9969 |
| G correlation | 0.9952 |
| B correlation | 0.9938 |
| R mean (out vs ref) | 9031 vs 9030 |
| G mean (out vs ref) | 4170 vs 4169 |
| B mean (out vs ref) | 2656 vs 2655 |
| Mean abs pixel diff | 284.6 |
| RMSE | 465.7 |
| % pixels within ±500 | 84.3% |

The residual per-pixel difference (~285 mean abs) is likely due to even/odd column gain
differences from the two CCD amplifiers. SilverFast appears to apply a mild per-column
gain correction that is not replicated here.

## Raw Data Format (3200 DPI)

### Line Width and Doubling
Each raw line is **15552 uint16 = 31104 bytes = 5184 pixels x 3 channels**.

The scanner sends each scan line **twice** as consecutive lines, giving 7508 total raw lines
(3754 pairs). The two copies are nearly identical (corr=0.997) but not exact (max diff
~2000–3000 in uint16). The **odd lines** (second of each pair) match the reference;
even lines also work (corr=0.999961 vs 0.999995 for odd).

### Pixel Format
Same pixel-interleaved RGB as 7200 DPI:
```
R[0] G[0] B[0] R[1] G[1] B[1] ... R[5183] G[5183] B[5183]
```

### CCD Column Reordering

Same dual-amplifier reversed readout, but with a different split point and no border crop
(CCD width = TIFF width = 5184):

| Output (TIFF) columns | Raw columns     | Direction |
|------------------------|-----------------|-----------|
| 0 — 2058               | 2058 — 0        | reversed  |
| 2059 — 5183            | 5183 — 2059     | reversed  |

The mapping formulas:
```
output col 0–2058:     raw_col = 2058 − output_col
output col 2059–5183:  raw_col = 7242 − output_col
```

### CCD Tri-Linear Line Offset

Exactly half the 7200 DPI values (matching the 2x resolution ratio):

| Channel | Line offset (odd lines, relative to R) | Correlation with ref |
|---------|---------------------------------------|---------------------|
| R       | +0                                    | 0.999995            |
| G       | +12                                   | 0.999992            |
| B       | +24                                   | 0.999994            |

To reconstruct output row Y (using odd lines only):
- R comes from odd line Y + 129
- G comes from odd line Y + 141  (129 + 12)
- B comes from odd line Y + 153  (129 + 24)

### Verification (3200 DPI)

| Metric | Value |
|--------|-------|
| Output dimensions | 3600 x 5184 x 3 (exact match) |
| R correlation | 0.9964 |
| G correlation | 0.9941 |
| B correlation | 0.9933 |
| R mean (out vs ref) | 9214 vs 9213 |
| G mean (out vs ref) | 4233 vs 4233 |
| B mean (out vs ref) | 2680 vs 2680 |
| Mean abs pixel diff | 180.6 |
| RMSE | 263.6 |
| % pixels within ±500 | 93.5% |

## Key Numbers Reference

| Parameter | 3200 DPI | 7200 DPI |
|-----------|----------|----------|
| TIFF dimensions | 3600 x 5184 x 3 | 7200 x 10368 x 3 |
| CCD pixel width | 5184 | 10918 |
| Line width (uint16) | 15552 (doubled: 7508 raw lines) | 32754 |
| Line width (bytes) | 31104 | 65508 |
| Bulk IN total | 233,541,180 bytes | 491,129,328 bytes |
| Total raw lines | 7508 (3754 pairs, use odd) | 7497 |
| CCD line offset G | +12 | +24 |
| CCD line offset B | +24 | +48 |
| Y offset (line 0 = ref row 0) | odd line 129 | 248 |
| Column reorder split | 2058/2059 | 2092/2093 |

## USB Replay: DMA Flow Control and Status Polls

During a scan, SilverFast interleaves large data reads (~62 KB) with small 512-byte status
polls — roughly one poll every three data reads, totaling ~2000 polls across a full scan.
These polls are not just informational: they synchronize the host's read pointer with the
scanner's circular DMA buffer on the GL128 chip.

The scanner's CCD sensor writes scan data via DMA into a fixed-size RAM buffer on the chip.
This buffer is circular — when the write pointer reaches the end, it wraps to address 0.
The host reads from the same buffer via USB bulk transfers, advancing its own read pointer.
As long as the read and write pointers advance in lockstep, data comes out in order.

The 512-byte status polls maintain this synchronization. When they are omitted (e.g. by
replacing the captured read pattern with continuous 64 KB bulk reads), the read pointer
drifts relative to the write pointer. The result is an image that appears shifted by ~1/3
of the frame — the scan data wraps around the circular buffer boundary, so the end of the
image appears at the beginning of the file and vice versa.

The correct approach for replay is to execute the exact captured op sequence (same read
sizes, same order, including the 512-byte polls) but strip all artificial inter-op delays.
The USB bulk reads block naturally until the scanner's DMA buffer has data available,
providing implicit flow control without any `sleep()` calls. This achieves maximum USB
transfer speed while keeping the image correctly aligned.

## Dependencies
- numpy
- tifffile
- Pillow (for preview PNGs only)
- No tshark/pyshark/scapy needed — raw pcap parsing with struct works fine
