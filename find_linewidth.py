#!/usr/bin/env python3
"""Find the true scan line width by autocorrelation on the raw data."""
import numpy as np
import sys

raw_path = sys.argv[1] if len(sys.argv) > 1 else '/home/luca/win7/scan_3200dpi.raw'
data = np.fromfile(raw_path, dtype='<u2')
total_samples = len(data)
total_bytes = total_samples * 2
print(f"Total: {total_samples:,} samples ({total_bytes:,} bytes)")

# Try to find the line width by looking at correlation between rows
# Sample a chunk from the middle of the data (skip calibration margins)
# Use ~1000 lines worth of data starting from 40% into the file
start = int(total_samples * 0.4)
chunk_size = 500000  # enough for many lines at any plausible width
chunk = data[start:start + chunk_size].astype(np.float32)

# Test candidate line widths (in uint16 samples, so pixels*3 for RGB)
# 5184 pixels * 3 channels = 15552 samples per line
# Other candidates based on common CCD widths
candidates = []
for pixels in range(1000, 11000, 1):
    candidates.append(pixels * 3)  # interleaved RGB

print(f"\nTesting {len(candidates)} candidate widths...")
print(f"Looking at correlation between consecutive rows.\n")

best_corr = -1
best_width = 0
best_pixels = 0

results = []
for samples_per_line in candidates:
    if samples_per_line * 10 > len(chunk):
        continue

    n_lines = len(chunk) // samples_per_line
    if n_lines < 5:
        continue

    # Compare line i with line i+1 (adjacent lines should be very similar in a photo)
    line0 = chunk[:samples_per_line]
    line1 = chunk[samples_per_line:2*samples_per_line]

    # Normalized correlation
    m0 = line0 - line0.mean()
    m1 = line1 - line1.mean()

    denom = np.sqrt(np.sum(m0**2) * np.sum(m1**2))
    if denom == 0:
        continue
    corr = np.sum(m0 * m1) / denom

    pixels = samples_per_line // 3
    results.append((corr, pixels, samples_per_line))

    if corr > best_corr:
        best_corr = corr
        best_width = samples_per_line
        best_pixels = pixels

# Sort by correlation and show top 20
results.sort(reverse=True)
print("Top 20 candidate line widths by inter-line correlation:")
print(f"{'Corr':>8} {'Pixels':>8} {'Samples/line':>14} {'Bytes/line':>12} {'Lines':>8}")
for corr, pixels, spl in results[:20]:
    n_lines = total_samples // spl
    line_bytes = spl * 2
    print(f"{corr:8.5f} {pixels:8d} {spl:14d} {line_bytes:12d} {n_lines:8d}")

print(f"\nBest: {best_pixels} pixels/line ({best_width} samples, {best_width*2} bytes)")
print(f"Total lines at this width: {total_samples // best_width}")
print(f"Remainder: {total_samples % best_width} samples")

# Also check if the data might be line-sequential (R,G,B planes per line)
# In that case, the "pixel width" in the reshape would be 3× wider
print(f"\nIf line-sequential (RRR...GGG...BBB... per row):")
seq_width = best_pixels * 3  # samples per line = pixels * 1 channel
seq_lines = total_samples // seq_width
if total_samples % seq_width == 0:
    print(f"  {best_pixels} pixels × 3 channels per line, {seq_lines} lines (exact)")
else:
    print(f"  Doesn't divide evenly")
