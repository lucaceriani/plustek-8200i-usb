#!/usr/bin/env python3
"""Check image parameters from the captured data."""
import struct, pickle, zlib

with open('/home/luca/win7/capture3200_replay.pkl', 'rb') as f:
    data = pickle.loads(zlib.decompress(f.read()))

scan_ops = data['scan_ops']
bulk_reads = [(i, op) for i, op in enumerate(scan_ops) if op[0] == 'BR']
bulk_writes = [(i, op) for i, op in enumerate(scan_ops) if op[0] == 'BW']

print(f"Total scan ops: {len(scan_ops)}")
print(f"Bulk reads: {len(bulk_reads)}")
print(f"Bulk writes: {len(bulk_writes)}")

# Find where bulk writes end and pure bulk reads begin
last_bw_idx = max(i for i, _ in bulk_writes)
print(f"Last bulk write at scan_ops index: {last_bw_idx}")

# Calculate data before and after last BW
data_before_last_bw = sum(op[2] for i, op in bulk_reads if i < last_bw_idx)
data_after_last_bw = sum(op[2] for i, op in bulk_reads if i > last_bw_idx)
print(f"Bulk IN data before last BW: {data_before_last_bw:,} bytes ({data_before_last_bw/1024/1024:.1f} MB)")
print(f"Bulk IN data after last BW:  {data_after_last_bw:,} bytes ({data_after_last_bw/1024/1024:.1f} MB)")

total = data_before_last_bw + data_after_last_bw
print(f"Total: {total:,} bytes ({total/1024/1024:.1f} MB)")

# The image is likely the data after all setup completes
# Try different widths
for width in [5184, 5120, 4800, 4409, 4408, 4320, 4096, 3456, 3200]:
    line_bytes = width * 6  # 48-bit RGB
    if data_after_last_bw % line_bytes == 0:
        height = data_after_last_bw // line_bytes
        print(f"  Width {width} -> height {height} (exact fit for post-BW data)")
    if total % line_bytes == 0:
        height = total // line_bytes
        print(f"  Width {width} -> height {height} (exact fit for total data)")

# Show read size pattern after last BW
print(f"\nBulk reads after last BW (first 30):")
reads_after = [(i, op) for i, op in bulk_reads if i > last_bw_idx]
for i, (idx, op) in enumerate(reads_after[:30]):
    print(f"  [{i}] scan_ops[{idx}] read {op[2]} bytes")

# Check line-by-line: 512-byte reads are likely status, not data
print(f"\nRead size distribution in post-BW phase:")
from collections import Counter
sizes = Counter(op[2] for _, op in reads_after)
for sz, cnt in sorted(sizes.items()):
    print(f"  {sz:6d} bytes: {cnt:5d} reads ({sz * cnt / 1024 / 1024:.1f} MB)")

# Calculate without 512-byte reads
data_no_512 = sum(op[2] for _, op in reads_after if op[2] != 512)
print(f"\nPost-BW data excluding 512-byte reads: {data_no_512:,} bytes ({data_no_512/1024/1024:.1f} MB)")

for width in [5184, 5120, 4800, 4409, 4408, 4320, 4096, 3456, 3200, 2592, 1728]:
    line_bytes = width * 6
    if line_bytes == 0:
        continue
    height = data_no_512 / line_bytes
    if abs(height - round(height)) < 0.001:
        print(f"  Width {width} -> height {int(height)} (exact)")
    elif abs(height - round(height)) < 1:
        print(f"  Width {width} -> height ~{height:.1f}")

# Also check the total minus 512-byte reads
total_no_512 = sum(op[2] for _, op in bulk_reads if op[2] != 512)
print(f"\nAll bulk IN data excluding 512-byte reads: {total_no_512:,} bytes ({total_no_512/1024/1024:.1f} MB)")

for width in [5184, 5120, 4800, 4409, 4408, 4320, 4096, 3456]:
    line_bytes = width * 6
    height = total_no_512 / line_bytes
    if abs(height - round(height)) < 0.5:
        print(f"  Width {width} -> height ~{height:.1f}")
