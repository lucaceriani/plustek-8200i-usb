#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["tifffile", "numpy", "Pillow"]
# ///
"""
Extract scanned image from Plustek OpticFilm 8200i USB capture (pcap).

Handles three key CCD/readout quirks:
1. Dual-amplifier column reordering: the CCD reads out in two reversed segments
2. Tri-linear CCD offset: R/G/B sensor rows are physically separated
3. Raw uint16 output matching SilverFast's TIFF (no flat-field, no gamma)

At 3200 DPI, each scan line is sent twice (odd lines match the reference).
"""

import struct
import sys
import os
import numpy as np


def parse_bulk_in(pcap_file):
    """Extract all bulk IN payload bytes from a USBPcap pcap file."""
    data = bytearray()
    with open(pcap_file, 'rb') as f:
        f.read(24)  # global pcap header
        while True:
            phdr = f.read(16)
            if len(phdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', phdr)
            pkt = f.read(incl_len)
            if len(pkt) < 27:
                continue
            hdr_len = struct.unpack_from('<H', pkt, 0)[0]
            info = pkt[16]
            tt = pkt[22]
            payload = pkt[hdr_len:]
            if tt == 3 and (info & 1) and len(payload) > 0:  # bulk IN
                data.extend(payload)
    return bytes(data)


def _build_col_map(tiff_w, split, offset_b):
    """Build CCD column reordering lookup.

    The CCD has dual-amplifier readout. Each segment is read in reverse:
      - Output cols 0..split        -> raw cols split..0        (reversed)
      - Output cols (split+1)..end  -> raw cols end..(split+1)  (reversed)

    offset_b is added to the second segment formula: raw = (tiff_w - 1 + split + 1 + offset_b) - out_col
    """
    col_map = np.empty(tiff_w, dtype=np.intp)
    for i in range(tiff_w):
        if i <= split:
            col_map[i] = split - i
        else:
            col_map[i] = (split + 1 + tiff_w - 1 + offset_b) - i
    return col_map


def build_col_map_7200():
    """CCD column reorder for 7200 DPI (10918 CCD pixels -> 10368 output, 550 border)."""
    TIFF_W = 10368
    col_map = np.empty(TIFF_W, dtype=np.intp)
    for i in range(TIFF_W):
        if i <= 2092:
            col_map[i] = 2092 - i
        else:
            col_map[i] = 13010 - i
    return col_map


def build_col_map_3200():
    """CCD column reorder for 3200 DPI (5184 CCD pixels -> 5184 output, no border)."""
    TIFF_W = 5184
    col_map = np.empty(TIFF_W, dtype=np.intp)
    for i in range(TIFF_W):
        if i <= 2058:
            col_map[i] = 2058 - i
        else:
            col_map[i] = 7242 - i
    return col_map


def extract_7200(raw_data, output_file="output_7200.tif"):
    """Extract 7200 DPI image matching SilverFast's scan7200.tif output."""

    raw = np.frombuffer(raw_data, dtype='<u2')

    W_u16 = 32754        # uint16 per raw line (10918 pixels * 3 channels)
    TIFF_W = 10368       # output width
    HEIGHT = 7200        # output height

    n_lines = len(raw) // W_u16
    lines = raw[:n_lines * W_u16].reshape(n_lines, W_u16)
    print(f"Total scan lines: {n_lines}")

    # CCD tri-linear offset: R+0, G+24, B+48
    # Y alignment: raw line 248 = output row 0
    R_START = 248
    G_START = 272
    B_START = 296

    max_needed = B_START + HEIGHT
    if max_needed > n_lines:
        print(f"WARNING: need {max_needed} lines but only have {n_lines}")
        HEIGHT = n_lines - B_START

    col_map = build_col_map_7200()

    R = lines[R_START:R_START + HEIGHT, 0::3][:, col_map]
    G = lines[G_START:G_START + HEIGHT, 1::3][:, col_map]
    B = lines[B_START:B_START + HEIGHT, 2::3][:, col_map]

    result = np.stack([R, G, B], axis=2)
    print(f"Output: {result.shape} ({result.dtype})")
    print(f"  R mean={R.astype(float).mean():.0f}, "
          f"G mean={G.astype(float).mean():.0f}, "
          f"B mean={B.astype(float).mean():.0f}")

    import tifffile
    tifffile.imwrite(output_file, result, photometric='rgb',
                     resolution=(7200, 7200), resolutionunit=2)
    print(f"Saved: {output_file}")

    _save_preview(result, f"previews/{os.path.splitext(os.path.basename(output_file))[0]}_preview.png")
    return result


def extract_3200(raw_data, output_file="output_3200.tif"):
    """Extract 3200 DPI image matching SilverFast's scan3200.tif output."""

    raw = np.frombuffer(raw_data, dtype='<u2')

    W_u16 = 15552        # uint16 per raw line (5184 pixels * 3 channels)
    TIFF_W = 5184        # output width (= CCD width, no border crop)
    HEIGHT = 3600        # output height

    n_lines = len(raw) // W_u16
    lines = raw[:n_lines * W_u16].reshape(n_lines, W_u16)
    print(f"Total raw lines: {n_lines}")

    # Each scan line is sent twice (consecutive pairs). Odd lines match the reference.
    odd_lines = lines[1::2]
    n_odd = odd_lines.shape[0]
    print(f"Odd lines (used): {n_odd}")

    # CCD tri-linear offset: R+0, G+12, B+24 (half the 7200 DPI values)
    # Y alignment: odd line 129 = output row 0
    R_START = 129
    G_START = 141
    B_START = 153

    max_needed = B_START + HEIGHT
    if max_needed > n_odd:
        print(f"WARNING: need {max_needed} odd lines but only have {n_odd}")
        HEIGHT = n_odd - B_START

    col_map = build_col_map_3200()

    R = odd_lines[R_START:R_START + HEIGHT, 0::3][:, col_map]
    G = odd_lines[G_START:G_START + HEIGHT, 1::3][:, col_map]
    B = odd_lines[B_START:B_START + HEIGHT, 2::3][:, col_map]

    result = np.stack([R, G, B], axis=2)
    print(f"Output: {result.shape} ({result.dtype})")
    print(f"  R mean={R.astype(float).mean():.0f}, "
          f"G mean={G.astype(float).mean():.0f}, "
          f"B mean={B.astype(float).mean():.0f}")

    import tifffile
    tifffile.imwrite(output_file, result, photometric='rgb',
                     resolution=(3200, 3200), resolutionunit=2)
    print(f"Saved: {output_file}")

    _save_preview(result, f"previews/{os.path.splitext(os.path.basename(output_file))[0]}_preview.png",
                  scale=2)
    return result


def _save_preview(data, path, scale=4):
    """Save a displayable 8-bit PNG preview with auto-levels + gamma."""
    from PIL import Image

    preview = data[::scale, ::scale, :].astype(np.float64)
    for ch in range(3):
        p1 = np.percentile(preview[:, :, ch], 1)
        p99 = np.percentile(preview[:, :, ch], 99)
        preview[:, :, ch] = (preview[:, :, ch] - p1) / max(p99 - p1, 1)
    np.clip(preview, 0, 1, out=preview)
    np.power(preview, 1 / 2.2, out=preview)
    preview_8 = (preview * 255).astype(np.uint8)

    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    Image.fromarray(preview_8, 'RGB').save(path)
    print(f"Saved preview: {path}")


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "7200"
    output = sys.argv[2] if len(sys.argv) > 2 else None

    if mode == "7200":
        raw_file = "raw_bulk_in_7200.data"
        if os.path.exists(raw_file):
            print(f"Loading pre-extracted data: {raw_file}")
            with open(raw_file, 'rb') as f:
                raw_data = f.read()
        else:
            pcap_file = "capture7200.pcap"
            print(f"Parsing pcap: {pcap_file}")
            raw_data = parse_bulk_in(pcap_file)
        extract_7200(raw_data, output or "output_7200.tif")

    elif mode == "3200":
        pcap_file = "capture3200.pcap"
        print(f"Parsing pcap: {pcap_file}")
        raw_data = parse_bulk_in(pcap_file)
        extract_3200(raw_data, output or "output_3200.tif")

    else:
        print(f"Usage: {sys.argv[0]} [7200|3200] [output.tif]")
        sys.exit(1)


if __name__ == '__main__':
    main()
