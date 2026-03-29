#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["pyusb", "tifffile", "numpy"]
# ///
"""
Plustek OpticFilm 8200i (GL128) scan replay tool.

Replays a captured USB scan sequence to perform a 3200 DPI, 48-bit RGB scan
and saves the result as a TIFF file.

Usage:
    uv run scan_plustek.py [output.tiff]

Requirements:
    - Plustek OpticFilm 8200i connected via USB
    - Linux with appropriate USB permissions (udev rule or root)
    - The scan_commands.bin file in the same directory

The scan_commands.bin file contains the exact USB command sequences extracted
from a Windows SilverFast capture. The scanner has no open-source driver
(GL128 chip), so we replay the captured protocol verbatim.
"""

import sys
import os
import time
import pickle
import zlib
import struct
import numpy as np

# Scanner identifiers
VENDOR_ID = 0x07B3
PRODUCT_ID = 0x1825

# Image parameters (3200 DPI, 48-bit RGB)
IMG_WIDTH = 5184       # pixels (full CCD width)
IMG_HEIGHT = 6959      # pixels (full motor travel, uncropped)
IMG_BPP = 6            # bytes per pixel (3 channels x 16-bit)
LINE_BYTES = IMG_WIDTH * IMG_BPP  # 31104
TOTAL_IMAGE_BYTES = IMG_WIDTH * IMG_HEIGHT * IMG_BPP  # 216,452,736
DPI = 3200
PREAMBLE_BYTES = 15209856  # calibration data before image (~14.5MB)

# Endpoints
EP_BULK_IN = 0x81
EP_BULK_OUT = 0x02

# Timeouts (ms)
CTRL_TIMEOUT = 5000
BULK_TIMEOUT = 10000


def load_commands(path):
    """Load the captured command sequences from scan_commands.bin."""
    with open(path, 'rb') as f:
        compressed = f.read()
    blob = zlib.decompress(compressed)
    return pickle.loads(blob)


def find_scanner():
    """Find and claim the Plustek OpticFilm 8200i."""
    import usb.core
    import usb.util

    dev = usb.core.find(idVendor=VENDOR_ID, idProduct=PRODUCT_ID)
    if dev is None:
        print("ERROR: Scanner not found. Check USB connection and permissions.")
        print(f"  Looking for vendor=0x{VENDOR_ID:04x} product=0x{PRODUCT_ID:04x}")
        sys.exit(1)

    try:
        mfr = dev.manufacturer or 'Plustek'
        prod = dev.product or 'OpticFilm 8200i'
    except (ValueError, usb.core.USBError):
        mfr, prod = 'Plustek', 'OpticFilm 8200i'
    print(f"Found scanner: {mfr} {prod}")
    print(f"  Bus {dev.bus:03d} Device {dev.address:03d}")

    # Detach kernel driver if attached
    if dev.is_kernel_driver_active(0):
        print("  Detaching kernel driver...")
        dev.detach_kernel_driver(0)

    # Set configuration
    try:
        dev.set_configuration()
    except Exception:
        pass  # May already be configured

    cfg = dev.get_active_configuration()
    intf = cfg[(0, 0)]

    # Claim interface
    import usb.util
    usb.util.claim_interface(dev, intf)

    print(f"  Configuration: {cfg.bConfigurationValue}")
    print(f"  Interface: {intf.bInterfaceNumber}")

    return dev


def replay_op(dev, op):
    """Replay a single USB operation.

    op format:
      ('CW', bmRT, bReq, wVal, wIdx, data_bytes)  - control write
      ('CR', bmRT, bReq, wVal, wIdx, wLen)          - control read
      ('BW', ep, data_bytes)                         - bulk write
      ('BR', ep, expected_len)                       - bulk read
    """
    kind = op[0]

    if kind == 'CW':
        _, bmRT, bReq, wVal, wIdx, data = op
        dev.ctrl_transfer(bmRT, bReq, wVal, wIdx, data, CTRL_TIMEOUT)

    elif kind == 'CR':
        _, bmRT, bReq, wVal, wIdx, wLen = op
        dev.ctrl_transfer(bmRT, bReq, wVal, wIdx, wLen, CTRL_TIMEOUT)

    elif kind == 'BW':
        _, ep, data = op
        dev.write(ep, data, BULK_TIMEOUT)

    elif kind == 'BR':
        _, ep, expected_len = op
        return dev.read(ep, expected_len, BULK_TIMEOUT)

    return None


def run_phase(dev, ops, phase_name):
    """Replay a sequence of operations."""
    print(f"  {phase_name}: {len(ops)} operations...")
    for i, op in enumerate(ops):
        try:
            replay_op(dev, op)
        except Exception as e:
            print(f"    WARNING: op[{i}] {op[0]} failed: {e}")
            # Continue anyway - some status reads may differ


def run_data_phase(dev, ops):
    """Replay the data phase, collecting image data with progress."""
    total_ops = len(ops)
    bulk_count = sum(1 for op in ops if op[0] == 'BR')
    print(f"  DATA: {total_ops} operations ({bulk_count} bulk reads)...")
    print(f"  Expected: {PREAMBLE_BYTES + TOTAL_IMAGE_BYTES:,} bytes")

    raw_data = bytearray()
    ops_done = 0
    last_progress = -1

    for op in ops:
        try:
            result = replay_op(dev, op)
            if result is not None and op[0] == 'BR':
                raw_data.extend(result)
        except Exception as e:
            if op[0] == 'BR':
                # Bulk read timeout might mean scan is done
                print(f"\n    Bulk read ended: {e}")
                break
            # Control ops can fail non-fatally
            pass

        ops_done += 1

        # Progress
        progress = len(raw_data) * 100 // (PREAMBLE_BYTES + TOTAL_IMAGE_BYTES)
        if progress != last_progress and progress % 5 == 0:
            last_progress = progress
            bar_len = 40
            filled = bar_len * progress // 100
            bar = '█' * filled + '░' * (bar_len - filled)
            print(f"\r  [{bar}] {progress:3d}% ({len(raw_data):,} bytes)", end='', flush=True)

    print(f"\n  Received {len(raw_data):,} bytes total")
    return bytes(raw_data)


def extract_image(raw_data):
    """Extract the RGB image from raw scanner data (skip calibration preamble)."""
    if len(raw_data) <= PREAMBLE_BYTES:
        print(f"ERROR: Not enough data ({len(raw_data)} bytes, need > {PREAMBLE_BYTES})")
        sys.exit(1)

    image_data = raw_data[PREAMBLE_BYTES:]
    expected = TOTAL_IMAGE_BYTES

    if len(image_data) < expected:
        print(f"WARNING: Image data shorter than expected ({len(image_data):,} < {expected:,})")
        print(f"  Padding with zeros to fill frame")
        image_data = image_data + b'\x00' * (expected - len(image_data))
    elif len(image_data) > expected:
        print(f"NOTE: Extra data after image ({len(image_data) - expected:,} bytes), trimming")
        image_data = image_data[:expected]

    # Reshape to HxWx3 array of uint16
    pixels = np.frombuffer(image_data, dtype='<u2')  # little-endian uint16
    pixels = pixels.reshape((IMG_HEIGHT, IMG_WIDTH, 3))

    return pixels


def save_tiff(pixels, filename):
    """Save the image as a 48-bit RGB TIFF with proper DPI metadata."""
    import tifffile

    # tifffile expects (H, W, C) for RGB
    tifffile.imwrite(
        filename,
        pixels,
        photometric='rgb',
        resolution=(DPI, DPI),
        resolutionunit=2,  # DPI (inches)
        compression='deflate',
        metadata={
            'Software': 'scan_plustek.py (USB replay)',
            'Make': 'Plustek',
            'Model': 'OpticFilm 8200i',
            'XResolution': DPI,
            'YResolution': DPI,
        }
    )
    fsize = os.path.getsize(filename)
    print(f"  Saved: {filename} ({fsize/1024/1024:.1f} MB)")
    print(f"  Dimensions: {IMG_WIDTH} x {IMG_HEIGHT} pixels")
    print(f"  Color depth: 48-bit RGB (16-bit per channel)")
    print(f"  Resolution: {DPI} DPI")


def main():
    output_file = sys.argv[1] if len(sys.argv) > 1 else "scan_output.tiff"

    # Load command sequences
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cmd_path = os.path.join(script_dir, 'scan_commands.bin')
    if not os.path.exists(cmd_path):
        print(f"ERROR: {cmd_path} not found.")
        print("  Run analyze3.py first to extract commands from the capture.")
        sys.exit(1)

    print("Loading scan commands...")
    cmds = load_commands(cmd_path)

    print("Connecting to scanner...")
    dev = find_scanner()

    try:
        print("\nStarting scan sequence:")

        # Phase 1: INIT - device setup, register configuration
        run_phase(dev, cmds['init'], "INIT")

        # Phase 2: SCAN_CMD - gamma tables, shading data, scan trigger
        run_phase(dev, cmds['scan_cmd'], "SCAN_CMD")

        # Phase 3: DATA - read image data with status polling
        print("\nReading scan data...")
        raw_data = run_data_phase(dev, cmds['data_phase'])

        # Phase 4: CLEANUP - post-scan teardown
        run_phase(dev, cmds['cleanup'], "CLEANUP")

        print("\nProcessing image...")
        pixels = extract_image(raw_data)

        print("Saving TIFF...")
        save_tiff(pixels, output_file)

        print("\nScan complete!")

    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR during scan: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        # Release the USB interface
        import usb.util
        try:
            usb.util.release_interface(dev, 0)
        except Exception:
            pass


if __name__ == '__main__':
    main()
