#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["pyusb", "tifffile", "numpy"]
# ///
"""
Plustek OpticFilm 8200i (GL128) — USB scan replay.

Replays the EXACT captured USB sequence from a SilverFast 3200 DPI scan.
Every operation is replayed in order, including calibration sub-scans.

Usage:
    uv run replay_scan.py [output.tiff]
"""

import sys
import os
import time
import pickle
import zlib
import numpy as np

VENDOR_ID  = 0x07B3
PRODUCT_ID = 0x1825
EP_BULK_IN  = 0x81
EP_BULK_OUT = 0x02
CTRL_TIMEOUT = 5000
BULK_TIMEOUT = 60000  # 60s — generous for calibration scans

# Image parameters from capture analysis:
# Post-setup data = 225,504,000 bytes = 5184 × 7250 × 6
IMG_WIDTH  = 5184
IMG_HEIGHT = 7250
IMG_BPP    = 6
EXPECTED_IMAGE_BYTES = IMG_WIDTH * IMG_HEIGHT * IMG_BPP
DPI        = 3200

# Index in the full op list where the pure data-read block starts/ends
# (5438 consecutive BRs with no control ops between them)
DATA_BR_START = 2026  # first BR in the continuous block (timed replay indices)
DATA_BR_END   = 7463  # last BR in the continuous block


def load_replay():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    pkl = os.path.join(script_dir, 'capture3200_timed_replay.pkl')
    if not os.path.exists(pkl):
        print(f"ERROR: {pkl} not found")
        sys.exit(1)
    with open(pkl, 'rb') as f:
        return pickle.loads(zlib.decompress(f.read()))


def find_scanner():
    import usb.core
    import usb.util

    dev = usb.core.find(idVendor=VENDOR_ID, idProduct=PRODUCT_ID)
    if dev is None:
        print(f"ERROR: Scanner not found (0x{VENDOR_ID:04x}:0x{PRODUCT_ID:04x})")
        sys.exit(1)

    try:
        desc = f"{dev.manufacturer} {dev.product}"
    except Exception:
        desc = "Plustek OpticFilm 8200i"
    print(f"Found: {desc} (bus {dev.bus:03d} dev {dev.address:03d})")
    return dev


def init_device(dev):
    """Reset, configure, and claim the scanner."""
    import usb.core
    import usb.util

    # USB reset — clears any bad state from previous failed scans
    print("  Resetting USB device...")
    dev.reset()
    time.sleep(1)

    # Re-find after reset (device handle may be invalidated)
    dev = usb.core.find(idVendor=VENDOR_ID, idProduct=PRODUCT_ID)
    if dev is None:
        print("ERROR: Scanner disappeared after reset")
        sys.exit(1)

    for iface in range(2):
        try:
            if dev.is_kernel_driver_active(iface):
                dev.detach_kernel_driver(iface)
        except Exception:
            pass

    try:
        dev.set_configuration()
    except Exception:
        pass

    cfg = dev.get_active_configuration()
    intf = cfg[(0, 0)]
    usb.util.claim_interface(dev, intf)
    print(f"  Configured and claimed interface {intf.bInterfaceNumber}")

    # Clear any stalled endpoints
    for ep_addr in (EP_BULK_IN, EP_BULK_OUT):
        try:
            usb.util.clear_halt(dev, ep_addr)
        except Exception:
            pass

    return dev


def replay_op(dev, op):
    kind = op[0]
    if kind == 'CW':
        dev.ctrl_transfer(op[1], op[2], op[3], op[4], op[5], CTRL_TIMEOUT)
    elif kind == 'CR':
        return bytes(dev.ctrl_transfer(op[1], op[2], op[3], op[4], op[5], CTRL_TIMEOUT))
    elif kind == 'BW':
        dev.write(op[1], op[2], BULK_TIMEOUT)
    elif kind == 'BR':
        return bytes(dev.read(op[1], op[2], BULK_TIMEOUT))
    return None


def main():
    output = sys.argv[1] if len(sys.argv) > 1 else 'scan_3200dpi.tiff'

    print("Loading replay data...")
    data = load_replay()
    # Combine setup + cleanup into one ordered list with their timestamps
    all_timed_ops = data['setup_ops'] + data['cleanup_ops']
    # all_timed_ops is [(timestamp, op), ...] but we also need the data BRs

    # We'll replay setup_ops, then continuous data reads, then cleanup_ops
    setup_ops = data['setup_ops']      # includes calibration sub-scans
    cleanup_ops = data['cleanup_ops']

    total_setup = len(setup_ops)
    total_cleanup = len(cleanup_ops)
    print(f"  Setup: {total_setup} ops, Cleanup: {total_cleanup} ops")

    print("\nConnecting...")
    dev = find_scanner()
    dev = init_device(dev)

    try:
        print(f"\n{'=' * 60}")
        print("SCAN REPLAY")
        print(f"{'=' * 60}\n")

        t0 = time.time()

        # ── Phase 1: SETUP (init + calibration + scan trigger) ───────────
        # Replay every op exactly as captured. The calibration BRs naturally
        # block until the scanner has data, providing implicit timing.
        print(f"SETUP: replaying {total_setup} operations...")
        calib_data = bytearray()
        errors = 0
        suppress_errors = False

        for i, (ts, op) in enumerate(setup_ops):
            # Strip user-interaction delays (>2s) but keep short hardware delays
            if i > 0:
                gap = ts - setup_ops[i - 1][0]
                if 0.01 < gap <= 2.0:
                    # Keep short delays (motor/lamp settling)
                    time.sleep(gap)

            try:
                result = replay_op(dev, op)
                if result and op[0] == 'BR':
                    calib_data.extend(result)
            except Exception as e:
                errors += 1
                if not suppress_errors:
                    print(f"\r  [{i}/{total_setup}] {op[0]} error: {e}                    ")
                    if errors >= 10:
                        suppress_errors = True
                        print("  (suppressing further errors)")
                # For calibration BRs that fail, we MUST continue —
                # the scanner may not have data ready yet.
                # But for CW (register writes), a failure is more serious.
                if op[0] == 'CW':
                    # Retry once after a short delay
                    time.sleep(0.05)
                    try:
                        replay_op(dev, op)
                    except Exception:
                        pass

            if i % 200 == 0 or i == total_setup - 1:
                elapsed = time.time() - t0
                print(f"\r  [{i + 1}/{total_setup}] t+{elapsed:.0f}s "
                      f"calib={len(calib_data) / 1024:.0f}KB "
                      f"errors={errors}       ", end='', flush=True)

        print(f"\r  Setup done: {errors} errors, "
              f"calibration={len(calib_data):,} bytes          ")

        # ── Phase 2: DATA (continuous fast bulk reads) ───────────────────
        # The setup sequence ends with the scan trigger and DMA config.
        # Now read the image data as fast as possible.
        print(f"\nDATA: reading image ({EXPECTED_IMAGE_BYTES / 1024 / 1024:.0f} MB)...")
        raw_data = bytearray()
        last_pct = -1
        timeouts = 0
        read_t0 = time.time()

        while len(raw_data) < EXPECTED_IMAGE_BYTES:
            try:
                chunk = dev.read(EP_BULK_IN, 0x10000, BULK_TIMEOUT)
                if chunk:
                    raw_data.extend(chunk)
                    timeouts = 0
            except Exception as e:
                timeouts += 1
                if timeouts >= 15:
                    print(f"\n  Read stopped ({timeouts} timeouts): {e}")
                    break
                continue

            pct = min(100, len(raw_data) * 100 // EXPECTED_IMAGE_BYTES)
            if pct != last_pct:
                last_pct = pct
                elapsed = time.time() - read_t0
                rate = len(raw_data) / elapsed / 1024 / 1024 if elapsed > 0 else 0
                filled = pct * 40 // 100
                bar = '\u2588' * filled + '\u2591' * (40 - filled)
                print(f"\r  [{bar}] {pct:3d}% "
                      f"({len(raw_data) / 1024 / 1024:6.1f}/{EXPECTED_IMAGE_BYTES / 1024 / 1024:.0f} MB) "
                      f"{rate:.1f} MB/s", end='', flush=True)

        elapsed = time.time() - read_t0
        rate = len(raw_data) / elapsed / 1024 / 1024 if elapsed > 0 else 0
        print(f"\n  {len(raw_data):,} bytes in {elapsed:.1f}s ({rate:.1f} MB/s)")

        # ── Phase 3: CLEANUP ─────────────────────────────────────────────
        print(f"\nCLEANUP: {total_cleanup} operations...")
        for _, op in cleanup_ops:
            try:
                replay_op(dev, op)
            except Exception:
                pass
        print("  Done")

        total_time = time.time() - t0
        print(f"\n  Total: {total_time:.1f}s")

        # ── Save image ───────────────────────────────────────────────────
        print("\nSaving...")

        # Raw dump first (always useful for debugging)
        raw_path = output.rsplit('.', 1)[0] + '.raw'
        with open(raw_path, 'wb') as f:
            f.write(raw_data)
        print(f"  Raw: {raw_path} ({len(raw_data):,} bytes)")

        # TIFF
        expected = EXPECTED_IMAGE_BYTES
        if len(raw_data) < expected:
            deficit = expected - len(raw_data)
            pct = deficit * 100 // expected
            print(f"  WARNING: {deficit:,} bytes short ({pct}%), padding")
            padded = raw_data + b'\x00' * deficit
        elif len(raw_data) > expected:
            padded = raw_data[:expected]
        else:
            padded = raw_data

        raw_lines = np.frombuffer(bytes(padded), dtype='<u2').reshape((IMG_HEIGHT, IMG_WIDTH, 3))

        # ── CCD tri-linear correction ────────────────────────────────
        # The R, G, B CCD rows are physically separated on the sensor.
        # At 3200 DPI: G is +12 lines, B is +24 lines relative to R.
        # The scanner sends each line twice (odd lines match reference).
        # With doubled lines, the offsets in raw data are 2x: G +24, B +48.
        G_OFFSET = 24   # in raw (doubled) lines
        B_OFFSET = 48
        usable = IMG_HEIGHT - B_OFFSET  # lines where all 3 channels exist
        print(f"  CCD line alignment: G+{G_OFFSET}, B+{B_OFFSET}, usable={usable} lines")

        aligned = np.empty((usable, IMG_WIDTH, 3), dtype=np.uint16)
        aligned[:, :, 0] = raw_lines[:usable, :, 0]                    # R
        aligned[:, :, 1] = raw_lines[G_OFFSET:G_OFFSET + usable, :, 1] # G
        aligned[:, :, 2] = raw_lines[B_OFFSET:B_OFFSET + usable, :, 2] # B

        # ── Aspect ratio correction ──────────────────────────────────
        # CCD (columns) ~3532 DPI, motor (rows) ~7274 DPI.
        # Downsample rows to match column DPI.
        Y_SCALE = (5008 / 36.0) * (24.0 / 6871)  # ~0.486
        new_height = int(round(usable * Y_SCALE))
        print(f"  Aspect correction: {usable} -> {new_height} rows (scale {Y_SCALE:.4f})")

        new_rows = np.linspace(0, usable - 1, new_height)
        idx_floor = np.floor(new_rows).astype(int)
        idx_ceil = np.minimum(idx_floor + 1, usable - 1)
        frac = (new_rows - idx_floor).astype(np.float32)[:, None, None]

        corrected = (
            aligned[idx_floor].astype(np.float32) * (1 - frac) +
            aligned[idx_ceil].astype(np.float32) * frac
        ).round().astype(np.uint16)

        out_h, out_w = corrected.shape[:2]
        effective_dpi = int(round(5008 / (36.0 / 25.4)))  # ~3532

        import tifffile
        tifffile.imwrite(
            output, corrected,
            photometric='rgb', resolution=(effective_dpi, effective_dpi), resolutionunit=2,
            compression='deflate',
            metadata={'Software': 'replay_scan.py', 'Make': 'Plustek', 'Model': 'OpticFilm 8200i'},
        )
        sz = os.path.getsize(output)
        print(f"  TIFF: {output} ({sz / 1024 / 1024:.1f} MB)")
        print(f"  {out_w}x{out_h} @ {effective_dpi} DPI, 48-bit RGB")

        print("\nDone!")

    except KeyboardInterrupt:
        print("\n\nInterrupted.")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        import usb.util
        try:
            usb.util.release_interface(dev, 0)
        except Exception:
            pass


if __name__ == '__main__':
    main()
