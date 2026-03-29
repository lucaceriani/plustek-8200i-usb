#!/usr/bin/env python3
"""
negafix.py – Convert a film negative scan into a positive image.

Pipeline inspired by NegPy's physics-based approach:
  1. Load & linearize
  2. Auto-detect orange film base
  3. Invert via division (mask / pixel)
  4. Per-channel auto-levels in log space (neutralizes orange mask)
  5. Logistic sigmoid tone curve (models photographic paper H&D response)
  6. Save

Usage:
  python negafix.py input.tiff -o output.tiff
  python negafix.py input.tiff -o output.tiff --contrast 1.2 --brightness 0.5
"""

import argparse
import sys
from pathlib import Path

import cv2
import numpy as np


# ---------------------------------------------------------------------------
# 1. Load & Linearize
# ---------------------------------------------------------------------------
def load_and_linearize(path: str) -> np.ndarray:
    """Load an image (8- or 16-bit) and return a float64 array in [0, 1]."""
    img = cv2.imread(path, cv2.IMREAD_UNCHANGED | cv2.IMREAD_COLOR)
    if img is None:
        sys.exit(f"Error: cannot open '{path}'")

    img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)

    if img.dtype == np.uint16:
        return img.astype(np.float64) / 65535.0
    elif img.dtype == np.uint8:
        return img.astype(np.float64) / 255.0
    else:
        return img.astype(np.float64)


# ---------------------------------------------------------------------------
# 2. Mask Detection
# ---------------------------------------------------------------------------
def sample_mask_at(img: np.ndarray, x: int, y: int, radius: int = 5) -> np.ndarray:
    """Sample the mask color as the mean of a small patch around (x, y)."""
    h, w = img.shape[:2]
    y0, y1 = max(0, y - radius), min(h, y + radius + 1)
    x0, x1 = max(0, x - radius), min(w, x + radius + 1)
    return img[y0:y1, x0:x1].mean(axis=(0, 1))


def mask_from_base_scan(path: str) -> np.ndarray:
    """Load a scan of unexposed film leader and return its average RGB.

    Averages the center 50% of the frame to avoid dark scanner borders.
    """
    base = load_and_linearize(path)
    h, w = base.shape[:2]
    y0, y1 = h // 4, h * 3 // 4
    x0, x1 = w // 4, w * 3 // 4
    mask_rgb = base[y0:y1, x0:x1].mean(axis=(0, 1))
    print(f"Base scan mask from {path} (center crop): "
          f"R={mask_rgb[0]:.4f} G={mask_rgb[1]:.4f} B={mask_rgb[2]:.4f}")
    return mask_rgb


def auto_detect_mask(img: np.ndarray, patch_size: int = 31) -> np.ndarray:
    """Fallback: find the orangest region (unexposed film base) and return its color."""
    r, g, b = img[:, :, 0], img[:, :, 1], img[:, :, 2]
    orangeness = r / (g + b + 1e-10)
    smoothed = cv2.blur(orangeness.astype(np.float32), (patch_size, patch_size))

    _, _, _, max_loc = cv2.minMaxLoc(smoothed)
    cx, cy = max_loc

    h, w = img.shape[:2]
    half = patch_size // 2
    y0, y1 = max(0, cy - half), min(h, cy + half + 1)
    x0, x1 = max(0, cx - half), min(w, cx + half + 1)
    mask_rgb = img[y0:y1, x0:x1].mean(axis=(0, 1))

    print(f"Auto-detected mask at ({cx}, {cy}): "
          f"R={mask_rgb[0]:.4f} G={mask_rgb[1]:.4f} B={mask_rgb[2]:.4f}")
    return mask_rgb


# ---------------------------------------------------------------------------
# 3. Division-Based Inversion
# ---------------------------------------------------------------------------
def invert_negative(img: np.ndarray, mask_rgb: np.ndarray) -> np.ndarray:
    """Invert via division: positive = mask / pixel.

    Simultaneously removes orange base and inverts tonality.
    No clipping — full dynamic range preserved.
    """
    return mask_rgb / np.maximum(img, 1e-10)


# ---------------------------------------------------------------------------
# 4. Per-Channel Auto-Levels in Log Space
# ---------------------------------------------------------------------------
def auto_levels_log(img: np.ndarray,
                    black_pct: float = 0.5,
                    white_pct: float = 99.5) -> np.ndarray:
    """Per-channel percentile stretch in log space.

    After division inversion, channels have wildly different scales.
    Log space turns multiplicative imbalance into additive offsets,
    so a per-channel stretch fully corrects the color balance.
    Returns values in [0, 1].
    """
    log_img = np.log(np.maximum(img, 1e-10))

    out = np.empty_like(log_img)
    for ch in range(3):
        plane = log_img[:, :, ch]
        lo = np.percentile(plane, black_pct)
        hi = np.percentile(plane, white_pct)
        if hi - lo < 1e-10:
            out[:, :, ch] = 0.0
        else:
            out[:, :, ch] = (plane - lo) / (hi - lo)

    return np.clip(out, 0.0, 1.0)


# ---------------------------------------------------------------------------
# 5. Logistic Sigmoid Tone Curve (H&D paper simulation)
# ---------------------------------------------------------------------------
def sigmoid_tone_curve(img: np.ndarray,
                       contrast: float = 1.0,
                       brightness: float = 0.5) -> np.ndarray:
    """Apply a logistic sigmoid that models photographic paper response.

    Real photographic paper has an S-shaped response (the H&D curve):
      - Shadows roll off gently (toe)
      - Midtones have good separation
      - Highlights roll off gently (shoulder)

    Formula:
        D_print = D_max / (1 + exp(-k * (x - x0)))

    Where:
        k   = contrast grade (steepness of the S-curve)
        x0  = brightness pivot (shifts the curve left/right)
        D_max = 1.0 (normalized output range)

    contrast param: 1.0 = normal, >1 = harder, <1 = softer
    brightness param: 0.0–1.0, where the midtones sit (0.5 = centered)
    """
    # Map contrast param to sigmoid steepness.
    # k ≈ 5-7 gives a natural paper-like curve; scale by user contrast.
    k = 6.0 * contrast

    # x0 is the pivot point. Input is [0, 1], sigmoid is centered at x0.
    # We shift the input so that 'brightness' maps to the sigmoid midpoint.
    x0 = brightness

    # Apply sigmoid
    out = 1.0 / (1.0 + np.exp(-k * (img - x0)))

    # The sigmoid doesn't map [0,1] → [0,1] exactly, so normalize.
    # Compute the actual output range and remap.
    out_at_0 = 1.0 / (1.0 + np.exp(-k * (0.0 - x0)))
    out_at_1 = 1.0 / (1.0 + np.exp(-k * (1.0 - x0)))
    out = (out - out_at_0) / (out_at_1 - out_at_0)

    return np.clip(out, 0.0, 1.0)


# ---------------------------------------------------------------------------
# 6. Save
# ---------------------------------------------------------------------------
def save_image(img: np.ndarray, path: str) -> None:
    """Save the [0,1] float64 RGB image as TIFF (16-bit) or JPEG (quality 97)."""
    ext = Path(path).suffix.lower()
    bgr = cv2.cvtColor(img.astype(np.float32), cv2.COLOR_RGB2BGR)

    if ext in (".tif", ".tiff"):
        out = np.clip(bgr * 65535.0, 0, 65535).astype(np.uint16)
        cv2.imwrite(path, out)
    elif ext in (".jpg", ".jpeg"):
        out = np.clip(bgr * 255.0, 0, 255).astype(np.uint8)
        cv2.imwrite(path, out, [cv2.IMWRITE_JPEG_QUALITY, 97])
    elif ext == ".png":
        out = np.clip(bgr * 65535.0, 0, 65535).astype(np.uint16)
        cv2.imwrite(path, out)
    else:
        out = np.clip(bgr * 255.0, 0, 255).astype(np.uint8)
        cv2.imwrite(path, out)

    print(f"Saved: {path}")


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------
def convert_negative(input_path: str,
                     output_path: str,
                     mask_rgb: np.ndarray | None = None,
                     mask_coord: tuple[int, int] | None = None,
                     base_scan: str | None = None,
                     black_pct: float = 0.5,
                     white_pct: float = 99.5,
                     contrast: float = 1.0,
                     brightness: float = 0.5) -> np.ndarray:
    """Full pipeline:
      1. Load & linearize
      2. Detect orange film base
      3. Invert via division (mask / pixel)
      4. Per-channel auto-levels in log space
      5. Logistic sigmoid tone curve (H&D paper simulation)
      6. Save
    """

    # 1. Load
    img = load_and_linearize(input_path)
    print(f"Loaded {input_path}  shape={img.shape}  dtype={img.dtype}")

    # 2. Detect mask (priority: base-scan > mask-coord > explicit RGB > auto-detect)
    if base_scan is not None:
        mask_rgb = mask_from_base_scan(base_scan)
    elif mask_coord is not None:
        mask_rgb = sample_mask_at(img, *mask_coord)
        print(f"Sampled mask at ({mask_coord[0]}, {mask_coord[1]}): "
              f"R={mask_rgb[0]:.4f} G={mask_rgb[1]:.4f} B={mask_rgb[2]:.4f}")
    elif mask_rgb is None:
        mask_rgb = auto_detect_mask(img)

    # 3. Division inversion
    img = invert_negative(img, mask_rgb)

    # 4. Per-channel auto-levels in log space
    img = auto_levels_log(img, black_pct, white_pct)

    # 5. Sigmoid tone curve (replaces gamma — models real paper response)
    img = sigmoid_tone_curve(img, contrast=contrast, brightness=brightness)

    # 6. Save
    save_image(img, output_path)
    return img


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Convert a film negative scan to a positive image.")
    p.add_argument("input", help="Path to the negative scan")
    p.add_argument("-o", "--output", default="positive.tiff",
                   help="Output path (.tiff, .jpg, .png). Default: positive.tiff")
    p.add_argument("--mask", type=str, default=None,
                   help="Orange mask as R,G,B floats in [0,1]")
    p.add_argument("--mask-coord", type=str, default=None,
                   help="Sample mask from pixel coordinate X,Y")
    p.add_argument("--base-scan", type=str, default=None,
                   help="Path to a scan of unexposed film leader (best accuracy)")
    p.add_argument("--black-pct", type=float, default=0.5,
                   help="Black-point percentile (default 0.5)")
    p.add_argument("--white-pct", type=float, default=99.5,
                   help="White-point percentile (default 99.5)")
    p.add_argument("--contrast", type=float, default=1.0,
                   help="Contrast grade: 1.0=normal, >1=harder, <1=softer")
    p.add_argument("--brightness", type=float, default=0.5,
                   help="Brightness pivot 0.0–1.0 (default 0.5)")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    mask_rgb = None
    if args.mask:
        parts = [float(v) for v in args.mask.split(",")]
        if len(parts) != 3:
            sys.exit("--mask must be three comma-separated floats (R,G,B)")
        mask_rgb = np.array(parts)

    mask_coord = None
    if args.mask_coord:
        parts = [int(v) for v in args.mask_coord.split(",")]
        if len(parts) != 2:
            sys.exit("--mask-coord must be two comma-separated ints (X,Y)")
        mask_coord = tuple(parts)

    convert_negative(
        input_path=args.input,
        output_path=args.output,
        mask_rgb=mask_rgb,
        mask_coord=mask_coord,
        base_scan=args.base_scan,
        black_pct=args.black_pct,
        white_pct=args.white_pct,
        contrast=args.contrast,
        brightness=args.brightness,
    )


if __name__ == "__main__":
    main()
