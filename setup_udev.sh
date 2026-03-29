#!/bin/bash
# Set up udev rule for Plustek OpticFilm 8200i so it can be used without root.
# Run this once: sudo bash setup_udev.sh

set -e

RULE='SUBSYSTEM=="usb", ATTR{idVendor}=="07b3", ATTR{idProduct}=="1825", MODE="0666"'
RULE_FILE="/etc/udev/rules.d/99-plustek.rules"

echo "$RULE" > "$RULE_FILE"
udevadm control --reload-rules
udevadm trigger

echo "Done. Unplug and replug the scanner, then run:"
echo "  uv run scan_plustek.py output.tiff"
