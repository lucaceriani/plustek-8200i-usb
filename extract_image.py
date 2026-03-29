#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["tifffile", "numpy"]
# ///
"""Extract image data from USBPcap capture of Plustek OpticFilm 8200i scan."""

import struct
import sys
import numpy as np

PCAP_GLOBAL_HEADER_SIZE = 24
PCAP_PACKET_HEADER_SIZE = 16

# USBPcap header fields
# https://desowin.org/usbpcap/captureformat.html
USBPCAP_TRANSFER_ISOCHRONOUS = 0
USBPCAP_TRANSFER_INTERRUPT = 1
USBPCAP_TRANSFER_CONTROL = 2
USBPCAP_TRANSFER_BULK = 3

def parse_pcap(filename):
    """Parse pcap file and yield (packet_header, usbpcap_header, data) tuples."""
    with open(filename, 'rb') as f:
        # Global header
        ghdr = f.read(PCAP_GLOBAL_HEADER_SIZE)
        magic, ver_maj, ver_min, _, _, snaplen, linktype = struct.unpack('<IHHIIII', ghdr)
        assert linktype == 249, f"Expected USBPcap linktype 249, got {linktype}"

        while True:
            phdr = f.read(PCAP_PACKET_HEADER_SIZE)
            if len(phdr) < PCAP_PACKET_HEADER_SIZE:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', phdr)

            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break

            # Parse USBPcap header (minimum 27 bytes)
            if len(pkt_data) < 27:
                continue

            hdr_len = struct.unpack_from('<H', pkt_data, 0)[0]
            irp_id = struct.unpack_from('<Q', pkt_data, 2)[0]
            usbd_status = struct.unpack_from('<I', pkt_data, 10)[0]
            urb_function = struct.unpack_from('<H', pkt_data, 14)[0]
            info = pkt_data[16]  # bit 0: 1=device-to-host (IN)
            bus = struct.unpack_from('<H', pkt_data, 17)[0]
            device = struct.unpack_from('<H', pkt_data, 19)[0]
            endpoint = pkt_data[21]
            transfer_type = pkt_data[22]
            data_length = struct.unpack_from('<I', pkt_data, 23)[0]

            payload = pkt_data[hdr_len:]

            yield {
                'irp_id': irp_id,
                'usbd_status': usbd_status,
                'urb_function': urb_function,
                'direction': 'IN' if (info & 1) else 'OUT',
                'bus': bus,
                'device': device,
                'endpoint': endpoint,
                'transfer_type': transfer_type,
                'data_length': data_length,
                'hdr_len': hdr_len,
            }, payload


def main():
    pcap_file = sys.argv[1] if len(sys.argv) > 1 else "capture7200.pcap"

    print(f"Parsing {pcap_file}...")

    # Collect stats
    stats = {'control': 0, 'bulk_in': 0, 'bulk_out': 0, 'interrupt': 0, 'other': 0}
    endpoints = set()
    devices = set()
    total_bulk_in_bytes = 0
    total_packets = 0

    # Collect all bulk IN data
    bulk_in_data = bytearray()
    bulk_in_packets = []

    for hdr, payload in parse_pcap(pcap_file):
        total_packets += 1
        devices.add((hdr['bus'], hdr['device']))
        ep = hdr['endpoint']
        tt = hdr['transfer_type']
        direction = hdr['direction']

        if tt == USBPCAP_TRANSFER_CONTROL:
            stats['control'] += 1
        elif tt == USBPCAP_TRANSFER_BULK:
            endpoints.add(ep)
            if direction == 'IN' and len(payload) > 0:
                stats['bulk_in'] += 1
                total_bulk_in_bytes += len(payload)
                bulk_in_data.extend(payload)
                bulk_in_packets.append(len(payload))
            elif direction == 'OUT':
                stats['bulk_out'] += 1
        elif tt == USBPCAP_TRANSFER_INTERRUPT:
            stats['interrupt'] += 1
        else:
            stats['other'] += 1

    print(f"\n=== Traffic Summary ===")
    print(f"Total packets: {total_packets}")
    print(f"Devices: {devices}")
    print(f"Endpoints used: {[f'0x{e:02x}' for e in sorted(endpoints)]}")
    print(f"Control:   {stats['control']}")
    print(f"Bulk IN:   {stats['bulk_in']} ({total_bulk_in_bytes:,} bytes)")
    print(f"Bulk OUT:  {stats['bulk_out']}")
    print(f"Interrupt: {stats['interrupt']}")
    print(f"Other:     {stats['other']}")

    print(f"\nBulk IN data collected: {len(bulk_in_data):,} bytes")

    # Show packet size distribution
    if bulk_in_packets:
        from collections import Counter
        size_counts = Counter(bulk_in_packets)
        print(f"Bulk IN packet sizes: {dict(sorted(size_counts.items(), key=lambda x: -x[1])[:10])}")

    # Reference image info
    # scan7200.tif: 7200x10368x3 uint16 = 447,897,600 bytes
    ref_size = 7200 * 10368 * 3 * 2
    print(f"\nReference TIFF raw size: {ref_size:,} bytes")
    print(f"Ratio bulk_in/ref: {len(bulk_in_data)/ref_size:.4f}")

    # Save raw bulk IN data
    raw_file = "raw_bulk_in_7200.data"
    with open(raw_file, 'wb') as f:
        f.write(bulk_in_data)
    print(f"\nSaved raw bulk IN data to {raw_file}")

    # Try to reconstruct image
    # The scanner sends 48-bit RGB (3x16-bit), likely line by line
    width = 10368
    height = 7200
    bpp = 6  # bytes per pixel (3 channels * 2 bytes)
    line_bytes = width * bpp  # 62208
    image_bytes = width * height * bpp  # 447,897,600

    print(f"\nExpected image: {width}x{height}, line={line_bytes} bytes, total={image_bytes:,} bytes")

    # Check if bulk IN data contains the image directly or has overhead
    # Try different offsets to find where image data starts
    if len(bulk_in_data) >= image_bytes:
        offset = len(bulk_in_data) - image_bytes
        print(f"Data has {offset:,} bytes before image-sized region")

        # Try extracting from end (image data likely at end, calibration at start)
        img_data = bulk_in_data[offset:offset + image_bytes]
        pixels = np.frombuffer(bytes(img_data), dtype='<u2').reshape((height, width, 3))

        import tifffile
        out_file = "extracted_7200.tif"
        tifffile.imwrite(out_file, pixels, photometric='rgb',
                        resolution=(7200, 7200), resolutionunit=2)
        print(f"Saved {out_file}")

        # Also try from start
        img_data0 = bulk_in_data[:image_bytes]
        pixels0 = np.frombuffer(bytes(img_data0), dtype='<u2').reshape((height, width, 3))
        out_file0 = "extracted_7200_from_start.tif"
        tifffile.imwrite(out_file0, pixels0, photometric='rgb',
                        resolution=(7200, 7200), resolutionunit=2)
        print(f"Saved {out_file0}")
    else:
        shortfall = image_bytes - len(bulk_in_data)
        print(f"WARNING: Bulk IN data is {shortfall:,} bytes SHORT of expected image size")
        print("The image data might be split differently or have a different format")

        # Try with what we have - pad with zeros
        padded = bulk_in_data + b'\x00' * (image_bytes - len(bulk_in_data))
        pixels = np.frombuffer(bytes(padded), dtype='<u2').reshape((height, width, 3))

        import tifffile
        out_file = "extracted_7200_partial.tif"
        tifffile.imwrite(out_file, pixels, photometric='rgb',
                        resolution=(7200, 7200), resolutionunit=2)
        print(f"Saved {out_file} (padded)")


if __name__ == '__main__':
    main()
