#!/usr/bin/env python3
"""Analyze USB pcap capture from Plustek OpticFilm 8200i scanner."""

import struct
import sys
from collections import defaultdict

PCAP_MAGIC_LE = 0xa1b2c3d4
PCAP_MAGIC_BE = 0xd4c3b2a1
PCAPNG_MAGIC = 0x0a0d0d0a

# USB transfer types
XFER_TYPES = {0: 'ISOCHRONOUS', 1: 'INTERRUPT', 2: 'CONTROL', 3: 'BULK'}

# URB types (USBPcap)
URB_SUBMIT = ord('S')
URB_COMPLETE = ord('C')

def read_pcap(path):
    """Read pcap file and yield (timestamp, raw_packet) tuples."""
    with open(path, 'rb') as f:
        # Read global header
        magic = struct.unpack('<I', f.read(4))[0]
        if magic == PCAP_MAGIC_LE:
            endian = '<'
        elif magic == PCAP_MAGIC_BE:
            endian = '>'
        else:
            print(f"Magic: 0x{magic:08x}")
            raise ValueError("Not a pcap file (might be pcapng)")

        ver_major, ver_minor, tz_off, tz_acc, snap_len, link_type = struct.unpack(
            endian + 'HHiIII', f.read(20))
        print(f"PCAP version: {ver_major}.{ver_minor}")
        print(f"Link type: {link_type} (249=USBPcap)")
        print(f"Snap length: {snap_len}")

        # Read packets
        pkt_num = 0
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', hdr)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            ts = ts_sec + ts_usec / 1e6
            pkt_num += 1
            yield pkt_num, ts, data, orig_len


def parse_usbpcap_header(data):
    """Parse USBPcap packet header.

    USBPcap header format (27 bytes minimum):
    offset  size  field
    0       2     headerLen
    1       1     irpId (not used directly)
    2       8     irpId (64-bit)
    10      4     status (USBD_STATUS)
    14      2     function
    16      1     info (direction: bit 0 = 1 means IN)
    17      2     bus
    19      2     device
    21      1     endpoint
    22      1     transfer type
    23      4     data length after header
    """
    if len(data) < 27:
        return None

    hdr_len = struct.unpack_from('<H', data, 0)[0]
    irp_id = struct.unpack_from('<Q', data, 2)[0]
    status = struct.unpack_from('<I', data, 10)[0]
    function = struct.unpack_from('<H', data, 14)[0]
    info = data[16]
    bus = struct.unpack_from('<H', data, 17)[0]
    device = struct.unpack_from('<H', data, 19)[0]
    endpoint = data[21]
    xfer_type = data[22]
    data_len = struct.unpack_from('<I', data, 23)[0]

    direction = 'IN' if (info & 1) else 'OUT'
    payload = data[hdr_len:hdr_len + data_len] if hdr_len + data_len <= len(data) else data[hdr_len:]

    # For control transfers, parse setup packet if present
    setup = None
    if xfer_type == 2 and hdr_len >= 27 + 8:  # control transfer with setup data
        # Setup packet is at offset 27 in USBPcap
        setup_data = data[27:35]
        if len(setup_data) == 8:
            bmRT, bReq, wVal, wIdx, wLen = struct.unpack_from('<BBHHH', setup_data, 0)
            setup = (bmRT, bReq, wVal, wIdx, wLen)

    return {
        'hdr_len': hdr_len,
        'irp_id': irp_id,
        'status': status,
        'function': function,
        'info': info,
        'direction': direction,
        'bus': bus,
        'device': device,
        'endpoint': endpoint,
        'xfer_type': xfer_type,
        'xfer_type_name': XFER_TYPES.get(xfer_type, f'UNKNOWN({xfer_type})'),
        'data_len': data_len,
        'payload': payload,
        'setup': setup,
    }


def analyze(pcap_path):
    print(f"Analyzing: {pcap_path}")
    print("=" * 70)

    total = 0
    xfer_counts = defaultdict(int)
    ep_counts = defaultdict(int)
    dir_counts = defaultdict(int)
    bulk_in_bytes = 0
    bulk_out_bytes = 0
    ctrl_count = 0

    # Track phases by looking at patterns
    first_ts = None
    last_ts = None

    # Collect all parsed packets for phase analysis
    packets = []

    # Track IRP pairs (submit -> complete)
    irp_submits = {}  # irp_id -> submit packet info
    transfers = []    # completed transfers

    for pkt_num, ts, data, orig_len in read_pcap(pcap_path):
        total += 1
        if first_ts is None:
            first_ts = ts
        last_ts = ts

        parsed = parse_usbpcap_header(data)
        if parsed is None:
            continue

        parsed['pkt_num'] = pkt_num
        parsed['ts'] = ts
        parsed['rel_ts'] = ts - first_ts

        xfer_counts[parsed['xfer_type_name']] += 1
        ep_addr = parsed['endpoint']
        if parsed['direction'] == 'IN':
            ep_addr |= 0x80
        ep_counts[f"0x{ep_addr:02x} ({parsed['direction']})"] += 1
        dir_counts[parsed['direction']] += 1

        if parsed['xfer_type_name'] == 'BULK' and parsed['direction'] == 'IN':
            bulk_in_bytes += len(parsed['payload'])
        elif parsed['xfer_type_name'] == 'BULK' and parsed['direction'] == 'OUT':
            bulk_out_bytes += len(parsed['payload'])

        # Track IRP submit/complete pairs
        func = parsed['function']
        # function 9 = URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER
        # function 8 = URB_FUNCTION_VENDOR_DEVICE (control)
        # function 0 = URB_FUNCTION_SELECT_CONFIGURATION
        # In USBPcap, info bit 0 = direction, and we look at function to determine submit vs complete
        # Actually, USBPcap uses 'function' differently. Let's track by looking at data presence.

        packets.append(parsed)

    duration = last_ts - first_ts if first_ts and last_ts else 0

    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"Total packets:     {total:,}")
    print(f"Duration:          {duration:.1f} seconds ({duration/60:.1f} min)")
    print(f"\nBy transfer type:")
    for k, v in sorted(xfer_counts.items()):
        print(f"  {k:20s}: {v:,}")

    print(f"\nBy endpoint:")
    for k, v in sorted(ep_counts.items()):
        print(f"  {k:20s}: {v:,}")

    print(f"\nBy direction:")
    for k, v in sorted(dir_counts.items()):
        print(f"  {k:20s}: {v:,}")

    print(f"\nBulk IN data:      {bulk_in_bytes:,} bytes ({bulk_in_bytes/1024/1024:.1f} MB)")
    print(f"Bulk OUT data:     {bulk_out_bytes:,} bytes ({bulk_out_bytes/1024/1024:.1f} MB)")

    # Phase analysis - look at transitions in traffic patterns
    print(f"\n{'='*70}")
    print(f"PHASE ANALYSIS")
    print(f"{'='*70}")

    # Find transitions: look at windows of activity
    window = 1.0  # 1 second windows
    time_slots = defaultdict(lambda: defaultdict(int))
    time_bytes = defaultdict(int)

    for p in packets:
        slot = int(p['rel_ts'])
        time_slots[slot][p['xfer_type_name'] + '_' + p['direction']] += 1
        if p['xfer_type_name'] == 'BULK' and p['direction'] == 'IN':
            time_bytes[slot] += len(p['payload'])

    # Find when bulk IN data starts flowing heavily (= image data phase)
    data_start = None
    data_end = None
    threshold = 100000  # 100KB/sec = image data flowing

    for slot in sorted(time_bytes.keys()):
        bps = time_bytes[slot]
        if bps > threshold and data_start is None:
            data_start = slot
        if bps > threshold:
            data_end = slot

    if data_start is not None:
        print(f"\nImage data transfer detected:")
        print(f"  Starts at:  t+{data_start}s")
        print(f"  Ends at:    t+{data_end}s")
        print(f"  Duration:   {data_end - data_start}s")
        print(f"\nEstimated phases:")
        print(f"  INIT:     t+0s to t+{data_start}s ({data_start}s)")
        print(f"  DATA:     t+{data_start}s to t+{data_end}s ({data_end - data_start}s)")
        print(f"  CLEANUP:  t+{data_end}s to t+{int(duration)}s ({int(duration) - data_end}s)")

    # Show first 30 packets detail to understand protocol
    print(f"\n{'='*70}")
    print(f"FIRST 30 PACKETS (protocol overview)")
    print(f"{'='*70}")
    for p in packets[:30]:
        ep_str = f"EP 0x{p['endpoint']:02x}" if p['endpoint'] else "EP0"
        setup_str = ""
        if p['setup']:
            bmRT, bReq, wVal, wIdx, wLen = p['setup']
            setup_str = f" setup=(bmRT=0x{bmRT:02x} bReq=0x{bReq:02x} wVal=0x{wVal:04x} wIdx=0x{wIdx:04x} wLen={wLen})"
        payload_hex = ""
        if p['payload'] and len(p['payload']) <= 16:
            payload_hex = f" data=[{p['payload'].hex()}]"
        elif p['payload']:
            payload_hex = f" data=[{p['payload'][:16].hex()}...] ({len(p['payload'])} bytes)"

        print(f"  #{p['pkt_num']:5d} t+{p['rel_ts']:8.3f}s {p['xfer_type_name']:12s} {p['direction']:3s} "
              f"{ep_str:8s} func={p['function']:2d} len={p['data_len']:5d}{setup_str}{payload_hex}")

    # Show last 30 packets
    print(f"\n{'='*70}")
    print(f"LAST 30 PACKETS (cleanup overview)")
    print(f"{'='*70}")
    for p in packets[-30:]:
        ep_str = f"EP 0x{p['endpoint']:02x}" if p['endpoint'] else "EP0"
        setup_str = ""
        if p['setup']:
            bmRT, bReq, wVal, wIdx, wLen = p['setup']
            setup_str = f" setup=(bmRT=0x{bmRT:02x} bReq=0x{bReq:02x} wVal=0x{wVal:04x} wIdx=0x{wIdx:04x} wLen={wLen})"
        payload_hex = ""
        if p['payload'] and len(p['payload']) <= 16:
            payload_hex = f" data=[{p['payload'].hex()}]"
        elif p['payload']:
            payload_hex = f" data=[{p['payload'][:16].hex()}...] ({len(p['payload'])} bytes)"

        print(f"  #{p['pkt_num']:5d} t+{p['rel_ts']:8.3f}s {p['xfer_type_name']:12s} {p['direction']:3s} "
              f"{ep_str:8s} func={p['function']:2d} len={p['data_len']:5d}{setup_str}{payload_hex}")

    # Count unique control operations
    print(f"\n{'='*70}")
    print(f"CONTROL TRANSFER ANALYSIS")
    print(f"{'='*70}")
    ctrl_ops = defaultdict(int)
    for p in packets:
        if p['xfer_type_name'] == 'CONTROL' and p['setup']:
            bmRT, bReq, wVal, wIdx, wLen = p['setup']
            key = f"bmRT=0x{bmRT:02x} bReq=0x{bReq:02x} wVal=0x{wVal:04x}"
            ctrl_ops[key] += 1
    for k, v in sorted(ctrl_ops.items(), key=lambda x: -x[1]):
        print(f"  {k:50s}: {v:,}")

    # Analyze bulk OUT patterns
    print(f"\n{'='*70}")
    print(f"BULK OUT TRANSFERS (commands to scanner)")
    print(f"{'='*70}")
    bout_sizes = defaultdict(int)
    bout_first_bytes = defaultdict(int)
    for p in packets:
        if p['xfer_type_name'] == 'BULK' and p['direction'] == 'OUT' and p['payload']:
            bout_sizes[len(p['payload'])] += 1
            fb = p['payload'][0]
            bout_first_bytes[f"0x{fb:02x}"] += 1
    print("Sizes:")
    for k, v in sorted(bout_sizes.items()):
        print(f"  {k:6d} bytes: {v:,} transfers")
    print("First bytes:")
    for k, v in sorted(bout_first_bytes.items(), key=lambda x: -x[1]):
        print(f"  {k}: {v:,} transfers")

    # Analyze bulk IN sizes
    print(f"\n{'='*70}")
    print(f"BULK IN TRANSFER SIZES")
    print(f"{'='*70}")
    bin_sizes = defaultdict(int)
    for p in packets:
        if p['xfer_type_name'] == 'BULK' and p['direction'] == 'IN' and p['payload']:
            bin_sizes[len(p['payload'])] += 1
    for k, v in sorted(bin_sizes.items()):
        print(f"  {k:6d} bytes: {v:,} transfers")

    print(f"\n{'='*70}")
    print(f"TIME PROFILE (bytes per second of bulk IN data)")
    print(f"{'='*70}")
    for slot in sorted(time_bytes.keys()):
        if time_bytes[slot] > 0:
            bar = '#' * min(70, time_bytes[slot] // 100000)
            print(f"  t+{slot:4d}s: {time_bytes[slot]:>10,} bytes {bar}")

    return packets


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else '/home/luca/win7/capture3200.pcap'
    analyze(path)
