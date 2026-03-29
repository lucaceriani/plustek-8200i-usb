#!/usr/bin/env python3
"""Detailed phase analysis - extract all non-bulk-IN transfers for replay."""

import struct
import sys
from collections import defaultdict

def read_pcap(path):
    with open(path, 'rb') as f:
        magic = struct.unpack('<I', f.read(4))[0]
        endian = '<' if magic == 0xa1b2c3d4 else '>'
        f.read(20)  # rest of global header
        pkt_num = 0
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', hdr)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            pkt_num += 1
            yield pkt_num, ts_sec + ts_usec / 1e6, data

def parse_usbpcap(data):
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

    setup = None
    if xfer_type == 2 and hdr_len >= 35:  # control with setup
        setup_data = data[27:35]
        if len(setup_data) == 8:
            bmRT, bReq, wVal, wIdx, wLen = struct.unpack_from('<BBHHH', setup_data, 0)
            setup = (bmRT, bReq, wVal, wIdx, wLen)

    return {
        'hdr_len': hdr_len, 'irp_id': irp_id, 'status': status,
        'function': function, 'info': info, 'direction': direction,
        'bus': bus, 'device': device, 'endpoint': endpoint,
        'xfer_type': xfer_type, 'data_len': data_len,
        'payload': payload, 'setup': setup,
    }

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else '/home/luca/win7/capture3200.pcap'

    first_ts = None
    packets = []
    # Track device of interest (skip hub traffic)
    scanner_device = None

    for pkt_num, ts, data in read_pcap(path):
        if first_ts is None:
            first_ts = ts
        p = parse_usbpcap(data)
        if p is None:
            continue
        p['pkt_num'] = pkt_num
        p['rel_ts'] = ts - first_ts
        packets.append(p)

    # Find the scanner device by looking for the configuration descriptor
    # that matches our device
    print("=" * 70)
    print("IDENTIFYING SCANNER DEVICE")
    print("=" * 70)

    # Look for unique devices
    devices = set()
    for p in packets:
        devices.add((p['bus'], p['device']))
    print(f"Unique (bus, device) pairs: {devices}")

    # Focus on device traffic - filter by the device that has bulk transfers
    bulk_devices = set()
    for p in packets:
        if p['xfer_type'] == 3:  # BULK
            bulk_devices.add((p['bus'], p['device']))
    print(f"Devices with bulk transfers: {bulk_devices}")

    if len(bulk_devices) == 1:
        scanner_bus, scanner_dev = bulk_devices.pop()
        print(f"Scanner is bus={scanner_bus}, device={scanner_dev}")
    else:
        # Use the one with most traffic
        dev_counts = defaultdict(int)
        for p in packets:
            if p['xfer_type'] == 3:
                dev_counts[(p['bus'], p['device'])] += 1
        scanner_bus, scanner_dev = max(dev_counts, key=dev_counts.get)
        print(f"Scanner (most bulk traffic): bus={scanner_bus}, device={scanner_dev}")

    # Filter to scanner only
    scanner_pkts = [p for p in packets if p['bus'] == scanner_bus and p['device'] == scanner_dev]
    print(f"Scanner packets: {len(scanner_pkts)}")

    # Now reconstruct the actual USB transactions by pairing submit/complete
    # In USBPcap:
    # - Direction OUT + no data = submit for IN transfer
    # - Direction OUT + data = submit for OUT transfer
    # - Direction IN + data = completion with returned data
    # - Direction IN + no data = completion for OUT transfer

    # The IRP ID pairs submits with completions
    print("\n" + "=" * 70)
    print("RECONSTRUCTING USB TRANSACTIONS")
    print("=" * 70)

    # Group by IRP ID
    irp_pairs = defaultdict(list)
    for p in scanner_pkts:
        irp_pairs[p['irp_id']].append(p)

    # Build transaction list
    transactions = []
    for irp_id, pkts in irp_pairs.items():
        if len(pkts) < 2:
            # Incomplete transaction
            continue

        submit = None
        complete = None
        for p in pkts:
            if p['direction'] == 'OUT':
                submit = p
            else:
                complete = p

        if submit is None or complete is None:
            # Try by order - first is submit, second is complete
            submit = pkts[0]
            complete = pkts[-1]

        xfer_type = submit['xfer_type']
        ep = submit['endpoint']

        txn = {
            'rel_ts': submit['rel_ts'],
            'pkt_submit': submit['pkt_num'],
            'pkt_complete': complete['pkt_num'],
            'xfer_type': xfer_type,
            'endpoint': ep,
            'setup': submit.get('setup'),
            'status': complete['status'],
        }

        # Determine actual direction and data
        if xfer_type == 2:  # CONTROL
            if submit['setup']:
                bmRT = submit['setup'][0]
                if bmRT & 0x80:  # Device-to-host
                    txn['ctrl_dir'] = 'IN'
                    txn['data_out'] = None
                    txn['data_in'] = complete['payload']
                else:  # Host-to-device
                    txn['ctrl_dir'] = 'OUT'
                    txn['data_out'] = submit['payload']
                    txn['data_in'] = None
            else:
                txn['ctrl_dir'] = 'OUT'
                txn['data_out'] = submit['payload']
                txn['data_in'] = complete['payload']
        elif xfer_type == 3:  # BULK
            if submit['data_len'] > 0:  # BULK OUT
                txn['bulk_dir'] = 'OUT'
                txn['data_out'] = submit['payload']
                txn['data_in'] = None
            else:  # BULK IN
                txn['bulk_dir'] = 'IN'
                txn['data_out'] = None
                txn['data_in'] = complete['payload']
        elif xfer_type == 1:  # INTERRUPT
            txn['int_dir'] = 'IN'
            txn['data_in'] = complete['payload']

        transactions.append(txn)

    transactions.sort(key=lambda t: t['pkt_submit'])
    print(f"Total transactions: {len(transactions)}")

    # Show all non-bulk-IN transactions (the command sequence)
    print("\n" + "=" * 70)
    print("COMMAND SEQUENCE (non-bulk-IN, non-interrupt transactions)")
    print("=" * 70)
    cmd_count = 0
    for txn in transactions:
        xt = txn['xfer_type']
        # Skip interrupt
        if xt == 1:
            continue
        # Skip bulk IN (image data)
        if xt == 3 and txn.get('bulk_dir') == 'IN':
            # Show only first few and summary
            continue

        cmd_count += 1
        ep = txn['endpoint']
        ts = txn['rel_ts']

        if xt == 2:  # CONTROL
            if txn['setup']:
                bmRT, bReq, wVal, wIdx, wLen = txn['setup']
                d = txn.get('data_out') or txn.get('data_in') or b''
                data_hex = d[:32].hex() if d else ''
                if len(d) > 32:
                    data_hex += f'... ({len(d)} bytes)'
                print(f"  #{txn['pkt_submit']:5d} t+{ts:8.3f}s CTRL {txn['ctrl_dir']:3s} "
                      f"bmRT=0x{bmRT:02x} bReq=0x{bReq:02x} wVal=0x{wVal:04x} wIdx=0x{wIdx:04x} "
                      f"wLen={wLen:5d} status=0x{txn['status']:08x} [{data_hex}]")
            else:
                print(f"  #{txn['pkt_submit']:5d} t+{ts:8.3f}s CTRL (no setup)")

        elif xt == 3:  # BULK OUT
            d = txn.get('data_out', b'') or b''
            data_hex = d[:32].hex() if d else ''
            if len(d) > 32:
                data_hex += f'... ({len(d)} bytes)'
            print(f"  #{txn['pkt_submit']:5d} t+{ts:8.3f}s BULK OUT EP 0x{ep:02x} "
                  f"len={len(d):6d} status=0x{txn['status']:08x} [{data_hex}]")

    print(f"\nTotal command transactions: {cmd_count}")

    # Now show bulk IN summary
    print("\n" + "=" * 70)
    print("BULK IN TRANSACTIONS (image data)")
    print("=" * 70)
    bulk_in_txns = [t for t in transactions if t['xfer_type'] == 3 and t.get('bulk_dir') == 'IN']
    total_bulk_in = sum(len(t.get('data_in', b'') or b'') for t in bulk_in_txns)
    print(f"Total bulk IN transactions: {len(bulk_in_txns)}")
    print(f"Total bulk IN data: {total_bulk_in:,} bytes ({total_bulk_in/1024/1024:.1f} MB)")

    if bulk_in_txns:
        first_bin = bulk_in_txns[0]
        last_bin = bulk_in_txns[-1]
        print(f"First bulk IN: pkt #{first_bin['pkt_submit']} at t+{first_bin['rel_ts']:.3f}s")
        print(f"Last bulk IN:  pkt #{last_bin['pkt_submit']} at t+{last_bin['rel_ts']:.3f}s")

        # Show first few bulk IN with data preview
        print("\nFirst 5 bulk IN transfers:")
        for t in bulk_in_txns[:5]:
            d = t.get('data_in', b'') or b''
            print(f"  pkt #{t['pkt_submit']} t+{t['rel_ts']:.3f}s len={len(d):6d} [{d[:16].hex()}...]")

    # Show interrupt summary
    int_txns = [t for t in transactions if t['xfer_type'] == 1]
    print(f"\n{'='*70}")
    print(f"INTERRUPT TRANSACTIONS: {len(int_txns)}")
    print(f"{'='*70}")
    if int_txns:
        print(f"First: pkt #{int_txns[0]['pkt_submit']} at t+{int_txns[0]['rel_ts']:.3f}s")
        print(f"Last:  pkt #{int_txns[-1]['pkt_submit']} at t+{int_txns[-1]['rel_ts']:.3f}s")
        # Show unique data values
        int_data = set()
        for t in int_txns:
            d = t.get('data_in', b'')
            if d:
                int_data.add(d.hex())
        print(f"Unique interrupt data values: {len(int_data)}")
        if len(int_data) <= 20:
            for v in sorted(int_data):
                print(f"  {v}")

    # Build the exact sequence needed for replay
    # We need: all control transfers + bulk OUT + the bulk IN read sizes
    print(f"\n{'='*70}")
    print(f"REPLAY SEQUENCE SUMMARY")
    print(f"{'='*70}")

    phases = {'init': [], 'calibration': [], 'scan_data': [], 'cleanup': []}

    # Find phase boundaries
    # INIT: from start until first large bulk transfer
    # The first big bulk OUT is likely gamma/shading table upload
    # Then bulk IN starts (calibration + image data)

    first_bulk_in_ts = bulk_in_txns[0]['rel_ts'] if bulk_in_txns else 999999
    last_bulk_in_ts = bulk_in_txns[-1]['rel_ts'] if bulk_in_txns else 0

    print(f"\nPhase boundaries:")
    print(f"  First bulk IN: t+{first_bulk_in_ts:.3f}s")
    print(f"  Last bulk IN:  t+{last_bulk_in_ts:.3f}s")

    # Group non-interrupt transactions by phase
    for txn in transactions:
        if txn['xfer_type'] == 1:  # Skip interrupts
            continue
        ts = txn['rel_ts']
        if ts < first_bulk_in_ts - 1:
            phases['init'].append(txn)
        elif ts <= last_bulk_in_ts + 1:
            if txn['xfer_type'] == 3 and txn.get('bulk_dir') == 'IN':
                phases['scan_data'].append(txn)
            else:
                phases['calibration'].append(txn)
        else:
            phases['cleanup'].append(txn)

    for name, txns in phases.items():
        ctrl = sum(1 for t in txns if t['xfer_type'] == 2)
        bout = sum(1 for t in txns if t['xfer_type'] == 3 and t.get('bulk_dir') == 'OUT')
        bin_ = sum(1 for t in txns if t['xfer_type'] == 3 and t.get('bulk_dir') == 'IN')
        print(f"  {name:15s}: {len(txns):5d} txns (ctrl={ctrl}, bulk_out={bout}, bulk_in={bin_})")

    # Show all INIT phase commands in detail
    print(f"\n{'='*70}")
    print(f"INIT PHASE DETAIL ({len(phases['init'])} transactions)")
    print(f"{'='*70}")
    for txn in phases['init']:
        xt = txn['xfer_type']
        ts = txn['rel_ts']
        if xt == 2 and txn['setup']:
            bmRT, bReq, wVal, wIdx, wLen = txn['setup']
            d = txn.get('data_out') or txn.get('data_in') or b''
            data_hex = d[:48].hex() if d else ''
            if len(d) > 48:
                data_hex += f'... ({len(d)} bytes)'
            print(f"  t+{ts:8.3f}s CTRL {txn['ctrl_dir']:3s} bmRT=0x{bmRT:02x} bReq=0x{bReq:02x} "
                  f"wVal=0x{wVal:04x} wIdx=0x{wIdx:04x} wLen={wLen:5d} [{data_hex}]")
        elif xt == 3:
            d = txn.get('data_out', b'') or b''
            data_hex = d[:48].hex() if d else ''
            if len(d) > 48:
                data_hex += f'... ({len(d)} bytes)'
            print(f"  t+{ts:8.3f}s BULK {txn.get('bulk_dir','?'):3s} EP 0x{txn['endpoint']:02x} "
                  f"len={len(d):6d} [{data_hex}]")

    # Show CALIBRATION (interleaved commands during data phase)
    print(f"\n{'='*70}")
    print(f"CALIBRATION/SCAN COMMANDS ({len(phases['calibration'])} transactions)")
    print(f"{'='*70}")
    for txn in phases['calibration']:
        xt = txn['xfer_type']
        ts = txn['rel_ts']
        if xt == 2 and txn['setup']:
            bmRT, bReq, wVal, wIdx, wLen = txn['setup']
            d = txn.get('data_out') or txn.get('data_in') or b''
            data_hex = d[:48].hex() if d else ''
            if len(d) > 48:
                data_hex += f'... ({len(d)} bytes)'
            print(f"  t+{ts:8.3f}s CTRL {txn['ctrl_dir']:3s} bmRT=0x{bmRT:02x} bReq=0x{bReq:02x} "
                  f"wVal=0x{wVal:04x} wIdx=0x{wIdx:04x} wLen={wLen:5d} [{data_hex}]")
        elif xt == 3:
            d = txn.get('data_out') or txn.get('data_in') or b''
            data_hex = d[:48].hex() if d else ''
            if len(d) > 48:
                data_hex += f'... ({len(d)} bytes)'
            print(f"  t+{ts:8.3f}s BULK {txn.get('bulk_dir','?'):3s} EP 0x{txn['endpoint']:02x} "
                  f"len={len(d):6d} [{data_hex}]")

    # Show CLEANUP phase
    print(f"\n{'='*70}")
    print(f"CLEANUP PHASE ({len(phases['cleanup'])} transactions)")
    print(f"{'='*70}")
    for txn in phases['cleanup']:
        xt = txn['xfer_type']
        ts = txn['rel_ts']
        if xt == 2 and txn['setup']:
            bmRT, bReq, wVal, wIdx, wLen = txn['setup']
            d = txn.get('data_out') or txn.get('data_in') or b''
            data_hex = d[:48].hex() if d else ''
            if len(d) > 48:
                data_hex += f'... ({len(d)} bytes)'
            print(f"  t+{ts:8.3f}s CTRL {txn['ctrl_dir']:3s} bmRT=0x{bmRT:02x} bReq=0x{bReq:02x} "
                  f"wVal=0x{wVal:04x} wIdx=0x{wIdx:04x} wLen={wLen:5d} [{data_hex}]")
        elif xt == 3:
            d = txn.get('data_out') or txn.get('data_in') or b''
            data_hex = d[:48].hex() if d else ''
            if len(d) > 48:
                data_hex += f'... ({len(d)} bytes)'
            print(f"  t+{ts:8.3f}s BULK {txn.get('bulk_dir','?'):3s} EP 0x{txn['endpoint']:02x} "
                  f"len={len(d):6d} [{data_hex}]")


if __name__ == '__main__':
    main()
