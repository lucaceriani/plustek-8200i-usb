#!/usr/bin/env python3
"""Final analysis - handle all control transfer formats correctly."""

import struct
import sys
import pickle
import zlib
from collections import defaultdict

def read_pcap(path):
    with open(path, 'rb') as f:
        magic = struct.unpack('<I', f.read(4))[0]
        assert magic == 0xa1b2c3d4
        f.read(20)
        pkt_num = 0
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, _ = struct.unpack('<IIII', hdr)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            pkt_num += 1
            yield pkt_num, ts_sec + ts_usec / 1e6, data

def parse_pkt(data):
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
    is_complete = bool(info & 1)

    payload = data[hdr_len:hdr_len + data_len] if data_len > 0 else b''

    # Parse setup packet for control transfers
    setup = None
    ctrl_data = b''
    if xfer_type == 2 and not is_complete:
        if hdr_len >= 36:
            # Extended header with stage + setup
            stage = data[27]
            if stage == 0 and len(data) >= 36:
                setup_bytes = data[28:36]
                bmRT, bReq, wVal, wIdx, wLen = struct.unpack_from('<BBHHH', setup_bytes)
                setup = (bmRT, bReq, wVal, wIdx, wLen)
                ctrl_data = payload
        elif data_len >= 8:
            # Setup might be in the payload (func=23 vendor transfers)
            bmRT, bReq, wVal, wIdx, wLen = struct.unpack_from('<BBHHH', payload, 0)
            # Sanity check: bmRT should have valid type bits
            if (bmRT & 0x60) in (0x00, 0x20, 0x40):
                setup = (bmRT, bReq, wVal, wIdx, wLen)
                ctrl_data = payload[8:]  # data after setup packet

    return {
        'hdr_len': hdr_len, 'irp_id': irp_id, 'status': status,
        'function': function, 'is_complete': is_complete,
        'bus': bus, 'device': device, 'endpoint': endpoint,
        'xfer_type': xfer_type, 'data_len': data_len,
        'payload': payload, 'setup': setup, 'ctrl_data': ctrl_data,
    }

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else '/home/luca/win7/capture3200.pcap'

    first_ts = None
    pkts = []

    for pkt_num, ts, data in read_pcap(path):
        if first_ts is None:
            first_ts = ts
        p = parse_pkt(data)
        if p:
            p['pkt'] = pkt_num
            p['ts'] = ts - first_ts
            pkts.append(p)

    # Filter to scanner
    scanner_pkts = [p for p in pkts if p['bus'] == 1 and p['device'] == 2]
    print(f"Scanner packets: {len(scanner_pkts)}")

    # Pair submits/completions
    pending = {}
    transactions = []

    for p in scanner_pkts:
        if not p['is_complete']:
            pending[p['irp_id']] = p
        else:
            s = pending.pop(p['irp_id'], None)
            if s is None:
                continue

            xfer_type = s['xfer_type']
            endpoint = s['endpoint']
            ep_dir = 'IN' if (endpoint & 0x80) else 'OUT'

            txn = {
                'ts': s['ts'],
                'pkt_s': s['pkt'],
                'pkt_c': p['pkt'],
                'xfer_type': xfer_type,
                'endpoint': endpoint,
                'status': p['status'],
                'function': s['function'],
            }

            if xfer_type == 2:  # CONTROL
                txn['setup'] = s['setup']
                if s['setup']:
                    bmRT = s['setup'][0]
                    if bmRT & 0x80:  # Device-to-host
                        txn['direction'] = 'IN'
                        txn['data'] = p['payload']  # response in completion
                        txn['ctrl_data_out'] = s.get('ctrl_data', b'')
                    else:  # Host-to-device
                        txn['direction'] = 'OUT'
                        txn['data'] = s.get('ctrl_data', b'')  # data sent with setup
                else:
                    txn['direction'] = ep_dir
                    txn['data'] = p['payload'] if ep_dir == 'IN' else s['payload']
            elif xfer_type == 3:  # BULK
                if ep_dir == 'IN':
                    txn['direction'] = 'IN'
                    txn['data'] = p['payload']
                else:
                    txn['direction'] = 'OUT'
                    txn['data'] = s['payload']
            elif xfer_type == 1:  # INTERRUPT
                txn['direction'] = 'IN'
                txn['data'] = p['payload']

            transactions.append(txn)

    print(f"Paired transactions: {len(transactions)}")

    # Stats
    ctrl = [t for t in transactions if t['xfer_type'] == 2]
    ctrl_setup = [t for t in ctrl if t.get('setup')]
    ctrl_vendor = [t for t in ctrl_setup if (t['setup'][0] & 0x60) == 0x40]
    ctrl_std = [t for t in ctrl_setup if (t['setup'][0] & 0x60) == 0x00]
    bout = [t for t in transactions if t['xfer_type'] == 3 and t['direction'] == 'OUT']
    bin_ = [t for t in transactions if t['xfer_type'] == 3 and t['direction'] == 'IN']

    total_bin = sum(len(t.get('data', b'') or b'') for t in bin_)
    print(f"\nControl total: {len(ctrl)} (with setup: {len(ctrl_setup)}, vendor: {len(ctrl_vendor)}, standard: {len(ctrl_std)})")
    print(f"Bulk OUT: {len(bout)}, Bulk IN: {len(bin_)}")
    print(f"Bulk IN total: {total_bin:,} bytes ({total_bin/1024/1024:.1f} MB)")

    # Show ALL vendor control transfers
    print(f"\n{'='*70}")
    print(f"ALL VENDOR CONTROL TRANSFERS ({len(ctrl_vendor)})")
    print(f"{'='*70}")
    for i, t in enumerate(ctrl_vendor):
        bmRT, bReq, wVal, wIdx, wLen = t['setup']
        d = t.get('data', b'') or b''
        dh = d[:32].hex() if d else ''
        if len(d) > 32:
            dh += f'...({len(d)}B)'
        print(f"  [{i:4d}] #{t['pkt_s']:5d} t+{t['ts']:8.3f}s {t['direction']:3s} "
              f"bmRT=0x{bmRT:02x} bReq=0x{bReq:02x} wVal=0x{wVal:04x} wIdx=0x{wIdx:04x} "
              f"wLen={wLen:5d} status=0x{t['status']:08x} [{dh}]")

    # Build full replay sequence: vendor ctrl + bulk, ordered by time
    replay = []
    for t in transactions:
        if t['xfer_type'] == 2:
            if not t.get('setup'):
                continue
            bmRT = t['setup'][0]
            if (bmRT & 0x60) != 0x40:
                continue  # Skip standard/class requests
            replay.append(t)
        elif t['xfer_type'] == 3:
            replay.append(t)

    replay.sort(key=lambda t: t['pkt_s'])
    print(f"\n{'='*70}")
    print(f"FULL REPLAY SEQUENCE: {len(replay)} operations")
    print(f"{'='*70}")

    # Find phase boundaries
    first_bin_ts = None
    last_bin_ts = None
    first_bout_ts = None

    for t in replay:
        if t['xfer_type'] == 3:
            if t['direction'] == 'IN' and first_bin_ts is None:
                first_bin_ts = t['ts']
            if t['direction'] == 'IN':
                last_bin_ts = t['ts']
            if t['direction'] == 'OUT' and first_bout_ts is None:
                first_bout_ts = t['ts']

    print(f"First bulk OUT: t+{first_bout_ts:.3f}s")
    print(f"First bulk IN:  t+{first_bin_ts:.3f}s")
    print(f"Last bulk IN:   t+{last_bin_ts:.3f}s")

    # Print ordered sequence (non-bulk-IN in full, bulk-IN summarized)
    print(f"\nDetailed sequence:")
    bin_count = 0
    suppressed = False
    for i, t in enumerate(replay):
        d = t.get('data', b'') or b''
        if t['xfer_type'] == 2:
            s = t['setup']
            dh = d[:48].hex() if d else ''
            if len(d) > 48:
                dh += f'...({len(d)}B)'
            print(f"  [{i:4d}] t+{t['ts']:8.3f}s CTRL {t['direction']:3s} "
                  f"0x{s[0]:02x}/0x{s[1]:02x} wVal=0x{s[2]:04x} wIdx=0x{s[3]:04x} "
                  f"wLen={s[4]:5d} [{dh}]")
            suppressed = False
        elif t['xfer_type'] == 3 and t['direction'] == 'OUT':
            dh = d[:48].hex() if d else ''
            if len(d) > 48:
                dh += f'...({len(d)}B)'
            print(f"  [{i:4d}] t+{t['ts']:8.3f}s BOUT EP 0x{t['endpoint']:02x} "
                  f"len={len(d):6d} [{dh}]")
            suppressed = False
        elif t['xfer_type'] == 3 and t['direction'] == 'IN':
            bin_count += 1
            # Only show first 10 and last 5 bulk INs
            if bin_count <= 10 or (last_bin_ts and t['ts'] > last_bin_ts - 0.5):
                print(f"  [{i:4d}] t+{t['ts']:8.3f}s BIN  EP 0x{t['endpoint']:02x} len={len(d):6d}")
                suppressed = False
            elif not suppressed:
                print(f"        ... (bulk IN reads continue) ...")
                suppressed = True

    # ===== Build ops for the replay script =====
    print(f"\n{'='*70}")
    print(f"BUILDING REPLAY OPS")
    print(f"{'='*70}")

    # Group into phases based on the interleaving pattern
    ops = []  # ordered list of all operations
    for t in replay:
        d = t.get('data', b'') or b''
        if t['xfer_type'] == 2:  # CTRL
            s = t['setup']
            if t['direction'] == 'OUT':
                ops.append(('CW', s[0], s[1], s[2], s[3], bytes(d)))
            else:
                ops.append(('CR', s[0], s[1], s[2], s[3], s[4]))
        elif t['xfer_type'] == 3:
            if t['direction'] == 'OUT':
                ops.append(('BW', t['endpoint'], bytes(d)))
            else:
                ops.append(('BR', t['endpoint'], len(d)))

    # Now identify the natural phases by looking at the sequence pattern:
    # Phase 1 (INIT): ops before first bulk IN
    # Phase 2 (SCAN): includes calibration reads, setup writes, and the main data stream
    # The interleaving is: some writes, some reads, more writes, then the big read stream

    # Find indices of transitions
    first_br_idx = None
    last_br_idx = None
    for i, op in enumerate(ops):
        if op[0] == 'BR':
            if first_br_idx is None:
                first_br_idx = i
            last_br_idx = i

    # Find the last BW after the first BR (interleaved commands during scan)
    last_bw_during_scan = None
    for i, op in enumerate(ops):
        if op[0] == 'BW' and first_br_idx and i > first_br_idx:
            last_bw_during_scan = i

    print(f"First BR at index: {first_br_idx}")
    print(f"Last BR at index:  {last_br_idx}")
    print(f"Last BW during scan at index: {last_bw_during_scan}")
    print(f"Total ops: {len(ops)}")

    # Separate into init (before first BR) and the interleaved scan sequence
    init_ops = ops[:first_br_idx] if first_br_idx else ops
    scan_ops = ops[first_br_idx:] if first_br_idx else []

    # In the scan_ops, separate the setup writes from the data reads
    # The pattern is: some initial calibration reads, then setup writes, then the main data stream
    # For simplicity in replay, we'll keep them interleaved exactly as captured

    print(f"\nINIT ops: {len(init_ops)}")
    for i, op in enumerate(init_ops):
        if op[0] in ('CW', 'CR'):
            data_str = op[5].hex()[:48] if isinstance(op[5], bytes) else str(op[5])
            print(f"  [{i}] {op[0]} bmRT=0x{op[1]:02x} bReq=0x{op[2]:02x} wVal=0x{op[3]:04x} wIdx=0x{op[4]:04x} [{data_str}]")
        elif op[0] == 'BW':
            print(f"  [{i}] BW EP 0x{op[1]:02x} len={len(op[2])} [{op[2][:24].hex()}...]")
        elif op[0] == 'BR':
            print(f"  [{i}] BR EP 0x{op[1]:02x} len={op[2]}")

    print(f"\nSCAN ops: {len(scan_ops)} (first 50):")
    for i, op in enumerate(scan_ops[:50]):
        if op[0] in ('CW', 'CR'):
            data_str = op[5].hex()[:48] if isinstance(op[5], bytes) else str(op[5])
            print(f"  [{i}] {op[0]} bmRT=0x{op[1]:02x} bReq=0x{op[2]:02x} wVal=0x{op[3]:04x} wIdx=0x{op[4]:04x} [{data_str}]")
        elif op[0] == 'BW':
            print(f"  [{i}] BW EP 0x{op[1]:02x} len={len(op[2])} [{op[2][:24].hex()}...]")
        elif op[0] == 'BR':
            print(f"  [{i}] BR EP 0x{op[1]:02x} len={op[2]}")

    # Count how many BRs vs BWs in scan_ops
    scan_br = sum(1 for op in scan_ops if op[0] == 'BR')
    scan_bw = sum(1 for op in scan_ops if op[0] == 'BW')
    scan_cw = sum(1 for op in scan_ops if op[0] == 'CW')
    scan_cr = sum(1 for op in scan_ops if op[0] == 'CR')
    total_read = sum(op[2] for op in scan_ops if op[0] == 'BR')
    print(f"\nScan ops breakdown: BR={scan_br}, BW={scan_bw}, CW={scan_cw}, CR={scan_cr}")
    print(f"Total expected read in scan: {total_read:,} bytes ({total_read/1024/1024:.1f} MB)")

    # Save the complete replay data
    replay_data = {
        'init_ops': init_ops,
        'scan_ops': scan_ops,
        'total_expected_bytes': total_read,
        'bulk_in_ep': 0x81,
        'bulk_out_ep': 0x02,
    }

    out_path = path.replace('.pcap', '_replay.pkl')
    blob = pickle.dumps(replay_data)
    compressed = zlib.compress(blob, 9)
    with open(out_path, 'wb') as f:
        f.write(compressed)
    print(f"\nSaved: {out_path} ({len(compressed):,} bytes)")

    # Also save the full bulk OUT data for reference
    print(f"\n{'='*70}")
    print(f"BULK OUT DATA ANALYSIS")
    print(f"{'='*70}")
    for i, t in enumerate(bout):
        d = t.get('data', b'') or b''
        # Check if it's mostly zeros
        nonzero = sum(1 for b in d if b != 0)
        print(f"  BOUT[{i:2d}] t+{t['ts']:8.3f}s len={len(d):6d} nonzero_bytes={nonzero:5d} "
              f"first_32=[{d[:32].hex()}]")
        if len(d) <= 512 and nonzero > 0 and nonzero < 200:
            # Show all non-zero regions
            for off in range(0, len(d), 16):
                chunk = d[off:off+16]
                if any(b != 0 for b in chunk):
                    print(f"         @0x{off:03x}: {chunk.hex()}")


if __name__ == '__main__':
    main()
