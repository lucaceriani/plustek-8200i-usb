#!/usr/bin/env python3
"""Final analysis - proper IRP pairing with sequential matching."""

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
    ep_dir = 'IN' if (endpoint & 0x80) else 'OUT'
    ep_num = endpoint & 0x7F

    setup = None
    if xfer_type == 2 and hdr_len >= 36 and not is_complete:
        stage = data[27]
        if stage == 0 and len(data) >= 36:
            bmRT, bReq, wVal, wIdx, wLen = struct.unpack_from('<BBHHH', data, 28)
            setup = (bmRT, bReq, wVal, wIdx, wLen)

    payload = data[hdr_len:hdr_len + data_len] if data_len > 0 else b''

    return {
        'hdr_len': hdr_len, 'irp_id': irp_id, 'status': status,
        'function': function, 'is_complete': is_complete,
        'bus': bus, 'device': device, 'endpoint': endpoint,
        'ep_num': ep_num, 'ep_dir': ep_dir, 'xfer_type': xfer_type,
        'data_len': data_len, 'payload': payload, 'setup': setup,
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

    # Filter to scanner device (bus=1, dev=2 based on prior analysis)
    scanner_pkts = [p for p in pkts if p['bus'] == 1 and p['device'] == 2]
    print(f"Scanner packets: {len(scanner_pkts)}")

    # Pair submits with completions sequentially per IRP ID
    # IRP IDs get reused, so we need a queue per IRP ID
    pending = {}  # irp_id -> submit packet (most recent unpaired)
    transactions = []

    for p in scanner_pkts:
        if not p['is_complete']:
            # Submit - store it
            pending[p['irp_id']] = p
        else:
            # Completion - pair with pending submit
            s = pending.pop(p['irp_id'], None)
            if s is None:
                continue  # orphan completion

            xfer_type = s['xfer_type']
            endpoint = s['endpoint']

            txn = {
                'ts': s['ts'],
                'pkt_s': s['pkt'],
                'pkt_c': p['pkt'],
                'xfer_type': xfer_type,
                'endpoint': endpoint,
                'ep_num': s['ep_num'],
                'ep_dir': s['ep_dir'],
                'status': p['status'],
                'function': s['function'],
            }

            if xfer_type == 2:  # CONTROL
                txn['setup'] = s['setup']
                if s['setup'] and (s['setup'][0] & 0x80):
                    # Device-to-host: data in completion
                    txn['direction'] = 'IN'
                    txn['data'] = p['payload']
                else:
                    # Host-to-device: data in submit
                    txn['direction'] = 'OUT'
                    txn['data'] = s['payload']
            elif xfer_type == 3:  # BULK
                if s['ep_dir'] == 'IN':
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

    # Categorize
    ctrl = [t for t in transactions if t['xfer_type'] == 2]
    bout = [t for t in transactions if t['xfer_type'] == 3 and t['direction'] == 'OUT']
    bin_ = [t for t in transactions if t['xfer_type'] == 3 and t['direction'] == 'IN']
    intr = [t for t in transactions if t['xfer_type'] == 1]

    total_bin = sum(len(t['data']) for t in bin_)
    total_bout = sum(len(t['data']) for t in bout)

    print(f"Control: {len(ctrl)}, Bulk OUT: {len(bout)}, Bulk IN: {len(bin_)}, Interrupt: {len(intr)}")
    print(f"Bulk IN: {total_bin:,} bytes ({total_bin/1024/1024:.1f} MB)")
    print(f"Bulk OUT: {total_bout:,} bytes ({total_bout/1024/1024:.1f} KB)")

    # Endpoint breakdown
    print(f"\n{'='*70}")
    print("ENDPOINT USAGE")
    ep_stats = defaultdict(lambda: {'count': 0, 'bytes': 0})
    for t in transactions:
        k = f"EP 0x{t['endpoint']:02x} {t['direction']}"
        ep_stats[k]['count'] += 1
        ep_stats[k]['bytes'] += len(t.get('data', b''))
    for k, v in sorted(ep_stats.items()):
        print(f"  {k:25s} {v['count']:6d} txns  {v['bytes']:>12,} bytes")

    # ===== Show all control transfers with setup =====
    ctrl_with_setup = [t for t in ctrl if t.get('setup')]
    ctrl_no_setup = [t for t in ctrl if not t.get('setup')]
    print(f"\n{'='*70}")
    print(f"CONTROL WITH SETUP: {len(ctrl_with_setup)}")
    print(f"CONTROL WITHOUT SETUP: {len(ctrl_no_setup)}")
    print(f"{'='*70}")

    for t in ctrl_with_setup:
        bmRT, bReq, wVal, wIdx, wLen = t['setup']
        d = t['data'] or b''
        dh = d[:48].hex() if d else ''
        if len(d) > 48:
            dh += f'...({len(d)}B)'
        req_type = 'STD' if (bmRT & 0x60) == 0 else 'VND' if (bmRT & 0x60) == 0x40 else 'CLS'
        print(f"  #{t['pkt_s']:5d} t+{t['ts']:8.3f}s {req_type} {t['direction']:3s} "
              f"bmRT=0x{bmRT:02x} bReq=0x{bReq:02x} wVal=0x{wVal:04x} wIdx=0x{wIdx:04x} "
              f"wLen={wLen:5d} [{dh}]")

    # ===== Control without setup - show first few =====
    if ctrl_no_setup:
        print(f"\nControl without setup (first 10):")
        for t in ctrl_no_setup[:10]:
            d = t['data'] or b''
            print(f"  #{t['pkt_s']:5d} t+{t['ts']:8.3f}s {t['direction']:3s} func={t['function']:3d} "
                  f"len={len(d)} [{d[:16].hex() if d else ''}]")

    # ===== ALL BULK OUT =====
    print(f"\n{'='*70}")
    print(f"ALL BULK OUT TRANSFERS ({len(bout)})")
    print(f"{'='*70}")
    for i, t in enumerate(bout):
        d = t['data'] or b''
        dh = d[:64].hex() if d else ''
        if len(d) > 64:
            dh += f'...({len(d)}B)'
        print(f"  [{i:3d}] #{t['pkt_s']:5d} t+{t['ts']:8.3f}s EP 0x{t['endpoint']:02x} "
              f"len={len(d):6d} [{dh}]")

    # ===== BULK IN summary =====
    print(f"\n{'='*70}")
    print(f"BULK IN TRANSFERS ({len(bin_)})")
    print(f"{'='*70}")
    # Group by size
    size_counts = defaultdict(int)
    for t in bin_:
        size_counts[len(t['data'])] += 1
    print("Size distribution:")
    for sz, cnt in sorted(size_counts.items()):
        print(f"  {sz:6d} bytes: {cnt:5d} transfers")

    if bin_:
        print(f"\nFirst bulk IN: #{bin_[0]['pkt_s']} t+{bin_[0]['ts']:.3f}s")
        print(f"Last bulk IN:  #{bin_[-1]['pkt_s']} t+{bin_[-1]['ts']:.3f}s")
        print("\nFirst 5:")
        for t in bin_[:5]:
            d = t['data']
            print(f"  #{t['pkt_s']:5d} t+{t['ts']:.3f}s len={len(d):6d} [{d[:16].hex()}...]")

    # ===== Build replay sequence =====
    # For replay we need: vendor control transfers + bulk OUT + bulk IN reads
    # Skip: standard USB enumeration, interrupts
    print(f"\n{'='*70}")
    print(f"REPLAY SEQUENCE (vendor ctrl + bulk)")
    print(f"{'='*70}")

    replay = []
    for t in transactions:
        if t['xfer_type'] == 2:  # CTRL
            if t.get('setup'):
                bmRT = t['setup'][0]
                if (bmRT & 0x60) == 0x00:
                    continue  # Standard USB request - skip
            else:
                continue  # No setup - skip
            replay.append(t)
        elif t['xfer_type'] == 3:  # BULK
            replay.append(t)
        # Skip interrupts

    replay.sort(key=lambda t: t['pkt_s'])
    print(f"Total replay operations: {len(replay)}")

    # Identify phases
    first_bin = None
    last_bin = None
    for t in replay:
        if t['xfer_type'] == 3 and t['direction'] == 'IN':
            if first_bin is None:
                first_bin = t
            last_bin = t

    if first_bin:
        print(f"First bulk IN at: t+{first_bin['ts']:.3f}s (pkt #{first_bin['pkt_s']})")
        print(f"Last bulk IN at:  t+{last_bin['ts']:.3f}s (pkt #{last_bin['pkt_s']})")

    # Print the full sequence with phase markers
    phase = 'INIT'
    for i, t in enumerate(replay):
        if first_bin and t['ts'] >= first_bin['ts'] - 5 and phase == 'INIT':
            phase = 'SCAN'
            print(f"\n  --- PHASE: SCAN (calibration + data) ---")
        if last_bin and t['ts'] > last_bin['ts'] + 1 and phase == 'SCAN':
            phase = 'CLEANUP'
            print(f"\n  --- PHASE: CLEANUP ---")

        d = t.get('data', b'') or b''

        if t['xfer_type'] == 2:  # CTRL
            s = t['setup']
            dh = d[:32].hex() if d else ''
            if len(d) > 32:
                dh += f'...({len(d)}B)'
            print(f"  [{i:4d}] t+{t['ts']:8.3f}s CTRL {t['direction']:3s} "
                  f"0x{s[0]:02x}/0x{s[1]:02x} val=0x{s[2]:04x} idx=0x{s[3]:04x} "
                  f"len={s[4]:5d} [{dh}]")
        elif t['xfer_type'] == 3:
            if t['direction'] == 'OUT':
                dh = d[:32].hex() if d else ''
                if len(d) > 32:
                    dh += f'...({len(d)}B)'
                print(f"  [{i:4d}] t+{t['ts']:8.3f}s BOUT EP 0x{t['endpoint']:02x} "
                      f"len={len(d):6d} [{dh}]")
            else:
                # Only show first/last few bulk INs to avoid spam
                if i < 20 or (last_bin and t['ts'] > last_bin['ts'] - 2):
                    print(f"  [{i:4d}] t+{t['ts']:8.3f}s BIN  EP 0x{t['endpoint']:02x} "
                          f"len={len(d):6d}")
                elif i == 20:
                    remaining_bin = sum(1 for t2 in replay[i:] if t2['xfer_type'] == 3 and t2['direction'] == 'IN')
                    print(f"        ... {remaining_bin} bulk IN transfers ...")

    # ===== Save replay data for the scan script =====
    print(f"\n{'='*70}")
    print(f"SAVING REPLAY DATA")
    print(f"{'='*70}")

    # Build operation list for replay
    ops_init = []
    ops_scan = []
    ops_data_reads = []  # just the read sizes in order
    ops_cleanup = []
    total_expected_read = 0

    data_phase_started = False
    data_phase_ended = False

    for t in replay:
        is_before_data = first_bin is None or t['ts'] < first_bin['ts'] - 5
        is_after_data = last_bin is not None and t['ts'] > last_bin['ts'] + 1
        is_data = not is_before_data and not is_after_data

        d = t.get('data', b'') or b''

        if t['xfer_type'] == 2:  # CTRL
            s = t['setup']
            if t['direction'] == 'OUT':
                op = ('CW', s[0], s[1], s[2], s[3], bytes(d))
            else:
                op = ('CR', s[0], s[1], s[2], s[3], s[4])

            if is_before_data:
                ops_init.append(op)
            elif is_after_data:
                ops_cleanup.append(op)
            else:
                ops_scan.append(op)

        elif t['xfer_type'] == 3:
            if t['direction'] == 'OUT':
                op = ('BW', t['endpoint'], bytes(d))
                if is_before_data:
                    ops_init.append(op)
                elif is_after_data:
                    ops_cleanup.append(op)
                else:
                    ops_scan.append(op)
            else:
                # Bulk IN - record the read size
                ops_data_reads.append(len(d))
                total_expected_read += len(d)

    print(f"  INIT ops:     {len(ops_init)}")
    print(f"  SCAN ops:     {len(ops_scan)}")
    print(f"  DATA reads:   {len(ops_data_reads)}")
    print(f"  CLEANUP ops:  {len(ops_cleanup)}")
    print(f"  Total expected read: {total_expected_read:,} bytes ({total_expected_read/1024/1024:.1f} MB)")

    # Print init ops detail
    print(f"\n  INIT ops detail:")
    for i, op in enumerate(ops_init):
        print(f"    [{i}] {op[0]} ", end='')
        if op[0] in ('CW', 'CR'):
            print(f"bmRT=0x{op[1]:02x} bReq=0x{op[2]:02x} wVal=0x{op[3]:04x} wIdx=0x{op[4]:04x}", end='')
            if op[0] == 'CW':
                print(f" data={op[5][:32].hex()}{'...' if len(op[5]) > 32 else ''}", end='')
            else:
                print(f" wLen={op[5]}", end='')
        elif op[0] == 'BW':
            print(f"EP 0x{op[1]:02x} len={len(op[2])} data={op[2][:32].hex()}{'...' if len(op[2]) > 32 else ''}", end='')
        print()

    print(f"\n  SCAN ops detail:")
    for i, op in enumerate(ops_scan):
        print(f"    [{i}] {op[0]} ", end='')
        if op[0] in ('CW', 'CR'):
            print(f"bmRT=0x{op[1]:02x} bReq=0x{op[2]:02x} wVal=0x{op[3]:04x} wIdx=0x{op[4]:04x}", end='')
            if op[0] == 'CW':
                print(f" data={op[5][:32].hex()}{'...' if len(op[5]) > 32 else ''}", end='')
            else:
                print(f" wLen={op[5]}", end='')
        elif op[0] == 'BW':
            print(f"EP 0x{op[1]:02x} len={len(op[2])} data={op[2][:32].hex()}{'...' if len(op[2]) > 32 else ''}", end='')
        print()

    print(f"\n  CLEANUP ops detail:")
    for i, op in enumerate(ops_cleanup):
        print(f"    [{i}] {op[0]} ", end='')
        if op[0] in ('CW', 'CR'):
            print(f"bmRT=0x{op[1]:02x} bReq=0x{op[2]:02x} wVal=0x{op[3]:04x} wIdx=0x{op[4]:04x}", end='')
            if op[0] == 'CW':
                print(f" data={op[5][:32].hex()}{'...' if len(op[5]) > 32 else ''}", end='')
            else:
                print(f" wLen={op[5]}", end='')
        elif op[0] == 'BW':
            print(f"EP 0x{op[1]:02x} len={len(op[2])} data={op[2][:32].hex()}{'...' if len(op[2]) > 32 else ''}", end='')
        print()

    print(f"\n  DATA read sizes (first 20):")
    for i, sz in enumerate(ops_data_reads[:20]):
        print(f"    [{i}] read {sz} bytes")
    if len(ops_data_reads) > 20:
        print(f"    ... {len(ops_data_reads) - 20} more reads ...")

    # Save for the scan script
    replay_data = {
        'init': ops_init,
        'scan': ops_scan,
        'data_read_sizes': ops_data_reads,
        'cleanup': ops_cleanup,
        'total_expected_bytes': total_expected_read,
        'bulk_in_ep': 0x81,
        'bulk_out_ep': 0x02,
    }

    out_path = path.replace('.pcap', '_replay.bin')
    blob = pickle.dumps(replay_data)
    compressed = zlib.compress(blob, 9)
    with open(out_path, 'wb') as f:
        f.write(compressed)
    print(f"\n  Saved replay data to: {out_path}")
    print(f"  Size: {len(compressed):,} bytes (compressed from {len(blob):,})")


if __name__ == '__main__':
    main()
