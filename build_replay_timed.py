#!/usr/bin/env python3
"""Rebuild replay data WITH timestamps from the capture."""

import struct
import pickle
import zlib

def read_pcap(path):
    with open(path, 'rb') as f:
        f.read(24)
        pkt_num = 0
        while True:
            hdr = f.read(16)
            if len(hdr) < 16: break
            ts_sec, ts_usec, incl_len, _ = struct.unpack('<IIII', hdr)
            data = f.read(incl_len)
            if len(data) < incl_len: break
            pkt_num += 1
            yield pkt_num, ts_sec + ts_usec / 1e6, data

def parse(data):
    if len(data) < 27: return None
    hdr_len = struct.unpack_from('<H', data, 0)[0]
    irp_id = struct.unpack_from('<Q', data, 2)[0]
    info = data[16]
    bus = struct.unpack_from('<H', data, 17)[0]
    device = struct.unpack_from('<H', data, 19)[0]
    endpoint = data[21]
    xfer_type = data[22]
    data_len = struct.unpack_from('<I', data, 23)[0]
    is_complete = bool(info & 1)
    payload = data[hdr_len:hdr_len + data_len] if data_len > 0 else b''

    setup = None
    ctrl_data = b''
    if xfer_type == 2 and not is_complete and data_len >= 8:
        if hdr_len >= 36:
            stage = data[27]
            if stage == 0 and len(data) >= 36:
                setup = struct.unpack_from('<BBHHH', data, 28)
                ctrl_data = payload
        else:
            bmRT = payload[0]
            if (bmRT & 0x60) in (0x00, 0x20, 0x40):
                setup = struct.unpack_from('<BBHHH', payload, 0)
                ctrl_data = payload[8:]

    return {
        'irp_id': irp_id, 'is_complete': is_complete, 'bus': bus, 'device': device,
        'endpoint': endpoint, 'xfer_type': xfer_type, 'data_len': data_len,
        'payload': payload, 'setup': setup, 'ctrl_data': ctrl_data,
    }

def main():
    path = '/home/luca/win7/capture3200.pcap'
    first_ts = None
    pending = {}
    transactions = []

    for pkt_num, ts, data in read_pcap(path):
        if first_ts is None: first_ts = ts
        p = parse(data)
        if not p or p['bus'] != 1 or p['device'] != 2: continue
        p['ts'] = ts - first_ts

        if not p['is_complete']:
            pending[p['irp_id']] = p
        else:
            s = pending.pop(p['irp_id'], None)
            if not s: continue

            xtype = s['xfer_type']
            ep = s['endpoint']
            ep_dir = 'IN' if (ep & 0x80) else 'OUT'

            txn = {
                'ts': s['ts'],
                'xfer_type': xtype,
                'endpoint': ep,
                'status': struct.unpack_from('<I', data, 10)[0] if len(data) >= 14 else 0,
            }

            if xtype == 2:  # CONTROL
                txn['setup'] = s.get('setup')
                if s.get('setup') and (s['setup'][0] & 0x80):
                    txn['direction'] = 'IN'
                    txn['data'] = p['payload']
                else:
                    txn['direction'] = 'OUT'
                    txn['data'] = s.get('ctrl_data', b'')
            elif xtype == 3:  # BULK
                if ep_dir == 'IN':
                    txn['direction'] = 'IN'
                    txn['data'] = p['payload']
                else:
                    txn['direction'] = 'OUT'
                    txn['data'] = s['payload']
            else:
                continue

            transactions.append(txn)

    # Build replay ops with timestamps
    replay = []
    for t in transactions:
        if t['xfer_type'] == 2:
            if not t.get('setup'): continue
            if (t['setup'][0] & 0x60) != 0x40: continue
            s = t['setup']
            d = t.get('data', b'') or b''
            if t['direction'] == 'OUT':
                replay.append((t['ts'], ('CW', s[0], s[1], s[2], s[3], bytes(d))))
            else:
                replay.append((t['ts'], ('CR', s[0], s[1], s[2], s[3], s[4])))
        elif t['xfer_type'] == 3:
            d = t.get('data', b'') or b''
            if t['direction'] == 'OUT':
                replay.append((t['ts'], ('BW', t['endpoint'], bytes(d))))
            else:
                replay.append((t['ts'], ('BR', t['endpoint'], len(d))))

    replay.sort(key=lambda x: x[0])

    # Normalize timestamps relative to the first op
    t0 = replay[0][0]
    replay = [(ts - t0, op) for ts, op in replay]

    print(f"Total replay ops: {len(replay)}")
    print(f"Duration: {replay[-1][0]:.1f}s")

    # Find phase boundaries
    first_br_ts = None
    last_br_ts = None
    last_bw_ts = None
    last_bw_idx = None

    for i, (ts, op) in enumerate(replay):
        if op[0] == 'BR':
            if first_br_ts is None:
                first_br_ts = ts
            last_br_ts = ts
        if op[0] == 'BW':
            last_bw_ts = ts
            last_bw_idx = i

    # Find first BR after last BW
    first_data_br_idx = None
    for i, (ts, op) in enumerate(replay):
        if i > last_bw_idx and op[0] == 'BR':
            first_data_br_idx = i
            break

    # Find last BR
    last_data_br_idx = None
    for i in range(len(replay) - 1, -1, -1):
        if replay[i][1][0] == 'BR':
            last_data_br_idx = i
            break

    print(f"Last BW at index {last_bw_idx}, ts={last_bw_ts:.3f}s")
    print(f"First data BR at index {first_data_br_idx}, ts={replay[first_data_br_idx][0]:.3f}s")
    print(f"Last data BR at index {last_data_br_idx}, ts={replay[last_data_br_idx][0]:.3f}s")

    # Split into phases
    setup_ops = replay[:first_data_br_idx]   # everything before pure BR block
    data_br_ops = replay[first_data_br_idx:last_data_br_idx + 1]  # pure BR block
    cleanup_ops = replay[last_data_br_idx + 1:]  # after BR block

    total_data = sum(op[2] for _, op in data_br_ops if op[0] == 'BR')

    print(f"\nSetup ops: {len(setup_ops)} (t={setup_ops[0][0]:.1f}s - t={setup_ops[-1][0]:.1f}s)")
    print(f"Data BRs: {len(data_br_ops)} ({total_data:,} bytes)")
    print(f"Cleanup ops: {len(cleanup_ops)}")

    # Show timing gaps in setup phase
    print("\nSetup timing gaps > 0.5s:")
    for i in range(1, len(setup_ops)):
        gap = setup_ops[i][0] - setup_ops[i-1][0]
        if gap > 0.5:
            print(f"  Between [{i-1}] t={setup_ops[i-1][0]:.3f}s and [{i}] t={setup_ops[i][0]:.3f}s: {gap:.1f}s gap")

    # Save
    replay_data = {
        'setup_ops': setup_ops,      # list of (timestamp, op_tuple)
        'cleanup_ops': cleanup_ops,   # list of (timestamp, op_tuple)
        'total_data_bytes': total_data,
        'bulk_in_ep': 0x81,
        'bulk_out_ep': 0x02,
    }

    out_path = '/home/luca/win7/capture3200_timed_replay.pkl'
    blob = pickle.dumps(replay_data)
    compressed = zlib.compress(blob, 9)
    with open(out_path, 'wb') as f:
        f.write(compressed)
    print(f"\nSaved: {out_path} ({len(compressed):,} bytes)")


if __name__ == '__main__':
    main()
