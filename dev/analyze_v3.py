#!/usr/bin/env python3
"""Proper USB pcap analysis with correct USBPcap header parsing."""

import struct
import sys
from collections import defaultdict

XFER_TYPES = {0: 'ISO', 1: 'INT', 2: 'CTRL', 3: 'BULK'}

def read_pcap(path):
    with open(path, 'rb') as f:
        magic = struct.unpack('<I', f.read(4))[0]
        assert magic == 0xa1b2c3d4, f"Not LE pcap: 0x{magic:08x}"
        f.read(20)
        pkt_num = 0
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', hdr)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            pkt_num += 1
            yield pkt_num, ts_sec + ts_usec / 1e6, data

def parse_pkt(data):
    """Parse USBPcap header properly.

    Standard header (27 bytes):
      0: headerLen (u16)
      2: irpId (u64)
     10: status (u32) - USBD_STATUS
     14: function (u16) - URB function code
     16: info (u8) - bit0: 0=submit(PDO->FDO), 1=complete(FDO->PDO)
     17: bus (u16)
     19: device (u16)
     21: endpoint (u8) - includes direction bit (0x80 for IN)
     22: transfer (u8) - transfer type
     23: dataLength (u32)

    For control transfers (headerLen >= 36):
     27: stage (u8) - 0=setup, 1=data, 2=status
     28: setup[8] - only meaningful when stage==0 and info bit0==0 (submit)
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

    is_complete = bool(info & 1)  # bit 0: 0=submit, 1=complete
    ep_dir = 'IN' if (endpoint & 0x80) else 'OUT'
    ep_num = endpoint & 0x7F

    setup = None
    if xfer_type == 2 and hdr_len >= 36 and not is_complete:
        stage = data[27]
        if stage == 0:  # Setup stage
            setup_bytes = data[28:36]
            if len(setup_bytes) == 8:
                bmRT, bReq, wVal, wIdx, wLen = struct.unpack_from('<BBHHH', setup_bytes)
                setup = {'bmRT': bmRT, 'bReq': bReq, 'wVal': wVal, 'wIdx': wIdx, 'wLen': wLen}

    payload = data[hdr_len:hdr_len + data_len] if data_len > 0 else b''
    if len(payload) < data_len:
        payload = payload  # truncated

    return {
        'hdr_len': hdr_len, 'irp_id': irp_id, 'status': status,
        'function': function, 'is_complete': is_complete,
        'bus': bus, 'device': device, 'endpoint': endpoint,
        'ep_num': ep_num, 'ep_dir': ep_dir, 'xfer_type': xfer_type,
        'xfer_name': XFER_TYPES.get(xfer_type, '???'),
        'data_len': data_len, 'payload': payload, 'setup': setup,
    }

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else '/home/luca/win7/capture3200.pcap'

    first_ts = None
    all_pkts = []

    for pkt_num, ts, data in read_pcap(path):
        if first_ts is None:
            first_ts = ts
        p = parse_pkt(data)
        if p is None:
            continue
        p['pkt'] = pkt_num
        p['ts'] = ts - first_ts
        all_pkts.append(p)

    print(f"Total packets: {len(all_pkts)}")

    # Find scanner device (the one with bulk transfers)
    bulk_devs = set()
    for p in all_pkts:
        if p['xfer_type'] == 3:
            bulk_devs.add((p['bus'], p['device']))

    if not bulk_devs:
        print("No bulk transfers found!")
        return

    # Pick device with most bulk data
    dev_bytes = defaultdict(int)
    for p in all_pkts:
        if p['xfer_type'] == 3:
            dev_bytes[(p['bus'], p['device'])] += len(p['payload'])
    scanner = max(dev_bytes, key=dev_bytes.get)
    print(f"Scanner device: bus={scanner[0]}, device={scanner[1]}")

    pkts = [p for p in all_pkts if (p['bus'], p['device']) == scanner]
    print(f"Scanner packets: {len(pkts)}")

    # Separate submits and completions
    submits = [p for p in pkts if not p['is_complete']]
    completes = [p for p in pkts if p['is_complete']]
    print(f"Submits: {len(submits)}, Completions: {len(completes)}")

    # Pair by IRP ID
    submit_map = {}
    for p in submits:
        submit_map[p['irp_id']] = p

    transactions = []
    for c in completes:
        s = submit_map.get(c['irp_id'])
        if s is None:
            continue

        txn = {
            'ts': s['ts'],
            'pkt_s': s['pkt'],
            'pkt_c': c['pkt'],
            'xfer_type': s['xfer_type'],
            'xfer_name': s['xfer_name'],
            'endpoint': s['endpoint'],
            'ep_num': s['ep_num'],
            'ep_dir': s['ep_dir'],
            'status': c['status'],
            'setup': s.get('setup'),
        }

        # Data depends on direction
        if s['xfer_type'] == 2:  # CONTROL
            if s['setup'] and (s['setup']['bmRT'] & 0x80):
                # Control IN: data in completion
                txn['direction'] = 'IN'
                txn['data'] = c['payload']
            else:
                # Control OUT: data in submit
                txn['direction'] = 'OUT'
                txn['data'] = s['payload']
        elif s['xfer_type'] == 3:  # BULK
            if s['ep_dir'] == 'IN':
                txn['direction'] = 'IN'
                txn['data'] = c['payload']
            else:
                txn['direction'] = 'OUT'
                txn['data'] = s['payload']
        elif s['xfer_type'] == 1:  # INTERRUPT
            txn['direction'] = 'IN'
            txn['data'] = c['payload']

        transactions.append(txn)

    transactions.sort(key=lambda t: t['pkt_s'])
    print(f"Paired transactions: {len(transactions)}")

    # Categorize
    ctrl_txns = [t for t in transactions if t['xfer_type'] == 2]
    bulk_out_txns = [t for t in transactions if t['xfer_type'] == 3 and t['direction'] == 'OUT']
    bulk_in_txns = [t for t in transactions if t['xfer_type'] == 3 and t['direction'] == 'IN']
    int_txns = [t for t in transactions if t['xfer_type'] == 1]

    print(f"\nControl: {len(ctrl_txns)}, Bulk OUT: {len(bulk_out_txns)}, Bulk IN: {len(bulk_in_txns)}, Interrupt: {len(int_txns)}")

    total_bin = sum(len(t['data']) for t in bulk_in_txns)
    total_bout = sum(len(t['data']) for t in bulk_out_txns)
    print(f"Bulk IN total: {total_bin:,} bytes ({total_bin/1024/1024:.1f} MB)")
    print(f"Bulk OUT total: {total_bout:,} bytes ({total_bout/1024/1024:.1f} MB)")

    # Endpoint analysis
    print(f"\n{'='*70}")
    print("ENDPOINT BREAKDOWN")
    ep_info = defaultdict(lambda: {'count': 0, 'bytes': 0, 'types': set()})
    for t in transactions:
        key = f"EP 0x{t['endpoint']:02x} ({t['direction']})"
        ep_info[key]['count'] += 1
        ep_info[key]['bytes'] += len(t.get('data', b''))
        ep_info[key]['types'].add(t['xfer_name'])
    for k, v in sorted(ep_info.items()):
        print(f"  {k:25s}: {v['count']:6d} txns, {v['bytes']:>12,} bytes  types={v['types']}")

    # Show ALL control transfers
    print(f"\n{'='*70}")
    print(f"ALL CONTROL TRANSFERS ({len(ctrl_txns)})")
    print(f"{'='*70}")
    for t in ctrl_txns:
        s = t['setup']
        d = t['data'] or b''
        if s:
            data_hex = d[:32].hex() if d else ''
            if len(d) > 32:
                data_hex += f'... ({len(d)}B)'
            print(f"  #{t['pkt_s']:5d} t+{t['ts']:8.3f}s CTRL {t['direction']:3s} "
                  f"bmRT=0x{s['bmRT']:02x} bReq=0x{s['bReq']:02x} wVal=0x{s['wVal']:04x} "
                  f"wIdx=0x{s['wIdx']:04x} wLen={s['wLen']:5d} [{data_hex}]")
        else:
            print(f"  #{t['pkt_s']:5d} t+{t['ts']:8.3f}s CTRL {t['direction']:3s} (no setup)")

    # Show ALL bulk OUT transfers
    print(f"\n{'='*70}")
    print(f"ALL BULK OUT TRANSFERS ({len(bulk_out_txns)})")
    print(f"{'='*70}")
    for t in bulk_out_txns:
        d = t['data'] or b''
        data_hex = d[:64].hex() if d else ''
        if len(d) > 64:
            data_hex += f'... ({len(d)}B)'
        print(f"  #{t['pkt_s']:5d} t+{t['ts']:8.3f}s BULK OUT EP 0x{t['endpoint']:02x} "
              f"len={len(d):6d} [{data_hex}]")

    # Show bulk IN summary
    print(f"\n{'='*70}")
    print(f"BULK IN TRANSFERS ({len(bulk_in_txns)})")
    print(f"{'='*70}")
    if bulk_in_txns:
        # Show first 10
        for t in bulk_in_txns[:10]:
            d = t['data'] or b''
            print(f"  #{t['pkt_s']:5d} t+{t['ts']:8.3f}s BULK IN  EP 0x{t['endpoint']:02x} "
                  f"len={len(d):6d} [{d[:16].hex() if d else ''}...]")
        if len(bulk_in_txns) > 10:
            print(f"  ... ({len(bulk_in_txns) - 10} more)")
        # Show last 5
        for t in bulk_in_txns[-5:]:
            d = t['data'] or b''
            print(f"  #{t['pkt_s']:5d} t+{t['ts']:8.3f}s BULK IN  EP 0x{t['endpoint']:02x} "
                  f"len={len(d):6d} [{d[:16].hex() if d else ''}...]")

    # Show interrupt summary
    print(f"\n{'='*70}")
    print(f"INTERRUPT TRANSFERS ({len(int_txns)})")
    print(f"{'='*70}")
    if int_txns:
        print(f"  First: #{int_txns[0]['pkt_s']} t+{int_txns[0]['ts']:.3f}s")
        print(f"  Last:  #{int_txns[-1]['pkt_s']} t+{int_txns[-1]['ts']:.3f}s")
        for t in int_txns[:5]:
            d = t['data'] or b''
            print(f"  #{t['pkt_s']:5d} t+{t['ts']:8.3f}s INT IN EP 0x{t['endpoint']:02x} [{d.hex()}]")
        if len(int_txns) > 5:
            print(f"  ... ({len(int_txns) - 5} more)")

    # =====================================================================
    # Now build the FULL ordered replay sequence
    # =====================================================================
    print(f"\n{'='*70}")
    print(f"FULL ORDERED REPLAY SEQUENCE")
    print(f"{'='*70}")

    # Filter out descriptor reads and configuration (function 0, 11 etc)
    # We want vendor-specific control transfers + bulk + interrupt
    replay_txns = []
    for t in transactions:
        # Skip standard USB enumeration (GET_DESCRIPTOR, SET_CONFIGURATION)
        if t['xfer_type'] == 2 and t['setup']:
            bmRT = t['setup']['bmRT']
            bReq = t['setup']['bReq']
            # Standard requests: bmRequestType & 0x60 == 0x00
            if (bmRT & 0x60) == 0x00:
                # Standard USB requests - skip (handled by kernel)
                continue
            # Vendor requests: bmRequestType & 0x60 == 0x40
            replay_txns.append(t)
        elif t['xfer_type'] == 2:
            # Control without setup - skip enumeration completions
            continue
        else:
            replay_txns.append(t)

    print(f"Replay transactions (excl. enumeration): {len(replay_txns)}")

    # Show them all
    for i, t in enumerate(replay_txns):
        d = t.get('data', b'') or b''
        if t['xfer_type'] == 2:  # CTRL
            s = t['setup']
            data_hex = d[:32].hex() if d else ''
            if len(d) > 32:
                data_hex += f'...({len(d)}B)'
            print(f"  [{i:4d}] #{t['pkt_s']:5d} t+{t['ts']:8.3f}s CTRL {t['direction']:3s} "
                  f"0x{s['bmRT']:02x}/0x{s['bReq']:02x} val=0x{s['wVal']:04x} idx=0x{s['wIdx']:04x} "
                  f"len={s['wLen']:5d} [{data_hex}]")
        elif t['xfer_type'] == 3:  # BULK
            data_hex = d[:32].hex() if d else ''
            if len(d) > 32:
                data_hex += f'...({len(d)}B)'
            elif t['direction'] == 'IN':
                data_hex = f'{len(d)} bytes'
            print(f"  [{i:4d}] #{t['pkt_s']:5d} t+{t['ts']:8.3f}s BULK {t['direction']:3s} "
                  f"EP 0x{t['endpoint']:02x} len={len(d):6d} [{data_hex}]")
        elif t['xfer_type'] == 1:  # INT
            print(f"  [{i:4d}] #{t['pkt_s']:5d} t+{t['ts']:8.3f}s INT  IN  "
                  f"EP 0x{t['endpoint']:02x} [{d.hex()}]")

        if i > 50:
            remaining = len(replay_txns) - i - 1
            if remaining > 20:
                print(f"  ... {remaining} more ...")
                # Show last 20
                for j, t2 in enumerate(replay_txns[-20:]):
                    d2 = t2.get('data', b'') or b''
                    idx = len(replay_txns) - 20 + j
                    if t2['xfer_type'] == 3 and t2['direction'] == 'IN':
                        print(f"  [{idx:4d}] #{t2['pkt_s']:5d} t+{t2['ts']:8.3f}s BULK IN  "
                              f"EP 0x{t2['endpoint']:02x} len={len(d2):6d}")
                    elif t2['xfer_type'] == 2 and t2['setup']:
                        s2 = t2['setup']
                        dh = d2[:32].hex() if d2 else ''
                        print(f"  [{idx:4d}] #{t2['pkt_s']:5d} t+{t2['ts']:8.3f}s CTRL {t2['direction']:3s} "
                              f"0x{s2['bmRT']:02x}/0x{s2['bReq']:02x} val=0x{s2['wVal']:04x} [{dh}]")
                    else:
                        print(f"  [{idx:4d}] #{t2['pkt_s']:5d} t+{t2['ts']:8.3f}s {t2['xfer_name']} "
                              f"{t2['direction']} len={len(d2)}")
                break


if __name__ == '__main__':
    main()
