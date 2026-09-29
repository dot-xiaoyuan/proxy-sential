"""Inspect captured packets and parser output without inventing endpoint counts."""
import collections
import json
import pathlib
import struct
import sys

path = pathlib.Path(sys.argv[1])
ttls = collections.Counter()
packets = 0
with (path/'nat.pcap').open('rb') as stream:
    header = stream.read(24)
    endian = {b'\xd4\xc3\xb2\xa1':'<', b'\xa1\xb2\xc3\xd4':'>'}.get(header[:4])
    if endian is None or struct.unpack(endian+'I', header[20:24])[0] != 1:
        raise ValueError('expected Ethernet microsecond PCAP')
    while True:
        record = stream.read(16)
        if not record:
            break
        if len(record) != 16:
            raise ValueError('truncated PCAP record')
        size = struct.unpack(endian+'IIII', record)[2]
        if size > 16*1024*1024:
            raise ValueError('oversized PCAP record')
        frame = stream.read(size)
        if len(frame) != size:
            raise ValueError('truncated PCAP packet')
        packets += 1
        if len(frame) >= 34 and frame[12:14] == b'\x08\x00' and frame[26:30] == bytes([172,29,250,2]):
            ttls[frame[22]] += 1

types = collections.Counter()
uas, fingerprints = set(), set()
with (path/'parsed/eve.json').open() as stream:
    for line in stream:
        item = json.loads(line)
        types[item['event_type']] += 1
        if item.get('src_ip') != '172.29.250.2':
            continue
        http = item.get('http', {})
        if http.get('http_user_agent'):
            uas.add(http['http_user_agent'])
        ja3 = item.get('tls', {}).get('ja3', {}).get('hash')
        if ja3:
            fingerprints.add(ja3)
clients = [json.loads((path/(profile+'.json')).read_text()) for profile in ('android','windows')]
scenario = json.loads((path/'scenario.json').read_text())['scenario']
expected = {'heterogeneous': (2,2,2), 'homogeneous': (1,1,1), 'single': (1,1,1), 'multi_browser': (1,2,2)}[scenario]
observed = (len(ttls), len(uas), len(fingerprints))
capture_loss_free = '0 packets dropped by kernel' in (path/'capture.log').read_text()
result = {'scenario':scenario, 'capture_loss_free':capture_loss_free,'label':'isolated NAT topology with programmed OS/TLS profiles', 'client_results':clients, 'captured_packets':packets, 'outbound_nat_ttl_counts':dict(ttls), 'http_user_agents':sorted(uas), 'tls_ja3_hashes':sorted(fingerprints), 'parser_event_types':dict(types), 'acceptance': all(c['failed']==0 for c in clients) and observed == expected and capture_loss_free, 'limitation':'packet transport and parsing validation only; not identity attribution, policy execution, real-campus accuracy or physical device count inference'}
print(json.dumps(result, indent=2))
if not result['acceptance']:
    sys.exit(1)
