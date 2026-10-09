#!/usr/bin/env python3
"""Generate controlled CONNECT header-boundary PCAPs without opening sockets."""
import json
from pathlib import Path
import socket
import struct
import sys

folder = Path(sys.argv[1])
folder.mkdir(mode=0o700)
out = (folder / 'replay.pcap').open('wb')
out.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
clock = 1790916000.0
cases = []


def packet(src, dst, sport, dport, seq, ack, flags, payload=b''):
    global clock
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    data = b'\0' * 12 + b'\x08\x00' + ip + tcp
    sec = int(clock)
    out.write(struct.pack('<IIII', sec, int((clock-sec)*1e6), len(data), len(data)) + data)
    clock += .01


def flow(name, messages, expected, fragment=False, reset=False, retransmit=False, gap=False):
    a, b, sp, port, x, y = '192.0.2.1', '198.51.100.1', 41000 + len(cases), 3128, 1000, 2000
    packet(a, b, sp, port, x, 0, 2); x += 1
    packet(b, a, port, sp, y, x, 18); y += 1
    packet(a, b, sp, port, x, y, 16)
    for server, data in messages:
        for chunk in ([bytes([byte]) for byte in data] if fragment else [data]):
            if server:
                packet(b, a, port, sp, y, x, 24, chunk)
                if retransmit:
                    packet(b, a, port, sp, y, x, 24, chunk)
                y += len(chunk)
            else:
                packet(a, b, sp, port, x, y, 24, chunk)
                if retransmit:
                    packet(a, b, sp, port, x, y, 24, chunk)
                x += len(chunk)
        if gap and not server:
            x += 8  # Acknowledged bytes absent from the capture, never fabricated.
    if reset:
        packet(b, a, port, sp, y, x, 20)
    else:
        packet(a, b, sp, port, x, y, 17)
        packet(b, a, port, sp, y, x+1, 17)
    cases.append({'name': name, 'client_port': sp, 'server_port': port, 'expected': expected})


request = b'CONNECT target.invalid:443 HTTP/1.1\r\nHost: target.invalid:443\r\n\r\n'
success = b'HTTP/1.1 200 Connection Established\r\n\r\n'
for fragment in (False, True):
    suffix = '-one-byte' if fragment else '-whole'
    flow('complete'+suffix, [(False, request), (True, success)], ['success'], fragment)
    flow('truncated-response-line'+suffix, [(False, request), (True, success[:12])], ['incomplete'], fragment)
    flow('response-line-only'+suffix, [(False, request), (True, success[:-2])], ['incomplete'], fragment)
    flow('truncated-response-header'+suffix, [(False, request), (True, success[:-2]+b'X-Fixture: partial')], ['incomplete'], fragment)
    flow('request-line-only'+suffix, [(False, request.split(b'\r\n')[0]+b'\r\n'), (True, success)], ['incomplete'], fragment)
    flow('truncated-request-header'+suffix, [(False, request[:-2]), (True, success)], ['incomplete'], fragment)
    flow('interim-then-complete'+suffix, [(False, request), (True, b'HTTP/1.1 100 Continue\r\n\r\n'), (True, success)], ['success'], fragment)
    flow('interim-then-truncated'+suffix, [(False, request), (True, b'HTTP/1.1 100 Continue\r\n\r\n'), (True, success[:-2])], ['incomplete'], fragment)
for code in (201, 204, 206, 299):
    flow('success-status-'+str(code), [(False, request), (True, ('HTTP/1.1 '+str(code)+' Established\r\n\r\n').encode())], ['success'])
flow('reset-after-response-line', [(False, request), (True, success[:-2])], ['incomplete'], reset=True)
flow('reset-after-complete-response', [(False, request), (True, success)], ['success'], reset=True)
flow('valid-retransmissions', [(False, request), (True, success)], ['success'], retransmit=True)
flow('truncated-retransmissions', [(False, request), (True, success[:-2])], ['incomplete'], retransmit=True)
flow('reply-before-request-headers', [(False, request[:-2]), (True, success), (False, b'\r\n')], ['incomplete'])
flow('reply-starts-before-request-headers', [(False, request[:-2]), (True, success[:-2]), (False, b'\r\n'), (True, b'\r\n')], ['incomplete'])
flow('request-capture-gap', [(False, request[:-2]), (False, b'\r\n'), (True, success)], ['incomplete'], gap=True)
flow('length-header-ignored', [(False, request), (True, success[:-2]+b'Content-Length: 123\r\n\r\n')], ['success'])
flow('transfer-header-ignored', [(False, request), (True, success[:-2]+b'Transfer-Encoding: chunked\r\n\r\n')], ['success'])
flow('denied-complete', [(False, request), (True, b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n')], ['failed'])
flow('denied-truncated', [(False, request), (True, b'HTTP/1.1 403 Forbidden\r\n')], ['incomplete'])
flow('retry-after-denial', [(False, request), (True, b'HTTP/1.1 407 Auth\r\nContent-Length: 0\r\n\r\n'), (False, request), (True, success)], ['failed', 'success'])
flow('interim-and-success-coalesced', [(False, request), (True, b'HTTP/1.1 100 Continue\r\n\r\n'+success)], ['success'])
flow('success-and-tunnel-coalesced', [(False, request), (True, success+b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')], ['success'])
flow('failure-body-truncated-after-headers', [(False, request), (True, b'HTTP/1.1 403 Forbidden\r\nContent-Length: 8\r\n\r\nabc')], ['failed'])
flow('ordinary-get', [(False, b'GET / HTTP/1.1\r\nHost: target.invalid\r\n\r\n'), (True, b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')], [])
out.close()
(folder/'manifest.json').write_text(json.dumps({'kind': 'generated-tcp-segmentation-replay', 'cases': cases, 'uid_cases': {}, 'production_database_used': False}, indent=2)+'\n')
print(json.dumps({'cases': len(cases), 'directory': str(folder)}))
