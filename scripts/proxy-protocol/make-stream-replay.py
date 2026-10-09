#!/usr/bin/env python3
"""Generate bounded TCP-segmentation fixtures; no network sockets are opened."""
import json
from pathlib import Path
import socket
import struct
import sys

folder = Path(sys.argv[1])
folder.mkdir(mode=0o700)
out = (folder / 'replay.pcap').open('wb')
out.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
clock = 1790913321.0
cases = []


def packet(src, dst, sport, dport, seq, ack, flags, payload=b''):
    global clock
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    data = b'\x00' * 12 + b'\x08\x00' + ip + tcp
    sec = int(clock)
    out.write(struct.pack('<IIII', sec, int((clock-sec)*1e6), len(data), len(data)) + data)
    clock += .01


def flow(name, messages, expected, fragment=False, port=49305):
    a, b, sp, x, y = '192.0.2.1', '198.51.100.1', 40000 + len(cases), 1000, 2000
    packet(a,b,sp,port,x,0,2); x += 1
    packet(b,a,port,sp,y,x,18); y += 1
    packet(a,b,sp,port,x,y,16)
    for server, data in messages:
        chunks = [bytes([byte]) for byte in data] if fragment else [data]
        for chunk in chunks:
            if server:
                packet(b,a,port,sp,y,x,24,chunk); y += len(chunk)
            else:
                packet(a,b,sp,port,x,y,24,chunk); x += len(chunk)
    packet(a,b,sp,port,x,y,17); packet(b,a,port,sp,y,x+1,17)
    cases.append({'name':name,'client_port':sp,'server_port':port,'expected':expected})


def v5(request, reply, method=0, auth_code=0, greeting=None):
    messages = [(False,greeting or bytes([5,1,method])),(True,bytes([5,method]))]
    if method==2:
        messages += [(False,b'\x01\x01u\x01p'),(True,bytes([1,auth_code]))]
    if request is not None:
        messages.append((False,request))
    if reply is not None:
        messages.append((True,reply))
    return messages


req = bytes.fromhex('050100017f0000010050')
reply = bytes.fromhex('050000017f0000010000')
for fragment in (False,True):
    suffix = '-one-byte' if fragment else '-whole'
    flow('ipv4'+suffix,v5(req,reply),['success'],fragment)
    flow('ipv6'+suffix,v5(bytes.fromhex('05010004')+b'\0'*16+b'\x00\x50',bytes.fromhex('05000004')+b'\0'*18),['success'],fragment)
    flow('domain255'+suffix,v5(bytes.fromhex('05010003ff')+b'a'*255+b'\x00\x50',bytes.fromhex('0500000301610000')),['success'],fragment)
    flow('userpass'+suffix,v5(req,reply,method=2),['success'],fragment)
    flow('multiple-methods'+suffix,v5(req,reply,greeting=bytes.fromhex('05020100')),['success'],fragment)
    flow('socks4'+suffix,[(False,bytes.fromhex('040100507f0000017500')),(True,bytes.fromhex('005a00007f000001'))],['unsupported'],fragment)
    flow('socks4a'+suffix,[(False,bytes.fromhex('04010050000000017500612e6578616d706c6500')),(True,bytes.fromhex('005a00007f000001'))],['unsupported'],fragment)
flow('udp-command',v5(bytes.fromhex('050300017f0000010050'),reply),['unsupported'],True)
flow('bind-command',v5(bytes.fromhex('050200017f0000010050'),reply),['unsupported'],True)
flow('auth-only',v5(None,None),[],True)
flow('userpass-auth-only',v5(None,None,method=2),[],True)
flow('failed-auth-then-request',v5(req,reply,method=2,auth_code=1),[],True)
flow('unoffered-method',v5(req,reply,greeting=bytes.fromhex('050101')),[],True)
flow('zero-methods',v5(req,reply,greeting=bytes.fromhex('0500')),[],True)
flow('bad-reserved',v5(bytes.fromhex('050101017f0000010050'),reply),[],True)
flow('bad-command',v5(bytes.fromhex('050400017f0000010050'),reply),[],True)
flow('empty-domain',v5(bytes.fromhex('05010003000050'),reply),[],True)
flow('bad-reply-reserved',v5(req,bytes.fromhex('050001017f0000010000')),['incomplete'],True)
flow('bad-reply-code',v5(req,bytes.fromhex('050900017f0000010000')),['incomplete'],True)
flow('truncated-request',v5(req[:4],None),[],True)
flow('truncated-reply',v5(req,reply[:4]),['incomplete'],True)
flow('unanswered-request',v5(req,None),['incomplete'],True)
flow('binary-looks-like-greeting',[(False,bytes.fromhex('05016f6f7061717565')),(True,bytes.fromhex('0500')),(False,req),(True,reply)],[],True)
flow('ordinary-http',[(False,b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n'),(True,b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')],[],True)
flow('ordinary-tls',[(False,bytes.fromhex('16030300050100000100')),(True,bytes.fromhex('15030300020228'))],[],True)
# A response must not be buffered and relabelled as occurring after a later request.
flow('reply-before-request',[(False,b'\x05\x01\x00'),(True,b'\x05\x00'),(True,reply),(False,req)],[],True)
flow('selection-and-early-reply-coalesced',[(False,b'\x05\x01\x00'),(True,b'\x05\x00'+reply),(False,req)],[])
flow('request-before-selection',[(False,b'\x05\x01\x00'),(False,req),(True,b'\x05\x00'),(True,reply)],[],True)
flow('greeting-and-early-request-coalesced',[(False,b'\x05\x01\x00'+req),(True,b'\x05\x00'),(True,reply)],[])
flow('request-before-auth-success',[(False,b'\x05\x01\x02'),(True,b'\x05\x02'),(False,b'\x01\x01u\x01p'),(False,req),(True,b'\x01\x00'),(True,reply)],[],True)
flow('auth-success-and-early-reply-coalesced',[(False,b'\x05\x01\x02'),(True,b'\x05\x02'),(False,b'\x01\x01u\x01p'),(True,b'\x01\x00'+reply),(False,req)],[])
flow('reply-before-request-complete',[(False,b'\x05\x01\x00'),(True,b'\x05\x00'),(False,req[:4]),(True,reply),(False,req[4:])],[])
flow('client-data-before-success',[(False,b'\x05\x01\x00'),(True,b'\x05\x00'),(False,req),(False,b'premature-client-data'),(True,reply)],['incomplete'])
flow('reply-and-tunnel-data-coalesced',[(False,b'\x05\x01\x00'),(True,b'\x05\x00'),(False,req),(True,reply+b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')],['success'])
out.close()
(folder/'manifest.json').write_text(json.dumps({'kind':'generated-tcp-segmentation-replay','cases':cases,'uid_cases':{},'production_database_used':False},indent=2)+'\n')
print(json.dumps({'cases':len(cases),'directory':str(folder)}))
