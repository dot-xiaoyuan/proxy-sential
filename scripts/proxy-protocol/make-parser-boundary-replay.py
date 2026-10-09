#!/usr/bin/env python3
"""Generate private timeout and control-octet captures; no sockets are opened."""
import json
from pathlib import Path
import socket
import struct
import sys

folder = Path(sys.argv[1])
folder.mkdir(mode=0o700)
out = (folder/'replay.pcap').open('wb')
out.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
clock = 1790917800.0
cases = []


def packet(src,dst,sport,dport,seq,ack,flags,payload=b''):
    global clock
    tcp = struct.pack('!HHIIBBHHH',sport,dport,seq,ack,5<<4,flags,65535,0,0)+payload
    ip = struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(tcp),1,0,64,6,0,socket.inet_aton(src),socket.inet_aton(dst))
    data = b'\0'*12+b'\x08\x00'+ip+tcp
    sec = int(clock)
    out.write(struct.pack('<IIII',sec,int((clock-sec)*1e6),len(data),len(data))+data)
    clock += .001


def flow(name,messages,expected,port=3128,fragment=False):
    global clock
    a,b,sp,x,y = '192.0.2.1','198.51.100.1',43000+len(cases),1000,2000
    packet(a,b,sp,port,x,0,2); x += 1
    packet(b,a,port,sp,y,x,18); y += 1
    packet(a,b,sp,port,x,y,16)
    for server,data in messages:
        if isinstance(data,(int,float)):
            clock += data
            packet(a,b,sp,port,x,y,16)
            continue
        for chunk in ([bytes([v]) for v in data] if fragment else [data]):
            if server:
                packet(b,a,port,sp,y,x,24,chunk); y += len(chunk)
            else:
                packet(a,b,sp,port,x,y,24,chunk); x += len(chunk)
    packet(a,b,sp,port,x,y,17); packet(b,a,port,sp,y,x+1,17)
    cases.append({'name':name,'client_port':sp,'server_port':port,'expected':expected})


request = b'CONNECT target.invalid:443 HTTP/1.1\r\nHost: target.invalid:443\r\n\r\n'
success = b'HTTP/1.1 200 Established\r\n\r\n'
for fragment in (False,True):
    suffix = '-one-byte' if fragment else '-whole'
    flow('nul-request-terminator'+suffix,[(False,request[:-2]+b'\0not-a-boundary\r\n'),(True,success)],['incomplete'],fragment=fragment)
    flow('nul-response-terminator'+suffix,[(False,request),(True,success[:-2]+b'\0not-a-boundary\r\n')],['incomplete'],fragment=fragment)
    flow('nul-request-value'+suffix,[(False,request[:-2]+b'X-Fixture: prefix\0suffix\r\n\r\n'),(True,success)],['incomplete'],fragment=fragment)
    flow('nul-response-value'+suffix,[(False,request),(True,success[:-2]+b'X-Fixture: prefix\0suffix\r\n\r\n')],['incomplete'],fragment=fragment)
    flow('nul-request-target'+suffix,[(False,request.replace(b'target.invalid:443 HTTP',b'target.invalid:443\0bad HTTP',1)),(True,success)],[],fragment=fragment)
flow('binary-tunnel-coalesced',[(False,request),(True,success+b'\x16\x03\x03\x00\x05\x01\x00\x00\x01\x00')],['success'])
flow('binary-tunnel-separate',[(False,request),(True,success),(False,b'\x16\x03\x03\x00\x05\x01\x00\x00\x01\x00'),(True,b'\x15\x03\x03\x00\x02\x02\x28')],['success'])
flow('binary-denial-body',[(False,request),(True,b'HTTP/1.1 403 Forbidden\r\nContent-Length: 3\r\n\r\na\0b')],['failed'])
flow('ordinary-binary-http',[(False,b'POST / HTTP/1.1\r\nHost: target.invalid\r\nContent-Length: 3\r\n\r\na\0b'),(True,b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\na\0b')],[])
greeting = [(False,b'\x05\x01\x00'),(True,b'\x05\x00')]
socks_request = bytes.fromhex('050100017f0000010050')
socks_reply = bytes.fromhex('050000017f0000010000')
for delay in (299,360):
    waits = [(False,30)]*9+[(False,29)] if delay==299 else [(False,30)]*12
    flow('socks-reply-'+str(delay),greeting+[(False,socks_request)]+waits+[(True,socks_reply)],['success'] if delay==299 else ['incomplete'],port=1080)
    flow('socks-denial-'+str(delay),greeting+[(False,socks_request)]+waits+[(True,bytes.fromhex('050500017f0000010000'))],['failed'] if delay==299 else ['incomplete'],port=1080)
flow('fresh-socks-after-expired',greeting+[(False,socks_request),(True,socks_reply)],['success'],port=1080)
out.close()
(folder/'manifest.json').write_text(json.dumps({'kind':'generated-tcp-segmentation-replay','cases':cases,'uid_cases':{},'production_database_used':False},indent=2)+'\n')
print(json.dumps({'cases':len(cases),'directory':str(folder)}))
