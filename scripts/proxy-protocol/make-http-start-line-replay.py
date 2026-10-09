#!/usr/bin/env python3
"""Generate private HTTP start-line grammar captures; no sockets are opened."""
import json
from pathlib import Path
import socket
import struct
import sys

folder = Path(sys.argv[1])
folder.mkdir(mode=0o700)
out = (folder/'replay.pcap').open('wb')
out.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
clock = 1790920000.0
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
    a,b,sp,x,y = '192.0.2.1','198.51.100.1',44000+len(cases),1000,2000
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
    for name,version in [('suffix',b'1.1junk'),('nul',b'1.1\0bad'),('minor-wide',b'1.10'),('major-wide',b'10.1'),('invalid-digit',b'1.x')]:
        flow('request-version-'+name+suffix,[(False,request.replace(b'HTTP/1.1',b'HTTP/'+version)),(True,success)],[],fragment=fragment)
    for name,line in [('version-suffix',b'HTTP/1.1junk 200 Established'),('version-minor-wide',b'HTTP/1.10 200 Established'),('version-invalid-digit',b'HTTP/1.x 200 Established'),('code-wide',b'HTTP/1.1 2000 Established'),('code-suffix',b'HTTP/1.1 200junk Established')]:
        flow('response-'+name+suffix,[(False,request),(True,line+b'\r\n\r\n')],['incomplete'],fragment=fragment)
for name,rq,rp in [
    ('normal-1.0',request.replace(b'HTTP/1.1',b'HTTP/1.0'),success.replace(b'HTTP/1.1',b'HTTP/1.0')),
    ('normal-1.1',request,success),
    ('normal-empty-reason',request,b'HTTP/1.1 200\r\n\r\n'),
    ('normal-tab-separator',request,b'HTTP/1.1\t200\tEstablished\r\n\r\n'),
    ('normal-request-trailing-space',request.replace(b'HTTP/1.1\r\n',b'HTTP/1.1  \r\n'),success),
    ('normal-response-reason-digits',request,b'HTTP/1.1 200 2000 tunneled\r\n\r\n'),
    ('normal-lowercase-response-prefix',request,b'http/1.1 200 Established\r\n\r\n'),
    ('fresh-after-malformed',request,success),
]:
    flow(name,[(False,rq),(True,rp)],['success'])
out.close()
(folder/'manifest.json').write_text(json.dumps({'kind':'generated-tcp-segmentation-replay','cases':cases,'uid_cases':{},'production_database_used':False},indent=2)+'\n')
print(json.dumps({'cases':len(cases),'directory':str(folder)}))
