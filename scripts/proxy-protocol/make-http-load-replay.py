#!/usr/bin/env python3
"""Generate private CONNECT queue/expiry captures without network sockets."""
import json
from pathlib import Path
import socket
import struct
import sys

folder = Path(sys.argv[1])
folder.mkdir(mode=0o700)
out = (folder/'replay.pcap').open('wb')
out.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
clock = 1790917200.0
cases = []
limit = int(sys.argv[2]) if len(sys.argv) > 2 else 100
if not 1 < limit <= 100:
    raise SystemExit('controlled queue limit must be between 2 and 100')
delayed_expiry = '--delayed-expiry' in sys.argv[3:]
native_unlimited = '--native-unlimited' in sys.argv[3:]


def packet(src, dst, sport, dport, seq, ack, flags, payload=b''):
    global clock
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)+payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(tcp), 1, 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    data = b'\0'*12+b'\x08\x00'+ip+tcp
    sec = int(clock)
    out.write(struct.pack('<IIII', sec, int((clock-sec)*1e6), len(data), len(data))+data)
    clock += .001


def flow(name, messages, expected, peak, remaining, first_reply, ambiguous=False):
    global clock
    a, b, sp, port, x, y = '192.0.2.1', '198.51.100.1', 42000+len(cases), 3128, 1000, 2000
    packet(a,b,sp,port,x,0,2); x += 1
    packet(b,a,port,sp,y,x,18); y += 1
    packet(a,b,sp,port,x,y,16)
    for server, data in messages:
        if data is None or isinstance(data, (int,float)):
            # Keep this same connection alive while PCAP time crosses the TTL.
            clock += 30 if data is None else data
            packet(a,b,sp,port,x,y,16)
        elif server:
            packet(b,a,port,sp,y,x,24,data); y += len(data)
        else:
            packet(a,b,sp,port,x,y,24,data); x += len(data)
    packet(a,b,sp,port,x,y,17); packet(b,a,port,sp,y,x+1,17)
    cases.append({'name':name,'client_port':sp,'server_port':port,'expected':expected,'state_expected':{'peak_pending':peak,'remaining_pending':remaining,'first_reply_pending':first_reply,'ambiguous':ambiguous}})


request = b'CONNECT target.invalid:443 HTTP/1.1\r\nHost: target.invalid:443\r\n\r\n'
success = b'HTTP/1.1 200 Established\r\n\r\n'
denial = b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n'
for count in (limit-1,limit):
    flow('pending-'+str(count), [(False,request)]*count+[(True,denial)], ['failed']+['incomplete']*(count-1), count,count-1,count)
for count in (limit+1,500,5000):
    flow('overflow-'+str(count), [(False,request)]*count+[(True,success)], ['incomplete']*limit,limit,0,0,True)
flow('sequential-300-denials', [(side,data) for _ in range(300) for side,data in ((False,request),(True,denial))], ['failed']*300,1,0,1)
flow('expired-response', [(False,request)]+[(False,None)]*12+[(True,success)], ['incomplete'],1,0,1 if delayed_expiry else 0)
flow('fresh-connection-after-overflow', [(False,request),(True,success)], ['success'],1,0,1)
flow('mixed-native-queue-pressure', [(False,request)]+[(False,b'GET / HTTP/1.1\r\nHost: target.invalid\r\n\r\n')]*150+[(True,success)], ['success'] if native_unlimited else ['incomplete'],1,0,1 if native_unlimited else 0,not native_unlimited)
flow('within-window-response', [(False,request)]+[(False,None)]*9+[(False,29.0),(True,success)], ['success'],1,0,1)
out.close()
(folder/'manifest.json').write_text(json.dumps({'kind':'generated-tcp-segmentation-replay','cases':cases,'uid_cases':{},'production_database_used':False,'maximum_pending_http_transactions':limit,'delayed_expiry':delayed_expiry,'native_pending_limit_disabled':native_unlimited},indent=2)+'\n')
print(json.dumps({'cases':len(cases),'directory':str(folder)}))
