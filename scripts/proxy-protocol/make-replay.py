#!/usr/bin/env python3
"""Generate local TCP fixtures; never opens a network socket."""
import struct, socket, sys
out=open(sys.argv[1], 'wb')
out.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
clock=1789088400.0

def packet(src,dst,sport,dport,seq,ack,flags,payload=b''):
 global clock
 tcp=struct.pack('!HHIIBBHHH',sport,dport,seq,ack,5<<4,flags,65535,0,0)+payload
 ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(tcp),1,0,64,6,0,socket.inet_aton(src),socket.inet_aton(dst))
 data=b'\x00'*12+b'\x08\x00'+ip+tcp
 sec=int(clock);out.write(struct.pack('<IIII',sec,int((clock-sec)*1e6),len(data),len(data))+data);clock+=.01

def flow(n,port,messages):
 a,b='192.0.2.1','198.51.100.1';sp=40000+n;x,y=1000,2000
 packet(a,b,sp,port,x,0,2);x+=1;packet(b,a,port,sp,y,x,18);y+=1;packet(a,b,sp,port,x,y,16)
 for server,data in messages:
  if server:packet(b,a,port,sp,y,x,24,data);y+=len(data)
  else:packet(a,b,sp,port,x,y,24,data);x+=len(data)
 packet(a,b,sp,port,x,y,17);packet(b,a,port,sp,y,x+1,17)

req=b'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n'
for n,status in enumerate([200,403,407,None]):
 messages=[(False,req)]
 if status:messages.append((True,f'HTTP/1.1 {status} Result\r\nContent-Length: 0\r\n\r\n'.encode()))
 flow(n,3128,messages)
for n,(cmd,reply) in enumerate([(1,0),(1,5),(1,None),(3,0)],4):
 messages=[(False,b'\x05\x01\x00'),(True,b'\x05\x00'),(False,bytes([5,cmd,0,1,8,8,8,8,0,80]))]
 if reply is not None:messages.append((True,bytes([5,reply,0,1,0,0,0,0,0,0])))
 flow(n,1080,messages)
# Authentication-method acceptance is not a successful CONNECT transaction.
flow(8,1080,[(False,b'\x05\x01\x00'),(True,b'\x05\x00')])
flow(9,1080,[(False,b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'),(True,b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')])
out.close()
