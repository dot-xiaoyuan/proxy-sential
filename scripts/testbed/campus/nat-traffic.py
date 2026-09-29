"""Actual isolated NAT traffic. UA and TLS profiles are programmed, not real OSes."""
import concurrent.futures
import http.client
import json
import socket
import ssl
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEST = '172.29.250.10'
class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_GET(self):
        body = b'campus isolated NAT laboratory\n'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_):
        pass

def server():
    plain = ThreadingHTTPServer((DEST, 80), Handler)
    secure = ThreadingHTTPServer((DEST, 443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('/tmp/cert.pem', '/tmp/key.pem')
    secure.socket = context.wrap_socket(secure.socket, server_side=True)
    threading.Thread(target=plain.serve_forever, daemon=True).start()
    threading.Thread(target=secure.serve_forever, daemon=True).start()
    dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns.bind((DEST, 53))
    while True:
        q, addr = dns.recvfrom(512)
        if len(q) >= 12:
            response = q[:2] + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' + q[12:]
            response += b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04' + socket.inet_aton(DEST)
            dns.sendto(response, addr)

def client(profile):
    if profile not in ('android', 'windows'):
        raise ValueError('unknown laboratory profile')
    context = ssl.create_default_context(cafile='/tmp/cert.pem')
    # Certificate includes the isolated server IP; verification stays enabled.
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256' if profile == 'android' else 'ECDHE-RSA-AES256-GCM-SHA384')
    ua = 'Mozilla/5.0 (Linux; Android 14) CampusLab' if profile == 'android' else 'Mozilla/5.0 (Windows NT 10.0) CampusLab'
    def request(i):
        began = time.monotonic()
        try:
            if i % 3 == 0:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(5)
                    query = struct.pack('!HHHHHH', i, 256, 1, 0, 0, 0) + b'\x06campus\x04test\x00\x00\x01\x00\x01'
                    sock.sendto(query, (DEST, 53))
                    result, _ = sock.recvfrom(512)
                    assert result[:2] == query[:2] and result[-4:] == socket.inet_aton(DEST)
            else:
                conn = http.client.HTTPConnection(DEST, timeout=5) if i % 3 == 1 else http.client.HTTPSConnection(DEST, timeout=5, context=context)
                try:
                    conn.request('GET', '/campus/'+profile, headers={'User-Agent': ua, 'Host':'campus.test'})
                    response = conn.getresponse()
                    assert response.status == 200 and response.read() == b'campus isolated NAT laboratory\n'
                finally:
                    conn.close()
            return True, time.monotonic()-began
        except (OSError, AssertionError, http.client.HTTPException):
            return False, time.monotonic()-began
    start = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(request, range(3000)))
    failed = sum(not ok for ok, _ in results)
    print(json.dumps({'profile':profile, 'requests':len(results), 'failed':failed, 'seconds':time.monotonic()-start, 'p95_seconds':sorted(dt for _,dt in results)[2849], 'label':'programmed profile, actual container/NAT traffic'}), flush=True)
    if failed:
        sys.exit(1)

if __name__ == '__main__':
    server() if sys.argv[1] == 'server' else client(sys.argv[2])
