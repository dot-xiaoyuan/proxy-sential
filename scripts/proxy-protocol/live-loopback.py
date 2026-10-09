#!/usr/bin/env python3
"""Capture real loopback-only proxy exchanges in a fresh acceptance directory."""
import argparse
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import socketserver
import struct
import subprocess
import threading
import time


def read_exact(sock, size):
    value = b''
    while len(value) < size:
        part = sock.recv(size - len(value))
        if not part:
            raise EOFError('peer closed the controlled exchange')
        value += part
    return value


def headers(sock, allow_eof=False):
    value = b''
    while not value.endswith(b'\r\n\r\n'):
        if len(value) >= 8192:
            raise ValueError('fixture header too large')
        try:
            value += read_exact(sock, 1)
        except EOFError:
            if allow_eof and value:
                return value
            raise
    return value


def all_bytes(sock):
    value = b''
    while True:
        part = sock.recv(4096)
        if not part:
            return value
        value += part
        if len(value) > 16384:
            raise ValueError('fixture response too large')


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        request = headers(self.request)
        marker = request.split(b' ')[1]
        body = b'loopback-echo:' + marker
        if marker == b'/connect-binary-tunnel':
            assert b'Content-Length: 3\r\n' in request
            assert read_exact(self.request, 3) == b'a\0b'
            body += b'a\0b'
        self.request.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)


class HTTPProxy(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        while True:
            try:
                request = headers(self.request, allow_eof=True)
            except EOFError:
                return
            authority = request.split(b' ')[1]
            if authority.startswith(b'version-request-'):
                self.request.sendall(b'HTTP/1.1 200 Established\r\n\r\n')
                return
            if authority.startswith(b'nul-request'):
                assert b'\0' in request
                self.request.sendall(b'HTTP/1.1 200 Established\r\n\r\n')
                return
            if not request.endswith(b'\r\n\r\n'):
                if authority == b'request-truncated.invalid:1':
                    self.request.sendall(b'HTTP/1.1 200 Established\r\n\r\n')
                return
            if authority == b'burst.invalid:1':
                # This deliberately invalid peer never forwards a target;
                # force the request queue to overflow before any response.
                for _ in range(100):
                    assert headers(self.request).startswith(b'CONNECT burst.invalid:1 ')
                self.request.sendall(b'HTTP/1.1 200 Established\r\n\r\n')
                return
            malformed = {
                b'response-line.invalid:1': b'HTTP/1.1 200 Established\r\n',
                b'response-header.invalid:1': b'HTTP/1.1 200 Established\r\nX-Fixture: partial',
                b'denial-line.invalid:1': b'HTTP/1.1 403 Forbidden\r\n',
                b'reset-line.invalid:1': b'HTTP/1.1 200 Established\r\n',
                b'nul-response-terminator.invalid:1': b'HTTP/1.1 200 Established\r\n\0not-a-boundary\r\n',
                b'nul-response-value.invalid:1': b'HTTP/1.1 200 Established\r\nX-Fixture: a\0b\r\n\r\n',
                b'version-response-suffix.invalid:1': b'HTTP/1.1junk 200 Established\r\n\r\n',
                b'version-response-minor-wide.invalid:1': b'HTTP/1.10 200 Established\r\n\r\n',
                b'version-response-invalid-digit.invalid:1': b'HTTP/1.x 200 Established\r\n\r\n',
                b'version-response-code-wide.invalid:1': b'HTTP/1.1 2000 Established\r\n\r\n',
                b'version-response-code-suffix.invalid:1': b'HTTP/1.1 200junk Established\r\n\r\n',
            }
            if authority in malformed:
                self.request.sendall(malformed[authority])
                if authority == b'reset-line.invalid:1':
                    self.request.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                return
            if authority == b'deny.invalid:1':
                self.request.sendall(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n')
                continue
            if authority == b'auth.invalid:1':
                self.request.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n')
                return
            if authority == b'no-response.invalid:1':
                return
            if authority != ('127.0.0.1:' + str(self.server.target_port)).encode():
                raise ValueError('fixture refused a non-loopback target')
            with socket.create_connection(('127.0.0.1', self.server.target_port), timeout=3) as upstream:
                if b'X-Fixture-Interim: yes' in request:
                    self.request.sendall(b'HTTP/1.1 100 Continue\r\n\r\n')
                code = b'201' if b'X-Fixture-Status: 201' in request else b'204' if b'X-Fixture-Status: 204' in request else b'200'
                extra = b'Content-Length: 123\r\n' if b'X-Fixture-Length: yes' in request else b''
                version = b'1.0' if b'X-Fixture-Version: 1.0' in request else b'1.1'
                phrase = b'' if b'X-Fixture-Empty-Reason: yes' in request else b' Connection Established'
                separator = b'\t' if b'X-Fixture-Tab: yes' in request else b' '
                self.request.sendall(b'HTTP/'+version+separator+code+phrase+b'\r\n'+extra+b'\r\n')
                inner = headers(self.request)
                upstream.sendall(inner)
                if b'Content-Length: 3\r\n' in inner:
                    upstream.sendall(read_exact(self.request, 3))
                self.request.sendall(all_bytes(upstream))
            return


class SOCKSProxy(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        greeting = read_exact(self.request, 2)
        assert greeting[0] == 5
        methods = read_exact(self.request, greeting[1])
        # Deliberately invalid peers exercise phase-order validation.
        if methods in (b'\x00\x09', b'\x00\x08', b'\x02\x07', b'\x00\x07'):
            fake_success = b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00'
            if methods == b'\x00\x09':
                self.request.sendall(b'\x05\x00' + fake_success)
                read_exact(self.request, 10)
            elif methods == b'\x00\x08':
                read_exact(self.request, 10)
                self.request.sendall(b'\x05\x00' + fake_success)
            elif methods == b'\x02\x07':
                self.request.sendall(b'\x05\x02')
                assert read_exact(self.request, 5) == b'\x01\x01u\x01p'
                read_exact(self.request, 10)
                self.request.sendall(b'\x01\x00' + fake_success)
            else:
                self.request.sendall(b'\x05\x00')
                read_exact(self.request, 10)
                assert read_exact(self.request, 14) == b'premature-data'
                self.request.sendall(fake_success)
            return
        if 2 in methods:
            self.request.sendall(b'\x05\x02')
            auth = read_exact(self.request, 2)
            assert auth[0] == 1
            read_exact(self.request, auth[1])
            read_exact(self.request, read_exact(self.request, 1)[0])
            self.request.sendall(b'\x01\x00')
        else:
            self.request.sendall(b'\x05\x00')
        try:
            request = read_exact(self.request, 10)
        except EOFError:
            return
        assert request[:1] == b'\x05' and request[3] == 1
        command, destination, port = request[1], socket.inet_ntoa(request[4:8]), int.from_bytes(request[8:10], 'big')
        assert destination == '127.0.0.1'
        reply = b'\x05' + bytes([7 if command != 1 else 5 if port == 1 else 0]) + b'\x00\x01\x7f\x00\x00\x01\x00\x00'
        if port == 2:
            return
        if port == 3:
            self.request.sendall(reply[:4])
            return
        self.request.sendall(reply)
        if command != 1 or port == 1:
            return
        assert port == self.server.target_port
        with socket.create_connection(('127.0.0.1', port), timeout=3) as upstream:
            upstream.sendall(headers(self.request))
            self.request.sendall(all_bytes(upstream))


def run(directory, zeek_script, extra_script=None, plugin_path=None):
    directory.mkdir(mode=0o700)
    servers = [Server(('127.0.0.1', 0), handler) for handler in (Echo, HTTPProxy, SOCKSProxy)]
    target, http_proxy, socks_proxy = servers
    for server in servers:
        server.target_port = target.server_address[1]
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
    for thread in threads:
        thread.start()
    ports = [server.server_address[1] for server in servers]
    packet_filter = 'host 127.0.0.1 and tcp and (' + ' or '.join('port ' + str(port) for port in ports) + ')'
    started = time.time()
    cases = []
    capture = subprocess.Popen(['tcpdump', '-Z', 'root', '--immediate-mode', '-i', 'lo', '-nn', '-s', '0', '-U', '-w', str(directory / 'live.pcap'), packet_filter], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        ready = False
        capture_prefix = b''
        with selectors.DefaultSelector() as selector:
            selector.register(capture.stderr, selectors.EVENT_READ)
            until = time.monotonic() + 10
            while time.monotonic() < until:
                if capture.poll() is not None:
                    raise RuntimeError('private capture ended before readiness')
                if selector.select(.2):
                    capture_prefix += os.read(capture.stderr.fileno(), 4096)
                    if b'listening on lo' in capture_prefix:
                        ready = True
                        break
        if not ready:
            raise RuntimeError('private capture readiness timed out')

        def connect(name, server, expected):
            sock = socket.create_connection(server.server_address, timeout=3)
            sock.settimeout(3)
            case = {'name': name, 'client_port': sock.getsockname()[1], 'server_port': server.server_address[1], 'expected': expected, 'echo_verified': False}
            cases.append(case)
            return sock, case

        def tunnel_echo(sock, case):
            marker = '/' + case['name']
            binary = case['name'] == 'connect-binary-tunnel'
            extra = 'Content-Length: 3\r\n' if binary else ''
            sock.sendall(('GET ' + marker + ' HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n'+extra+'\r\n').encode() + (b'a\0b' if binary else b''))
            response = all_bytes(sock)
            assert response.endswith(('loopback-echo:' + marker).encode() + (b'a\0b' if binary else b''))
            case['echo_verified'] = True

        for name, authority, expected in [
            ('connect-success', '127.0.0.1:' + str(ports[0]), ['success']),
            ('connect-interim-success', '127.0.0.1:' + str(ports[0]), ['success']),
            ('connect-denied', 'deny.invalid:1', ['failed']),
            ('connect-auth-required', 'auth.invalid:1', ['failed']),
            ('connect-no-response', 'no-response.invalid:1', ['incomplete']),
            ('connect-retry-same-connection', 'deny.invalid:1', ['failed', 'success']),
            ('connect-success-201', '127.0.0.1:' + str(ports[0]), ['success']),
            ('connect-success-204', '127.0.0.1:' + str(ports[0]), ['success']),
            ('connect-success-length-header', '127.0.0.1:' + str(ports[0]), ['success']),
            ('connect-response-line-only', 'response-line.invalid:1', ['incomplete']),
            ('connect-response-header-truncated', 'response-header.invalid:1', ['incomplete']),
            ('connect-denial-line-only', 'denial-line.invalid:1', ['incomplete']),
            ('connect-reset-line-only', 'reset-line.invalid:1', ['incomplete']),
            ('connect-request-truncated', 'request-truncated.invalid:1', ['incomplete']),
            ('connect-pending-overflow', 'burst.invalid:1', ['incomplete'] * 100),
            ('connect-nul-request-terminator', 'nul-request-terminator.invalid:1', ['incomplete']),
            ('connect-nul-request-value', 'nul-request-value.invalid:1', ['incomplete']),
            ('connect-nul-request-target', 'nul-request-target.invalid:1\0bad', []),
            ('connect-nul-response-terminator', 'nul-response-terminator.invalid:1', ['incomplete']),
            ('connect-nul-response-value', 'nul-response-value.invalid:1', ['incomplete']),
            ('connect-binary-tunnel', '127.0.0.1:' + str(ports[0]), ['success']),
            ('connect-request-version-suffix', 'version-request-suffix.invalid:1', []),
            ('connect-request-version-nul', 'version-request-nul.invalid:1', []),
            ('connect-request-version-minor-wide', 'version-request-minor-wide.invalid:1', []),
            ('connect-request-version-major-wide', 'version-request-major-wide.invalid:1', []),
            ('connect-request-version-invalid-digit', 'version-request-invalid-digit.invalid:1', []),
            ('connect-response-version-suffix', 'version-response-suffix.invalid:1', ['incomplete']),
            ('connect-response-version-minor-wide', 'version-response-minor-wide.invalid:1', ['incomplete']),
            ('connect-response-version-invalid-digit', 'version-response-invalid-digit.invalid:1', ['incomplete']),
            ('connect-response-code-wide', 'version-response-code-wide.invalid:1', ['incomplete']),
            ('connect-response-code-suffix', 'version-response-code-suffix.invalid:1', ['incomplete']),
            ('connect-success-empty-reason', '127.0.0.1:' + str(ports[0]), ['success']),
            ('connect-success-tab-separator', '127.0.0.1:' + str(ports[0]), ['success']),
            ('connect-success-1.0', '127.0.0.1:' + str(ports[0]), ['success']),
        ]:
            sock, case = connect(name, http_proxy, expected)
            with sock:
                interim = 'X-Fixture-Interim: yes\r\n' if name == 'connect-interim-success' else ''
                if name in ('connect-success-201', 'connect-success-204'):
                    interim += 'X-Fixture-Status: '+name[-3:]+'\r\n'
                if name == 'connect-success-length-header':
                    interim += 'X-Fixture-Length: yes\r\n'
                if name == 'connect-success-empty-reason': interim += 'X-Fixture-Empty-Reason: yes\r\n'
                if name == 'connect-success-tab-separator': interim += 'X-Fixture-Tab: yes\r\n'
                if name == 'connect-success-1.0': interim += 'X-Fixture-Version: 1.0\r\n'
                request = ('CONNECT ' + authority + ' HTTP/1.1\r\nHost: ' + authority + '\r\n' + interim + '\r\n').encode()
                versions = {'suffix': b'1.1junk', 'nul': b'1.1\0bad', 'minor-wide': b'1.10', 'major-wide': b'10.1', 'invalid-digit': b'1.x'}
                if name.startswith('connect-request-version-'):
                    request = request.replace(b'HTTP/1.1', b'HTTP/'+versions[name.removeprefix('connect-request-version-')])
                if name == 'connect-success-1.0': request = request.replace(b'HTTP/1.1', b'HTTP/1.0')
                if name == 'connect-nul-request-terminator':
                    request = request[:-2]+b'\0not-a-boundary\r\n\r\n'
                if name == 'connect-nul-request-value':
                    request = request[:-2]+b'X-Fixture: a\0b\r\n\r\n'
                if name == 'connect-pending-overflow':
                    sock.sendall(request*101)
                    assert all_bytes(sock).startswith(b'HTTP/1.1 200 ')
                    continue
                if name == 'connect-request-truncated':
                    sock.sendall(request[:-2]); sock.shutdown(socket.SHUT_WR)
                    assert all_bytes(sock).startswith(b'HTTP/1.1 200 ')
                    continue
                sock.sendall(request[:9]); sock.sendall(request[9:])
                if name.startswith('connect-nul-'):
                    assert all_bytes(sock).startswith(b'HTTP/1.1 200 ')
                    continue
                if authority.startswith('version-request-') or authority.startswith('version-response-'):
                    assert all_bytes(sock).startswith(b'HTTP/')
                    continue
                if authority in ('response-line.invalid:1', 'response-header.invalid:1', 'denial-line.invalid:1', 'reset-line.invalid:1'):
                    try:
                        response = all_bytes(sock)
                        assert b'\r\n\r\n' not in response
                    except ConnectionResetError:
                        assert name == 'connect-reset-line-only'
                    continue
                if name == 'connect-no-response':
                    assert all_bytes(sock) == b''
                    continue
                response = headers(sock)
                if name == 'connect-interim-success':
                    assert response.startswith(b'HTTP/1.1 100 ')
                    response = headers(sock)
                if name == 'connect-retry-same-connection':
                    assert response.startswith(b'HTTP/1.1 403 ')
                    authority = '127.0.0.1:' + str(ports[0])
                    sock.sendall(('CONNECT ' + authority + ' HTTP/1.1\r\nHost: ' + authority + '\r\n\r\n').encode())
                    response = headers(sock)
                if 'success' in expected:
                    expected_code = name[-3:] if name in ('connect-success-201', 'connect-success-204') else '200'
                    if name == 'connect-success-empty-reason': assert response.startswith(b'HTTP/1.1 200\r\n')
                    elif name == 'connect-success-tab-separator': assert response.startswith(b'HTTP/1.1\t200 ')
                    elif name == 'connect-success-1.0': assert response.startswith(b'HTTP/1.0 200 ')
                    else: assert response.startswith(('HTTP/1.1 '+expected_code+' ').encode())
                    tunnel_echo(sock, case)
                elif expected == ['failed']:
                    assert response.startswith(b'HTTP/1.1 403 ') or response.startswith(b'HTTP/1.1 407 ')

        for name, command, port, expected in [
            ('socks-success', 1, ports[0], ['success']),
            ('socks-denied', 1, 1, ['failed']),
            ('socks-no-response', 1, 2, ['incomplete']),
            ('socks-unsupported-command', 3, ports[0], ['unsupported']),
            ('socks-authentication-only', None, None, []),
            ('socks-userpass-success', 1, ports[0], ['success']),
            ('socks-userpass-auth-only', None, None, []),
            ('socks-fragmented-greeting-success', 1, ports[0], ['success']),
            ('socks-invalid-selection', 1, 1, []),
            ('socks-invalid-reserved', 1, 1, []),
            ('socks-truncated-reply', 1, 3, ['incomplete']),
        ]:
            sock, case = connect(name, socks_proxy, expected)
            with sock:
                method = 2 if 'userpass' in name else 1 if name == 'socks-invalid-selection' else 0
                greeting = bytes([5, 1, method])
                if name == 'socks-fragmented-greeting-success':
                    for byte in greeting:
                        sock.sendall(bytes([byte]))
                        time.sleep(.01)
                else:
                    sock.sendall(greeting)
                assert read_exact(sock, 2) == bytes([5, 2 if method == 2 else 0])
                if method == 2:
                    # Synthetic fixture values are never included in transaction logs.
                    sock.sendall(b'\x01\x01u\x01p')
                    assert read_exact(sock, 2) == b'\x01\x00'
                if command is None:
                    continue
                request = b'\x05' + bytes([command, 1 if name == 'socks-invalid-reserved' else 0]) + b'\x01\x7f\x00\x00\x01' + port.to_bytes(2, 'big')
                sock.sendall(request[:4]); sock.sendall(request[4:])
                if name == 'socks-truncated-reply':
                    assert all_bytes(sock) == b'\x05\x00\x00\x01'
                    continue
                if name == 'socks-no-response':
                    assert all_bytes(sock) == b''
                    continue
                reply = read_exact(sock, 10)
                assert reply[1] == (7 if command != 1 else 5 if port == 1 else 0)
                if expected == ['success']:
                    tunnel_echo(sock, case)

        request = b'\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x01'
        for name, greeting, expected in (
            ('socks-early-reply', b'\x05\x02\x00\x09', []),
            ('socks-before-selection', b'\x05\x02\x00\x08', []),
            ('socks-before-auth-success', b'\x05\x02\x02\x07', []),
            ('socks-data-before-success', b'\x05\x02\x00\x07', ['incomplete']),
        ):
            sock, case = connect(name, socks_proxy, expected)
            with sock:
                sock.sendall(greeting)
                if name == 'socks-early-reply':
                    assert read_exact(sock, 12) == b'\x05\x00\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00'
                    sock.sendall(request)
                elif name == 'socks-before-selection':
                    sock.sendall(request)
                    assert read_exact(sock, 12) == b'\x05\x00\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00'
                elif name == 'socks-before-auth-success':
                    assert read_exact(sock, 2) == b'\x05\x02'
                    sock.sendall(b'\x01\x01u\x01p' + request)
                    assert read_exact(sock, 12) == b'\x01\x00\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00'
                else:
                    assert read_exact(sock, 2) == b'\x05\x00'
                    sock.sendall(request)
                    time.sleep(.01)
                    sock.sendall(b'premature-data')
                    assert read_exact(sock, 10) == b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00'

        sock, case = connect('ordinary-http', target, [])
        with sock:
            tunnel_echo(sock, case)
    finally:
        if capture.poll() is None:
            capture.send_signal(signal.SIGINT)
        _, stderr = capture.communicate(timeout=10)
        (directory / 'capture.log').write_bytes(capture_prefix + stderr)
        for server in servers:
            server.shutdown(); server.server_close()
        for thread in threads:
            thread.join(timeout=5)
        assert all(not thread.is_alive() for thread in threads)
    if capture.returncode != 0:
        raise RuntimeError('private packet capture failed')
    command = ['zeek', '-C', '-r', str(directory / 'live.pcap')]
    if extra_script:
        command.append(str(extra_script))
    command.extend([str(zeek_script), 'LogAscii::use_json=T'])
    env = os.environ.copy()
    if plugin_path:
        env['ZEEK_PLUGIN_PATH'] = str(plugin_path)
    subprocess.run(command, cwd=directory, env=env, check=True, timeout=30)
    rows = [json.loads(line) for line in (directory / 'proxy_transactions.log').read_text().splitlines()]
    case_by_port = {(case['client_port'], case['server_port']): case for case in cases}
    uid_cases = {}
    for row in rows:
        case = case_by_port.get((row['id.orig_p'], row['id.resp_p']))
        if case is None:
            raise RuntimeError('proxy log contains a transaction outside the private test clients')
        uid_cases[row['uid']] = case['name']
    manifest = {'kind': 'real-loopback-socket-acceptance', 'started_at': started, 'finished_at': time.time(), 'capture_filter': packet_filter, 'cases': cases, 'uid_cases': uid_cases, 'parser_rows': len(rows), 'servers_stopped': True, 'production_database_used': False}
    (directory / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'cases': len(cases), 'tunneled_echoes_verified': sum(case['echo_verified'] and bool(case['expected']) for case in cases), 'parser_rows': len(rows), 'directory': str(directory)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--zeek-script', type=Path, required=True)
    parser.add_argument('--zeek-extra-script', type=Path)
    parser.add_argument('--zeek-plugin-path', type=Path)
    args = parser.parse_args()
    if not args.output.is_absolute() or args.output.exists() or not args.zeek_script.is_file():
        raise SystemExit('fresh absolute output directory and existing Zeek script required')
    run(args.output, args.zeek_script.resolve(), args.zeek_extra_script.resolve() if args.zeek_extra_script else None, args.zeek_plugin_path.resolve() if args.zeek_plugin_path else None)
