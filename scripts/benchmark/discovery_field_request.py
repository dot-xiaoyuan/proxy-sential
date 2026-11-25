"""Executed by ssh on 204. Input is one JSON request on stdin; stdout is framed HTTP."""
import http.client
import json
import sys
import time
from urllib.parse import urlsplit

request = json.load(sys.stdin)
method, path = request['method'], request['path']
target = urlsplit(path)
if not path.startswith('/') or target.scheme or target.netloc or target.fragment:
    raise ValueError('origin-form request target required')
login = method == 'POST' and path == '/api/v1/auth/login'
if method not in ('GET', 'HEAD') and not login:
    raise ValueError('unexpected HTTP method')
headers = {key: value for key, value in request.get('headers', {}).items()
           if key in ('cookie', 'accept', 'content-type')}
connection = http.client.HTTPConnection('127.0.0.1', 18080, timeout=90)
started = time.monotonic()
connection.request(method, path, body=request['body'].encode() if login else None, headers=headers)
response = connection.getresponse()
body = response.read(256 * 1024 * 1024 + 1)
if len(body) > 256 * 1024 * 1024:
    raise ValueError('response exceeds 256 MiB')
meta = {'status': response.status, 'headers': dict(response.getheaders()),
        'loopback_ms': round((time.monotonic() - started) * 1000, 2)}
out = sys.stdout.buffer
out.write(json.dumps(meta).encode() + b'\n')
out.write(body)
connection.close()
