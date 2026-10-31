# Page load benchmark

Run against a live UI with an existing session token:

```bash
PAGE_TOKEN='...' ITERATIONS=2 node scripts/benchmark/page-load-benchmark.mjs
```

Environment:

- `BASE_URL`: default `http://222.204.3.184:8088`
- `PAGE_TOKEN`: authenticated `proxy_sentinel_session` cookie value; required
- `ITERATIONS`: default `2`
- `TIMEOUT_MS`: default `20000`
- `OUTPUT`: default `artifacts/benchmark/page-load.json`
- `CHROME_PATH`: local Chrome executable

The benchmark is read-only. It records navigation time, API status/latency,
console/page errors, failed requests, and P50/P95/max per route. A route that
times out makes the process exit non-zero.
