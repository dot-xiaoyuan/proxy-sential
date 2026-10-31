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

## Metrics

- `nav p50/p95`: `DOMContentLoaded` latency; this is the browser navigation cost.
- `total p50/p95`: navigation plus a bounded 1.2s data-settle window.
  Background pollers are deliberately not included; otherwise long-poll pages
  would look permanently slow.
- `slow APIs`: API responses at or above 500ms.
- `failed APIs`: HTTP status >= 400.
- A navigation timeout marks the process non-zero.

Do not compare this live benchmark with the mock-based `all-pages-audit`
Playwright suite; this script measures the real 184 UI and API.
