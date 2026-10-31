# Page load benchmark

- base: http://222.204.3.184:8088
- iterations: 2
- timeout: 20000 ms
- generated: 2026-10-31T07:01:56.856Z

| route | p50 ms | p95 ms | max ms | timeouts | failed APIs | slow APIs |
|---|---:|---:|---:|---:|---|---|
| /overview | 4124 | 4404 | 4404 | 0 | 0 | 0 |
| /audit | 4147 | 4262 | 4262 | 0 | 0 | 0 |
| /events | 3025 | 3043 | 3043 | 0 | 0 | 1 |
| /devices?tab=terminal | 2969 | 2997 | 2997 | 0 | 0 | 1 |
| /devices?tab=discovery | 2723 | 2783 | 2783 | 0 | 0 | 1 |
| /shared-access?tab=devices | 2431 | 2459 | 2459 | 0 | 0 | 0 |
| /cases | 2433 | 2450 | 2450 | 0 | 0 | 0 |
| /settings/sources?tab=diagnostics | 2316 | 2391 | 2391 | 0 | 0 | 0 |
| /shared-access?tab=associations | 2295 | 2339 | 2339 | 0 | 0 | 0 |
| /activity?section=access | 2206 | 2300 | 2300 | 0 | 0 | 0 |
| /shared-access?tab=reviews | 2262 | 2296 | 2296 | 0 | 0 | 0 |
| /activity?section=applications | 2165 | 2215 | 2215 | 0 | 0 | 0 |
| /devices?tab=network | 2207 | 2208 | 2208 | 0 | 0 | 0 |
| /activity?section=technical | 2101 | 2188 | 2188 | 0 | 0 | 0 |
| /settings/rules | 2112 | 2141 | 2141 | 0 | 0 | 0 |
| /settings/behavior-reports | 2119 | 2135 | 2135 | 0 | 0 | 0 |
| /settings/notifications | 2108 | 2119 | 2119 | 0 | 0 | 0 |
| /policies | 2089 | 2094 | 2094 | 0 | 0 | 0 |
