# Page load benchmark

- base: http://222.204.3.184:8088
- iterations: 2
- timeout: 20000 ms
- generated: 2026-10-31T07:03:27.046Z

| route | nav p50 ms | nav p95 ms | total p50 ms | total p95 ms | timeouts | failed APIs | slow APIs |
|---|---:|---:|---:|---:|---:|---|---|
| /overview | 120 | 494 | 1322 | 1697 | 0 | 0 | 0 |
| /settings/behavior-reports | 119 | 162 | 1321 | 1389 | 0 | 0 | 0 |
| /shared-access?tab=associations | 119 | 137 | 1323 | 1339 | 0 | 0 | 0 |
| /settings/rules | 125 | 133 | 1328 | 1336 | 0 | 0 | 0 |
| /activity?section=technical | 126 | 133 | 1329 | 1335 | 0 | 0 | 0 |
| /settings/notifications | 118 | 132 | 1320 | 1334 | 0 | 0 | 0 |
| /audit | 125 | 129 | 1327 | 1331 | 0 | 0 | 0 |
| /devices?tab=discovery | 118 | 127 | 1321 | 1329 | 0 | 0 | 1 |
| /events | 119 | 126 | 1321 | 1329 | 0 | 0 | 0 |
| /devices?tab=terminal | 124 | 125 | 1327 | 1328 | 0 | 0 | 0 |
| /devices?tab=network | 123 | 125 | 1325 | 1327 | 0 | 0 | 0 |
| /activity?section=access | 118 | 126 | 1321 | 1327 | 0 | 0 | 0 |
| /shared-access?tab=devices | 120 | 125 | 1322 | 1327 | 0 | 0 | 0 |
| /shared-access?tab=reviews | 122 | 123 | 1324 | 1327 | 0 | 0 | 0 |
| /activity?section=applications | 121 | 121 | 1323 | 1325 | 0 | 0 | 0 |
| /cases | 120 | 121 | 1322 | 1324 | 0 | 0 | 0 |
| /policies | 120 | 122 | 1323 | 1323 | 0 | 0 | 0 |
| /settings/sources?tab=diagnostics | 117 | 119 | 1319 | 1322 | 0 | 0 | 0 |
