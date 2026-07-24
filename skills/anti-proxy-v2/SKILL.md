# Anti Proxy V2 Skill

Use this skill when working on Proxy Sentinel, the next-generation anti-proxy and shared-network detection project.

## Mission

Build Proxy Sentinel as an evidence-driven detection system. Do not recreate the old `dpi-analyze` architecture where packet capture, protocol parsing, feature counting, device merging, and policy actions are tightly coupled.

## Required Architecture

All work must preserve this boundary:

```text
Capture Backend -> Adapter -> Normalized Event -> Evidence -> Risk -> Decision
```

The risk engine must never depend directly on Suricata, Zeek, AF_XDP, DPDK, or pcap-specific raw fields.

## Development Priorities

1. Validate detection signals before optimizing packet capture.
2. Start with Suricata EVE JSON.
3. Build adapters that emit `NormalizedEvent`.
4. Implement replayable tests from JSONL fixtures.
5. Run in shadow mode before any enforcement action.
6. Keep every risk result explainable with evidence IDs.

## Event Rules

When adding a new event type:

- Update `docs/event-model.md`.
- Update `schemas/normalized-event-v1.schema.json` when fields are required.
- Add at least one JSONL fixture under `examples/`.
- Ensure adapter output remains backward compatible.

## Evidence Rules

Every evidence rule must return:

- `evidence_id`
- `ip`
- `type`
- `window`
- `score`
- `confidence`
- `severity`
- `reason`
- `samples`
- `created_at`

Rules that only count events without explaining why they matter are not acceptable.

## Risk Rules

Risk scoring must:

- Support `normal`, `suspicious`, `high`, and `confirmed`.
- Include all contributing evidence IDs.
- Include a short summary suitable for UI display.
- Apply negative evidence for accelerators, emulators, downloaders, allowlists, and known campus services.
- Avoid enforcement from a single weak signal.

## Enforcement Rules

Any action beyond logging must support:

- shadow mode
- cooldown
- audit log
- manual override
- allowlist check
- user group policy

## Testing Expectations

Before using real traffic, add replay tests. A useful test includes:

- fixture input
- expected evidence
- expected risk level
- explanation check

## Suggested First Implementation

Implement the following minimal path first:

```text
suricata-adapter -> normalized JSONL -> replay -> evidence aggregator -> risk snapshot CLI
```

The first useful CLI can be:

```bash
proxy-sentinel adapter suricata --input eve.json --output events.jsonl
proxy-sentinel replay --input events.jsonl
proxy-sentinel risk inspect --ip 10.1.2.3
```

