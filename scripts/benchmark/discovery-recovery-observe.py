#!/usr/bin/env python3
"""Read-only recovery observation. Writes evidence; never starts/stops a service."""
import argparse
import datetime
import json
import os
from pathlib import Path
import time
import urllib.request
from urllib.parse import urlsplit


def totals(sample):
    lanes = sample["pipeline"]["lanes"]
    return {key: sum(lane.get(key, 0) for lane in lanes) for key in (
        "remaining_events", "processed_events", "completed_segments", "retries", "timeout_failures")}


def generation(sample):
    return sorted((lane["lane"], lane.get("started_at")) for lane in sample["pipeline"]["lanes"])


def assess(samples, phase, duration):
    reasons = []
    latest = samples[-1]
    lanes = latest["pipeline"].get("lanes", [])
    if not lanes or latest["pipeline"].get("status") in ("unavailable", "initializing"):
        reasons.append("pipeline_unavailable")
    if latest.get("ready_status") != "ready":
        reasons.append("control_plane_unavailable")
    if any(lane.get("status") in ("stalled", "interrupted", "stale") for lane in lanes):
        reasons.append("consumer_no_progress_or_stale")
    if any(lane.get("last_error") == "content_conflict" for lane in lanes):
        reasons.append("content_conflict")
    if any(generation(row) != generation(latest) for row in samples):
        reasons.append("consumer_restarted_restart_observation")
    timeout_windows = []
    # Two consecutive complete five-minute windows, including zero-success ones.
    for end in (latest["elapsed"] - 300, latest["elapsed"]):
        start = end - 300
        before = [row for row in samples if row["elapsed"] <= start]
        after = [row for row in samples if row["elapsed"] <= end]
        if not before or not after:
            continue
        a, b = totals(before[-1]), totals(after[-1])
        attempts = b["completed_segments"] - a["completed_segments"] + b["retries"] - a["retries"]
        failures = b["timeout_failures"] - a["timeout_failures"]
        timeout_windows.append(failures / attempts if attempts > 0 else 0)
    if len(timeout_windows) == 2 and all(rate > .01 for rate in timeout_windows):
        reasons.append("timeout_rate_above_one_percent_two_windows")
    first, last = totals(samples[0]), totals(latest)
    if latest["elapsed"] < duration:
        reasons.append("observation_incomplete")
    if phase.startswith("consume") and last["remaining_events"] > 0 and last["remaining_events"] >= first["remaining_events"]:
        reasons.append("backlog_not_decreasing")
    if phase == "passive":
        consumers = latest["pipeline"].get("consumers", [])
        if not consumers or any(row.get("status") != "running" for row in consumers):
            reasons.append("dhcp_consumer_not_running")
        # A strict decrease with uninterrupted counters proves processing exceeded
        # admissions. Queue moves cancel out because both lanes are included.
        for index in range(4):
            end = latest["elapsed"] - index * 900
            before = [row for row in samples if row["elapsed"] <= end - 900]
            after = [row for row in samples if row["elapsed"] <= end]
            if not before or not after:
                reasons.append("four_decreasing_fifteen_minute_windows_not_met")
                break
            a, b = totals(before[-1]), totals(after[-1])
            drained = b["remaining_events"] < a["remaining_events"]
            caught_up = a["remaining_events"] == b["remaining_events"] == 0 and b["completed_segments"] > a["completed_segments"]
            if not (drained or caught_up):
                reasons.append("four_decreasing_fifteen_minute_windows_not_met")
                break
    elapsed = latest["elapsed"] - samples[0]["elapsed"]
    net_rate = (first["remaining_events"] - last["remaining_events"]) / elapsed if elapsed > 0 else 0
    return {"passed": not reasons, "reasons": sorted(set(reasons)), "timeout_ratios": timeout_windows,
            "remaining_events": last["remaining_events"], "net_drain_events_per_second": net_rate,
            "estimated_drain_seconds": last["remaining_events"] / net_rate if net_rate > 0 else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--phase", choices=("consume-one", "consume-two", "passive"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--duration", type=int)
    parser.add_argument("--smoke", action="store_true", help="short instrumentation check, never acceptance")
    args = parser.parse_args()
    url = urlsplit(args.base_url)
    if url.scheme not in ("http", "https") or url.username or url.password or url.query or url.fragment:
        parser.error("base URL must not contain credentials, query or fragment")
    minimum = 7200 if args.phase == "passive" else 1800
    duration = args.duration if args.duration is not None else minimum
    if duration < 1 or (duration < minimum and not args.smoke):
        parser.error("short runs require --smoke and do not satisfy recovery acceptance")
    token = os.getenv("PROXY_SENTINEL_BENCHMARK_TOKEN", "")

    def fetch(path):
        request = urllib.request.Request(args.base_url.rstrip("/") + path)
        if token:
            request.add_header("Authorization", "Bearer " + token)
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.load(response)

    samples = []
    begin = time.monotonic()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as output:
        while True:
            sample = {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      "elapsed": time.monotonic() - begin}
            try:
                coverage = fetch("/api/v1/discovery/coverage")
                sample["pipeline"] = coverage.get("pipeline", {"status": "unavailable", "lanes": []})
                sample["ready_status"] = fetch("/readyz").get("status")
            except Exception as error:
                # Never include credential-bearing request URLs or response bodies.
                sample.update(error=type(error).__name__, pipeline={"status": "unavailable", "lanes": []})
            samples.append(sample)
            output.write(json.dumps(sample) + "\n")
            output.flush()
            result = assess(samples, args.phase, duration)
            fatal = set(result["reasons"]) - {"observation_incomplete", "backlog_not_decreasing", "four_decreasing_fifteen_minute_windows_not_met"}
            if fatal or sample["elapsed"] >= duration:
                result["acceptance"] = result["passed"] and not args.smoke
                print(json.dumps(result))
                raise SystemExit(0 if result["passed"] else 1)
            time.sleep(min(5, max(0, duration - (time.monotonic() - begin))))


if __name__ == "__main__":
    main()
