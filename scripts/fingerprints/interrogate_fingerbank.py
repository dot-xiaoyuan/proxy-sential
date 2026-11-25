"""Interrogate Fingerbank for the DHCP fingerprints this site actually sees.

The public bulk SQLite download contains DHCP attributes and device names, but
no combination-to-device mappings. Query only the distinct
(requested_options, vendor_class) pairs extracted from the site's DHCP facts.
Requests are paced below the free 600/hour limit and completed responses are
cached so an interrupted run resumes without re-querying.

Input : JSONL with {"requested_options": "...", "vendor_class": "...", "count": N}
Output: JSONL raw records for CompileFingerbankSnapshot plus a cache file.

The legacy query mode sends only the two DHCP fields. --plan-fields works
offline on JSONL rows with pre-attributed mDNS, UPnP SERVER and client JA3
arrays and writes a deduplicated plan of clues. It does not read credentials.
"""
import argparse
import fcntl
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

API = "https://api.fingerbank.org/api/v2/combinations/interrogate"
PILOT_FIELDS = {"mdns_services", "upnp_server_strings", "ja3_fingerprints"}
SERVICE_TYPE = re.compile(r"_[a-z0-9][a-z0-9-]{0,14}\._(?:tcp|udp)", re.ASCII)
UPNP_PRODUCT = r"[a-zA-Z][a-zA-Z0-9_-]*(?: [a-zA-Z][a-zA-Z0-9_-]*){0,7}/[0-9]{1,4}(?:\.[0-9]{1,4}){0,2}"
UPNP_HEADER = re.compile(rf"{UPNP_PRODUCT}(?:(?:, ?| ){UPNP_PRODUCT}){{0,5}}", re.ASCII)
HARDWARE_ID = re.compile(r"(?i)(?:[0-9a-f]{2}[-:]){5}[0-9a-f]{2}|[0-9a-f]{12,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def generic_upnp(value):
    return isinstance(value, str) and len(value) <= 160 and UPNP_HEADER.fullmatch(value) is not None and not HARDWARE_ID.search(value)


def pilot_payload(row, fields, reviewed_upnp):
    """Keep only selected wire fields from one already scoped observation."""
    if not fields or not set(fields) <= PILOT_FIELDS:
        raise ValueError("select only supported pilot fields")
    payload = {}
    for name in sorted(set(fields)):
        values = row.get(name, [])
        if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
            raise ValueError(f"{name} must be an array of strings")
        approved = set()
        for value in values:
            if name == "upnp_server_strings":
                if value in reviewed_upnp and generic_upnp(value):
                    approved.add(value)
            elif name == "mdns_services":
                value = value.lower().removesuffix(".").removesuffix(".local")
                if SERVICE_TYPE.fullmatch(value):
                    approved.add(value + ".local")
            elif re.fullmatch(r"[a-fA-F0-9]{32}", value):
                approved.add(value.lower())
        if approved:
            # Select deterministically before hashing, so the key describes
            # exactly what an eventual, approved request would contain.
            payload[name] = sorted(approved)[:5]
    return payload


def pilot_key(payload):
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(b"fingerbank-interrogate-v2-pilot\0" + encoded).hexdigest()


def offline_plan(rows, fields, reviewed_upnp, cache_path, limit, source):
    if not fields or not set(fields) <= PILOT_FIELDS or (limit is not None and limit < 1):
        raise ValueError("provide supported fields and a positive combination limit")
    combinations = {}
    skipped = total = 0
    for row in rows:
        total += 1
        payload = pilot_payload(row, fields, reviewed_upnp)
        if not payload:
            skipped += 1
            continue
        key = pilot_key(payload)
        if key not in combinations:
            combinations[key] = {"cache_key": key, "payload": payload, "rows": 0}
        combinations[key]["rows"] += 1
    # Cache namespaces keep simulated results and legacy DHCP-only responses
    # out of external clue output. Retryable errors never become cache hits.
    if cache_path and os.path.exists(cache_path):
        with open(cache_path, "rb") as cache:
            for line in cache:
                try:
                    record = json.loads(line)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                if not isinstance(record, dict) or record.get("source") != source or not isinstance(record.get("cache_key"), str):
                    continue
                item = combinations.get(record.get("cache_key"))
                if not item or record.get("payload") != item["payload"]:
                    continue
                status = record.get("status")
                if status == 404:
                    item["result"] = {"source": source, "status": 404}
                elif status == 200:
                    score = record.get("score")
                    name = record.get("device_name")
                    if type(score) in (int, float) and 0 <= score <= 100 and isinstance(name, str) and name.strip():
                        item["result"] = {"source": source, "status": 200, "device_name": name, "score": score}
    selected = list(combinations.values())[:limit]
    return {"mode": "offline", "selected_fields": sorted(fields), "input_rows": total,
            "rows_without_eligible_signals": skipped, "distinct_combinations": len(combinations),
            "deferred_by_limit": len(combinations) - len(selected), "combinations": selected}


class NoPilotRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def query_pilot(rows, fields, reviewed_upnp, cache_path, limit, interval, timeout, key):
    if not key or not 1 <= limit <= 20 or not 10 <= interval <= 3600 or not 0 < timeout <= 120:
        raise ValueError("pilot requires credentials, 1–20 requests, interval 10–3600s and timeout at most 120s")
    transport = urllib.request.build_opener(NoPilotRedirect())
    fd = os.open(cache_path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a+b") as cache:
        fcntl.flock(cache, fcntl.LOCK_EX | fcntl.LOCK_NB)
        plan = offline_plan(rows, fields, reviewed_upnp, cache_path, None, "fingerbank_v2")
        pending = [item for item in plan["combinations"] if "result" not in item]
        plan.update(mode="external", queries=0, deferred_by_limit=max(0, len(pending) - limit))
        last_start = 0
        cache.seek(0)
        for line in cache:
            try:
                record = json.loads(line)
            except (ValueError, UnicodeDecodeError):
                continue
            if isinstance(record, dict) and record.get("source") == "fingerbank_v2" and type(record.get("started_at")) in (int, float):
                last_start = max(last_start, min(record["started_at"], time.time()))
        if cache.seek(0, os.SEEK_END) > 0:
            cache.seek(-1, os.SEEK_END)
            if cache.read(1) != b"\n":
                cache.write(b"\n")
        for item in pending[:limit]:
            payload = pilot_payload(item["payload"], fields, reviewed_upnp)
            if not payload or payload != item["payload"] or pilot_key(payload) != item["cache_key"]:
                raise ValueError("pilot payload changed after validation")
            wait = last_start + interval - time.time()
            if wait > 0:
                time.sleep(wait)
            request = urllib.request.Request(API, data=json.dumps(payload).encode("utf-8"), method="POST",
                    headers={"Content-Type": "application/json", "Authorization": "Bearer " + key})
            last_start = time.time()
            attempt = {"source": "fingerbank_v2", "cache_key": item["cache_key"], "started_at": last_start, "status": "pending"}
            cache.write((json.dumps(attempt) + "\n").encode())
            cache.flush()
            os.fsync(cache.fileno())
            plan["queries"] += 1
            try:
                with transport.open(request, timeout=timeout) as response:
                    if response.status != 200:
                        raise ValueError("unexpected status")
                    raw = response.read(1024 * 1024 + 1)
                    if len(raw) > 1024 * 1024:
                        raise ValueError("response too large")
                    body = json.loads(raw)
                    name = body.get("device_name") if isinstance(body, dict) else None
                    score = body.get("score") if isinstance(body, dict) else None
                    if not isinstance(name, str) or not name.strip() or type(score) not in (float, int) or not 0 <= score <= 100:
                        raise ValueError("invalid response")
                    result = {"source": "fingerbank_v2", "status": 200, "device_name": name, "score": score}
            except urllib.error.HTTPError as error:
                error.close()
                if error.code != 404:
                    plan["stopped"] = f"HTTP {error.code}"
                    break
                result = {"source": "fingerbank_v2", "status": 404}
            except (ValueError, OSError) as error:
                plan["stopped"] = type(error).__name__
                break
            record = dict(result, payload=payload, cache_key=item["cache_key"], queried_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
            cache.write((json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8"))
            cache.flush()
            os.fsync(cache.fileno())
            item["result"] = result
        return plan


def build_request(key, fingerprint, vendor_class):
    body = {"dhcp_fingerprint": fingerprint}
    if vendor_class:
        body["dhcp_vendor"] = vendor_class
    return urllib.request.Request(
        API,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + key},
        method="POST",
    )


def load_done(path):
    done = {}
    if not os.path.exists(path):
        return done
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict) or not isinstance(record.get("requested_options"), str) or record.get("source") in ("fingerbank_mock", "fingerbank_v2"):
                continue
            if record.get("status") in (200, 404):
                done[(record["requested_options"], record.get("vendor_class") or "")] = record
    return done


def raw_records(done, pairs, include_cached=False):
    identities = sorted(done) if include_cached else [
        (pair.get("requested_options"), pair.get("vendor_class", "")) for pair in pairs
    ]
    records = []
    for identity in identities:
        record = done.get(identity)
        if not record or record.get("status") != 200:
            continue
        if not record.get("device_name") or float(record.get("score") or 0) <= 0:
            continue
        item = {"fingerprints": [record["requested_options"]], "device_path": record["device_name"], "score": record.get("score", 0)}
        if record.get("vendor_class"):
            item["vendor_classes"] = [record["vendor_class"]]
        records.append(item)
    return records


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--cache", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--interval", type=float, default=10.0)
    parser.add_argument("--timeout", type=float, default=25.0)
    parser.add_argument("--include-cached", action="store_true", help="retain completed combinations outside the current input window")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--plan-fields", nargs="+", choices=sorted(PILOT_FIELDS),
                      help="prepare an offline multisignal plan for the selected fields")
    mode.add_argument("--query-fields", nargs="+", choices=sorted(PILOT_FIELDS),
                      help="interrogate only the selected pilot fields; maximum 20 uncached queries per run")
    parser.add_argument("--reviewed-upnp", help="JSON array of exact, reviewed non-identifying UPnP SERVER strings")
    parser.add_argument("--mock-cache", action="store_true", help="use only explicitly synthetic offline cache entries")
    args = parser.parse_args()

    if args.plan_fields or args.query_fields:
        if args.include_cached or (args.query_fields and args.mock_cache):
            parser.error("pilot query uses only its current input and real cache")
        if os.path.realpath(args.output) in {os.path.realpath(p) for p in (args.input, args.cache, args.reviewed_upnp) if p}:
            parser.error("plan output must be separate from the input and cache files")
        reviewed = []
        if args.reviewed_upnp:
            with open(args.reviewed_upnp, encoding="utf-8") as handle:
                reviewed = json.load(handle)
            if not isinstance(reviewed, list) or not all(generic_upnp(v) for v in reviewed):
                parser.error("reviewed UPnP values must be exact product/version headers")
        with open(args.input, encoding="utf-8") as handle:
            rows = (json.loads(line) for line in handle if line.strip())
            if args.query_fields:
                key = os.environ.get("FB_API_KEY", "").strip()
                plan = query_pilot(rows, args.query_fields, set(reviewed), args.cache,
                                   20 if args.limit is None else args.limit, args.interval, args.timeout, key)
            else:
                plan = offline_plan(rows, args.plan_fields, set(reviewed), args.cache,
                                    200 if args.limit is None else args.limit, "fingerbank_mock" if args.mock_cache else "fingerbank_v2")
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(plan, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        if plan.get("stopped"):
            sys.exit(f"pilot stopped: {plan['stopped']}")
        return
    if args.reviewed_upnp or args.mock_cache:
        parser.error("use --plan-fields for pilot options")
    key = os.environ.get("FB_API_KEY", "").strip()
    if not key:
        sys.exit("FB_API_KEY is required")

    pairs = []
    with open(args.input, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                pairs.append(json.loads(line))
    pairs = pairs[: 200 if args.limit is None else args.limit]
    done = load_done(args.cache)
    cache = open(args.cache, "a", encoding="utf-8")
    queried = 0
    for index, pair in enumerate(pairs, 1):
        identity = (pair.get("requested_options"), pair.get("vendor_class", ""))
        if identity in done:
            continue
        request = build_request(key, identity[0], identity[1])
        record = {"requested_options": identity[0], "vendor_class": identity[1], "queried_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        for attempt in range(4):
            try:
                with urllib.request.urlopen(request, timeout=args.timeout) as response:
                    data = json.loads(response.read().decode())
                record.update(
                    status=200,
                    device_name=data.get("device_name", ""),
                    score=data.get("score", 0),
                    request_id=data.get("request_id", ""),
                )
                break
            except urllib.error.HTTPError as err:
                if err.code == 404:
                    record.update(status=404, reason="no_match")
                    break
                if err.code == 429:
                    sys.stderr.write("rate limited; sleeping 60s\n")
                    time.sleep(60)
                    continue
                record.update(status=err.code, reason=err.read().decode(errors="replace")[:200])
                break
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as err:
                record.update(status=-1, reason=str(err)[:200])
                time.sleep(5 + attempt * 5)
        cache.write(json.dumps(record, ensure_ascii=False) + "\n")
        cache.flush()
        done[identity] = record
        queried += 1
        if index % 20 == 0:
            sys.stderr.write(f"progress {index}/{len(pairs)} queried={queried} last={record.get('status')}\n")
        time.sleep(args.interval)

    records = raw_records(done, pairs, args.include_cached)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(records, handle, ensure_ascii=False, indent=1)
    sys.stderr.write(f"wrote {len(records)} raw records from {len(pairs)} pairs\n")


if __name__ == "__main__":
    main()
