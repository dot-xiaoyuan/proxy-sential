"""Interrogate Fingerbank for the DHCP fingerprints this site actually sees.

The daily bulk download is limited to one fetch per day, so this script queries
only the distinct (requested_options, vendor_class) pairs extracted from the
field DHCP logs. Requests are paced below the free hourly limit and every
response is cached so an interrupted run resumes without re-querying.

Input : JSONL with {"requested_options": "...", "vendor_class": "...", "count": N}
Output: JSONL raw records for CompileFingerbankSnapshot plus a cache file.

Only the two non-identifying DHCP fields are sent.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.fingerbank.org/api/v2/combinations/interrogate"


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
            done[(record.get("requested_options"), record.get("vendor_class"))] = record
    return done


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--cache", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--interval", type=float, default=10.0)
    parser.add_argument("--timeout", type=float, default=25.0)
    args = parser.parse_args()

    key = os.environ.get("FB_API_KEY", "").strip()
    if not key:
        sys.exit("FB_API_KEY is required")

    pairs = []
    with open(args.input, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                pairs.append(json.loads(line))
    pairs = pairs[: args.limit]
    done = load_done(args.cache)
    cache = open(args.cache, "a", encoding="utf-8")
    queried = 0
    for index, pair in enumerate(pairs, 1):
        identity = (pair.get("requested_options"), pair.get("vendor_class", ""))
        if identity in done:
            continue
        body = {"dhcp_fingerprint": identity[0]}
        if identity[1]:
            body["dhcp_vendor"] = identity[1]
        payload = json.dumps(body).encode()
        url = API + "?key=" + urllib.parse.quote(key)
        request = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
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

    records = []
    for pair in pairs:
        record = done.get((pair.get("requested_options"), pair.get("vendor_class", "")))
        if not record or record.get("status") != 200:
            continue
        if not record.get("device_name") or float(record.get("score") or 0) <= 0:
            continue
        item = {"fingerprints": [record["requested_options"]], "device_path": record["device_name"], "score": record.get("score", 0)}
        if record.get("vendor_class"):
            item["vendor_classes"] = [record["vendor_class"]]
        records.append(item)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(records, handle, ensure_ascii=False, indent=1)
    sys.stderr.write(f"wrote {len(records)} raw records from {len(pairs)} pairs\n")


if __name__ == "__main__":
    main()
