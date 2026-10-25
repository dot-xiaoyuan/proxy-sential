#!/usr/bin/env python3
"""Prepare local discovery configuration candidates; never connects or deploys."""

import argparse
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import sys


OWNERS = {
    protocol: "discovery-worker"
    for protocol in (
        "dns_sd", "ssdp", "ws_discovery", "snmp", "arp", "ndp", "lldp", "cdp",
        "ieee1905_client_association", "dhcpv6", "nbns", "llmnr", "bacnet", "coap",
    )
}
OWNERS.update({protocol: "zeek" for protocol in ("dhcp", "ipp", "rtsp", "http", "tls", "mqtt")})
BATCHES = {
    "names": ("nbns", "llmnr"),
    "neighbors": ("lldp", "cdp"),
    "arp": ("arp",),
    "ndp": ("ndp",),
}
PRIVATE_SCOPE = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
    "fc00::/7", "fe80::/10",
))


def validate_config(config):
    if not isinstance(config, dict) or type(config.get("version")) is not int or config["version"] != 1:
        raise ValueError("collection version must be 1")
    cidrs = config.get("allowed_cidrs")
    if not isinstance(cidrs, str) or not cidrs.strip():
        raise ValueError("allowed_cidrs must be preserved and nonempty")
    networks = tuple(ipaddress.ip_network(value.strip(), strict=False) for value in cidrs.split(","))
    entries = config.get("protocols")
    if not isinstance(entries, list):
        raise ValueError("protocols must be an array")
    seen = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("protocol entry must be an object")
        protocol = entry.get("protocol")
        if not isinstance(protocol, str) or protocol in seen:
            raise ValueError("duplicate or invalid protocol")
        if protocol not in OWNERS or entry.get("source") != OWNERS[protocol]:
            raise ValueError("unsupported protocol or wrong owner: " + protocol)
        if type(entry.get("enabled")) is not bool:
            raise ValueError("enabled must be boolean: " + protocol)
        seen[protocol] = entry
    return seen, networks


def make_candidate(config, batch):
    seen, _ = validate_config(config)
    if batch not in BATCHES:
        raise ValueError("unsupported batch")
    for protocol in BATCHES[batch]:
        if protocol not in seen:
            raise ValueError("protocol missing from current configuration: " + protocol)
    changed = [protocol for protocol in BATCHES[batch] if not seen[protocol]["enabled"]]
    if not changed:
        raise ValueError("batch already enabled; no new change to apply")
    candidate = copy.deepcopy(config)
    for entry in candidate["protocols"]:
        if entry["protocol"] in changed:
            entry["enabled"] = True
    return candidate, changed


def write_plan(raw, batch, destination):
    candidate, changed = make_candidate(json.loads(raw), batch)
    candidate_bytes = (json.dumps(candidate, ensure_ascii=False, indent=2) + "\n").encode()
    plan = {
        "applied": False,
        "batch": batch,
        "changed_protocols": changed,
        "owner": "discovery-worker",
        "rollback_sha256": hashlib.sha256(raw).hexdigest(),
        "candidate_sha256": hashlib.sha256(candidate_bytes).hexdigest(),
        "minimum_observation_seconds": 1800,
        "requires_completed_original_recovery_observation": True,
        "zeek_bpf_change": False,
        "ingest_subscription_change": False,
        "notes": [],
    }
    if batch == "neighbors":
        plan["notes"].append("CDP capture received/parsed counters currently use other; inspect admitted receipts and bounded sample evidence.")
    if batch in {"arp", "ndp"}:
        plan["notes"].append("Only 100ms/250-record batch coalescing exists; estimate and observe input growth before proceeding.")
    # An exclusive directory preserves the exact baseline and prevents reusing a
    # prior review. The caller applies a candidate only after fresh host checks.
    destination = Path(destination)
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, data in (
        ("rollback.json", raw),
        ("candidate.json", candidate_bytes),
        ("plan.json", (json.dumps(plan, ensure_ascii=False, indent=2) + "\n").encode()),
    ):
        path = destination / name
        with path.open("xb") as output:
            path.chmod(0o600)
            output.write(data)
    return plan


def check_iot_candidates(config, rows):
    _, networks = validate_config(config)
    if not isinstance(rows, list):
        raise ValueError("candidates must be a JSON array from the bounded DISTINCT query")
    report = {
        "candidate_rows": len(rows), "maximum_candidate_rows": 128,
        "candidate_scope_ready": False,
        "status": "no_candidates" if not rows else "within_capacity",
        "applied": False,
    }
    if len(rows) > 128:
        report["status"] = "over_capacity"
        return report
    seen, identities = set(), {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("invalid candidate row")
        values = tuple(row.get(key) for key in ("ip", "vlan", "domain", "interface_name", "site"))
        if any(not isinstance(value, str) or any(c in value for c in "\t\r\n\x00") for value in values):
            raise ValueError("candidate fields must be bounded scope strings")
        ip, vlan, domain, interface, _ = values
        if not domain or not interface:
            raise ValueError("candidate requires domain and interface_name")
        address = ipaddress.ip_address(ip)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        if not any(address in network for network in PRIVATE_SCOPE):
            raise ValueError("candidate outside supported private scope")
        if not any(address in network for network in networks):
            raise ValueError("candidate outside current collection CIDRs")
        if values in seen:
            raise ValueError("duplicate candidate row; export must use DISTINCT")
        seen.add(values)
        key = (str(address), vlan)
        if key in identities:
            report["status"] = "ambiguous_scope"
        identities[key] = values
    report["candidate_scope_ready"] = bool(rows) and report["status"] == "within_capacity"
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare", help="write an unapplied candidate and exact rollback locally")
    prepare.add_argument("--config", type=Path, required=True)
    prepare.add_argument("--batch", choices=BATCHES, required=True)
    prepare.add_argument("--output-dir", type=Path, required=True)
    check = commands.add_parser("check-iot", help="check candidate count and scope only; does not enable IoT")
    check.add_argument("--config", type=Path, required=True)
    check.add_argument("--candidates", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.config.stat().st_size > 65536:
            raise ValueError("collection configuration budget exceeded")
        raw = args.config.read_bytes()
        if args.command == "prepare":
            result = write_plan(raw, args.batch, args.output_dir)
        else:
            if args.candidates.stat().st_size > 1024 * 1024:
                raise ValueError("candidate manifest budget exceeded")
            result = check_iot_candidates(json.loads(raw), json.loads(args.candidates.read_bytes()))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if args.command == "prepare" or result["candidate_scope_ready"] else 2
    except (ValueError, OSError) as error:
        parser.exit(2, "plan rejected: " + str(error) + "\n")


if __name__ == "__main__":
    sys.exit(main())
