#!/usr/bin/env python3
"""DHCP packet and two-process cluster replay; requires Zeek (validated on 8.0.9).

Run with ZEEK=/path/to/zeek python3 scripts/zeek/test_device_dhcp.py.
Only loopback Broker ports and temporary files are used; no live capture,
site/local.zeek, ZeekControl, databases, or running services are touched.
"""

import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "assets/zeek/device-dhcp.zeek"
FIXTURE = Path(__file__).with_name("fixtures") / "dhcp-cluster-replay.zeek"
ZEEK = os.environ.get("ZEEK", "zeek")
CASES = {
    "untagged-unicast": ([], [], False, "", False),
    "untagged-broadcast": ([], [], True, "", False),
    "single-vlan": ([42], [42], True, "42", False),
    "double-vlan": ([100, 42], [100, 42], False, "100/42", False),
    "different-vlan": ([42], [43], True, "43", True),
    "untagged-to-tagged": ([], [42], True, "42", True),
    "tagged-to-untagged": ([42], [], True, "", True),
    "different-inner-vlan": ([100, 42], [100, 43], True, "100/43", True),
}


def read_log(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def clean_env():
    env = os.environ.copy()
    # Do not inherit a production cluster layout or site script prefix.
    for key in ("CLUSTER_NODE", "ZEEKPATH", "ZEEK_PREFIXES", "ZEEK_SCRIPT_PREFIXES"):
        env.pop(key, None)
    return env


def dhcp_packet(xid, name, ack, broadcast, vlans, mac=None):
    if mac is None:
        mac = bytes.fromhex("020000000010")
    client = ipaddress.ip_address("192.0.2.10").packed
    server = ipaddress.ip_address("192.0.2.1").packed
    zero = bytes(4)
    bootp = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 2 if ack else 1,
                        1, 6, 0, xid, 0, 0x8000 if broadcast else 0,
                        client, client if ack else zero, server, zero,
                        mac.ljust(16, b"\0"), bytes(64), bytes(128))
    def option(code, data):
        return bytes([code, len(data)]) + data
    opts = option(53, bytes([5 if ack else 3]))
    opts += option(12, name.encode())
    opts += option(55, bytes([254]) if ack else bytes([1, 3, 6, 15, 119, 252]))
    opts += option(60, b"server-must-not-overwrite" if ack else b"sentinel-fixture")
    if ack:
        opts += option(51, struct.pack("!I", 600))
    payload = bootp + bytes.fromhex("63825363") + opts + b"\xff"
    udp = struct.pack("!HHHH", 67 if ack else 68, 68 if ack else 67, 8 + len(payload), 0) + payload
    src = server if ack else client
    dst = bytes([255] * 4) if ack and broadcast else (client if ack else server)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), xid, 0, 64, 17, 0, src, dst)
    eth = bytes.fromhex("ffffffffffff") + mac
    for i, vlan in enumerate(vlans):
        eth += struct.pack("!HH", 0x88A8 if len(vlans) == 2 and i == 0 else 0x8100, vlan)
    return eth + struct.pack("!H", 0x0800) + ip + udp


def write_pcap(path):
    with path.open("wb") as out:
        out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        # Each transaction is 20 seconds apart so Zeek's UDP connections have
        # expired: VLAN tests must not reuse a prior connection's first tag.
        for i, (name, (request_vlan, reply_vlan, broadcast, _, _)) in enumerate(CASES.items()):
            for ack, vlans in ((False, request_vlan), (True, reply_vlan)):
                packet = dhcp_packet(1001 + i, name, ack, broadcast, vlans)
                out.write(struct.pack("<IIII", 1700000000 + i * 20 + int(ack), 0, len(packet), len(packet)))
                out.write(packet)


def write_reused_xid_pcap(path):
    with path.open("wb") as out:
        out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, vlan in enumerate((42, 43)):
            mac = bytes.fromhex("0200000000" + ("10" if index == 0 else "11"))
            for ack in (False, True):
                packet = dhcp_packet(707, "overlap-" + str(vlan), ack, True, [vlan], mac)
                out.write(struct.pack("<IIII", 1700001000 + int(ack), index, len(packet), len(packet)))
                out.write(packet)


class DeviceDHCPReplay(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which(ZEEK):
            raise RuntimeError("Zeek is required; set ZEEK=/path/to/zeek (no tests skipped)")
        print(subprocess.check_output([ZEEK, "--version"], text=True).strip(), flush=True)

    def assert_logs(self, directory, cluster=False):
        rows = read_log(directory / "dhcp.log")
        records = {row["host_name"]: row for row in rows}
        expected = dict(CASES)
        if cluster:
            expected["missing-metadata"] = ([], [], False, None, False)
        self.assertEqual(len(rows), len(expected), "unexpected missing or duplicate DHCP transactions")
        self.assertEqual(set(records), set(expected))
        for name, (_, _, _, vlan, conflict) in expected.items():
            with self.subTest(case=name):
                row = records[name]
                self.assertEqual(row.get("requested_options"), "1,3,6,15,119,252")
                self.assertEqual(row.get("vendor_class"), "sentinel-fixture")
                self.assertGreater(row.get("lease_observed_at", 0), 0)
                self.assertIn("ACK", row["msg_types"])
                self.assertEqual(row.get("assigned_addr"), "192.0.2.10")
                self.assertEqual(row.get("lease_time"), 600)
                self.assertEqual(row.get("capture_vlan"), vlan)
                self.assertEqual(row.get("discovery_scope_conflict"), conflict)
                if not cluster:
                    index = list(CASES).index(name)
                    self.assertEqual(row["lease_observed_at"], 1700000001 + index * 20)
        errors = [row for row in read_log(directory / "reporter.log") if "ERROR" in row.get("level", "")]
        self.assertEqual(errors, [], "Zeek reported runtime errors")

    def test_packet_replay(self):
        self.run_packet_replay(50)

    def test_packet_replay_at_transaction_limit(self):
        self.run_packet_replay(2)

    def run_packet_replay(self, max_messages):
        with tempfile.TemporaryDirectory(prefix="sentinel-dhcp-packet-") as temp:
            directory = Path(temp)
            write_pcap(directory / "dhcp.pcap")
            result = subprocess.run([ZEEK, "-C", "-r", "dhcp.pcap", str(SCRIPT),
                                     "LogAscii::use_json=T", "udp_inactivity_timeout=5secs",
                                     f"DHCP::max_msg_types_per_log_entry={max_messages}"],
                                    cwd=directory, env=clean_env(), text=True, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assert_logs(directory)
            messages = read_log(directory / "device_dhcp_message.log")
            self.assertEqual(len(messages), 2 * len(CASES))
            acks = {row["xid"]: row for row in messages if row["msg_types"] == "ACK"}
            self.assertEqual(len(acks), len(CASES))
            for index, (_, (_, reply_vlan, _, _, _)) in enumerate(CASES.items()):
                row = acks[1001 + index]
                expected_vlan = "/".join(map(str, reply_vlan))
                self.assertEqual(row["capture_vlan"], expected_vlan)
                self.assertEqual(row["assigned_addr"], "192.0.2.10")
                self.assertEqual(row["mac"], "02:00:00:00:00:10")
            bindings = read_log(directory / "device_dhcp_binding.log")
            safe = {1001 + index for index, (_, (request_vlan, reply_vlan, _, _, _))
                    in enumerate(CASES.items()) if request_vlan == reply_vlan}
            self.assertEqual({row["xid"] for row in bindings}, safe)
            self.assertEqual(len(bindings), len(safe))

    def test_per_message_log_separates_reused_transaction_id(self):
        with tempfile.TemporaryDirectory(prefix="sentinel-dhcp-reused-xid-") as temp:
            directory = Path(temp)
            write_reused_xid_pcap(directory / "dhcp.pcap")
            result = subprocess.run([ZEEK, "-C", "-r", "dhcp.pcap", str(SCRIPT),
                                     "LogAscii::use_json=T", "udp_inactivity_timeout=5secs"],
                                    cwd=directory, env=clean_env(), text=True, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            messages = read_log(directory / "device_dhcp_message.log")
            acks = [row for row in messages if row["msg_types"] == "ACK"]
            self.assertEqual(len(acks), 2, messages)
            self.assertEqual({(row["capture_vlan"], row["mac"]) for row in acks},
                             {("42", "02:00:00:00:00:10"), ("43", "02:00:00:00:00:11")})
            bindings = read_log(directory / "device_dhcp_binding.log")
            self.assertEqual({(row["capture_vlan"], row["mac"]) for row in bindings},
                             {("42", "02:00:00:00:00:10"), ("43", "02:00:00:00:00:11")})

    def test_cluster_transport_without_local_connections(self):
        self.run_cluster_replay(50)

    def test_cluster_transport_at_transaction_limit(self):
        self.run_cluster_replay(2)

    def run_cluster_replay(self, max_messages):
        with tempfile.TemporaryDirectory(prefix="sentinel-dhcp-cluster-") as temp:
            directory = Path(temp)
            port = free_port()
            (directory / "cluster-layout.zeek").write_text(
                'redef Cluster::nodes = {\n'
                f' ["manager"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p={port}/tcp],\n'
                ' ["worker"] = [$node_type=Cluster::WORKER, $ip=127.0.0.1, $manager="manager"]\n};\n'
                'redef Broker::default_listen_address = "127.0.0.1";\n'
                'redef Cluster::retry_interval = 1sec;\n')
            processes = []
            try:
                for node in ("manager", "worker"):
                    cwd = directory / node
                    cwd.mkdir()
                    shutil.copyfile(directory / "cluster-layout.zeek", cwd / "cluster-layout.zeek")
                    env = clean_env()
                    env["CLUSTER_NODE"] = node
                    proc = subprocess.Popen([ZEEK, str(SCRIPT), str(FIXTURE), "LogAscii::use_json=T",
                                             f"DHCP::max_msg_types_per_log_entry={max_messages}"],
                                            cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    processes.append((node, proc))
                for node, proc in processes:
                    stdout, stderr = proc.communicate(timeout=20)
                    self.assertEqual(proc.returncode, 0, f"{node}: {stderr}\n{stdout}")
                    if node == "manager":
                        self.assertIn("fixture received 18 DHCP messages without local connections", stdout)
                self.assert_logs(directory / "manager", cluster=True)
            finally:
                for _, proc in processes:
                    if proc.poll() is None:
                        proc.kill()
                        proc.communicate()


if __name__ == "__main__":
    unittest.main(verbosity=2)
