import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "collection_enable_plan", Path(__file__).with_name("collection_enable_plan.py")
)
planner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(planner)


def baseline():
    return {
        "version": 1,
        "allowed_cidrs": "10.0.0.0/8,fd00::/8",
        "event_bindings": [{"source": "zeek", "protocol": "dhcp", "site": "preserve"}],
        "enrichment_paths": [],
        "protocols": [
            {"protocol": protocol, "source": owner, "enabled": protocol in {"dns_sd", "ssdp", "ws_discovery"}}
            for protocol, owner in planner.OWNERS.items()
        ],
        "site_extension": {"keep": True},
    }


class CollectionEnablePlanTests(unittest.TestCase):
    def test_names_preserve_scope_and_unrelated_protocols(self):
        config = baseline()
        original = copy.deepcopy(config)
        candidate, changes = planner.make_candidate(config, "names")
        self.assertEqual(config, original)
        self.assertEqual(set(changes), {"nbns", "llmnr"})
        expected = copy.deepcopy(config)
        for entry in expected["protocols"]:
            if entry["protocol"] in {"nbns", "llmnr"}:
                entry["enabled"] = True
        self.assertEqual(candidate, expected)

    def test_each_batch_only_enables_its_protocols(self):
        for batch, protocols in planner.BATCHES.items():
            with self.subTest(batch=batch):
                candidate, changes = planner.make_candidate(baseline(), batch)
                self.assertEqual(set(changes), set(protocols))
                for entry in candidate["protocols"]:
                    if entry["source"] == "zeek":
                        self.assertFalse(entry["enabled"])

    def test_missing_duplicate_wrong_owner_and_wrong_bool_rejected(self):
        cases = []
        missing = baseline()
        missing["protocols"] = [p for p in missing["protocols"] if p["protocol"] != "nbns"]
        cases.append(missing)
        duplicate = baseline()
        duplicate["protocols"].append(copy.deepcopy(duplicate["protocols"][0]))
        cases.append(duplicate)
        owner = baseline()
        owner["protocols"][0]["source"] = "zeek"
        cases.append(owner)
        enabled = baseline()
        enabled["protocols"][0]["enabled"] = "false"
        cases.append(enabled)
        for config in cases:
            with self.assertRaises(ValueError):
                planner.make_candidate(config, "names")

    def test_already_enabled_does_not_create_a_new_change(self):
        candidate, _ = planner.make_candidate(baseline(), "names")
        with self.assertRaisesRegex(ValueError, "already enabled"):
            planner.make_candidate(candidate, "names")

    def test_plan_preserves_exact_rollback_bytes_and_never_overwrites(self):
        raw = json.dumps(baseline(), indent=4).encode() + b"\n\n"
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "names"
            planner.write_plan(raw, "names", destination)
            self.assertEqual((destination / "rollback.json").read_bytes(), raw)
            plan = json.loads((destination / "plan.json").read_text())
            self.assertFalse(plan["applied"])
            self.assertEqual(plan["changed_protocols"], ["nbns", "llmnr"])
            with self.assertRaises(FileExistsError):
                planner.write_plan(raw, "names", destination)

    def test_iot_zero_is_not_ready_and_129_is_not_truncated(self):
        self.assertEqual(planner.check_iot_candidates(baseline(), [])["status"], "no_candidates")
        rows = [dict(ip=f"10.0.0.{i}", vlan="", domain="mirror", interface_name="bond0", site="s") for i in range(1, 130)]
        report = planner.check_iot_candidates(baseline(), rows)
        self.assertEqual(report["status"], "over_capacity")
        self.assertEqual(report["candidate_rows"], 129)
        self.assertFalse(report["candidate_scope_ready"])

    def test_iot_rejects_ambiguous_scope_and_nonprivate_or_outside_scope(self):
        row = dict(ip="10.1.2.3", vlan="20", domain="mirror", interface_name="bond0", site="s")
        self.assertTrue(planner.check_iot_candidates(baseline(), [row])["candidate_scope_ready"])
        other = dict(row, domain="other")
        self.assertEqual(planner.check_iot_candidates(baseline(), [row, other])["status"], "ambiguous_scope")
        for ip in ["8.8.8.8", "192.168.1.1", "0.0.0.0"]:
            with self.assertRaises(ValueError):
                planner.check_iot_candidates(baseline(), [dict(row, ip=ip)])

    def test_iot_rejects_duplicate_rows_or_missing_scope(self):
        row = dict(ip="10.1.2.3", vlan="", domain="mirror", interface_name="bond0", site="s")
        for rows in [[row, row], [dict(row, domain="")], [dict(row, interface_name="")]]:
            with self.assertRaises(ValueError):
                planner.check_iot_candidates(baseline(), rows)


if __name__ == "__main__":
    unittest.main()
