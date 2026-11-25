import csv
import tempfile
import unittest
from pathlib import Path
from inventory_compare import run, LEDGER_COLUMNS, SNAPSHOT_COLUMNS


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.system = self.root / "system.csv"
        self.ledger = self.root / "ledger.csv"
        self.out = self.root / "out"
        self.ip, self.mac = "10.161.64.28", "00:11:22:33:44:55"
        self.scope = ["campus-204", "campus", "mirror", "998", ""]

    def write(self, path, columns, rows):
        with path.open("w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(columns)
            writer.writerows(rows)

    def snapshot(self, *records):
        manifest = (
            ["manifest"]
            + [""] * 11
            + ["2026-11-25T03:00:00Z", str(len(records)), "2026-11-25T02:59:55Z"]
        )
        self.write(
            self.system,
            SNAPSHOT_COLUMNS,
            [manifest] + [list(r) + ["", "", ""] for r in records],
        )

    def binding(self, mac=None, state="identified", kind="access_point", model=""):
        return [
            "binding",
            *self.scope,
            self.ip,
            mac or self.mac,
            state,
            kind,
            model,
            "event-id",
        ]

    def entry(self, source, ip=None, mac=None, vlan="998", kind="AP", model="AP-model"):
        return [
            source,
            "2026-11-25T11:00:00+08:00",
            *self.scope[:3],
            vlan,
            "",
            ip or self.ip,
            mac or self.mac,
            kind,
            "厂商",
            model,
            "ID",
            "record-1",
        ]

    def test_exact_joins_and_three_sources(self):
        self.snapshot(
            self.binding(),
            ["ip", *self.scope, "10.161.64.88", "", "", "", "", "event-2"],
        )
        self.write(
            self.ledger,
            LEDGER_COLUMNS,
            [
                self.entry("AC 的 AP 清单"),
                self.entry("交换机台账", mac="02:00:00:00:00:01"),
                self.entry("一卡通平台", ip="10.161.64.88", mac="02:00:00:00:00:02"),
                self.entry("一卡通平台", ip="10.161.64.89", mac="02:00:00:00:00:03"),
            ],
        )
        result = run(self.system, [self.ledger], self.out)
        self.assertEqual(result["sources"]["AC 的 AP 清单"]["scoped_matches"], 1)
        self.assertEqual(
            result["sources"]["交换机台账"]["statuses"], {"换绑或归属差异": 1}
        )
        self.assertEqual(
            result["sources"]["一卡通平台"]["statuses"],
            {"仅见标识，缺有效绑定": 1, "窗口内未见标识": 1},
        )
        self.assertEqual(result["ap_model_supplements"], 1)

    def test_conflicts_incomplete_and_cross_scope(self):
        self.snapshot(self.binding(), self.binding(mac="02:00:00:00:00:01"))
        self.write(
            self.ledger,
            LEDGER_COLUMNS,
            [
                self.entry("AC 的 AP 清单"),
                self.entry("交换机台账", vlan="999"),
                self.entry("一卡通平台", vlan=""),
            ],
        )
        summary = run(self.system, [self.ledger], self.out)
        self.assertEqual(summary["ap_model_supplements"], 0)
        for name, reason in [
            ("AC 的 AP 清单", "系统绑定冲突"),
            ("交换机台账", "作用域差异"),
            ("一卡通平台", "台账字段待核实"),
        ]:
            self.assertEqual(summary["sources"][name]["statuses"], {reason: 1})

    def test_duplicate_ledger_and_incomplete_snapshot(self):
        self.snapshot(self.binding(state="candidate", kind=""))
        row = self.entry("AC 的 AP 清单")
        self.write(self.ledger, LEDGER_COLUMNS, [row, row])
        summary = run(self.system, [self.ledger], self.out)
        self.assertEqual(summary["ap_model_supplements"], 0)
        self.assertEqual(
            summary["sources"]["AC 的 AP 清单"]["statuses"], {"台账重复或冲突": 2}
        )
        self.system.write_text(self.system.read_text().splitlines()[0] + "\n")
        with self.assertRaises(ValueError):
            run(self.system, [self.ledger], self.root / "bad")
        self.assertFalse((self.root / "bad").exists())

    def test_missing_sources_do_not_report_zero_supplements(self):
        self.snapshot(self.binding())
        self.write(
            self.ledger,
            LEDGER_COLUMNS,
            [["AC 的 AP 清单"], ["交换机台账"], ["一卡通平台"]],
        )
        report = run(self.system, [self.ledger], self.out)
        self.assertFalse(
            any(source["provided"] for source in report["sources"].values())
        )
        self.assertIsNone(report["ap_model_supplements"])
        self.assertEqual([p.name for p in self.out.iterdir()], ["汇总.json"])

    def test_product_and_binding_reviews_do_not_supply_models(self):
        cases = [
            (self.binding(state="candidate", kind=""), {}, "已观测未定型", 1),
            (self.binding(model="Other"), {"model": "Different"}, "型号差异", 0),
            (self.binding(kind="switch"), {}, "类型差异", 0),
            (self.binding(state="product_conflict"), {}, "系统产品结论冲突", 0),
            (self.binding(), {"ip": "10.161.64.99"}, "换绑或归属差异", 0),
            (
                self.binding(),
                {"ip": "10.161.64.99", "mac": "02:12:34:00:00:01", "vlan": "3999"},
                "作用域缺观测",
                0,
            ),
        ]
        for index, (record, overrides, expected, model_count) in enumerate(cases):
            with self.subTest(expected=expected):
                self.snapshot(record)
                self.write(
                    self.ledger,
                    LEDGER_COLUMNS,
                    [self.entry("AC 的 AP 清单", **overrides)],
                )
                report = run(self.system, [self.ledger], self.root / str(index))
                self.assertEqual(
                    report["sources"]["AC 的 AP 清单"]["statuses"], {expected: 1}
                )
                self.assertEqual(report["ap_model_supplements"], model_count)

    def test_qinq_and_mac_formatting_without_vlan_guessing(self):
        self.scope[3] = "123/998"
        self.snapshot(self.binding(model="AP-model"))
        self.write(
            self.ledger,
            LEDGER_COLUMNS,
            [
                self.entry(
                    "AC 的 AP 清单", mac=self.mac.replace(":", "-"), vlan="0123/0998"
                ),
                self.entry("交换机台账", vlan="998/123"),
            ],
        )
        report = run(self.system, [self.ledger], self.out)
        self.assertEqual(report["sources"]["AC 的 AP 清单"]["statuses"], {"匹配": 1})
        self.assertEqual(report["sources"]["交换机台账"]["statuses"], {"作用域差异": 1})
