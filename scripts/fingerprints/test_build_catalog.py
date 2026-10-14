import tempfile, unittest
from pathlib import Path
from build_catalog import Builder, whatweb, satori, librenms


class ConversionReplay(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def put(self, name, value):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(value)

    def test_whatweb_does_not_convert_comments_requests_or_executable_blocks(self):
        self.put(
            "whatweb/plugins/test.rb",
            """name "Fixture"
# {:text => "comment"}
matches [
 {:text => "static"},
 {:text => "header", :search => "headers[server]"},
 {:text => "restricted", :url => "/private"},
]
def aggressive
 { :text => "dynamic" }
end
""",
        )
        b = Builder(self.root)
        whatweb(b)
        rules = [r for r in b.rules if r["status"] == "converted"]
        self.assertEqual(
            [r["conditions"][0]["value"] for r in rules], ["static", "header"]
        )
        self.assertEqual(rules[1]["conditions"][0]["field"], "http_server")
        self.assertEqual(b.rules[-1]["status"], "unsupported_syntax")

    def test_dhcp_message_type_is_not_dropped(self):
        self.put(
            "satori/fingerprints/dhcp.xml",
            '<DHCP><fingerprints><fingerprint name="fixture"><tests><test matchtype="exact" dhcptype="Discover" dhcpvendorcode="x"/><test matchtype="exact" dhcptype="Any" dhcpvendorcode="x"/></tests></fingerprint></fingerprints></DHCP>',
        )
        b = Builder(self.root)
        satori(b)
        self.assertEqual(
            [r["status"] for r in b.rules], ["unsupported_input", "converted"]
        )

    def test_snmp_invalid_values_are_accounted(self):
        self.put(
            "librenms/resources/definitions/os_detection/test.yaml",
            'text: Fixture\ndiscovery:\n - sysObjectID: [".1.3.6.1.4.1.9", 9]\n',
        )
        b = Builder(self.root)
        librenms(b)
        self.assertEqual(len(b.rules), 2)
        self.assertEqual(b.rules[0]["conditions"][0]["operator"], "oid_prefix")
        self.assertEqual(b.rules[1]["status"], "invalid_data")


if __name__ == "__main__":
    unittest.main()
