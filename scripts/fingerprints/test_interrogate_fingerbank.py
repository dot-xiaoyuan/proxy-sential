import unittest
import io
import json
import tempfile
import sys
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

from interrogate_fingerbank import API, NoPilotRedirect, build_request, load_done, main, offline_plan, pilot_key, pilot_payload, query_pilot, raw_records


class FingerbankRequestTest(unittest.TestCase):
    def test_external_pilot_uses_only_approved_payload_and_resumes_accepted_results(self):
        fields = ["mdns_services", "upnp_server_strings", "ja3_fingerprints"]
        inputs = [{"mac": "00:11:22:33:44:55", "hostname": "private.example", "destination_hosts": ["secret.example"],
                   "mdns_services": ["_ipp._tcp", "room._ipp._tcp.local"], "upnp_server_strings": ["UPnP/1.1", "private.example"],
                   "ja3_fingerprints": ["A" * 32], "requested_options": "1,2,3"},
                  {"mdns_services": ["_raop._tcp"]}]
        response = MagicMock()
        response.__enter__.return_value.status = 200
        response.__enter__.return_value.read.return_value = b'{"device_name":"Printer","score":89}'
        missing = urllib.error.HTTPError(API, 404, "no match", {}, io.BytesIO())
        with tempfile.TemporaryDirectory() as directory, patch("urllib.request.build_opener") as opener, patch("time.sleep") as sleep:
            cache = Path(directory) / "cache"
            cache.write_bytes(b'{"interrupted":')
            transport = opener.return_value.open
            transport.side_effect = [response, missing]
            def run():
                return query_pilot(inputs, fields, {"UPnP/1.1"}, cache, 2, 10, 20, "test-only")
            first = run()
            self.assertEqual(first["queries"], 2)
            self.assertEqual(run()["queries"], 0)
            self.assertIsInstance(opener.call_args.args[0], NoPilotRedirect)
            req = transport.call_args_list[0].args[0]
            self.assertEqual(req.full_url, API)
            self.assertEqual(req.get_method(), "POST")
            self.assertEqual(req.get_header("Authorization"), "Bearer test-only")
            self.assertEqual(json.loads(req.data), {"mdns_services": ["_ipp._tcp.local"], "upnp_server_strings": ["UPnP/1.1"], "ja3_fingerprints": ["a" * 32]})
            self.assertEqual(sleep.call_count, 1)
            self.assertEqual([v["result"]["status"] for v in first["combinations"]], [200, 404])
            self.assertNotIn("test-only", cache.read_text())

    def test_pilot_stops_after_denial_and_will_not_follow_a_redirect(self):
        fields = ["mdns_services"]
        inputs = [{"mdns_services": [f"_type{i}._tcp"]} for i in range(3)]
        for status in [301, 401, 403, 429, 502]:
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory, patch("urllib.request.build_opener") as opener:
                transport = opener.return_value.open
                transport.side_effect = urllib.error.HTTPError(API, status, "stop", {}, io.BytesIO())
                result = query_pilot(inputs, fields, set(), Path(directory) / "cache", 2, 10, 20, "test-only")
                self.assertEqual((result["queries"], result["stopped"]), (1, f"HTTP {status}"))
                self.assertEqual(transport.call_count, 1)
        self.assertIsNone(NoPilotRedirect().redirect_request(None, None, 302, "", {}, "https://elsewhere.invalid"))
        for limit, interval in [(21, 10), (0, 10), (20, 9.9)]:
            with self.assertRaises(ValueError):
                query_pilot(inputs, fields, set(), None, limit, interval, 20, "test-only")

    def test_pilot_resume_uses_next_uncached_combination_and_honors_rate(self):
        inputs = [{"mdns_services": [f"_type{i}._tcp"]} for i in range(2)]
        with tempfile.TemporaryDirectory() as directory, patch("time.time", return_value=1000.0), patch("time.sleep") as sleep, patch("urllib.request.build_opener") as opener:
            path = Path(directory) / "cache"
            opener.return_value.open.side_effect = [urllib.error.HTTPError(API, 404, "", {}, io.BytesIO()) for _ in inputs]
            for expected in [1, 0]:
                plan = query_pilot(inputs, ["mdns_services"], set(), path, 1, 10, 20, "test-only")
                self.assertEqual((plan["queries"], plan["deferred_by_limit"]), (1, expected))
            sleep.assert_called_once_with(10)

    def test_pilot_accepts_only_selected_scoped_patterns(self):
        signals = {"hostname": "private.example", "mac": "00:11:22:33:44:55", "oui": "001122",
                   "destination_hosts": ["private.example"], "ja3_data": {"private.example:443": ["opaque"]},
                   "mdns_services": ["_IPP._TCP.LOCAL.", "Room 101._ipp._tcp.local", "_ipp._tcp.example"],
                   "upnp_server_strings": ["UPnP/1.1", "System/1.0 private.example"],
                   "ja3_fingerprints": ["AB" * 16, "client.example"]}
        self.assertEqual(pilot_payload(signals, {"mdns_services", "upnp_server_strings", "ja3_fingerprints"}, {"UPnP/1.1"}),
                         {"mdns_services": ["_ipp._tcp.local"], "upnp_server_strings": ["UPnP/1.1"], "ja3_fingerprints": ["ab" * 16]})
        self.assertEqual(pilot_payload(signals, {"upnp_server_strings"}, set()), {})
        unsafe_servers = ["Box/192.0.2.10", "https://private.example", "AA-BB-CC-DD-EE-FF/1", "ABCDEF012345/1"]
        self.assertEqual(pilot_payload({"upnp_server_strings": unsafe_servers}, {"upnp_server_strings"}, set(unsafe_servers)), {})
        self.assertEqual(pilot_payload({"mdns_services": ["_ipp._tcp"]}, {"mdns_services"}, set()), {"mdns_services": ["_ipp._tcp.local"]})
        with self.assertRaises(ValueError):
            offline_plan([], ["mac"], set(), None, 2, "fingerbank_v2")
        with self.assertRaises(ValueError):
            pilot_payload({"mdns_services": "_ipp._tcp.local"}, ["mdns_services"], set())

    def test_pilot_keys_include_all_fields_and_deduplicate_before_limit(self):
        a, b = "a" * 32, "b" * 32
        rows = [{"ja3_fingerprints": [a, b]}, {"ja3_fingerprints": [b, a, a]}, {"ja3_fingerprints": [a]}, {"hostname": "ignored"}]
        plan = offline_plan(rows, ["ja3_fingerprints"], set(), None, 1, "fingerbank_mock")
        self.assertEqual((plan["distinct_combinations"], plan["deferred_by_limit"], plan["rows_without_eligible_signals"]), (2, 1, 1))
        self.assertEqual(plan["combinations"][0]["rows"], 2)
        self.assertNotEqual(pilot_key({"ja3_fingerprints": [a]}), plan["combinations"][0]["cache_key"])

    def test_offline_pilot_cache_is_resumable_and_separate_from_real_clues(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, cache, output = (root / name for name in ("input", "cache", "output"))
            payload = {"mdns_services": ["_ipp._tcp.local"]}
            source.write_text(json.dumps(payload) + "\n")
            record = dict(payload=payload, cache_key=pilot_key(payload), source="fingerbank_mock", status=200, device_name="Printer", score=93)
            cache.write_text(json.dumps(dict(record, status=429)) + "\n{incomplete\n")
            args = ["interrogate", "--input", str(source), "--cache", str(cache), "--output", str(output), "--plan-fields", "mdns_services"]
            def run(mock):
                with patch.object(sys, "argv", args + (["--mock-cache"] if mock else [])), patch("urllib.request.urlopen", side_effect=AssertionError("unexpected network")):
                    main()
                return json.loads(output.read_text())["combinations"][0].get("result")
            self.assertIsNone(run(True))
            cache.write_text(json.dumps(record) + "\n")
            self.assertEqual(load_done(cache), {})
            self.assertIsNone(run(False))
            self.assertEqual(run(True), {"source": "fingerbank_mock", "status": 200, "device_name": "Printer", "score": 93})
            cache.write_text(json.dumps(dict(record, status=404)) + "\n")
            self.assertEqual(run(True), {"source": "fingerbank_mock", "status": 404})
    def test_api_key_is_only_in_authorization_header(self):
        request = build_request("sample-secret", "1,3,6,15", "vendor")

        self.assertEqual(request.full_url, "https://api.fingerbank.org/api/v2/combinations/interrogate")
        self.assertEqual(request.get_header("Authorization"), "Bearer sample-secret")
        self.assertNotIn("sample-secret", request.full_url)
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.data, b'{"dhcp_fingerprint": "1,3,6,15", "dhcp_vendor": "vendor"}')

    def test_retryable_responses_are_not_treated_as_completed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cache.jsonl"
            path.write_text("\n".join(json.dumps({"requested_options": str(status), "vendor_class": "", "status": status}) for status in [200, 404, 429, -1]))
            done = load_done(path)
        self.assertEqual(set(done), {("200", ""), ("404", "")})

    def test_refresh_keeps_completed_combinations_outside_current_window(self):
        done = {
            ("1,3", "old"): {"requested_options": "1,3", "vendor_class": "old", "status": 200, "device_name": "Printer", "score": 90},
            ("1,6", "new"): {"requested_options": "1,6", "vendor_class": "new", "status": 200, "device_name": "Phone", "score": 80},
            ("1,9", "missing"): {"requested_options": "1,9", "vendor_class": "missing", "status": 404},
        }
        pairs = [{"requested_options": "1,6", "vendor_class": "new"}]

        current = raw_records(done, pairs, include_cached=False)
        refreshed = raw_records(done, pairs, include_cached=True)

        self.assertEqual(len(current), 1)
        self.assertEqual(len(refreshed), 2)
        self.assertEqual([record["fingerprints"][0] for record in refreshed], ["1,3", "1,6"])


if __name__ == "__main__":
    unittest.main()
