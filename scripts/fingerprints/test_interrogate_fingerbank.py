import unittest
import json
import tempfile
from pathlib import Path

from interrogate_fingerbank import build_request, load_done


class FingerbankRequestTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
