import datetime as dt
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('refresh', Path(__file__).with_name('refresh-proxy-sources.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class EpochReplay(unittest.TestCase):
    def test_restart_scope_change_and_inactive_collector(self):
        now = dt.datetime(2026, 9, 30, tzinfo=dt.timezone.utc)
        profile = dict(sensor_id='office-30', campus_id='office-test', access_domain='office-lan')
        first, active = module.refresh({}, profile, {'zeek': 'a' * 32, 'suricata': 'b' * 32}, now)
        same, _ = module.refresh(first, profile, {'zeek': 'a' * 32, 'suricata': 'b' * 32}, now + dt.timedelta(seconds=30))
        self.assertEqual(first, same)
        restarted, new = module.refresh(first, profile, {'zeek': 'c' * 32, 'suricata': 'b' * 32}, now + dt.timedelta(minutes=1))
        self.assertNotEqual(active['zeek'], new['zeek'])
        self.assertEqual(active['suricata'], new['suricata'])
        old = next(p for p in restarted['producers'] if p['instance_id'] == active['zeek'])
        self.assertIn('valid_until', old)
        self.assertEqual(len(restarted['producers']), 3)
        stopped, _ = module.refresh(restarted, profile, {}, now + dt.timedelta(minutes=2))
        self.assertTrue(all('valid_until' in p for p in stopped['producers']))
        changed, ids = module.refresh(first, dict(profile, campus_id='other'), {'zeek': 'a' * 32}, now + dt.timedelta(minutes=3))
        self.assertNotEqual(ids['zeek'], active['zeek'])
        self.assertTrue(all(p.get('valid_until') for p in changed['producers'] if p['campus_id'] == 'office-test'))
        expired, _ = module.refresh(stopped, profile, {}, now + dt.timedelta(days=9))
        self.assertEqual(expired['producers'], [])
        with self.assertRaises(ValueError):
            module.refresh(stopped, profile, {'zeek': 'c' * 32}, now + dt.timedelta(minutes=4))


if __name__ == '__main__':
    unittest.main()
