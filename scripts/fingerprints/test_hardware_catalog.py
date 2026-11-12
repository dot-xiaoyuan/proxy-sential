import unittest
from build_hardware_catalog import condition, hardware_type, Unsupported

class HardwareConversionTest(unittest.TestCase):
    def test_and_or_exclusions_and_extra_oid(self):
        c = condition({'sysObjectID':['.1.2.3','.1.2.4'], 'sysDescr_except':'simulator', 'snmpget':{'oid':'.1.2.5.0','op':'contains','value':'sensor'}})
        self.assertEqual(len(c['all']), 3)
        self.assertEqual(len(c['all'][0]['any']), 2)
        self.assertEqual(c['all'][1]['not']['operator'], 'contains')
        self.assertEqual(c['all'][2]['field'],'oid:1.2.5.0')
    def test_no_condition_is_dropped(self):
        with self.assertRaises(Unsupported): condition({'sysObjectID':'.1.2.3','snmpwalk':'unknown'})
        with self.assertRaises(Unsupported): condition({'snmpget':{'oid':'SYMBOLIC::OID','value':'foo'}})
    def test_network_and_hikvision_not_hardware_types(self):
        self.assertEqual(hardware_type({'type':'network','text':'HPE Comware'}),'')
        self.assertEqual(hardware_type({'type':'network','text':'Hikvision NVR'}),'')
        self.assertEqual(hardware_type({'type':'environment','text':'NetBotz Environment Sensor'}),'environment_monitor')

if __name__=='__main__': unittest.main()
