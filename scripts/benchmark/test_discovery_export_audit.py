import csv
import io
import unittest

from discovery_export_audit import audit


def sample(rows):
    data = io.StringIO(newline='')
    csv.writer(data).writerows([['标识', '记录种类', '筛选范围', '快照时间', '导出总数'], *rows])
    data.seek(0)
    return data


class ExportAuditTest(unittest.TestCase):
    def test_quoted_multiline(self):
        result = audit(sample([['a,\nb', '发现记录', 'mode=passive', 'stamp', '1']]),
                       {'record':'manifest', 'total':1, 'snapshot_at':'stamp'},
                       {'record':'end', 'count':1, 'complete':True}, 'mode=passive')
        self.assertEqual(result['device_rows'], 1)

    def test_empty_snapshot(self):
        result = audit(sample([['', '导出摘要', '', 'stamp', '0']]),
                       {'record':'manifest', 'total':0, 'snapshot_at':'stamp'},
                       {'record':'end', 'count':0, 'complete':True}, '')
        self.assertEqual(result['device_rows'], 0)

    def test_reject_invalid_manifest_or_rows(self):
        manifest = {'record':'manifest', 'total':1, 'snapshot_at':'stamp'}
        end = {'record':'end', 'count':1, 'complete':True}
        for rows, footer in [
            ([], end),
            ([['a','发现记录','','other','1']], end),
            ([['a','发现记录','','stamp','1']], dict(end, complete=False)),
            ([['a','发现记录','wrong','stamp','1']], end),
            ([['a','发现记录','','stamp','2']], end),
        ]:
            with self.subTest(rows=rows, footer=footer), self.assertRaises(ValueError):
                audit(sample(rows), manifest, footer, '')
