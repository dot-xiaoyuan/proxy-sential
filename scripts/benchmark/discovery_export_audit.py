"""Verify downloaded CSV against the same response's NDJSON manifest and trailer."""
import csv
import json
import sys


def audit(stream, manifest, end, scope):
    total = manifest.get('total')
    stamp = manifest.get('snapshot_at')
    if (manifest.get('record') != 'manifest' or type(total) is not int or
            not 0 <= total <= 200_000 or not stamp or end.get('record') != 'end' or
            end.get('complete') is not True or type(end.get('count')) is not int or
            end['count'] != total):
        raise ValueError('快照清单或结束记录无效')
    rows = csv.reader(stream, strict=True)
    header = next(rows, [])
    if header[-4:] != ['记录种类', '筛选范围', '快照时间', '导出总数']:
        raise ValueError('末尾四列字段名称有误')
    kind = '发现记录' if total else '导出摘要'
    count = 0
    for row in rows:
        count += 1
        if len(row) != len(header) or row[-4:] != [kind, scope, stamp, str(total)]:
            raise ValueError(f'第 {count} 行字段数或导出摘要不匹配')
        if not total and any(row[:-4]):
            raise ValueError('空快照含有设备字段')
    if count != max(1, total):
        raise ValueError('CSV 行数与快照总数不一致')
    return {'device_rows': total, 'csv_columns': len(header), 'summary_fields': header[-4:],
            'scope': scope, 'snapshot_at': stamp, 'record_kind': kind}


if __name__ == '__main__':
    metadata = json.load(sys.stdin)
    with open(sys.argv[1], encoding='utf-8-sig', newline='') as stream:
        print(json.dumps(audit(stream, **metadata), ensure_ascii=False))
