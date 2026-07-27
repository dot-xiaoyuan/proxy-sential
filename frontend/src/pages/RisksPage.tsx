import { useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Alert, Input, Select, Typography } from 'antd'

import { useRisks } from '../shared/api/queries'
import type { RiskLevel, RiskQuery } from '../shared/api/types'
import { RiskTable } from '../widgets/RiskTable'

const levelOptions: Array<{ label: string; value: RiskLevel | '' }> = [
  { label: '全部等级', value: '' },
  { label: '正常', value: 'normal' },
  { label: '可疑', value: 'suspicious' },
  { label: '高风险', value: 'high' },
  { label: '基本确认', value: 'confirmed' },
]

export function RisksPage() {
  const [params, setParams] = useSearchParams()
  const query = useMemo<RiskQuery>(
    () => ({
      level: (params.get('level') || undefined) as RiskLevel | undefined,
      q: params.get('q') || undefined,
      sensor_id: params.get('sensor_id') || undefined,
      limit: 50,
    }),
    [params],
  )
  const risks = useRisks(query)

  function updateParam(name: string, value?: string) {
    const next = new URLSearchParams(params)
    if (value) {
      next.set(name, value)
    } else {
      next.delete(name)
    }
    setParams(next)
  }

  return (
    <main className="page">
      <div className="page-header">
        <div>
          <Typography.Title className="page-title" level={3}>
            风险 IP
          </Typography.Title>
          <Typography.Text type="secondary">按等级、sensor 和关键词筛选风险快照。</Typography.Text>
        </div>
      </div>

      <section className="surface">
        <div className="toolbar">
          <Select
            aria-label="风险等级"
            options={levelOptions}
            style={{ width: 160 }}
            value={query.level ?? ''}
            onChange={(value) => updateParam('level', value)}
          />
          <Input.Search
            allowClear
            defaultValue={query.q}
            placeholder="搜索 IP 或解释"
            style={{ width: 260 }}
            onSearch={(value) => updateParam('q', value.trim())}
          />
          <Input.Search
            allowClear
            defaultValue={query.sensor_id}
            placeholder="sensor_id"
            style={{ width: 220 }}
            onSearch={(value) => updateParam('sensor_id', value.trim())}
          />
        </div>
      </section>

      {risks.isError && <Alert showIcon title="风险列表加载失败" type="error" />}
      <section className="surface">
        <RiskTable data={risks.data?.items ?? []} loading={risks.isLoading} />
      </section>
    </main>
  )
}
