import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { PassiveHealthPanel } from './PassiveHealthPanel'
import type { PassiveHealthSnapshot } from '../shared/api/types'

const sampleHealth: PassiveHealthSnapshot = {
  available: true,
  stale: false,
  age_seconds: 120,
  sampled_at: '2026-11-26T11:20:00Z',
  release: '2026.11.26-12a9f70c',
  alerts: ['archive_retry_exhausted'],
  failed_units: [],
  timers: [
    { unit: 'proxy-sentinel-zeek-log-prune.timer', active: true },
    { unit: 'proxy-sentinel-device-retention.timer', active: true },
  ],
  disk: { available: 950_000_000_000, total: 1_800_000_000_000 },
  storage: {
    postgres_bytes: 45_000_000_000,
    clickhouse_bytes: 520_000_000_000,
    zeek_logs_bytes: 12_000_000_000,
  },
  archive_hardware: {
    hardware_waiting: 18,
    hardware_errors: 0,
    waiting: 0,
    retrying: 0,
    failed: 120,
  },
  watermarks: [
    {
      sensor_id: 'campus-204',
      source_event_type: 'capwap',
      cursor_timestamp: '2026-11-26T11:18:00Z',
      updated_at: '2026-11-26T11:19:50Z',
      lag_seconds: 120,
    },
  ],
  max_watermark_lag_seconds: 120,
}

describe('PassiveHealthPanel', () => {
  it('renders disk usage, storage breakdown, timers, watermarks, and separates historical archive note', () => {
    render(
      <PassiveHealthPanel
        data={sampleHealth}
        isLoading={false}
        isError={false}
        isFetching={false}
        onRefresh={vi.fn()}
      />,
    )
    expect(screen.getByText('核心服务、磁盘水位与采集链路均运行正常')).toBeInTheDocument()
    expect(screen.getByText('历史归档与审计提示')).toBeInTheDocument()
    expect(screen.getByText('47%')).toBeInTheDocument()
    expect(screen.getByText('proxy-sentinel-zeek-log-prune.timer')).toBeInTheDocument()
    expect(screen.getByText('capwap')).toBeInTheDocument()
  })

  it('surfaces critical disk alert and unavailable state cleanly', () => {
    const { rerender } = render(
      <PassiveHealthPanel
        data={{ ...sampleHealth, alerts: ['disk_free_below_10_percent', 'source_watermark_lag_high'] }}
        isLoading={false}
        isError={false}
        isFetching={false}
        onRefresh={vi.fn()}
      />,
    )
    expect(screen.getByText('检测到 2 项运行告警')).toBeInTheDocument()
    expect(screen.getByText(/数据盘剩余空间低于 10%/)).toBeInTheDocument()

    rerender(
      <PassiveHealthPanel
        data={{ available: false, stale: false, age_seconds: 0, alerts: [], failed_units: [], max_watermark_lag_seconds: 0 }}
        isLoading={false}
        isError={false}
        isFetching={false}
        onRefresh={vi.fn()}
      />,
    )
    expect(screen.getByText('尚未生成被动发现巡检快照')).toBeInTheDocument()
  })
})
