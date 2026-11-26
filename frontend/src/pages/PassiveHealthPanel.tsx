import { Button, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ReloadOutlined } from '@ant-design/icons'

import type { PassiveHealthSnapshot } from '../shared/api/types'
import { Notice as Alert } from '../shared/ui/Notice'
import { AppErrorAlert, AppListHeader, AppLoadingState, AppMetricCard, AppTable, formatDateTime } from '../shared/ui'

type WatermarkRow = NonNullable<PassiveHealthSnapshot['watermarks']>[number]

const ALERT_DESCRIPTIONS: Record<string, { label: string; level: 'error' | 'warning' | 'info' }> = {
  disk_free_below_10_percent: { label: '数据盘剩余空间低于 10%（高危，请立即核查日志轮转与数据库容量）', level: 'error' },
  disk_free_below_20_percent: { label: '数据盘剩余空间低于 20%（预警，建议核查容量增长趋势）', level: 'warning' },
  readyz: { label: '控制面就绪检查异常', level: 'error' },
  failed_units: { label: '存在异常退出的 systemd 服务单元', level: 'error' },
  hardware_queue_error: { label: '硬件识别投影队列存在处理错误', level: 'error' },
  source_watermark_lag_high: { label: '存在被动发现采集源消费滞后超过 15 分钟', level: 'warning' },
  recent_delayed_inserts: { label: '近 1 小时 ClickHouse 出现写入延迟（DelayedInserts）', level: 'warning' },
  recent_clickhouse_parse_failure: { label: '近 1 小时 ClickHouse 出现解析错误', level: 'warning' },
  archive_retry_exhausted: { label: '存在历史归档重试耗尽缺口（保留原始审计记录，不阻塞实时发现）', level: 'info' },
}

function formatBytes(bytes?: number): string {
  if (bytes === undefined || bytes < 0) return ''
  if (bytes < 1024) return `${bytes} B`
  const units = ['KiB', 'MiB', 'GiB', 'TiB']
  let value = bytes / 1024
  let idx = 0
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024
    idx += 1
  }
  return `${value.toFixed(value >= 100 ? 0 : 1)} ${units[idx]}`
}

function formatDurationSeconds(seconds?: number): string {
  if (seconds === undefined || seconds < 0) return ''
  if (seconds < 60) return `${seconds} 秒`
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分 ${seconds % 60} 秒`
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  return `${hours} 小时 ${minutes} 分`
}

function describeAlert(code: string) {
  if (ALERT_DESCRIPTIONS[code]) return ALERT_DESCRIPTIONS[code]
  if (code.endsWith(':check_failed')) {
    return { label: `探针 ${code.replace(':check_failed', '')} 本次采样超时或失败`, level: 'warning' as const }
  }
  if (code.includes('writes_without_merges')) {
    return { label: `ClickHouse 图表表存在写入未合并分片（${code}）`, level: 'warning' as const }
  }
  if (code.includes('partition_part_pressure')) {
    return { label: `ClickHouse 分区分片数接近写入延迟阈值（${code}）`, level: 'warning' as const }
  }
  return { label: code, level: 'warning' as const }
}

const watermarkColumns: ColumnsType<WatermarkRow> = [
  {
    title: '采集源',
    dataIndex: 'source_event_type',
    width: 170,
    render: (value: string) => <span className="mono-path">{value}</span>,
  },
  {
    title: '传感器',
    dataIndex: 'sensor_id',
    width: 130,
  },
  {
    title: '当前游标时间',
    dataIndex: 'cursor_timestamp',
    width: 185,
    render: (value: string) => <span className="mono-path">{formatDateTime(value)}</span>,
  },
  {
    title: '最近推进',
    dataIndex: 'updated_at',
    width: 185,
    render: (value: string) => <span className="mono-path">{formatDateTime(value)}</span>,
  },
  {
    title: '滞后',
    dataIndex: 'lag_seconds',
    width: 110,
    render: (value?: number) => {
      const lag = value ?? 0
      const color = lag > 900 ? 'red' : lag > 300 ? 'gold' : 'green'
      return (
        <Tag className="passive-health-tag" color={color}>
          {formatDurationSeconds(lag)}
        </Tag>
      )
    },
  },
]

export function PassiveHealthPanel({
  data,
  isLoading,
  isError,
  isFetching,
  onRefresh,
}: {
  data?: PassiveHealthSnapshot
  isLoading: boolean
  isError: boolean
  isFetching: boolean
  onRefresh: () => void
}) {
  if (isLoading) {
    return <AppLoadingState rows={5} />
  }
  if (isError) {
    return <AppErrorAlert title="系统健康快照读取失败" />
  }
  if (!data || !data.available) {
    return (
      <div className="tab-content-stack">
        <Alert
          type="info"
          showIcon
          title="尚未生成被动发现巡检快照"
          description="请确认 proxy-sentinel-passive-health.timer 已启用，或等待下一次每 10 分钟定时采样落盘。"
        />
      </div>
    )
  }

  const diskTotal = data.disk?.total ?? 0
  const diskAvail = data.disk?.available ?? 0
  const diskUsed = Math.max(0, diskTotal - diskAvail)
  const diskUsedPct = diskTotal > 0 ? Math.round((diskUsed / diskTotal) * 100) : undefined
  const activeAlerts = data.alerts ?? []
  const criticalOrWarnAlerts = activeAlerts.filter((code) => describeAlert(code).level !== 'info')
  const infoAlerts = activeAlerts.filter((code) => describeAlert(code).level === 'info')
  const sortedWatermarks = [...(data.watermarks ?? [])].sort(
    (a, b) => (b.lag_seconds ?? 0) - (a.lag_seconds ?? 0) || a.source_event_type.localeCompare(b.source_event_type),
  )

  return (
    <div className="tab-content-stack passive-health-panel" aria-label="系统健康与容量看板">
      <div className="passive-health-header">
        <div className="passive-health-meta">
          {data.release && <Tag className="passive-health-tag" color="blue">版本 {data.release}</Tag>}
          {data.sampled_at && (
            <Typography.Text type="secondary">
              最近采样：{formatDateTime(data.sampled_at)}（{formatDurationSeconds(data.age_seconds)}前）
            </Typography.Text>
          )}
          {data.stale && <Tag className="passive-health-tag" color="orange">巡检快照已过期</Tag>}
        </div>
        <Button icon={<ReloadOutlined />} loading={isFetching} onClick={onRefresh} size="small">
          刷新巡检
        </Button>
      </div>

      {criticalOrWarnAlerts.length > 0 ? (
        <Alert
          type={criticalOrWarnAlerts.some((c) => describeAlert(c).level === 'error') ? 'error' : 'warning'}
          showIcon
          title={`检测到 ${criticalOrWarnAlerts.length} 项运行告警`}
          description={
            <ul className="passive-health-alert-list">
              {criticalOrWarnAlerts.map((code) => (
                <li key={code}>{describeAlert(code).label}</li>
              ))}
            </ul>
          }
        />
      ) : (
        <Alert type="success" showIcon title="核心服务、磁盘水位与采集链路均运行正常" />
      )}

      {infoAlerts.length > 0 && (
        <Alert
          type="info"
          showIcon
          title="历史归档与审计提示"
          description={infoAlerts.map((code) => describeAlert(code).label).join('；')}
        />
      )}

      <div className="passive-health-kpi-grid">
        <AppMetricCard
          title="数据盘使用率"
          value={diskUsedPct !== undefined ? `${diskUsedPct}%` : ''}
          unit={diskTotal > 0 ? `剩余 ${formatBytes(diskAvail)} / 共 ${formatBytes(diskTotal)}` : undefined}
          statusText={diskUsedPct !== undefined && diskUsedPct >= 90 ? '高危' : diskUsedPct !== undefined && diskUsedPct >= 80 ? '预警' : '稳态'}
          statusColor={diskUsedPct !== undefined && diskUsedPct >= 90 ? 'red' : diskUsedPct !== undefined && diskUsedPct >= 80 ? 'orange' : 'green'}
        />
        <AppMetricCard
          title="PostgreSQL 占用"
          value={formatBytes(data.storage?.postgres_bytes)}
          unit={data.archive_hardware ? `硬件待处理 ${data.archive_hardware.hardware_waiting}` : undefined}
        />
        <AppMetricCard
          title="ClickHouse 占用"
          value={formatBytes(data.storage?.clickhouse_bytes)}
          unit={data.archive_hardware ? `归档失败缺口 ${data.archive_hardware.failed}` : undefined}
        />
        <AppMetricCard
          title="Zeek 当前日志目录"
          value={formatBytes(data.storage?.zeek_logs_bytes)}
          unit={`最大滞后 ${formatDurationSeconds(data.max_watermark_lag_seconds)}`}
          statusText={data.max_watermark_lag_seconds > 900 ? '滞后偏高' : '实时'}
          statusColor={data.max_watermark_lag_seconds > 900 ? 'orange' : 'green'}
        />
      </div>

      {(data.timers?.length ?? 0) > 0 && (
        <section className="passive-health-section" aria-label="定时维护任务">
          <AppListHeader title="自动化生命周期与巡检定时器" count={`${data.timers?.length ?? 0} 项启用`} />
          <div className="passive-health-timer-strip">
            {(data.timers ?? []).map((timer) => (
              <Tag key={timer.unit} className="passive-health-tag" color={timer.active ? 'green' : 'red'}>
                {timer.unit}
              </Tag>
            ))}
          </div>
        </section>
      )}

      <section className="passive-health-section" aria-label="采集源消费水位">
        <AppListHeader title="被动发现采集源实时水位" count={`${sortedWatermarks.length} 个采集源`} />
        <AppTable<WatermarkRow>
          columns={watermarkColumns}
          dataSource={sortedWatermarks}
          pagination={false}
          rowKey={(row) => `${row.sensor_id}:${row.source_event_type}`}
          scroll={{ x: 'max-content', y: 360 }}
          size="small"
        />
      </section>
    </div>
  )
}
