import { Alert, Tag } from 'antd'
import type { RootFilesystemStatus } from '../../shared/api/types'
import { formatBytes } from '../../shared/ui/formatBytes'

type Props = { status?: RootFilesystemStatus; error?: string }

function capacityIssue({ status, error }: Props) {
  if (error) return { title: '根盘容量读取失败', severity: 'warning' }
  if (!status) return undefined
  if (status.available_bytes < 1024 ** 3) return { title: '根盘空间不足', severity: 'critical' }
  if (status.inodes_free !== undefined && status.inodes_free < 1024) return { title: '根盘 inode 不足', severity: 'critical' }
  if (status.used_percent >= 90) return { title: '根盘空间紧张', severity: 'warning' }
  if (status.inodes_used_percent !== undefined && status.inodes_used_percent >= 95) return { title: '根盘 inode 紧张', severity: 'warning' }
  return undefined
}

export function RootFilesystemWarning(props: Props) {
  const issue = capacityIssue(props)
  if (!issue) return null
  return <Tag className={`overview-root-capacity-${issue.severity}`}>{issue.title}</Tag>
}

export function RootFilesystemCapacity({ status, error }: Props) {
  if (error) return <Alert className="overview-inline-alert" type="warning" showIcon title="根盘容量读取失败" description={error} />
  if (!status) return null
  return (
    <div className="overview-root-capacity">
      <div className="overview-root-capacity-row"><span>根盘 {status.path}</span><strong>可用 {formatBytes(status.available_bytes)}</strong></div>
      <div className="overview-root-capacity-meta"><span>总容量 {formatBytes(status.total_bytes)}</span><span>已用 {status.used_percent.toFixed(1)}%</span></div>
      {status.inodes_total !== undefined && status.inodes_free !== undefined && (
        <div className="overview-root-capacity-meta"><span>inode 可用 {status.inodes_free.toLocaleString()}</span><span>总量 {status.inodes_total.toLocaleString()}</span></div>
      )}
    </div>
  )
}
