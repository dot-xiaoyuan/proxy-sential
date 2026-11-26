import { DeleteOutlined, DownloadOutlined, ReloadOutlined, UploadOutlined } from '@ant-design/icons'
import { useQueryClient } from '@tanstack/react-query'
import { Button, Input, Modal, Segmented, Select, Table, Tag, Typography, message } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { useMemo, useState } from 'react'
import { deviceTypeLabel } from '../entities/device/DeviceInventoryCells'
import { api } from '../shared/api/client'
import { queryKeys, useAssetLedgerReconcile, useAssetLedgers } from '../shared/api/queries'
import type { AssetLedgerEntry, AssetReconcileItem } from '../shared/api/types'
import { AppErrorAlert, AppMetricCard } from '../shared/ui'
import { observedTimeTitle } from '../shared/ui/observedTime'

const sourceKinds = [
  { value: 'ac_ap', label: '无线 AC 瘦 AP 台账' },
  { value: 'switch', label: '汇聚/接入交换机台账' },
  { value: 'camera', label: '安防摄像机台账' },
  { value: 'printer', label: '网络打印机台账' },
  { value: 'campus_card', label: '校园一卡通终端台账' },
  { value: 'general', label: '通用校园资产台账' },
] as const

const sourceKindLabelMap: Record<string, string> = Object.fromEntries(sourceKinds.map(k => [k.value, k.label]))

const statusMeta: Record<AssetReconcileItem['status'], { label: string; color: string }> = {
  registered_active: { label: '已登记在线', color: 'green' },
  discovered_unregistered: { label: '新发现未登记', color: 'orange' },
  ledger_offline: { label: '台账离线', color: 'default' },
  attribute_mismatch: { label: '属性不符', color: 'red' },
}

export function parseCampusLedgerCSV(text: string): AssetLedgerEntry[] {
  const lines = text
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(Boolean)
  if (lines.length === 0) return []

  const firstCells = lines[0].split(',').map(cell => cell.trim().toLowerCase())
  const hasHeader = firstCells.some(cell =>
    ['mac', 'ip', 'asset_name', 'name', 'expected_type', 'type', 'department', 'location', 'asset_tag'].includes(cell),
  )

  const headerIndex = (names: string[]) => firstCells.findIndex(cell => names.includes(cell))
  const start = hasHeader ? 1 : 0
  const entries: AssetLedgerEntry[] = []

  for (let i = start; i < lines.length; i++) {
    const cols = lines[i].split(',').map(cell => cell.trim())
    if (hasHeader) {
      const pick = (names: string[]) => {
        const idx = headerIndex(names)
        return idx >= 0 && idx < cols.length ? cols[idx] : ''
      }
      const entry: AssetLedgerEntry = {
        mac: pick(['mac', 'mac_address']),
        ip: pick(['ip', 'ip_address']),
        asset_name: pick(['asset_name', 'name', 'hostname']),
        expected_type: pick(['expected_type', 'type', 'device_type']),
        expected_vendor: pick(['expected_vendor', 'vendor', 'brand']),
        expected_model: pick(['expected_model', 'model']),
        department: pick(['department', 'dept']),
        location: pick(['location', 'room']),
        asset_tag: pick(['asset_tag', 'tag']),
      }
      if (entry.mac || entry.ip) entries.push(entry)
    } else {
      // 无表头简化模式：第 1 列自动识别 MAC 或 IP，后续列依次为名称、期望类型、单位
      const first = cols[0] ?? ''
      const isMAC = /^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i.test(first)
      const entry: AssetLedgerEntry = {
        mac: isMAC ? first : '',
        ip: isMAC ? (cols[1] && /^\d+\.\d+\.\d+\.\d+$/.test(cols[1]) ? cols[1] : '') : first,
        asset_name: isMAC ? (cols[1] && !/^\d+\.\d+\.\d+\.\d+$/.test(cols[1]) ? cols[1] : cols[2] ?? '') : cols[1] ?? '',
        expected_type: cols[2] ?? '',
        department: cols[3] ?? '',
      }
      if (entry.mac || entry.ip) entries.push(entry)
    }
  }
  return entries
}

function exportReconcileCSV(ledgerName: string, items: AssetReconcileItem[]) {
  const headers = ['对账结论', 'MAC', 'IP', '资产名称', '资产编号', '归属单位', '位置', '台账类型', '被动观测类型', '最近观测', '说明']
  const esc = (v?: string) => `"${String(v ?? '').replaceAll('"', '""')}"`
  const rows = [
    headers.join(','),
    ...items.map(item =>
      [
        statusMeta[item.status]?.label ?? item.status,
        item.mac,
        item.ip,
        item.asset_name,
        item.asset_tag,
        item.department,
        item.location,
        item.expected_type,
        item.observed_type,
        item.last_seen,
        item.detail,
      ]
        .map(esc)
        .join(','),
    ),
  ]
  const blob = new Blob(['\uFEFF' + rows.join('\n')], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `asset-reconcile-${ledgerName.replace(/[^a-zA-Z0-9\u4e00-\u9fa5_-]+/g, '_')}.csv`
  link.click()
  URL.revokeObjectURL(url)
}

export function AssetLedgerPanel() {
  const queryClient = useQueryClient()
  const ledgers = useAssetLedgers(true)
  const [selectedLedgerId, setSelectedLedgerId] = useState('')
  const [windowKey, setWindowKey] = useState<'24h' | '168h' | '720h'>('24h')
  const [statusFilter, setStatusFilter] = useState<string>('all')

  const [importOpen, setImportOpen] = useState(false)
  const [ledgerName, setLedgerName] = useState('')
  const [sourceKind, setSourceKind] = useState<string>('ac_ap')
  const [ledgerNote, setLedgerNote] = useState('')
  const [csvText, setCsvText] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const activeLedgerId = selectedLedgerId || ledgers.data?.items?.[0]?.ledger_id || ''
  const reconcile = useAssetLedgerReconcile(activeLedgerId, windowKey, Boolean(activeLedgerId))
  const writable = ledgers.data?.writable ?? false

  const filteredItems = useMemo(() => {
    const items = reconcile.data?.items ?? []
    if (statusFilter === 'all') return items
    return items.filter(item => item.status === statusFilter)
  }, [reconcile.data?.items, statusFilter])

  const submitImport = async () => {
    const entries = parseCampusLedgerCSV(csvText)
    if (!ledgerName.trim()) {
      message.warning('请填写台账名称')
      return
    }
    if (entries.length === 0) {
      message.warning('未解析出包含有效 MAC 或 IP 的台账记录')
      return
    }
    setSubmitting(true)
    try {
      const created = await api.createAssetLedger({
        name: ledgerName.trim(),
        source_kind: sourceKind,
        note: ledgerNote.trim(),
        entries,
      })
      await queryClient.invalidateQueries({ queryKey: queryKeys.assetLedgers })
      setSelectedLedgerId(created.ledger_id)
      setImportOpen(false)
      setLedgerName('')
      setLedgerNote('')
      setCsvText('')
      message.success(`已导入 ${created.entry_count} 条台账记录`)
    } catch (err) {
      message.error(err instanceof Error ? err.message : '导入台账失败')
    } finally {
      setSubmitting(false)
    }
  }

  const removeLedger = async (id: string) => {
    try {
      await api.deleteAssetLedger(id)
      await queryClient.invalidateQueries({ queryKey: queryKeys.assetLedgers })
      if (selectedLedgerId === id) setSelectedLedgerId('')
      message.success('已删除台账快照')
    } catch (err) {
      message.error(err instanceof Error ? err.message : '删除台账失败')
    }
  }

  const columns: ColumnsType<AssetReconcileItem> = [
    {
      title: '对账状态',
      dataIndex: 'status',
      width: 126,
      render: (value: AssetReconcileItem['status']) => {
        const meta = statusMeta[value]
        return <Tag color={meta?.color ?? 'default'}>{meta?.label ?? value}</Tag>
      },
    },
    {
      title: '设备标识',
      key: 'identity',
      width: 196,
      render: (_, record) => (
        <div className="asset-ledger-cell-stack">
          {record.ip && <span className="asset-ledger-mono">{record.ip}</span>}
          {record.mac && <span className="asset-ledger-mono">{record.mac}</span>}
        </div>
      ),
    },
    {
      title: '台账信息',
      key: 'ledger_info',
      width: 210,
      render: (_, record) => (
        <div className="asset-ledger-cell-stack">
          {record.asset_name && <Typography.Text strong>{record.asset_name}</Typography.Text>}
          {(record.department || record.location || record.asset_tag) && (
            <Typography.Text type="secondary">
              {[record.department, record.location, record.asset_tag].filter(Boolean).join(' · ')}
            </Typography.Text>
          )}
        </div>
      ),
    },
    {
      title: '品类对照',
      key: 'type_compare',
      width: 170,
      render: (_, record) => (
        <div className="asset-ledger-cell-stack">
          {record.expected_type && <span>台账：{deviceTypeLabel(record.expected_type)}</span>}
          {record.observed_type && <span>发现：{deviceTypeLabel(record.observed_type)}</span>}
        </div>
      ),
    },
    {
      title: '说明与观测时间',
      key: 'detail',
      render: (_, record) => (
        <div className="asset-ledger-cell-stack">
          {record.detail && <span>{record.detail}</span>}
          {record.last_seen && <Typography.Text type="secondary">{observedTimeTitle(record.last_seen)}</Typography.Text>}
        </div>
      ),
    },
  ]

  return (
    <section className="asset-ledger-panel" aria-label="校园资产台账持久对账">
      <div className="asset-ledger-toolbar">
        <div className="asset-ledger-title-group">
          <Typography.Title level={5}>校园资产台账对账</Typography.Title>
          <Typography.Text type="secondary">
            持久化导入 AC/交换机/安防台账，与当前窗口被动发现实时生成四象限差异清单
          </Typography.Text>
        </div>
        <div className="asset-ledger-actions">
          {writable && (
            <Button type="primary" icon={<UploadOutlined aria-hidden="true" />} onClick={() => setImportOpen(true)}>
              导入台账 CSV
            </Button>
          )}
          <Button
            icon={<ReloadOutlined aria-hidden="true" />}
            loading={ledgers.isFetching || reconcile.isFetching}
            onClick={() => {
              void ledgers.refetch()
              if (activeLedgerId) void reconcile.refetch()
            }}
          >
            刷新对账
          </Button>
        </div>
      </div>

      {ledgers.isError && <AppErrorAlert title="读取已导入台账失败" message={ledgers.error.message} />}

      {(ledgers.data?.items?.length ?? 0) === 0 && !ledgers.isLoading ? (
        <div className="asset-ledger-empty">
          <Typography.Text type="secondary">
            尚未导入校方资产台账。导入 CSV（含 mac 或 ip 列）后即可自动比对已登记在线、新发现未登记、台账离线与属性不符四类差异。
          </Typography.Text>
        </div>
      ) : (
        <>
          <div className="asset-ledger-selector-bar">
            <Select
              aria-label="选择已导入台账"
              className="asset-ledger-select"
              value={activeLedgerId || undefined}
              options={(ledgers.data?.items ?? []).map(item => ({
                value: item.ledger_id,
                label: `${item.name}（${sourceKindLabelMap[item.source_kind] ?? item.source_kind} · ${item.entry_count} 条）`,
              }))}
              onChange={value => setSelectedLedgerId(value)}
            />
            <Segmented<'24h' | '168h' | '720h'>
              aria-label="对账窗口"
              value={windowKey}
              options={[
                { value: '24h', label: '近 24 小时' },
                { value: '168h', label: '近 7 天' },
                { value: '720h', label: '近 30 天' },
              ]}
              onChange={value => setWindowKey(value)}
            />
            {reconcile.data && (
              <Button
                icon={<DownloadOutlined aria-hidden="true" />}
                onClick={() => exportReconcileCSV(reconcile.data!.ledger.name, filteredItems)}
              >
                导出差异 CSV
              </Button>
            )}
            {writable && activeLedgerId && (
              <Button danger icon={<DeleteOutlined aria-hidden="true" />} onClick={() => void removeLedger(activeLedgerId)}>
                删除台账
              </Button>
            )}
          </div>

          {reconcile.isError && <AppErrorAlert title="台账对账失败" message={reconcile.error.message} />}

          {reconcile.data && (
            <>
              <div className="asset-ledger-metrics">
                <AppMetricCard
                  title="已登记在线"
                  value={reconcile.data.summary.registered_active}
                  statusColor="green"
                  unit={`台账 ${reconcile.data.summary.ledger_total} 条`}
                />
                <AppMetricCard
                  title="新发现未登记"
                  value={reconcile.data.summary.discovered_unregistered}
                  statusColor={reconcile.data.summary.discovered_unregistered > 0 ? 'orange' : 'green'}
                  unit="台"
                />
                <AppMetricCard
                  title="台账离线"
                  value={reconcile.data.summary.ledger_offline}
                  statusColor={reconcile.data.summary.ledger_offline > 0 ? 'orange' : 'green'}
                  unit="台"
                />
                <AppMetricCard
                  title="属性不符"
                  value={reconcile.data.summary.attribute_mismatch}
                  statusColor={reconcile.data.summary.attribute_mismatch > 0 ? 'red' : 'green'}
                  unit="台"
                />
              </div>

              <div className="asset-ledger-filter-bar">
                <Segmented
                  aria-label="对账状态筛选"
                  value={statusFilter}
                  options={[
                    { value: 'all', label: `全部 (${reconcile.data.items.length})` },
                    { value: 'discovered_unregistered', label: `新发现未登记 (${reconcile.data.summary.discovered_unregistered})` },
                    { value: 'ledger_offline', label: `台账离线 (${reconcile.data.summary.ledger_offline})` },
                    { value: 'attribute_mismatch', label: `属性不符 (${reconcile.data.summary.attribute_mismatch})` },
                    { value: 'registered_active', label: `已登记在线 (${reconcile.data.summary.registered_active})` },
                  ]}
                  onChange={value => setStatusFilter(String(value))}
                />
              </div>

              <div className="asset-ledger-table-wrap">
                <Table
                  rowKey={row => `${row.status}-${row.mac ?? ''}-${row.ip ?? ''}-${row.asset_name ?? ''}-${row.detail ?? ''}`}
                  size="small"
                  columns={columns}
                  dataSource={filteredItems}
                  pagination={{ pageSize: 20, showSizeChanger: false }}
                  scroll={{ x: 760 }}
                />
              </div>
            </>
          )}
        </>
      )}

      <Modal
        title="导入校园资产台账（CSV）"
        open={importOpen}
        okText="持久化导入并立即对账"
        cancelText="取消"
        confirmLoading={submitting}
        onOk={() => void submitImport()}
        onCancel={() => setImportOpen(false)}
      >
        <div className="asset-ledger-import-form">
          <label className="asset-annotation-field">
            <span>台账名称</span>
            <Input
              aria-label="台账名称"
              placeholder="例如：2026秋季-核心区无线瘦AP台账"
              value={ledgerName}
              onChange={event => setLedgerName(event.target.value)}
            />
          </label>
          <label className="asset-annotation-field">
            <span>台账专项类别</span>
            <Select
              aria-label="台账专项类别"
              value={sourceKind}
              options={sourceKinds.map(k => ({ value: k.value, label: k.label }))}
              onChange={value => setSourceKind(value)}
            />
          </label>
          <label className="asset-annotation-field">
            <span>备注</span>
            <Input
              aria-label="台账备注"
              placeholder="导出自 AC 控制器或资产系统版本号"
              value={ledgerNote}
              onChange={event => setLedgerNote(event.target.value)}
            />
          </label>
          <label className="asset-annotation-field">
            <span>粘贴 CSV 内容（支持表头：mac,ip,asset_name,expected_type,expected_vendor,department,location,asset_tag）</span>
            <Input.TextArea
              aria-label="台账 CSV 内容"
              rows={7}
              placeholder={'mac,ip,asset_name,expected_type,department\n,10.42.1.11,教1-101-AP,access_point,网络中心'}
              value={csvText}
              onChange={event => setCsvText(event.target.value)}
            />
          </label>
        </div>
      </Modal>
    </section>
  )
}
