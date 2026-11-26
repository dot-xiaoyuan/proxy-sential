import { CheckCircleOutlined, DeleteOutlined, SaveOutlined } from '@ant-design/icons'
import { useQueryClient } from '@tanstack/react-query'
import { Button, Input, Select, Tag, Typography, message } from 'antd'
import { useEffect, useState } from 'react'
import { api } from '../shared/api/client'
import { queryKeys, useAssetAnnotations } from '../shared/api/queries'
import type { AssetManualAnnotation } from '../shared/api/types'
import { observedTimeTitle } from '../shared/ui/observedTime'

type Props = {
  targetKey: string
  sensorId?: string
  typeOptions: { value: string; label: string }[]
}

const statusOptions = [
  { value: 'verified', label: '人工已确认' },
  { value: 'corrected', label: '人工已纠偏' },
  { value: 'ignored', label: '暂不纳管' },
  { value: 'unverified', label: '待复核' },
] as const

const statusLabels: Record<string, string> = {
  verified: '人工已确认',
  corrected: '人工已纠偏',
  ignored: '暂不纳管',
  unverified: '待复核',
}

export function AssetAnnotationCard({ targetKey, sensorId, typeOptions }: Props) {
  const queryClient = useQueryClient()
  const { data, isLoading } = useAssetAnnotations(targetKey, Boolean(targetKey))
  const existing = data?.items?.[0]
  const writable = data?.writable ?? false

  const [status, setStatus] = useState<AssetManualAnnotation['verification_status']>('verified')
  const [overrideType, setOverrideType] = useState('')
  const [overrideBrand, setOverrideBrand] = useState('')
  const [overrideModel, setOverrideModel] = useState('')
  const [department, setDepartment] = useState('')
  const [ownerName, setOwnerName] = useState('')
  const [assetTag, setAssetTag] = useState('')
  const [note, setNote] = useState('')
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    setStatus(existing?.verification_status ?? 'verified')
    setOverrideType(existing?.override_device_type ?? '')
    setOverrideBrand(existing?.override_brand ?? '')
    setOverrideModel(existing?.override_model ?? '')
    setDepartment(existing?.department ?? '')
    setOwnerName(existing?.owner_name ?? '')
    setAssetTag(existing?.asset_tag ?? '')
    setNote(existing?.note ?? '')
  }, [existing, targetKey])

  if (!targetKey) return null

  const save = async () => {
    setSaving(true)
    try {
      await api.upsertAssetAnnotation({
        target_key: targetKey,
        sensor_id: sensorId ?? '',
        verification_status: status,
        override_device_type: overrideType,
        override_brand: overrideBrand,
        override_model: overrideModel,
        department,
        owner_name: ownerName,
        asset_tag: assetTag,
        note,
      })
      await queryClient.invalidateQueries({ queryKey: queryKeys.assetAnnotations(targetKey) })
      message.success('资产核验标注已保存并记入审计日志')
    } catch (err) {
      message.error(err instanceof Error ? err.message : '保存标注失败')
    } finally {
      setSaving(false)
    }
  }

  const remove = async () => {
    setSaving(true)
    try {
      await api.deleteAssetAnnotation(targetKey)
      await queryClient.invalidateQueries({ queryKey: queryKeys.assetAnnotations(targetKey) })
      message.success('已清除人工标注')
    } catch (err) {
      message.error(err instanceof Error ? err.message : '清除标注失败')
    } finally {
      setSaving(false)
    }
  }

  return (
    <section className="asset-annotation-card" aria-label="人工核验与资产备注">
      <div className="asset-annotation-head">
        <div className="asset-annotation-title">
          <CheckCircleOutlined aria-hidden="true" />
          <Typography.Text strong>人工核验与资产备注</Typography.Text>
          {existing && (
            <Tag color={existing.verification_status === 'corrected' ? 'blue' : existing.verification_status === 'verified' ? 'green' : 'default'}>
              {statusLabels[existing.verification_status] ?? existing.verification_status}
            </Tag>
          )}
        </div>
        {existing?.updated_at && (
          <Typography.Text type="secondary" className="asset-annotation-meta">
            {existing.updated_by ? `${existing.updated_by} · ` : ''}
            {observedTimeTitle(existing.updated_at)}
          </Typography.Text>
        )}
      </div>

      {!writable && !isLoading && (
        <Typography.Text type="secondary" className="asset-annotation-readonly">
          当前站点处于严格只读模式，人工标注仅支持查阅。
        </Typography.Text>
      )}

      <div className="asset-annotation-grid">
        <label className="asset-annotation-field">
          <span>核验状态</span>
          <Select
            aria-label="核验状态"
            size="small"
            disabled={!writable || saving}
            value={status}
            options={statusOptions.map(item => ({ value: item.value, label: item.label }))}
            onChange={value => setStatus(value)}
          />
        </label>
        <label className="asset-annotation-field">
          <span>人工纠偏类型</span>
          <Select
            aria-label="人工纠偏类型"
            size="small"
            allowClear
            showSearch
            optionFilterProp="label"
            placeholder="保持被动识别结果"
            disabled={!writable || saving}
            value={overrideType || undefined}
            options={typeOptions}
            onChange={value => setOverrideType(value ?? '')}
          />
        </label>
        <label className="asset-annotation-field">
          <span>品牌纠偏</span>
          <Input
            aria-label="品牌纠偏"
            size="small"
            placeholder="如 锐捷 / 华为"
            disabled={!writable || saving}
            value={overrideBrand}
            onChange={event => setOverrideBrand(event.target.value)}
          />
        </label>
        <label className="asset-annotation-field">
          <span>型号纠偏</span>
          <Input
            aria-label="型号纠偏"
            size="small"
            placeholder="如 RG-AP820-L"
            disabled={!writable || saving}
            value={overrideModel}
            onChange={event => setOverrideModel(event.target.value)}
          />
        </label>
        <label className="asset-annotation-field">
          <span>归属单位</span>
          <Input
            aria-label="归属单位"
            size="small"
            placeholder="院系或管理部门"
            disabled={!writable || saving}
            value={department}
            onChange={event => setDepartment(event.target.value)}
          />
        </label>
        <label className="asset-annotation-field">
          <span>责任人</span>
          <Input
            aria-label="责任人"
            size="small"
            placeholder="管理责任人"
            disabled={!writable || saving}
            value={ownerName}
            onChange={event => setOwnerName(event.target.value)}
          />
        </label>
        <label className="asset-annotation-field">
          <span>资产编号</span>
          <Input
            aria-label="资产编号"
            size="small"
            placeholder="固定资产编码"
            disabled={!writable || saving}
            value={assetTag}
            onChange={event => setAssetTag(event.target.value)}
          />
        </label>
        <label className="asset-annotation-field asset-annotation-field-wide">
          <span>核验备注</span>
          <Input
            aria-label="核验备注"
            size="small"
            placeholder="现场确认位置、端口或用途说明"
            disabled={!writable || saving}
            value={note}
            onChange={event => setNote(event.target.value)}
          />
        </label>
      </div>

      {writable && (
        <div className="asset-annotation-actions">
          <Button type="primary" size="small" icon={<SaveOutlined aria-hidden="true" />} loading={saving} onClick={() => void save()}>
            保存标注
          </Button>
          {existing && (
            <Button size="small" danger icon={<DeleteOutlined aria-hidden="true" />} disabled={saving} onClick={() => void remove()}>
              清除标注
            </Button>
          )}
        </div>
      )}
    </section>
  )
}
