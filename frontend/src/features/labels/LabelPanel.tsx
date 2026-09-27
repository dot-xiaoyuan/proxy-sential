import { Alert, App as AntApp, Button, Form, Input, Select } from 'antd'

import { useCreateLabel } from '../../shared/api/queries'
import type { LabelKind } from '../../shared/api/types'

const labelOptions: Array<{ label: string; value: LabelKind }> = [
  { label: '确认代理', value: 'confirmed_proxy' },
  { label: '误报', value: 'false_positive' },
  { label: '良性', value: 'benign' },
  { label: '需要更多数据', value: 'needs_more_data' },
]

type FormValue = {
  label: LabelKind
  reason: string
}

export function LabelPanel({
  targetId,
  targetType = 'ip',
  evidenceIds,
  disabled,
  onSubmitted,
}: {
  targetId: string
  targetType?: 'ip' | 'account' | 'endpoint'
  evidenceIds: string[]
  disabled?: boolean
  onSubmitted?: (label: LabelKind) => void
}) {
  const [form] = Form.useForm<FormValue>()
  const { message } = AntApp.useApp()
  const createLabel = useCreateLabel()
  const missingEvidence = evidenceIds.length === 0

  return (
    <Form
      form={form}
      layout="vertical"
      onFinish={(value) => {
        createLabel.mutate(
          {
            target_type: targetType,
            target_id: targetId,
            label: value.label,
            reason: value.reason,
            evidence_ids: evidenceIds,
          },
          {
            onSuccess: () => {
              message.success('标注已写入审计队列')
              onSubmitted?.(value.label)
              form.resetFields()
            },
          },
        )
      }}
    >
      {missingEvidence && (
        <Alert
          className="margin-bottom-md"
          showIcon
          title="当前对象没有可关联证据 ID，暂不能提交复核标注"
          type="warning"
        />
      )}
      <Form.Item
        label="复核结论"
        name="label"
        rules={[{ required: true, message: '请选择复核结论' }]}
      >
        <Select disabled={disabled || missingEvidence} options={labelOptions} placeholder="选择标注" />
      </Form.Item>
      <Form.Item
        label="复核原因"
        name="reason"
        rules={[{ required: true, min: 2, message: '请填写至少 2 个字符的原因' }]}
      >
        <Input.TextArea
          disabled={disabled || missingEvidence}
          placeholder="说明确认、误报或需要补充样本的依据"
          rows={4}
        />
      </Form.Item>
      <Button disabled={disabled || missingEvidence} htmlType="submit" loading={createLabel.isPending} type="primary">
        提交标注
      </Button>
    </Form>
  )
}
