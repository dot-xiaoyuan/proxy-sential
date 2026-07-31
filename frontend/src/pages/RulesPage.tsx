import { App as AntApp, Alert, Button, Descriptions, Skeleton, Space, Tag, Typography } from 'antd'

import { useReloadRules, useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'

const shadowActions = ['record', 'shadow_watch', 'shadow_manual_review', 'shadow_confirm_review']

export function RulesPage() {
  const session = useSession()
  const { message } = AntApp.useApp()
  const reloadRules = useReloadRules()
  const allowed = can(session.data, 'rules:reload')

  if (session.isLoading) {
    return <Skeleton active />
  }

  return (
    <main className="page">
      <div className="page-header">
        <div>
          <Typography.Title className="page-title" level={3}>
            规则配置
          </Typography.Title>
          <Typography.Text type="secondary">第一阶段只保留影子 reload 入口，不触发处罚动作。</Typography.Text>
        </div>
      </div>
      {!allowed && <Alert showIcon className="margin-bottom-md" title="当前会话没有 rules:reload 权限" type="warning" />}
      <section className="surface">
        <Typography.Title level={4}>影子模式规则矩阵</Typography.Title>
        <Descriptions bordered column={1} size="small" className="margin-bottom-lg">
          <Descriptions.Item label="配置版本">
            <Typography.Text className="mono">mock-rules-20260727</Typography.Text>
          </Descriptions.Item>
          <Descriptions.Item label="运行模式">
            <Tag color="processing">shadow</Tag>
          </Descriptions.Item>
          <Descriptions.Item label="动作边界">
            <Space wrap size={[6, 6]}>
              {shadowActions.map((action) => (
                <Tag color="blue" key={action} className="tag-margin-zero">
                  {action}
                </Tag>
              ))}
            </Space>
          </Descriptions.Item>
        </Descriptions>
        <Space wrap>
          <Button
            disabled={!allowed}
            loading={reloadRules.isPending}
            onClick={() =>
              reloadRules.mutate(undefined, {
                onSuccess: (result) => message.success(`规则 reload ${result.status}`),
              })
            }
            type="default"
          >
            影子 reload 重新加载
          </Button>
          <Typography.Text type="secondary" className="font-size-sm">
            此操作仅热重载风控规则与权重系数，不会写回防火墙或阻塞流量。
          </Typography.Text>
        </Space>
      </section>
    </main>
  )
}
