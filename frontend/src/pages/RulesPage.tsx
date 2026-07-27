import { App as AntApp, Alert, Button, Descriptions, Skeleton, Typography } from 'antd'

import { useReloadRules, useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'

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
      {!allowed && <Alert showIcon title="当前会话没有 rules:reload 权限" type="warning" />}
      <section className="surface">
        <Descriptions bordered column={1} size="small">
          <Descriptions.Item label="配置版本">mock-rules-20260727</Descriptions.Item>
          <Descriptions.Item label="模式">shadow</Descriptions.Item>
          <Descriptions.Item label="动作边界">record / shadow_watch / shadow_manual_review / shadow_confirm_review</Descriptions.Item>
        </Descriptions>
        <Button
          disabled={!allowed}
          loading={reloadRules.isPending}
          onClick={() =>
            reloadRules.mutate(undefined, {
              onSuccess: (result) => message.success(`规则 reload ${result.status}`),
            })
          }
          style={{ marginTop: 16 }}
          type="primary"
        >
          影子 reload
        </Button>
      </section>
    </main>
  )
}
