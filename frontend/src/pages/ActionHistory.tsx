import { statusText } from '../shared/ui/status'
import { useState } from 'react'
import { App as AntApp, Button, Card, List, Modal, Space, Table, Tag, Typography } from 'antd'
import { api } from '../shared/api/client'
import { useActions, useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'
import { NativeObservations } from '../entities/evidence/NativeObservations'
import { AppErrorAlert, AppLoadingState, AppServerPagination, useServerPagination } from '../shared/ui'
export function ActionHistory(){
  const pagination=useServerPagination('actions_')
  const actions=useActions({limit:pagination.pageSize,cursor:pagination.cursor})
  const session=useSession();const {message}=AntApp.useApp()
  const [selectedAction,setSelectedAction]=useState<string>()
  if(actions.isLoading)return <AppLoadingState rows={6}/>
  if(actions.isError||!actions.data)return <AppErrorAlert title="处置动作读取失败"/>
  return <>
        <Card className="margin-top-md" title="最近动作" extra={<Button onClick={()=>void actions.refetch()} loading={actions.isFetching}>刷新动作</Button>}>
          <div className="desktop-only">
            <Table
              className="compact-list-table"
              dataSource={actions.data.items}
              pagination={false}
              rowKey="action_id"
              columns={[
                { title: "动作", dataIndex: "action_type", render:(value:string)=>statusText(value) },
                {
                  title: "对象",
                  dataIndex: "subject_id",
                  render: (value: string) => (
                    <span className="nowrap-cell">{value}</span>
                  ),
                },
                {
                  title: "模式",
                  dataIndex: "mode",
                  render: (value: string) => <Tag>{statusText(value)}</Tag>,
                },
                {
                  title: "状态",
                  dataIndex: "status",
                  render: (value: string) => (
                    <Tag
                      color={
                        value === "succeeded"
                          ? "green"
                          : value === "failed" || value === "blocked"
                            ? "red"
                            : "blue"
                      }
                    >
                      {statusText(value)}
                    </Tag>
                  ),
                },
                {
                  title: "阻断原因",
                  dataIndex: "blockers",
                  render: (value?: string[]) => (
                    <span className="ellipsis-cell" title={value?.join("、")}>
                      {value?.join("、") || ""}
                    </span>
                  ),
                },
                { title: "重试", dataIndex: "retry_count" },
                {
                  title: "时间",
                  dataIndex: "created_at",
                  render: (value: string) => (
                    <span className="nowrap-cell">
                      {new Date(value).toLocaleString()}
                    </span>
                  ),
                },
                {
                  title: "操作",
                  render: (_, item) => (
                    <Space wrap>
                    <Button onClick={() => setSelectedAction(item.action_id)}>执行记录</Button>
                    <Button
                      disabled={
                        !can(session.data, "actions:revoke") ||
                        item.status !== "succeeded"
                      }
                      onClick={async () => {
                        await api.revokeAction(item.action_id);
                        void message.success("撤销请求已提交");
                        void actions.refetch();
                      }}
                    >
                      撤销
                    </Button>
                    </Space>
                  ),
                },
              ]}
            />
          </div>
          <List
            className="mobile-only"
            dataSource={actions.data.items}
            locale={{ emptyText: "暂无处置动作" }}
            renderItem={(item) => (
              <List.Item>
                <Card className="mobile-case-card" size="small">
                  <div className="mobile-case-head">
                    <Typography.Text className="nowrap-cell" strong>
                      {statusText(item.action_type)}
                    </Typography.Text>
                    <Tag>{statusText(item.status)}</Tag>
                  </div>
                  <div className="mobile-case-row">
                    <span className="ellipsis-cell" title={item.subject_id}>
                      {item.subject_id}
                    </span>
                    <span>{statusText(item.mode)}</span>
                  </div>
                  <div className="mobile-case-row">
                    <span>重试 {item.retry_count ?? 0}</span>
                    <span>{new Date(item.created_at).toLocaleString()}</span>
                  </div>
                  <Button onClick={() => setSelectedAction(item.action_id)}>执行记录</Button>
                </Card>
              </List.Item>
            )}
          />
          <AppServerPagination
            page={pagination.page}
            pageSize={pagination.pageSize}
            total={actions.data.page.total}
            onChange={pagination.update}
          />
        </Card>
      <Modal title="原生执行记录" open={Boolean(selectedAction)} footer={null} onCancel={() => setSelectedAction(undefined)} destroyOnHidden>
        {selectedAction && <NativeObservations key={selectedAction} actionId={selectedAction} />}
      </Modal>
</>
}
