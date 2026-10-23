import {
  statusText } from '../shared/ui/status'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { App as AntApp,
  Button,
  Modal,
  Space,
  Tag,
} from 'antd'
import { api } from '../shared/api/client'
import { useActions, useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'
import { NativeObservations } from '../entities/evidence/NativeObservations'
import { AppErrorAlert, AppListHeader, AppLoadingState, AppServerPagination, AppTable, formatDateTime, useServerPagination } from '../shared/ui'
export function ActionHistory(){
  const pagination=useServerPagination('actions_')
  const actions=useActions({limit:pagination.pageSize,cursor:pagination.cursor})
  const session=useSession();const {message}=AntApp.useApp()
  const [selectedAction,setSelectedAction]=useState<string>()
  if(actions.isLoading)return <AppLoadingState rows={6}/>
  if(actions.isError||!actions.data)return <AppErrorAlert title="处置动作读取失败"/>
  return <>
        <AppListHeader title="处置动作记录" count={`${actions.data.page.total} 条`} />
          <AppTable
              dataSource={actions.data.items}
              rowKey="action_id"
              scroll={{ x: 960 }}
              locale={{ emptyText: "暂无处置动作" }}
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
                  render: (value: string) => <Tag>{value==='record_only'?'仅记录':statusText(value)}</Tag>,
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
                      {value==='recorded'?'已记录，未执行':statusText(value)}
                    </Tag>
                  ),
                },
                {
                  title: "时间",
                  dataIndex: "created_at",
                  render: (value: string) => (
                    <span className="nowrap-cell">{formatDateTime(value)}</span>
                  ),
                },
                {
                  title: "操作",
                  render: (_, item) => (
                    <Space wrap>
                    {item.mode==='record_only' && item.policy_parameters?.observation_id
                      ? <Link to={`/actions?tab=decisions&observation_id=${encodeURIComponent(item.policy_parameters.observation_id)}&decision_result=all`}>策略依据</Link>
                      : <Button onClick={() => setSelectedAction(item.action_id)}>执行记录</Button>}
                    {item.mode!=='record_only' && <Button
                      disabled={!can(session.data, "actions:revoke") || item.status !== "succeeded"}
                      onClick={async () => {
                        await api.revokeAction(item.action_id);
                        void message.success("撤销请求已提交");
                        void actions.refetch();
                      }}
                    >撤销</Button>}
                    </Space>
                  ),
                },
              ]}
          />
          <AppServerPagination
            page={pagination.page}
            pageSize={pagination.pageSize}
            total={actions.data.page.total}
            onChange={pagination.update}
          />
      <Modal title="原生执行记录" open={Boolean(selectedAction)} footer={null} onCancel={() => setSelectedAction(undefined)} destroyOnHidden>
        {selectedAction && <NativeObservations key={selectedAction} actionId={selectedAction} />}
      </Modal>
</>
}
