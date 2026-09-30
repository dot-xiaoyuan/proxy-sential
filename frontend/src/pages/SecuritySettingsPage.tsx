import { useState } from "react";
import {
  Button,
  Card,
  Form,
  Input,
  Modal,
  Select,
  Space,
  Table,
  Tag,
  message,
} from "antd";
import type { ColumnsType } from "antd/es/table";

import {
  useUserMutation,
  useUsers,
} from "../shared/api/queries";
import type {
  LocalUser,
  UserMutation,
} from "../shared/api/types";
import {
  AppErrorAlert,
  AppLoadingState,
  AppPageHeader,
  AppServerPagination,
  useServerPagination,
} from "../shared/ui";

const roleLabels: Record<string, string> = {
  viewer: "只读查看",
  reviewer: "风险复核",
  operator: "运营处置",
  admin: "系统管理员",
};

export function SecuritySettingsPage(){
const userPage=useServerPagination('users_');const users=useUsers({limit:userPage.pageSize,cursor:userPage.cursor});const userMutation=useUserMutation();const [userOpen,setUserOpen]=useState(false);const [userForm]=Form.useForm<UserMutation>();
if(users.isLoading)return <AppLoadingState rows={6}/>;
if(users.isError)return <AppErrorAlert title="用户权限读取失败"/>;
  const userColumns: ColumnsType<LocalUser> = [
    {
      title: "账号",
      dataIndex: "username",
      render: (value) => <span className="nowrap-cell">{value}</span>,
    },
    {
      title: "姓名",
      dataIndex: "display_name",
      render: (value) => <span className="nowrap-cell">{value}</span>,
    },
    {
      title: "角色",
      dataIndex: "role",
      render: (value) => <Tag>{roleLabels[value] ?? value}</Tag>,
    },
    {
      title: "状态",
      dataIndex: "disabled",
      render: (value) => (
        <Tag color={value ? "default" : "green"}>
          {value ? "已停用" : "正常"}
        </Tag>
      ),
    },
    {
      title: "操作",
      key: "actions",
      render: (_, item) => (
        <Space wrap>
          <Button
            disabled={userMutation.isPending}
            onClick={() =>
              userMutation.mutate({
                userId: item.user_id,
                operation: item.disabled ? "enable" : "disable",
                payload: {},
              })
            }
            size="small"
          >
            {item.disabled ? "启用" : "停用"}
          </Button>
          <Button
            disabled={userMutation.isPending}
            onClick={() => {
              Modal.confirm({
                title: `重置 ${item.username} 的密码`,
                content: (
                  <Input.Password
                    id="reset-password"
                    placeholder="至少 12 位"
                  />
                ),
                onOk: async () => {
                  const input = document.getElementById(
                    "reset-password",
                  ) as HTMLInputElement | null;
                  if (!input || input.value.length < 12)
                    throw new Error("密码至少 12 位");
                  await userMutation.mutateAsync({
                    userId: item.user_id,
                    operation: "password",
                    payload: { password: input.value },
                  });
                  message.success("密码已重置，原会话已失效");
                },
              });
            }}
            size="small"
          >
            重置密码
          </Button>
        </Space>
      ),
    },
  ];
return <main className="page"><AppPageHeader title="用户权限" subtitle="管理本地账号、角色与会话失效" onRefresh={()=>void users.refetch()}/><Card>                  <div className="tab-toolbar">
                    <Button type="primary" onClick={() => setUserOpen(true)}>
                      新建用户
                    </Button>
                  </div>
                  <Table
                    className="compact-list-table"
                    columns={userColumns}
                    dataSource={users.data?.items ?? []}
                    pagination={false}
                    rowKey="user_id"
                    size="small"
                  />
                  <AppServerPagination
                    page={userPage.page}
                    pageSize={userPage.pageSize}
                    total={users.data?.page.total ?? 0}
                    onChange={userPage.update}
                  />
</Card>      <Modal
        title="新建本地用户"
        open={userOpen}
        confirmLoading={userMutation.isPending}
        onCancel={() => setUserOpen(false)}
        onOk={() =>
          void userForm.validateFields().then((payload) =>
            userMutation.mutateAsync({ payload }).then(() => {
              setUserOpen(false);
              userForm.resetFields();
              message.success("用户已创建");
            }),
          )
        }
      >
        <Form form={userForm} layout="vertical">
          <Form.Item
            name="username"
            label="登录账号"
            rules={[{ required: true }]}
          >
            <Input />
          </Form.Item>
          <Form.Item
            name="display_name"
            label="姓名"
            rules={[{ required: true }]}
          >
            <Input />
          </Form.Item>
          <Form.Item name="role" label="角色" rules={[{ required: true }]}>
            <Select
              options={Object.entries(roleLabels).map(([value, label]) => ({
                value,
                label,
              }))}
            />
          </Form.Item>
          <Form.Item
            name="password"
            label="初始密码"
            rules={[{ required: true, min: 12 }]}
          >
            <Input.Password />
          </Form.Item>
        </Form>
      </Modal>
</main>
}
