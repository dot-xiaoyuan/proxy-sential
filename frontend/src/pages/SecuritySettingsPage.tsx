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
  Tabs,
  Tag,
  message,
} from "antd";
import type { ColumnsType } from "antd/es/table";

import {
  useCampusExceptionMutation,
  useCampusExceptions,
  useUserMutation,
  useUsers,
} from "../shared/api/queries";
import type {
  CampusException,
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

export function SecuritySettingsPage() {
  const userPage = useServerPagination("users_");
  const exceptionPage = useServerPagination("exceptions_");
  const users = useUsers({ limit: userPage.pageSize, cursor: userPage.cursor });
  const exceptions = useCampusExceptions({
    limit: exceptionPage.pageSize,
    cursor: exceptionPage.cursor,
  });
  const userMutation = useUserMutation();
  const exceptionMutation = useCampusExceptionMutation();
  const [userOpen, setUserOpen] = useState(false);
  const [exceptionOpen, setExceptionOpen] = useState(false);
  const [userForm] = Form.useForm<UserMutation>();
  const [exceptionForm] = Form.useForm<CampusException>();
  if (users.isLoading || exceptions.isLoading)
    return <AppLoadingState rows={8} />;
  if (users.isError || exceptions.isError)
    return <AppErrorAlert title="权限与例外设置加载失败" />;
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
  const exceptionColumns: ColumnsType<CampusException> = [
    {
      title: "范围",
      render: (_, item) => (
        <span className="nowrap-cell">
          {item.scope_type}: {item.scope_value}
        </span>
      ),
    },
    {
      title: "校区",
      dataIndex: "campus_id",
      render: (value) => <span className="nowrap-cell">{value || "全校"}</span>,
    },
    { title: "原因", dataIndex: "reason", ellipsis: true },
    {
      title: "版本",
      dataIndex: "ruleset_version",
      render: (value) => <span className="nowrap-cell">{value || ""}</span>,
    },
    {
      title: "有效期",
      dataIndex: "expires_at",
      render: (value) => (
        <span className="nowrap-cell">
          {value ? new Date(value).toLocaleString() : "长期"}
        </span>
      ),
    },
    {
      title: "状态",
      dataIndex: "enabled",
      render: (value) => (
        <Tag color={value ? "green" : "default"}>
          {value ? "生效中" : "已停用"}
        </Tag>
      ),
    },
    {
      title: "操作",
      render: (_, item) => (
        <Button
          disabled={!item.enabled || exceptionMutation.isPending}
          onClick={() =>
            exceptionMutation.mutate({ exceptionId: item.exception_id })
          }
          size="small"
        >
          停用
        </Button>
      ),
    },
  ];
  return (
    <main className="page">
      <AppPageHeader
        title="权限与校园例外"
        subtitle="管理本地 RBAC 用户、会话失效与有版本和有效期的校园业务例外"
        loading={users.isFetching || exceptions.isFetching}
        onRefresh={() => {
          void users.refetch();
          void exceptions.refetch();
        }}
      />
      <Card className="surface-card operations-tabs-surface">
        <Tabs
          destroyOnHidden
          items={[
            {
              key: "users",
              label: "本地用户",
              children: (
                <>
                  <div className="tab-toolbar">
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
                </>
              ),
            },
            {
              key: "exceptions",
              label: "校园例外库",
              children: (
                <>
                  <div className="tab-toolbar">
                    <Button
                      type="primary"
                      onClick={() => setExceptionOpen(true)}
                    >
                      新增例外
                    </Button>
                  </div>
                  <Table
                    className="compact-list-table"
                    columns={exceptionColumns}
                    dataSource={exceptions.data?.items ?? []}
                    pagination={false}
                    rowKey="exception_id"
                    size="small"
                  />
                  <AppServerPagination
                    page={exceptionPage.page}
                    pageSize={exceptionPage.pageSize}
                    total={exceptions.data?.page.total ?? 0}
                    onChange={exceptionPage.update}
                  />
                </>
              ),
            },
          ]}
        />
      </Card>
      <Modal
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
      <Modal
        title="新增校园例外"
        open={exceptionOpen}
        confirmLoading={exceptionMutation.isPending}
        onCancel={() => setExceptionOpen(false)}
        onOk={() =>
          void exceptionForm.validateFields().then((payload) =>
            exceptionMutation.mutateAsync({ payload }).then(() => {
              setExceptionOpen(false);
              exceptionForm.resetFields();
              message.success("校园例外已生效");
            }),
          )
        }
      >
        <Form
          form={exceptionForm}
          layout="vertical"
          initialValues={{
            scope_type: "domain",
            ruleset_version: "campus-exceptions-v1",
          }}
        >
          <Form.Item
            name="scope_type"
            label="范围类型"
            rules={[{ required: true }]}
          >
            <Select
              options={[
                { value: "domain", label: "域名" },
                { value: "ip", label: "IP" },
                { value: "cidr", label: "网段" },
                { value: "account", label: "账号" },
                { value: "endpoint", label: "终端" },
                { value: "campus", label: "校区" },
              ]}
            />
          </Form.Item>
          <Form.Item
            name="scope_value"
            label="范围值"
            rules={[{ required: true }]}
          >
            <Input />
          </Form.Item>
          <Form.Item name="campus_id" label="限定校区">
            <Input placeholder="留空表示全校" />
          </Form.Item>
          <Form.Item
            name="reason"
            label="例外原因"
            rules={[{ required: true, min: 2 }]}
          >
            <Input />
          </Form.Item>
          <Form.Item
            name="ruleset_version"
            label="规则版本"
            rules={[{ required: true }]}
          >
            <Input />
          </Form.Item>
          <Form.Item name="expires_at" label="失效时间">
            <Input placeholder="RFC3339，例如 2027-01-01T00:00:00+08:00" />
          </Form.Item>
        </Form>
      </Modal>
    </main>
  );
}
