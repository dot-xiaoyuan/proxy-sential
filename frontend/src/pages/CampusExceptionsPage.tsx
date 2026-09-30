import { useState } from "react";
import {
  Button,
  Card,
  Form,
  Input,
  Modal,
  Select,
  Table,
  Tag,
  message,
} from "antd";
import type { ColumnsType } from "antd/es/table";

import {
  useCampusExceptionMutation,
  useCampusExceptions,
} from "../shared/api/queries";
import type {
  CampusException,
} from "../shared/api/types";
import {
  AppErrorAlert,
  AppLoadingState,
  AppPageHeader,
  AppServerPagination,
  useServerPagination,
} from "../shared/ui";

import { useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'
export function CampusExceptionsPage(){
const session=useSession();const writable=can(session.data,'rules:reload');
const exceptionPage=useServerPagination('exceptions_');const exceptions=useCampusExceptions({limit:exceptionPage.pageSize,cursor:exceptionPage.cursor});const exceptionMutation=useCampusExceptionMutation();const [exceptionOpen,setExceptionOpen]=useState(false);const [exceptionForm]=Form.useForm<CampusException>();
if(exceptions.isLoading)return <AppLoadingState rows={6}/>;
if(exceptions.isError)return <AppErrorAlert title="校园例外读取失败"/>;
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
          disabled={!writable || !item.enabled || exceptionMutation.isPending}
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
return <main className="page"><AppPageHeader title="校园例外" subtitle="维护有原因、版本和有效期的校园业务例外" onRefresh={()=>void exceptions.refetch()}/><Card>                  <div className="tab-toolbar">
                    <Button
                      type="primary" disabled={!writable}
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
</Card>      <Modal
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
}
