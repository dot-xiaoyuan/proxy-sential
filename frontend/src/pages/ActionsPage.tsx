import { IdentitySourceModal } from "../features/integrations/IdentitySourceModal";
import { useState } from "react";
import {
  Alert,
  App as AntApp,
  Button,
  Card,
  Collapse,
  Form,
  Input,
  List,
  Modal,
  Select,
  Space,
  Switch,
  Table,
  Tabs,
  Tag,
  Typography,
} from "antd";

import { api } from "../shared/api/client";
import { NativeAccountPreview } from "../entities/evidence/NativeAccountPreview";
import { FourKDatabaseModal } from "../features/integrations/FourKDatabaseModal";
import { NativeObservations } from "../entities/evidence/NativeObservations";
import {
  useActionConnectors,
  useActions,
  useSession,
} from "../shared/api/queries";
import type { ActionConnector } from "../shared/api/types";
import { can } from "../shared/auth/permissions";
import {
  AppErrorAlert,
  AppLoadingState,
  AppPageHeader,
  AppServerPagination,
  useServerPagination,
} from "../shared/ui";

type ConnectorForm = {
  certificate_pem?: string;
  four_k_host?: string;
  connector_type: "hmac" | "srun4k";
  connector_id: string;
  name: string;
  endpoint_url: string;
  secret?: string;
  mode: "shadow" | "active";
  enabled: boolean;
  action_mapping: string;
};

export function ActionsPage() {
  const pagination = useServerPagination();
  const connectors = useActionConnectors();
  const actions = useActions({
    limit: pagination.pageSize,
    cursor: pagination.cursor,
  });
  const session = useSession();
  const canManage = can(session.data, "integrations:write");
  const { message } = AntApp.useApp();
  const [editing, setEditing] = useState<ActionConnector | null | undefined>();
  const [saving, setSaving] = useState(false);
  const [selectedAction, setSelectedAction] = useState<string>();
  const [previewConnector, setPreviewConnector] = useState<string>();
  const [identityConnector, setIdentityConnector] = useState<string>();
  const [fourKConnector, setFourKConnector] = useState<string>();
  const [activeTab, setActiveTab] = useState("connectors");
  const [form] = Form.useForm<ConnectorForm>();
  const connectorType = Form.useWatch("connector_type", form);
  if (connectors.isLoading || actions.isLoading)
    return <AppLoadingState rows={7} />;
  if (
    connectors.isError ||
    actions.isError ||
    !connectors.data ||
    !actions.data
  )
    return <AppErrorAlert title="处置网关加载失败" />;
  const openEditor = (item?: ActionConnector, kind: "hmac" | "srun4k" = "hmac") => {
    setEditing(item ?? null);
    form.setFieldsValue({
      four_k_host: item?.endpoint_url ? new URL(item.endpoint_url).hostname.replace(/^\[|\]$/g, "") : "192.168.0.190",
      connector_type: item?.connector_type ?? kind,
      connector_id: item?.connector_id ?? "",
      name: item?.name ?? "",
      endpoint_url: item?.endpoint_url ?? (kind === "srun4k" ? "https://192.168.0.190:8001" : ""),
      certificate_pem: item?.certificate_pem ?? "",
      secret: "",
      mode: item?.mode ?? "shadow",
      enabled: item?.enabled ?? false,
      action_mapping: JSON.stringify(item?.action_mapping ?? {}, null, 2),
    });
  };
  const saveConnector = async () => {
    const value = await form.validateFields();
    if (value.connector_type === "srun4k") {
      value.endpoint_url = form.getFieldValue("endpoint_url") || `https://${value.four_k_host?.includes(":") ? `[${value.four_k_host}]` : value.four_k_host || "192.168.0.190"}:8001`;
      value.certificate_pem = form.getFieldValue("certificate_pem") ?? editing?.certificate_pem ?? "";
      value.connector_id = editing?.connector_id || `four-k-${Array.from(crypto.getRandomValues(new Uint8Array(12)), byte => byte.toString(16).padStart(2, "0")).join("")}`;
      value.name = editing?.name || `4K 认证系统（${new URL(value.endpoint_url).hostname}）`;
    }
    let mapping: Record<string, string>;
    try {
      mapping = JSON.parse(value.action_mapping || "{}") as Record<
        string,
        string
      >;
    } catch {
      void message.error("动作映射必须是合法 JSON");
      return;
    }
    setSaving(true);
    try {
      await api.saveActionConnector({
        ...value,
        secret: value.connector_type === "srun4k" ? undefined : value.secret,
        action_mapping: mapping,
        shadow_ready: editing?.shadow_ready ?? false,
        updated_at: editing?.updated_at ?? new Date().toISOString(),
      });
      void message.success("连接器配置已保存");
      setEditing(undefined);
      if (value.connector_type === "srun4k" && editing === null) setFourKConnector(value.connector_id);
      void connectors.refetch();
    } catch (error) {
      void message.error(
        error instanceof Error ? error.message : "连接器保存失败",
      );
    } finally {
      setSaving(false);
    }
  };
  const toggleConnector = async (item: ActionConnector, enabled: boolean) => {
    await api.saveActionConnector({ ...item, enabled });
    void message.success(enabled ? "连接器已启用" : "连接器已停用");
    void connectors.refetch();
  };
  return (
    <main className="page">
      <AppPageHeader
        title="旁路处置网关"
        subtitle="通过北向接口执行隔离、限速、踢线与解除；真实动作受硬门槛、冷却和熔断保护"
        onRefresh={() => {
          void connectors.refetch();
          void actions.refetch();
        }}
      />
      <Alert
        showIcon
        type={connectors.data.global_stop ? "error" : "info"}
        title={
          connectors.data.global_stop
            ? "全局紧急停止已启用，所有真实动作均被阻断"
            : "默认影子模式；只有高分、高置信、明确强规则和可定位身份同时满足才允许真实处置"
        }
        action={
          canManage ? (
            <Space>
              <Typography.Text>紧急停止</Typography.Text>
              <Switch
                checked={connectors.data.global_stop}
                onChange={async (value) => {
                  await api.emergencyStop(value);
                  void message.success("紧急停止状态已更新");
                  void connectors.refetch();
                }}
              />
            </Space>
          ) : undefined
        }
      />
      <section className="surface details-tab-shell margin-top-md">
        <Tabs
          activeKey={activeTab}
          onChange={setActiveTab}
          items={[
            { key: "connectors", label: "连接器与安全门槛" },
            { key: "actions", label: `处置动作 ${actions.data.page.total}` },
          ]}
        />
      </section>
      {activeTab === "connectors" && (
        <section className="details-grid margin-top-md">
          <Card
            className="actions-connectors"
            title="认证与处置连接器"
            extra={
              canManage ? (
                <Space wrap><Button type="primary" onClick={() => openEditor(undefined, "srun4k")}>配置 4K 接入</Button><Button onClick={() => openEditor()}>新增连接器</Button></Space>
              ) : undefined
            }
          >
            <List
              locale={{ emptyText: "尚未配置连接器，请点击「配置 4K 接入」设置认证系统与数据库授权" }}
              dataSource={connectors.data.items}
              renderItem={(item) => (
                <List.Item
                  actions={
                    canManage
                      ? [
                          item.connector_type === "srun4k" ? <Button key="identity" onClick={() => setIdentityConnector(item.connector_id)}>身份来源与范围</Button> : null,
                          <Button key="4k" onClick={() => setFourKConnector(item.connector_id)}>4K 数据库授权</Button>,
                          <Button key="preview" onClick={() => setPreviewConnector(item.connector_id)}>账号会话预览</Button>,
                          <Button
                            key="test"
                            onClick={async () => {
                              try {
                                const result = await api.testActionConnector(
                                  item.connector_id,
                                );
                                void message.success(result.identity_verified === false ? "管理 API 连通与授权检查通过；完整身份清单尚未接通，暂不能处置" : "连接检查通过，处置能力仍需单独验收");
                              } catch (error) {
                                void message.error(
                                  error instanceof Error
                                    ? error.message
                                    : "连通性测试失败",
                                );
                              }
                            }}
                          >
                            连通测试
                          </Button>,
                          <Button key="edit" onClick={() => openEditor(item)}>
                            配置
                          </Button>,
                          <Switch
                            aria-label={`${item.name}启用状态`}
                            key="enabled"
                            checked={item.enabled}
                            onChange={(value) =>
                              void toggleConnector(item, value)
                            }
                          />,
                        ]
                      : [
                          <Tag
                            color={item.enabled ? "green" : "default"}
                            key="enabled"
                          >
                            {item.enabled ? "启用" : "停用"}
                          </Tag>,
                        ]
                  }
                >
                  <List.Item.Meta
                    title={item.name}
                    description={
                      <div className="connector-summary">
                        <span className="nowrap-cell" title={item.endpoint_url}>
                          {item.endpoint_url}
                        </span>
                        <span>
                          {item.mode === "active" ? "真实模式" : "影子模式"} ·{" "}
                          {item.shadow_ready ? "影子验收通过" : "等待影子验收"}{" "}
                          · 已复核 {item.shadow_reviewed_count ?? 0}/
                          {item.shadow_candidate_count ?? 0} · 准确率{" "}
                          {Math.round((item.shadow_accuracy ?? 0) * 100)}%
                        </span>
                        {item.circuit_open_until && (
                          <Tag color="red">
                            熔断至{" "}
                            {new Date(item.circuit_open_until).toLocaleString()}
                          </Tag>
                        )}
                      </div>
                    }
                  />
                </List.Item>
              )}
            />
          </Card>
          <Card title="安全门槛">
            <List
              dataSource={[
                "风险分 ≥ 90",
                "风险置信度 ≥ 90%",
                "明确代理/隧道强规则",
                "账号与终端会话可定位",
                "无校园例外或良性结论",
                "24 小时对象冷却",
                "校区 5次/10分钟、全局20次/小时熔断",
                "影子运行至少 7 天且人工准确率 ≥ 95%",
              ]}
              renderItem={(item) => <List.Item>{item}</List.Item>}
            />
          </Card>
        </section>
      )}
      {activeTab === "actions" && (
        <Card className="margin-top-md" title="最近动作">
          <div className="desktop-only">
            <Table
              className="compact-list-table"
              dataSource={actions.data.items}
              pagination={false}
              rowKey="action_id"
              columns={[
                { title: "动作", dataIndex: "action_type" },
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
                  render: (value: string) => <Tag>{value}</Tag>,
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
                      {value}
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
                      {item.action_type}
                    </Typography.Text>
                    <Tag>{item.status}</Tag>
                  </div>
                  <div className="mobile-case-row">
                    <span className="ellipsis-cell" title={item.subject_id}>
                      {item.subject_id}
                    </span>
                    <span>{item.mode}</span>
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
      )}
      {identityConnector && <IdentitySourceModal key={identityConnector} connectorId={identityConnector} onClose={() => setIdentityConnector(undefined)} />}
      {fourKConnector && <FourKDatabaseModal key={fourKConnector} connectorId={fourKConnector} onClose={() => setFourKConnector(undefined)} />}
      <Modal title="账号会话预览" open={Boolean(previewConnector)} footer={null} onCancel={() => setPreviewConnector(undefined)} destroyOnHidden>
        {previewConnector && <NativeAccountPreview key={previewConnector} connectorId={previewConnector} />}
      </Modal>
      <Modal title="原生执行记录" open={Boolean(selectedAction)} footer={null} onCancel={() => setSelectedAction(undefined)} destroyOnHidden>
        {selectedAction && <NativeObservations key={selectedAction} actionId={selectedAction} />}
      </Modal>
      <Modal
        className="connector-editor-modal"
        title={editing ? "编辑连接器" : "新增连接器"}
        open={editing !== undefined}
        confirmLoading={saving}
        onCancel={() => setEditing(undefined)}
        onOk={() => void saveConnector()}
        destroyOnHidden
        forceRender
      >
        <Form form={form} layout="vertical">
          <Form.Item name="connector_type" label="连接器类型" rules={[{ required: true }]}>
            <Select options={[{ value: "hmac", label: "通用 HMAC 连接器" }, { value: "srun4k", label: "原生 4K 连接器" }]} />
          </Form.Item>
          {connectorType === "srun4k" ? <>
            <Form.Item name="four_k_host" label="认证系统 IP" rules={[{ required: true }, { validator: (_, value: string) => {
              try { if (!value || /[\s/?#@]/.test(value)) throw new Error(); new URL(`https://${value.includes(":") ? `[${value}]` : value}:8001`); return Promise.resolve(); }
              catch { return Promise.reject(new Error("请输入有效的 IP 或主机名")); }
            } }]} extra="默认 HTTPS、8001 端口。">
              <Input onChange={event => { const host = event.target.value; form.setFieldValue("endpoint_url", `https://${host.includes(":") ? `[${host}]` : host}:8001`); }} />
            </Form.Item>
            <Collapse items={[{ key: "advanced", label: "高级设置", children: <><Form.Item name="endpoint_url" label="管理 API 根地址" rules={[{ required: true }, { type: "url" }]}><Input /></Form.Item><Form.Item name="certificate_pem" label="服务器信任证书（PEM）" extra="留空使用系统信任；自签名证书请填写从管理方取得并核实的服务器证书。仅信任这张证书，证书轮换需更新。"><Input.TextArea rows={5} placeholder="-----BEGIN CERTIFICATE-----" /></Form.Item></> }]} />
          </> : <>          <Form.Item
            name="connector_id"
            label="连接器 ID"
            rules={[{ required: true }]}
          >
            <Input disabled={Boolean(editing)} />
          </Form.Item>
          <Form.Item name="name" label="名称" rules={[{ required: true }]}>
            <Input />
          </Form.Item>
          <Form.Item
            name="endpoint_url"
            label="北向 HTTP 地址"
            rules={[{ required: true }, { type: "url" }]}
          >
            <Input />
          </Form.Item>
          </>}
          {connectorType !== "srun4k" && <Form.Item
            name="secret"
            label={editing ? "HMAC 密钥（留空保持不变）" : "HMAC 密钥"}
            rules={editing ? [] : [{ required: true, min: 16 }]}
          >
            <Input.Password />
          </Form.Item>}
          <Form.Item name="mode" label="运行模式" extra="数据库授权和只读接口检查可在影子模式完成；真实处置需另行通过准入验收。">
            <Select
              options={[
                { value: "shadow", label: "影子模式" },
                { value: "active", label: "真实模式（需通过七天验收）", disabled: !editing?.shadow_ready },
              ]}
            />
          </Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked">
            <Switch />
          </Form.Item>
          {connectorType !== "srun4k" && <Form.Item name="action_mapping" label="动作映射 JSON">
            <Input.TextArea rows={5} />
          </Form.Item>}
        </Form>
      </Modal>
    </main>
  );
}
