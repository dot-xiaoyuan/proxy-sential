import { useState } from "react";
import {
  Alert,
  App as AntApp,
  Button,
  Card,
  Form,
  Input,
  List,
  Modal,
  Select,
  Space,
  Switch,
  Tag,
  Typography,
} from "antd";

import { api } from "../shared/api/client";
import { NativeAccountPreview } from "../entities/evidence/NativeAccountPreview";
import { FourKDatabaseModal } from "../features/integrations/FourKDatabaseModal";
import { IdentityBridgePanel } from "../features/integrations/IdentityBridgePanel";
import {
  useActionConnectors,
  useSession,
} from "../shared/api/queries";
import type { ActionConnector } from "../shared/api/types";
import { can } from "../shared/auth/permissions";
import {
  AppErrorAlert,
  AppLoadingState,
  AppPageHeader,
} from "../shared/ui";

type ConnectorForm = {
  connector_type: "hmac";
  connector_id: string;
  name: string;
  endpoint_url: string;
  secret?: string;
  mode: "shadow" | "active";
  enabled: boolean;
  action_mapping: string;
};

export function ActionsPage() {
  const connectors = useActionConnectors();
  const session = useSession();
  const canManage = can(session.data, "integrations:write");
  const { message } = AntApp.useApp();
  const [editing, setEditing] = useState<ActionConnector | null | undefined>();
  const [saving, setSaving] = useState(false);
  const [previewConnector, setPreviewConnector] = useState<string>();
  const [fourKConnector, setFourKConnector] = useState<{ id?: string; host?: string }>();
  const [form] = Form.useForm<ConnectorForm>();
  if (connectors.isLoading)
    return <AppLoadingState rows={7} />;
  if (
    connectors.isError ||
    !connectors.data
  )
    return <AppErrorAlert title="认证与处置接入加载失败" />;
  const openEditor = (item?: ActionConnector) => {
    setEditing(item ?? null);
    form.setFieldsValue({
      connector_type: "hmac",
      connector_id: item?.connector_id ?? "",
      name: item?.name ?? "",
      endpoint_url: item?.endpoint_url ?? "",
      secret: "",
      mode: item?.mode ?? "shadow",
      enabled: item?.enabled ?? false,
      action_mapping: JSON.stringify(item?.action_mapping ?? {}, null, 2),
    });
  };
  const saveConnector = async () => {
    const value = await form.validateFields();
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
        secret: value.secret,
        action_mapping: mapping,
        shadow_ready: editing?.shadow_ready ?? false,
        updated_at: editing?.updated_at ?? new Date().toISOString(),
      });
      void message.success("连接器配置已保存");
      setEditing(undefined);
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
        title="认证与处置接入"
        subtitle="通过北向接口执行隔离、限速、踢线与解除；真实动作受硬门槛、冷却和熔断保护"
        onRefresh={() => {
          void connectors.refetch();
        }}
      />
      <Alert
        showIcon
        type={connectors.data.global_stop ? "error" : "info"}
        title={
          connectors.data.global_stop
            ? "全局紧急停止已启用，所有真实动作均被阻断"
            : "真实动作受策略模式、当前身份、登录代次、事件通道、冷却与熔断共同保护"
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
      <IdentityBridgePanel />
      <section className="details-grid margin-top-md">
          <Card
            className="actions-connectors"
            title="通用认证与处置连接器"
            extra={
              canManage ? (
                <Space wrap><Button type="primary" onClick={() => setFourKConnector({})}>配置 4K 接入</Button><Button onClick={() => openEditor()}>新增通用连接器</Button></Space>
              ) : undefined
            }
          >
            <List
              locale={{ emptyText: "尚未配置通用处置连接器；南昌 4K 认证同步由上方独立服务运行" }}
              dataSource={connectors.data.items}
              renderItem={(item) => (
                <List.Item
                  actions={
                    canManage
                      ? [
                          item.connector_type === "srun4k" ? <Button key="4k" onClick={() => {
                            let host = "";
                            try { host = new URL(item.endpoint_url).hostname; } catch { host = ""; }
                            setFourKConnector({ id: item.connector_id, host });
                          }}>配置与同步4K</Button> : null,
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
                          item.connector_type !== "srun4k" ? <Button key="edit" onClick={() => openEditor(item)}>
                            配置
                          </Button> : null,
                          item.connector_type !== "srun4k" ? <Switch
                            aria-label={`${item.name}启用状态`}
                            key="enabled"
                            checked={item.enabled}
                            onChange={(value) =>
                              void toggleConnector(item, value)
                            }
                          /> : <Tag key="managed" color={item.enabled ? "green" : "default"}>托管接入</Tag>,
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
                        {item.connector_type === "srun4k" ? <span>身份与匹配目录由4K同步，动作由本地防代理策略配置</span> : <span>
                          {item.mode === "active" ? "真实模式" : "影子模式"} ·{" "}
                          {item.shadow_ready ? "影子验收通过" : "等待影子验收"}{" "}
                          · 已复核 {item.shadow_reviewed_count ?? 0}/
                          {item.shadow_candidate_count ?? 0} · 准确率{" "}
                          {Math.round((item.shadow_accuracy ?? 0) * 100)}%
                        </span>}
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
                "按触发类型检查设备配额、会话配额或可归责的风险证据",
                "核验当前账号、在线会话与登录代次",
                "检查策略范围、校园例外与人工复核结论",
                "真实动作遵守策略冷却和连接器熔断",
                "通用外部连接器需完成影子验收；4K 托管接入按事件通道状态准入",
                "全局紧急停止阻断真实动作；所有操作保留审计和撤销入口",
              ]}
              renderItem={(item) => <List.Item>{item}</List.Item>}
            />
          </Card>
      </section>
      {fourKConnector && <FourKDatabaseModal key={fourKConnector.id || "new"} connectorId={fourKConnector.id} initialHost={fourKConnector.host} onSaved={() => void connectors.refetch()} onClose={() => setFourKConnector(undefined)} />}
      <Modal title="账号会话预览" open={Boolean(previewConnector)} footer={null} onCancel={() => setPreviewConnector(undefined)} destroyOnHidden>
        {previewConnector && <NativeAccountPreview key={previewConnector} connectorId={previewConnector} />}
      </Modal>
      <Modal
        className="connector-editor-modal"
        title={editing ? "编辑通用连接器" : "新增通用连接器"}
        open={editing !== undefined}
        confirmLoading={saving}
        onCancel={() => setEditing(undefined)}
        onOk={() => void saveConnector()}
        destroyOnHidden
        forceRender
      >
        <Form form={form} layout="vertical">
          <Form.Item name="connector_type" label="连接器类型" rules={[{ required: true }]}>
            <Select options={[{ value: "hmac", label: "通用 HMAC 连接器" }]} />
          </Form.Item>
          <Form.Item
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
          <Form.Item
            name="secret"
            label={editing ? "HMAC 密钥（留空保持不变）" : "HMAC 密钥"}
            rules={editing ? [] : [{ required: true, min: 16 }]}
          >
            <Input.Password />
          </Form.Item>
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
          <Form.Item name="action_mapping" label="动作映射 JSON">
            <Input.TextArea rows={5} />
          </Form.Item>
        </Form>
      </Modal>
    </main>
  );
}
