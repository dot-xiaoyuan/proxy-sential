import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  App as AntApp,
  Button,
  Card,
  Form,
  Input,
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
import type { ColumnsType } from "antd/es/table";
import {
  AppListHeader,
  AppListSection,
  AppPageHeader,
  AppTable,
  formatDateTime,
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
  const connectors = useActionConnectors(true,true);
  const fourKIntegrations = useQuery({ queryKey: ['srun4k-integrations'], queryFn: api.srun4KIntegrations,refetchOnWindowFocus:false,refetchOnReconnect:false,refetchInterval:false,retry:false });
  const session = useSession();
  const canManage = can(session.data, "integrations:write");
  const { message } = AntApp.useApp();
  const [editing, setEditing] = useState<ActionConnector | null | undefined>();
  const [saving, setSaving] = useState(false);
  const [previewConnector, setPreviewConnector] = useState<string>();
  const [fourKConnector, setFourKConnector] = useState<{ id?: string; host?: string }>();
  const [form] = Form.useForm<ConnectorForm>();
  const connectorData=connectors.data;
  const readOnly = connectorData?.read_only !== false;
  const canWrite = canManage && !readOnly;
  const canConfigureSRun4K = canManage;
  const fourKIntegration = fourKIntegrations.data?.items[0];
  const genericConnectors = (connectorData?.items ?? []).filter((item) => item.connector_type !== 'srun4k')
  const fourKAction = canConfigureSRun4K ? <Button type="primary" disabled={fourKIntegrations.isLoading||fourKIntegrations.isError} onClick={() => {
    const legacyConnector = (connectorData?.items??[]).find((item) => item.connector_type === "srun4k");
    setFourKConnector(fourKIntegration ? { id: fourKIntegration.connector_id } : legacyConnector ? { id: legacyConnector.connector_id } : {});
  }}>{fourKIntegration ? "配置接入" : "新增接入"}</Button> : undefined
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
  const connectorColumns: ColumnsType<ActionConnector> = [
    {
      title: "连接器",
      key: "name",
      width: 160,
      render: (_, item) => (
        <div className="connector-name">
          <strong>{item.name}</strong>
          {item.connector_type === "srun4k" && <Tag>4K 托管</Tag>}
        </div>
      ),
    },
    {
      title: "端点",
      dataIndex: "endpoint_url",
      width: 210,
      onCell: () => ({ className: "connector-endpoint-cell" }),
      render: (value: string) => <span className="connector-endpoint" title={value}>{value}</span>,
    },
    {
      title: "运行与验收",
      key: "mode",
      width: 250,
      onCell: () => ({ className: "connector-mode-cell" }),
      render: (_, item) =>
        item.connector_type === "srun4k" ? (
          <span className="connector-muted">4K 托管通道，运行状态由 4K 接入配置维护</span>
        ) : (
          <div className="connector-mode">
            <span>{item.mode === "active" ? "真实模式" : "影子模式"}</span>
            <span>
              {item.shadow_ready ? "影子验收通过" : "等待影子验收"} · 已复核{" "}
              {item.shadow_reviewed_count ?? 0}/{item.shadow_candidate_count ?? 0} · 准确率{" "}
              {Math.round((item.shadow_accuracy ?? 0) * 100)}%
            </span>
            {item.circuit_open_until && <Tag color="red">熔断至 {formatDateTime(item.circuit_open_until)}</Tag>}
          </div>
        ),
    },
    {
      title: "状态",
      key: "enabled",
      width: 90,
      render: (_, item) =>
        canWrite && item.connector_type !== "srun4k" ? (
          <Switch
            aria-label={`${item.name}启用状态`}
            checked={item.enabled}
            onChange={(value) => void toggleConnector(item, value)}
          />
        ) : (
          <Tag color={item.enabled ? "green" : "default"}>{item.enabled ? "启用" : "停用"}</Tag>
        ),
    },
    {
      title: "操作",
      key: "action",
      width: 260,
      fixed: "right",
      render: (_, item) =>
        canManage ? (
          <Space wrap>
            {item.connector_type === "srun4k" && canConfigureSRun4K && (
              <Button onClick={() => setFourKConnector({ id: item.connector_id })}>配置接入通道</Button>
            )}
            <Button onClick={() => setPreviewConnector(item.connector_id)}>账号会话预览</Button>
            {canWrite && (
              <Button
                onClick={async () => {
                  try {
                    const result = await api.testActionConnector(item.connector_id);
                    void message.success(result.identity_verified === false ? "管理 API 连通与授权检查通过；完整身份清单尚未接通，暂不能处置" : "连接检查通过，处置能力仍需单独验收");
                  } catch (error) {
                    void message.error(error instanceof Error ? error.message : "连通性测试失败");
                  }
                }}
              >
                连通测试
              </Button>
            )}
            {canWrite && item.connector_type !== "srun4k" && (
              <Button onClick={() => openEditor(item)}>配置</Button>
            )}
          </Space>
        ) : null,
    },
  ]

  return (
    <main className="page actions-page">
      <AppPageHeader
        title="认证与处置接入"
        subtitle="认证同步（4K）和处置连接器（HMAC）分开维护；4K 接入配置用于授权库与目录，处置连接器用于发送处置动作。"
        extra={connectorData && <Space className="actions-mode-controls" wrap>
          {readOnly && <Tag>只读</Tag>}
          {connectorData.global_stop && !canWrite && <Tag color="red">紧急停止</Tag>}
          {canWrite && <Space><Typography.Text>紧急停止</Typography.Text><Switch checked={connectorData.global_stop} onChange={async (value) => {
            await api.emergencyStop(value);
            void message.success("紧急停止状态已更新");
            void connectors.refetch();
          }}/></Space>}
        </Space>}
      />
      <IdentityBridgePanel />
      <Card className="four-k-authority-card margin-top-md" title="4K 接入配置" extra={fourKAction}>
        <Typography.Paragraph type="secondary" className="actions-config-note">独立保存授权库、目录、上下线事件和北向 API；未保存时不影响上方认证同步，认证同步继续使用部署配置。</Typography.Paragraph>
        {fourKIntegrations.isError ? <p className="actions-inline-error" role="alert">4K接入配置读取失败</p> : fourKIntegration ? <div className="four-k-endpoint-summary">
          <span>授权数据库 <Typography.Text className="four-k-endpoint-value">{fourKIntegration.authorization_database_host}</Typography.Text></span>
          <span>在线清单 Redis <Typography.Text className="four-k-endpoint-value">{fourKIntegration.online_redis_host}</Typography.Text></span>
          <span>产品/控制目录 Redis <Typography.Text className="four-k-endpoint-value">{fourKIntegration.catalog_redis_host}</Typography.Text></span>
          {fourKIntegration.event_redis_host && <span>上下线事件 Redis <Typography.Text className="four-k-endpoint-value">{fourKIntegration.event_redis_host}</Typography.Text></span>}
          <span>北向 API <Typography.Text className="four-k-endpoint-value">{fourKIntegration.northbound_api_host}</Typography.Text></span>
          <span>北向授权 {fourKIntegration.authorization_ready ? '已验证' : '待验证'} · 校准周期 {fourKIntegration.reconcile_interval_hours} 小时</span>
        </div> : fourKIntegrations.isLoading ? <span className="actions-empty-state">正在读取独立 4K 接入配置</span> : <div className="actions-empty-state actions-empty-state-stack"><strong>未保存独立 4K 接入配置</strong><span>当前认证同步使用部署配置；如需维护授权库、目录或北向 API，请点击“新增接入”。</span></div>}
      </Card>
      <section className="actions-connector-section margin-top-md surface">
        <AppListHeader
          title="处置连接器"
          count={`${genericConnectors.length} 个`}
          actions={canWrite ? <Button onClick={() => openEditor()}>新增处置连接器</Button> : undefined}
        />
        <Typography.Paragraph type="secondary" className="actions-connector-intro">处置连接器用于向外部系统发送处置动作（HMAC 北向 HTTP），不参与 4K 认证同步。</Typography.Paragraph>
        <AppListSection
          isError={connectors.isError}
          errorTitle="连接器状态读取失败"
          isLoading={connectors.isLoading}
          loadingRows={4}
          isEmpty={!genericConnectors.length}
          emptyText="尚未配置处置连接器；不影响上方 4K 认证同步"
        >
          <AppTable rowKey="connector_id" columns={connectorColumns} dataSource={genericConnectors} scroll={{ x: 960 }} />
        </AppListSection>
      </section>
      {fourKConnector && <FourKDatabaseModal key={fourKConnector.id || "new"} connectorId={fourKConnector.id} initialHost={fourKConnector.host} onSaved={() => { void connectors.refetch(); void fourKIntegrations.refetch() }} onClose={() => setFourKConnector(undefined)} />}
      <Modal title="账号会话预览" open={Boolean(previewConnector)} footer={null} onCancel={() => setPreviewConnector(undefined)} destroyOnHidden>
        {previewConnector && <NativeAccountPreview key={previewConnector} connectorId={previewConnector} />}
      </Modal>
      <Modal
        className="connector-editor-modal"
        title={editing ? "编辑处置连接器" : "新增处置连接器"}
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
          <Form.Item name="mode" label="运行模式">
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
