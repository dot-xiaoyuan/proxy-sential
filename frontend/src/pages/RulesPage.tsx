import { ApplicationLibrary } from "../features/applications/ApplicationLibrary";
import { useQuery } from '@tanstack/react-query';
import { request } from '../shared/api/client';
import type { RulesStatus } from '../shared/api/types';
import { useSearchParams } from 'react-router-dom';
import { useState } from "react";
import { UploadOutlined } from "@ant-design/icons";
import {
  App as AntApp,
  Alert,
  Button,
  Descriptions,
  Skeleton,
  Space,
  Tabs,
  Tag,
  Typography,
  Upload,
} from "antd";

import {
  useDeviceFingerprintLibrary,
  useImportDeviceFingerprintBundle,
  useSession,
  useValidateDeviceFingerprintBundle,
} from "../shared/api/queries";
import type { DeviceFingerprintBundleManifest } from "../shared/api/types";
import { can } from "../shared/auth/permissions";
import { statusText } from '../shared/ui/status';



export function RulesPage() {
  const session = useSession();
  const { message } = AntApp.useApp();
  const [params,setParams] = useSearchParams();
  const ruleStatus = useQuery({queryKey:["rules-status"],queryFn:()=>request<RulesStatus>("/rules/status"),enabled:(params.get("tab")||"risk")==="risk"});
  const fingerprintLibrary = useDeviceFingerprintLibrary(params.get("tab")==="fingerprints");
  const validateBundle = useValidateDeviceFingerprintBundle();
  const importBundle = useImportDeviceFingerprintBundle();
  const [bundleFile, setBundleFile] = useState<File | null>(null);
  const [manifest, setManifest] =
    useState<DeviceFingerprintBundleManifest | null>(null);
  const canUpdateLibrary = can(
    session.data,
    "device-fingerprint-library:update",
  );

  if (session.isLoading) {
    return <Skeleton active />;
  }

  return (
    <main className="page">
      <div className="page-header">
        <div>
          <Typography.Title className="page-title" level={3}>
            规则与特征库
          </Typography.Title>
          <Typography.Text type="secondary">
            查看风险规则能力，维护应用与设备特征库。
          </Typography.Text>
        </div>
      </div>
      <section className="surface operations-tabs-surface">
        <Tabs
          activeKey={params.get("tab") || "risk"}
          onChange={tab=>setParams(current=>{const next=new URLSearchParams(current);next.set("tab",tab);return next})}
          destroyOnHidden
          items={[
            {key:"application-domains", label:"应用域名特征库", disabled:!can(session.data,'dpi:read'), children:<ApplicationLibrary />},
            {
              key: "risk",
              label: "风险规则",
              disabled:!can(session.data,'risks:read'),
              children: ruleStatus.isLoading ? <Skeleton active/> : ruleStatus.isError ? <Alert type="error" showIcon title="规则能力读取失败" description={ruleStatus.error.message}/> : <Alert type="info" showIcon title="风险规则热重载尚未开放" description="当前服务未开放风险规则在线热重载。应用和设备特征库分别展示各自实际生效版本。"/>,
            },
            {
              key: "fingerprints",
              label: "设备特征库",
              disabled:!can(session.data,'identity:read'),
              children: (
                <div>
                  <Typography.Title level={4}>设备特征库</Typography.Title>
                  {fingerprintLibrary.isError ? (
                    <Alert
                      showIcon
                      type="error"
                      title="设备特征库状态加载失败"
                    />
                  ) : (
                    <Descriptions
                      bordered
                      column={1}
                      size="small"
                      className="margin-bottom-lg"
                      items={[
                        {
                          key: "version",
                          label: "当前版本",
                          children: (
                            <Typography.Text className="mono list-cell-nowrap">
                              {fingerprintLibrary.data?.version || ""}
                            </Typography.Text>
                          ),
                        },
                        {
                          key: "source",
                          label: "数据来源",
                          children: fingerprintLibrary.data?.source || "",
                        },
                        {
                          key: "status",
                          label: "运行状态",
                          children: (
                            <Tag
                              color={
                                fingerprintLibrary.data?.status === "ready"
                                  ? "green"
                                  : "gold"
                              }
                            >
                              {statusText(fingerprintLibrary.data?.status)}
                            </Tag>
                          ),
                        },
                        {
                          key: "updated",
                          label: "最近更新",
                          children: fingerprintLibrary.data?.updated_at
                            ? new Date(
                                fingerprintLibrary.data.updated_at,
                              ).toLocaleString()
                            : "",
                        },
                        {
                          key: "error",
                          label: "最近错误",
                          children: fingerprintLibrary.data?.last_error || "",
                        },
                        {
                          key: "mode",
                          label: "更新模式",
                          children: fingerprintLibrary.data?.offline_mode
                            ? "离线包导入（30 机器不访问外网）"
                            : "联网更新",
                        },
                        {
                          key: "counts",
                          label: "规则规模",
                          children: `OUI ${fingerprintLibrary.data?.oui_count ?? 0} · UA/自有规则 ${fingerprintLibrary.data?.rule_count ?? 0} · DHCP ${fingerprintLibrary.data?.dhcp_rule_count ?? 0} · 域名 ${fingerprintLibrary.data?.domain_rule_count ?? 0} / ${fingerprintLibrary.data?.domain_ecosystem_count ?? 0} 个生态`,
                        },
                        {
                          key: "domain-availability",
                          label: "域名识别",
                          children: (fingerprintLibrary.data?.domain_rule_count ?? 0) === 0 ? "域名识别不可用：未加载域名规则" : `可用 · 可推断品牌规则 ${fingerprintLibrary.data?.brand_eligible_rule_count ?? 0} 条`,
                        },
                        {
                          key: "domain-provenance",
                          label: "域名来源明细",
                          children: <div className="brand-evidence-wrap">{fingerprintLibrary.data?.domain_sources?.map(source => <div key={`${source.name}-${source.version}`}>{source.name} · {source.version} · {source.rule_count} 条 / 可推断 {source.brand_eligible_rule_count} 条</div>) || "旧规则包未提供来源明细"}</div>,
                        },
                        {
                          key: "domain-processing",
                          label: "域名处理状态",
                          children: <div className="brand-evidence-wrap">生效 {fingerprintLibrary.data?.active_domain_version || ""} · 待重算 {fingerprintLibrary.data?.pending_domain_version || "无"} · {fingerprintLibrary.data?.domain_processing_error || "无处理错误"}</div>,
                        },
                        {
                          key: "domain-source",
                          label: "域名规则版本",
                          children: (
                            <Typography.Text className="mono list-cell-nowrap">
                              {fingerprintLibrary.data?.domain_source_version ||
                                "v1 包未包含域名规则"}
                            </Typography.Text>
                          ),
                        },
                        {
                          key: "domain-backfill",
                          label: "域名证据回填",
                          children: `${fingerprintLibrary.data?.domain_backfill_status || "未启动"} · ${fingerprintLibrary.data?.domain_backfill_processed ?? 0} 条`,
                        },
                        {
                          key: "domain-error",
                          label: "域名回填错误",
                          children:
                            fingerprintLibrary.data
                              ?.domain_backfill_last_error || "无",
                        },
                        {
                          key: "backfill",
                          label: "画像回填",
                          children: `${fingerprintLibrary.data?.backfill_status || "未启动"} · ${fingerprintLibrary.data?.backfill_processed ?? 0} 条`,
                        },
                        {
                          key: "licenses",
                          label: "数据许可",
                          children: (
                            fingerprintLibrary.data?.licenses || []
                          ).join("、"),
                        },
                      ]}
                    />
                  )}
                  <div className="fingerprint-import-panel">
                    <Space wrap>
                      <Upload
                        accept=".gz,.tgz,application/gzip"
                        beforeUpload={(file) => {
                          setBundleFile(file);
                          setManifest(null);
                          validateBundle.mutate(file, {
                            onSuccess: setManifest,
                            onError: (error) => message.error(error.message),
                          });
                          return false;
                        }}
                        fileList={
                          bundleFile
                            ? [
                                {
                                  uid: bundleFile.name,
                                  name: bundleFile.name,
                                  status: manifest ? "done" : "uploading",
                                },
                              ]
                            : []
                        }
                        maxCount={1}
                        onRemove={() => {
                          setBundleFile(null);
                          setManifest(null);
                        }}
                        showUploadList
                      >
                        <Button
                          disabled={!canUpdateLibrary}
                          icon={<UploadOutlined />}
                          loading={validateBundle.isPending}
                        >
                          选择并校验离线包
                        </Button>
                      </Upload>
                      <Button
                        type="primary"
                        disabled={!canUpdateLibrary || !bundleFile || !manifest}
                        loading={importBundle.isPending}
                        onClick={() =>
                          bundleFile &&
                          importBundle.mutate(bundleFile, {
                            onSuccess: (result) => {
                              message.success(`特征库已导入 ${result.version}`);
                              setBundleFile(null);
                              setManifest(null);
                            },
                            onError: (error) => message.error(error.message),
                          })
                        }
                      >
                        确认导入
                      </Button>
                    </Space>
                    {manifest && (
                      <Alert
                        showIcon
                        type="success"
                        title={`校验通过：${manifest.version}`}
                        description={`生成时间 ${new Date(manifest.created_at).toLocaleString()} · ${manifest.sources.map((source) => `${source.name} ${source.version}`).join(" · ")}`}
                      />
                    )}
                    <Typography.Text type="secondary">
                      离线包在可联网开发机生成；30
                      机器只执行校验、原子切换和画像回填，不上传现场设备数据。
                    </Typography.Text>
                  </div>
                </div>
              ),
            },
          ]}
        />
      </section>
    </main>
  );
}
