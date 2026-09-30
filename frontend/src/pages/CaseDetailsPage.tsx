import { useState } from "react";
import { CaseHistoryList } from "./CaseHistoryList";
import { Link, useParams } from "react-router-dom";
import {
  Alert,
  Button,
  Card,
  Descriptions,
  Divider,
  Input,
  Select,
  Space,
  Tabs,
  Tag,
  Timeline,
  Typography,
  message,
} from "antd";

import { can } from "../shared/auth/permissions";
import { useCase, useCaseMutation, useSession } from "../shared/api/queries";
import { AppErrorAlert, AppLoadingState, AppPageHeader } from "../shared/ui";

export function CaseDetailsPage() {
  const { caseId = "" } = useParams();
  const item = useCase(caseId);
  const mutation = useCaseMutation();
  const session = useSession();
  const [comment, setComment] = useState("");
  if (item.isLoading) return <AppLoadingState rows={8} />;
  if (item.isError || !item.data)
    return <AppErrorAlert title="案件不存在或已超过保留期" />;
  const data = item.data;
  const sharedEvidence = data.evidence_snapshot?.shared_access;
  const routerEvidence = data.evidence_snapshot?.router_observation;
  const isSharedAccess = data.risk_kind === "shared_access" || Boolean(sharedEvidence);
  const isRouterObservation = data.risk_kind === "router_observation" || Boolean(routerEvidence);
  const campusLocation = [data.campus_id, data.building_id].filter(Boolean).join(" / ");
  const accessLocation = [data.ssid, data.vlan, data.ap].filter(Boolean).join(" / ");
  const writable = can(session.data, "cases:write");
  const mutate = (
    operation: "assign" | "status" | "priority" | "disposition" | "comment",
    value: string,
  ) =>
    mutation.mutate(
      { caseId: data.case_id, operation, value },
      { onSuccess: () => message.success("案件已更新") },
    );
  return (
    <main className="page">
      <AppPageHeader
        title={`案件 ${data.case_id}`}
        subtitle="风险、身份、证据、复核结论与处置动作统一留痕"
        extra={<Link to="/cases">返回案件队列</Link>}
      />
      {!writable && <Alert showIcon title="当前角色只有查看权限" type="info" />}
      {data.identity_blocker && (
        <Alert
          className="margin-bottom-md"
          showIcon
          title="身份定位未满足自动处置条件"
          description={data.identity_blocker}
          type={data.identity_conflict ? "error" : "warning"}
        />
      )}
      <Card className="surface-card" title="案件摘要">
        <Space wrap>
          <Tag color="red">
            {isSharedAccess
              ? "已确认共享"
              : isRouterObservation
                ? data.assessment_level === "confirmed" ? "已确认路由器" : "较可信路由器观察"
                : data.assessment_level}
          </Tag>
          <Tag>{caseStatusText(data.status)}</Tag>
          <Typography.Text strong>
            风险分 {data.risk_score} · 置信度 {Math.round(data.risk_confidence * 100)}%
          </Typography.Text>
        </Space>
        <Descriptions
          className="margin-top-md"
          column={{ xs: 1, md: 3 }}
          items={[
            {
              key: "ip",
              label: "IP",
              children: (
                <Link to={`/ips/${encodeURIComponent(data.ip ?? "")}`}>
                  {data.ip || ""}
                </Link>
              ),
            },
            ...(data.account_id ? [{
              key: "account",
              label: "账号",
              children: data.account_id,
            }] : []),
            ...(data.endpoint_id ? [{
              key: "endpoint",
              label: "终端",
              children: data.endpoint_id,
            }] : []),
            ...(campusLocation ? [{
              key: "campus",
              label: "校区/楼宇",
              children: campusLocation,
            }] : []),
            ...(accessLocation ? [{
              key: "access",
              label: "SSID / VLAN / AP",
              children: accessLocation,
            }] : []),
            {
              key: "due",
              label: "SLA 截止",
              children: new Date(data.due_at).toLocaleString(),
            },
          ]}
        />
      </Card>
      <Card className="surface-card margin-top-md operations-tabs-surface">
        <Tabs
          destroyOnHidden
          items={[
            {
              key: "operations",
              label: "协同处置",
              children: (
                <>
                  <Space wrap>
                    <Input
                      aria-label="负责人"
                      className="case-assignee-input"
                      disabled={!writable}
                      placeholder="负责人账号"
                      onPressEnter={(event) =>
                        mutate("assign", event.currentTarget.value)
                      }
                    />
                    <Select
                      aria-label="案件状态"
                      disabled={!writable}
                      value={data.status}
                      onChange={(value) => mutate("status", value)}
                      options={caseNextStatuses(data.status).map((value) => ({
                        value,
                        label: caseStatusText(value),
                      }))}
                    />
                    <Select
                      aria-label="优先级"
                      disabled={!writable}
                      value={data.priority}
                      onChange={(value) => mutate("priority", value)}
                      options={[
                        { value: "high", label: "高" },
                        { value: "medium", label: "中" },
                        { value: "low", label: "低" },
                      ]}
                    />
                    <Select
                      aria-label="复核结论"
                      disabled={!writable}
                      placeholder="选择复核结论"
                      onChange={(value) => mutate("disposition", value)}
                      options={[
                        isSharedAccess
                          ? { value: "confirmed_shared_access", label: "确认共享行为" }
                          : isRouterObservation
                            ? { value: "confirmed_router", label: "确认路由设备" }
                          : { value: "confirmed_proxy", label: "确认代理" },
                        { value: "false_positive", label: "误报" },
                        { value: "benign", label: "良性" },
                        { value: "needs_more_data", label: "需要更多数据" },
                      ]}
                    />
                  </Space>
                  <Divider />
                  <Input.TextArea
                    disabled={!writable}
                    placeholder="补充调查记录"
                    value={comment}
                    onChange={(event) => setComment(event.target.value)}
                  />
                  <Button
                    className="margin-top-sm"
                    disabled={!writable || comment.trim().length < 2}
                    onClick={() => {
                      mutate("comment", comment);
                      setComment("");
                    }}
                  >
                    添加记录
                  </Button>
                  <CaseHistoryList caseId={data.case_id} kind="comments" total={data.history_page?.comments?.total} />
                </>
              ),
            },
            {
              key: "evidence",
              label: "证据快照",
              children: (
                <>
                  {sharedEvidence ? (
                    <div className="shared-behavior-evidence">
                      <Typography.Paragraph>
                        <Typography.Text strong>共享行为已确认</Typography.Text>
                        {` · 置信度 ${sharedEvidence.confidence}% · 当前设备下界 ${sharedEvidence.device_lower_bound} 台`}
                      </Typography.Paragraph>
                      <Typography.Paragraph>
                        强锚点：{sharedAnchorText(sharedEvidence.strong_anchor)} · 覆盖状态：
                        {sharedEvidence.coverage_state === "verified"
                          ? "完整覆盖已验证"
                          : sharedEvidence.coverage_state}
                      </Typography.Paragraph>
                      <Typography.Paragraph>
                        当前窗口：{formatTime(sharedEvidence.window_start)} — {formatTime(sharedEvidence.window_end)}
                      </Typography.Paragraph>
                      <Typography.Paragraph className="case-history-id">
                        当前代次：{sharedEvidence.generation_id}
                      </Typography.Paragraph>
                      {sharedEvidence.anchor_identities.length > 0 && (
                        <Space wrap>
                          {sharedEvidence.anchor_identities.map((identity) => (
                            <Tag key={identity}>{identity}</Tag>
                          ))}
                        </Space>
                      )}
                      {(sharedEvidence.reference_device_count_24h ?? 0) > 0 && (
                        <Typography.Paragraph type="secondary">
                          24 小时明确型号参考数：{sharedEvidence.reference_device_count_24h ?? 0}
                          （仅供详情参考，不参与本次确认）
                        </Typography.Paragraph>
                      )}
                      <details>
                        <summary>原始事件引用（{sharedEvidence.source_event_ids.length}）</summary>
                        <div className="case-history-json">
                          {sharedEvidence.source_event_ids.join("\n")}
                        </div>
                      </details>
                    </div>
                  ) : routerEvidence ? (
                    <div className="router-observation-evidence">
                      <Typography.Paragraph>
                        <Typography.Text strong>{routerEvidence.status === "confirmed" ? "路由设备已确认" : "较可信路由设备观察"}</Typography.Text>
                        {` · 置信度 ${routerEvidence.confidence}% · 独立证据源 ${routerEvidence.independent_sources} 类`}
                      </Typography.Paragraph>
                      <Descriptions
                        column={{ xs: 1, md: 2 }}
                        items={[
                          { key: "role", label: "设备角色", children: routerRoleText(routerEvidence.role) },
                          ...(routerEvidence.brand ? [{ key: "brand", label: "品牌", children: routerEvidence.brand }] : []),
                          ...(routerEvidence.series ? [{ key: "series", label: "系列", children: routerEvidence.series }] : []),
                          ...(routerEvidence.model ? [{ key: "model", label: "型号", children: routerEvidence.model }] : []),
                          ...(routerEvidence.mac ? [{ key: "mac", label: "MAC", children: <span className="mono wrap-anywhere">{routerEvidence.mac}</span> }] : []),
                          { key: "window", label: "当前有效观察", children: `${formatTime(routerEvidence.first_seen)} — ${formatTime(routerEvidence.expires_at)}` },
                          { key: "rules", label: "规则版本", children: routerEvidence.rule_version },
                        ]}
                      />
                      {routerEvidence.sources.length > 0 && <Space wrap>{routerEvidence.sources.map(source => <Tag key={source}>{routerSourceText(source)}</Tag>)}</Space>}
                      {routerEvidence.score_components.length > 0 && (
                        <div className="router-score-components">
                          {routerEvidence.score_components.map(component => (
                            <Typography.Paragraph key={`${component.source_family}-${component.evidence_id}`}>
                              <Typography.Text strong>{routerSourceText(component.source_family)} +{component.score}</Typography.Text>
                              {` · ${component.explanation}`}
                            </Typography.Paragraph>
                          ))}
                        </div>
                      )}
                      {routerEvidence.conflicts.length > 0 && <Alert showIcon type="warning" title="证据存在冲突" description={routerEvidence.conflicts.join("；")} />}
                    </div>
                  ) : (
                    <Typography.Paragraph>
                      {data.evidence_snapshot?.event_count
                        ? `共 ${data.evidence_snapshot.event_count} 条事件，TLS ${data.evidence_snapshot.tls_count}，QUIC ${data.evidence_snapshot.quic_count}，明确规则命中 ${data.evidence_snapshot.rule_matches?.length ?? 0} 条。`
                        : "暂无证据快照"}
                    </Typography.Paragraph>
                  )}
                  <Typography.Text type="secondary">
                    案件保存发现时证据，规则更新不会覆盖历史判断。
                  </Typography.Text>
                  <CaseHistoryList caseId={data.case_id} kind="evidence" total={data.history_page?.evidence?.total} />
                </>
              ),
            },
            {
              key: "timeline",
              label: `活动记录 ${(data.timeline ?? []).length}`,
              children: (
                <>
                <Timeline
                  items={(data.timeline ?? [])
                    .slice()
                    .reverse()
                    .map((event) => ({
                      children: (
                        <div>
                          <Typography.Text strong>{event.type}</Typography.Text>
                          <div>
                            <Typography.Text type="secondary">
                              {event.actor_id} ·{" "}
                              {new Date(event.created_at).toLocaleString()}
                            </Typography.Text>
                          </div>
                        </div>
                      ),
                    }))}
                />
                <CaseHistoryList caseId={data.case_id} kind="timeline" total={data.history_page?.timeline?.total} />
                </>
              ),
            },
          ]}
        />
      </Card>
    </main>
  );
}

const caseTransitions: Record<string, string[]> = {
  new: ["new", "assigned", "investigating", "waiting_data"],
  assigned: ["assigned", "investigating", "waiting_data"],
  investigating: ["investigating", "waiting_data"],
  waiting_data: ["waiting_data", "investigating"],
  resolved: ["resolved", "closed", "reopened"],
  closed: ["closed", "reopened"],
  reopened: ["reopened", "assigned", "investigating", "waiting_data"],
};
const caseStatusNames: Record<string, string> = {
  new: "新建",
  assigned: "已分派",
  investigating: "调查中",
  waiting_data: "等待数据",
  resolved: "已解决",
  closed: "已关闭",
  reopened: "重新打开",
};
function caseNextStatuses(status: string) {
  return caseTransitions[status] ?? [status];
}
function caseStatusText(status: string) {
  return caseStatusNames[status] ?? status;
}

function sharedAnchorText(anchor: string) {
  return (
    {
      ieee1905_association: "IEEE 1905.1 / EasyMesh 当前关联终端",
      coexisting_device_identities: "当前窗口稳定物理设备重复共现",
    } as Record<string, string>
  )[anchor] ?? anchor;
}

function routerRoleText(role:string) {
  return ({router:"路由器",ap:"无线接入点",switch:"交换机",firewall:"防火墙"} as Record<string,string>)[role] ?? role;
}

function routerSourceText(source:string) {
  return ({dhcp:"DHCP",oui:"MAC 厂商",tls:"TLS 管理面",shared_gateway_behavior:"共享网关行为",vendor_control_plane:"厂商控制面"} as Record<string,string>)[source] ?? source;
}

function formatTime(value: string) {
  return value ? new Date(value).toLocaleString() : "";
}
