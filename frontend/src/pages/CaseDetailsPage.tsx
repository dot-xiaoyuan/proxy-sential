import { useState } from "react";
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
          <Tag color="red">{data.assessment_level}</Tag>
          <Tag>{caseStatusText(data.status)}</Tag>
          <Typography.Text strong>
            {data.risk_score} 分 / {Math.round(data.risk_confidence * 100)}%
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
                  {data.ip || "-"}
                </Link>
              ),
            },
            {
              key: "account",
              label: "账号",
              children: data.account_id || "待关联",
            },
            {
              key: "endpoint",
              label: "终端",
              children: data.endpoint_id || "待关联",
            },
            {
              key: "campus",
              label: "校区/楼宇",
              children:
                [data.campus_id, data.building_id]
                  .filter(Boolean)
                  .join(" / ") || "待关联",
            },
            {
              key: "access",
              label: "SSID / VLAN / AP",
              children:
                [data.ssid, data.vlan, data.ap].filter(Boolean).join(" / ") ||
                "待关联",
            },
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
                        { value: "confirmed_proxy", label: "确认代理" },
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
                </>
              ),
            },
            {
              key: "evidence",
              label: "证据快照",
              children: (
                <>
                  <Typography.Paragraph>
                    {data.evidence_snapshot?.event_count
                      ? `共 ${data.evidence_snapshot.event_count} 条事件，TLS ${data.evidence_snapshot.tls_count}，QUIC ${data.evidence_snapshot.quic_count}，明确规则命中 ${data.evidence_snapshot.rule_matches?.length ?? 0} 条。`
                      : "暂无证据快照"}
                  </Typography.Paragraph>
                  <Typography.Text type="secondary">
                    案件保存发现时证据，规则更新不会覆盖历史判断。
                  </Typography.Text>
                </>
              ),
            },
            {
              key: "timeline",
              label: `活动记录 ${(data.timeline ?? []).length}`,
              children: (
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
