import { useUrlState } from '../shared/ui/useUrlState'
import { ApplicationActivity } from "../features/applications/ApplicationActivity";
import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Col, Row, Tabs } from "antd";

import { EChartsDualAxisTrend } from "../features/charts/EChartsDualAxisTrend";
import { EChartsTopReport } from "../features/charts/EChartsTopReport";
import { FingerprintConflictMatrix } from "../features/dpi/FingerprintConflictMatrix";
import { FlowInspectorDrawer } from "../features/dpi/FlowInspectorDrawer";
import {
  useActivityOverview,
  useActivityReport,
  useDpiFingerprintConflicts,
  useDpiTrends,
} from "../shared/api/queries";
import {
  AppErrorAlert,
  AppLoadingState,
  AppMetricCard,
  AppPageHeader,
  StatisticsTime,
  type ReportWindow,
} from "../shared/ui";

export function ActivityPage() {
  const navigate = useNavigate();
  const [params]=useSearchParams();
  const [windowValue,setQuickWindow]=useUrlState('window','1h',['10m','1h','24h','7d','30d']);const quickWindow=windowValue as ReportWindow;
  const [section]=useUrlState('section','applications',['applications','access','technical']);
  const allowed=section==='applications'?['visits']:section==='technical'?['matrix','fingerprints']:['applications','ecosystem','domains','network'];
  const [tabKey,setTabKey]=useUrlState('tab',allowed[0],allowed);
  const context={window:quickWindow,sensor_id:params.get('sensor_id')||undefined,campus_id:params.get('campus_id')||undefined};
  const [inspectIp, setInspectIp] = useState<string | null>(null);

  const activity = useActivityOverview(context,section!=='applications');
  const dpiTrends = useDpiTrends(context,section==='access');
  const fingerprintConflicts = useDpiFingerprintConflicts(
    context,
    tabKey === "matrix",
  );
  const applicationReport = useActivityReport(
    { ...context, dimension: "application", limit: 10 },
    tabKey === "applications",
  );
  const protocolReport = useActivityReport(
    { ...context, dimension: "protocol", limit: 10 },
    tabKey === "applications" || tabKey === "network",
  );
  const ecosystemReport = useActivityReport(
    { ...context, dimension: "ecosystem", limit: 10 },
    tabKey === "ecosystem",
  );
  const domainReport = useActivityReport(
    { ...context, dimension: "domain", limit: 10 },
    tabKey === "domains",
  );
  const hostReport = useActivityReport(
    { ...context, dimension: "http_host", limit: 10 },
    tabKey === "domains",
  );
  const sniReport = useActivityReport(
    { ...context, dimension: "tls_sni", limit: 10 },
    tabKey === "domains",
  );
  const uaReport = useActivityReport(
    { ...context, dimension: "user_agent", limit: 10 },
    tabKey === "fingerprints",
  );
  const portReport = useActivityReport(
    { ...context, dimension: "dst_port", limit: 10 },
    tabKey === "network",
  );
  const destinationReport = useActivityReport(
    { ...context, dimension: "dst_ip", limit: 10 },
    tabKey === "network",
  );
  const navigateReport = (dimension: string, key: string) =>
    navigate(reportSearchPath(dimension, key, quickWindow, params));

  if(section==='applications')return <main className="page"><AppPageHeader title="应用访问" subtitle="按明确应用特征查看服务访问与对应观测" quickWindow={quickWindow} quickWindows={['10m','1h','24h','7d','30d']} onQuickWindowChange={setQuickWindow}/><section className="surface"><ApplicationActivity window={quickWindow}/></section></main>;
  if (activity.isLoading) {
    return <AppLoadingState rows={8} />;
  }

  if (activity.isError || !activity.data) {
    return <AppErrorAlert title="DPI 访问态势加载失败" message={activity.error?.message} />;
  }

  const data = activity.data;

  const renderActiveTabContent = () => {
    switch (tabKey) {
      case "visits":
        return <ApplicationActivity window={quickWindow} />;
      case "applications":
        return (
          <Row className="activity-tab-panel" gutter={[16, 16]}>
            <Col xs={24} md={12}>
              <EChartsTopReport
                title="应用协议分布"
                kind="donut"
                report={applicationReport.data}
                note="仅使用传感器明确输出的应用协议；无法识别时保留在空值分组。"
                onSelect={(key) => navigateReport("application", key)}
              />
            </Col>
            <Col xs={24} md={12}>
              <EChartsTopReport
                title="网络协议分布"
                kind="donut"
                report={protocolReport.data}
                onSelect={(key) => navigateReport("protocol", key)}
              />
            </Col>
          </Row>
        );
      case "ecosystem":
        return (
          <div className="activity-tab-panel">
            <EChartsTopReport
              title="访问品牌生态"
              kind="donut"
              report={ecosystemReport.data}
              note="访问相关服务不等于确认终端硬件品牌，未归属命中也会计入本报表。"
              onSelect={(key) => navigateReport("ecosystem", key)}
            />
          </div>
        );
      case "matrix":
        return (
          <div className="activity-tab-panel">
            <FingerprintConflictMatrix
              items={fingerprintConflicts.data?.items ?? []}
              onInspectIp={(ip) => setInspectIp(ip)}
            />
          </div>
        );
      case "domains":
        return (
          <Row className="activity-tab-panel" gutter={[16, 16]}>
            <Col span={24}>
              <EChartsTopReport
                title="Top 访问域名（DNS / Host / SNI）"
                kind="bar"
                report={domainReport.data}
                onSelect={(key) => navigateReport("domain", key)}
              />
            </Col>
            <Col xs={24} md={12}>
              <EChartsTopReport
                title="HTTP Host"
                kind="bar"
                report={hostReport.data}
                onSelect={(key) => navigateReport("domain", key)}
              />
            </Col>
            <Col xs={24} md={12}>
              <EChartsTopReport
                title="TLS SNI"
                kind="bar"
                report={sniReport.data}
                onSelect={(key) => navigateReport("domain", key)}
              />
            </Col>
          </Row>
        );
      case "fingerprints":
        return (
          <Row className="activity-tab-panel" gutter={[16, 16]}>
            <Col xs={24} md={12}>
              <EChartsTopReport
                title="客户端软件标识（UA）"
                kind="bar"
                report={uaReport.data}
                note="UA 可重复、可伪造，只用于技术检索，不表示设备数量或硬件品牌。"
                onSelect={(key) => navigateReport("user_agent", key)}
              />
            </Col>
            <Col xs={24} md={12}>
              <EChartsTopReport
                title="TLS JA3 / JA4 客户端指纹"
                kind="bar"
                report={{
                  dimension: "fingerprint",
                  total: data.top_tls_fingerprints.reduce(
                    (sum, item) => sum + item.count,
                    0,
                  ),
                  classified_count: data.top_tls_fingerprints.reduce(
                    (sum, item) => sum + item.count,
                    0,
                  ),
                  unknown_count: 0,
                  items: data.top_tls_fingerprints.map((item) => ({
                    key: item.value,
                    label: item.value,
                    count: item.count,
                    share: 0,
                    last_seen: item.last_seen,
                  })),
                }}
                onSelect={(key) => navigateReport("fingerprint", key)}
              />
            </Col>
          </Row>
        );
      case "network":
        return (
          <Row className="activity-tab-panel" gutter={[16, 16]}>
            <Col xs={24} md={12}>
              <EChartsTopReport
                title="目的端口排行"
                kind="bar"
                report={portReport.data}
                onSelect={(key) => navigateReport("port", key)}
              />
            </Col>
            <Col xs={24} md={12}>
              <EChartsTopReport
                title="传输协议分布"
                kind="donut"
                report={protocolReport.data}
                onSelect={(key) => navigateReport("protocol", key)}
              />
            </Col>
            <Col xs={24} md={12}>
              <EChartsTopReport
                title="目的 IP 排行"
                kind="bar"
                report={destinationReport.data}
                onSelect={(key) => navigateReport("dst_ip", key)}
              />
            </Col>
            <Col xs={24} md={12}>
              <EChartsTopReport
                title="活跃源 IP 排行"
                kind="bar"
                report={{
                  dimension: "src_ip",
                  total: data.top_source_ips.reduce(
                    (sum, item) => sum + item.count,
                    0,
                  ),
                  classified_count: data.top_source_ips.reduce(
                    (sum, item) => sum + item.count,
                    0,
                  ),
                  unknown_count: 0,
                  items: data.top_source_ips.map((item) => ({
                    key: item.value,
                    label: item.value,
                    count: item.count,
                    share: 0,
                    last_seen: item.last_seen,
                  })),
                }}
                onSelect={(key) => navigateReport("src_ip", key)}
              />
            </Col>
          </Row>
        );
    }
  };

  const tabItems = [
    { key: "applications", label: "应用协议" },
    { key: "ecosystem", label: "访问生态" },
    { key: "matrix", label: "多源指纹一致性" },
    { key: "domains", label: "访问对象 (Domains)" },
    { key: "fingerprints", label: "客户端指纹 (UA/JA3)" },
    { key: "network", label: "网络与端口分布" },
  ].filter(item=>allowed.includes(item.key));

  return (
    <main className="page">
      <AppPageHeader
        loading={
          activity.isFetching ||
          dpiTrends.isFetching ||
          (tabKey === "matrix" && fingerprintConflicts.isFetching)
        }
        onQuickWindowChange={setQuickWindow}
        onRefresh={() => {
          void activity.refetch();
          void dpiTrends.refetch();
          if (tabKey === "matrix") void fingerprintConflicts.refetch();
        }}
        quickWindow={quickWindow}
        quickWindows={['10m', '1h', '24h', '7d', '30d']}
        subtitle="基于标准事件元数据呈现 L7 协议流向、终端指纹碰撞与访问对象排行"
        title={section==='technical'?'技术指纹':'访问分析'}
      />

      <StatisticsTime freshness={activity.data.data_freshness} value={activity.data.statistics_as_of} />

      <section className="metric-grid">
        <AppMetricCard
          statusColor="blue"
          statusText="标准格式"
          title="DPI 标准事件数"
          value={data.event_count}
        />
        <AppMetricCard
          statusColor="green"
          statusText="当前 sensor"
          title="观测域活跃 IP"
          value={data.active_ip_count}
        />
        <AppMetricCard
          statusColor="purple"
          statusText="SaaS/Web 目标"
          title="L7 访问目标数"
          value={data.access_object_count}
        />
      </section>

      {section==='access' && <section className="activity-trend-section">
        <EChartsDualAxisTrend
          title={`${quickWindow} 活跃 IP 与吞吐趋势`}
          loading={dpiTrends.isLoading}
          points={dpiTrends.data?.points ?? []}
        />
      </section>}

      <section className="surface">
        <Tabs
          activeKey={tabKey}
          items={tabItems}
          onChange={(k) => setTabKey(k as typeof tabKey)}
        />
        {renderActiveTabContent()}
      </section>

      <FlowInspectorDrawer
        context={{...context,from:params.get('from')||undefined,to:params.get('to')||undefined}}
        ip={inspectIp}
        onClose={() => setInspectIp(null)}
        open={Boolean(inspectIp)}
      />
    </main>
  );
}

export function reportSearchPath(kind: string, value: string, window: string, source = new URLSearchParams()) {
  const params = new URLSearchParams({ window });
  for(const key of ['sensor_id','campus_id','from','to'])if(source.get(key))params.set(key,source.get(key)!);
  if (kind === "port") {
    params.set("port", value);
  } else if (kind === "protocol") {
    params.set("proto", value);
  } else if (kind === "application") {
    params.set("app_protocol", value);
  } else {
    params.set(kind, value);
  }
  if(kind==='ecosystem')return `/devices?${params.toString()}`;
  return `/events?${params.toString()}`;
}
