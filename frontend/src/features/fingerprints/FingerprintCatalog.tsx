import { Notice as Alert } from '../../shared/ui/Notice'
import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {Button,
  Descriptions,
  Drawer,
  Select,
  Skeleton,
  Tabs,
  Tag,
  Typography} from "antd";
import { request } from "../../shared/api/client";
import type { ColumnsType } from 'antd/es/table';
import type { components } from "../../shared/api/generated";
import { AppEmptyState, AppErrorAlert, AppFactBar, AppListHeader, AppServerPagination, AppTable, AppTableBar, formatCount, formatDateTime } from '../../shared/ui'

type Source = components["schemas"]["FingerprintSource"];
type Rule = components["schemas"]["FingerprintSourceRule"];
type CoverageItem = components["schemas"]["FingerprintCoverage"]["items"][number];
const labels: Record<string, string> = {
  loaded: "已加载",
  registered: "已登记",
  license_required: "需授权",
  pending_adapter: "待适配",
  converted: "可执行",
  duplicate: "已去重",
  unsupported_input: "字段待适配",
  unsupported_syntax: "语法待适配",
  invalid_data: "校验未通过",
  legacy_loaded: "原引擎已加载",
  dictionary: "型号字典",
  tv:"电视",network_adapter:"网卡",wearable:"穿戴设备",scanner:"扫描仪",print_server:"打印服务器",wireless_controller:"无线控制器",storage:"存储设备",
  router: "路由器",
  access_point: "无线接入点",
  switch: "交换机",
  printer: "打印机",
  camera: "摄像头",
  iot: "物联网设备",
  mobile: "手机",
  desktop: "电脑",
  client: "客户端",
  server: "服务端",
  host: "终端自报",
  self_report: "终端自报",
  auxiliary: "辅助线索",
};
const label = (s?: string) => (s ? (labels[s] ?? s) : "");
const failure = (error: Error | null) => (
  <AppErrorAlert title="指纹目录读取失败" message={error?.message} />
);

export function FingerprintCatalog({canViewRules=false}:{canViewRules?:boolean}) {
  const [tab, setTab] = useState("overview");
  const [source, setSource] = useState<string>();
  const [status, setStatus] = useState<string>();
  const [protocol, setProtocol] = useState<string>();
  const [role, setRole] = useState<string>();
  const [search, setSearch] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [moreOpen, setMoreOpen] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [coveragePage, setCoveragePage] = useState(1);
  const [coveragePageSize, setCoveragePageSize] = useState(20);
  useEffect(() => {
    const timer = globalThis.setTimeout(() => {
      const next = searchInput.trim();
      if (next !== search) { setSearch(next); setPage(1); }
    }, 300);
    return () => globalThis.clearTimeout(timer);
  }, [searchInput]);
  const [selected, setSelected] = useState<Rule>();
  const [selectedSource, setSelectedSource] = useState<Source>();
  const sources = useQuery({
    queryKey: ["fingerprint-sources"],
    queryFn: () =>
      request<components["schemas"]["FingerprintSourcePage"]>(
        "/device-fingerprint-library/sources",
      ),
  });
  const params = new URLSearchParams({
    page: String(page),
    page_size: String(pageSize),
    q: search,
  });
  if (source) params.set("source", source);
  if (status) params.set("status", status);
  if (protocol) params.set("protocol", protocol);
  if (role) params.set("role", role);
  const rules = useQuery({
    queryKey: ["fingerprint-source-rules", params.toString()],
    queryFn: () =>
      request<components["schemas"]["FingerprintRulePage"]>(
        `/device-fingerprint-library/rules?${params}`,
      ),
    enabled: tab === "rules" && canViewRules,
  });
  const coverage = useQuery({
    queryKey: ["fingerprint-source-coverage"],
    queryFn: () =>
      request<components["schemas"]["FingerprintCoverage"]>(
        "/device-fingerprint-library/coverage",
      ),
    enabled: tab === "coverage" || tab === "overview",
  });
  const list = sources.data?.items ?? [];
  const sum = (key: "executable_count" | "model_count" | "raw_count") =>
    list.filter((x) => !x.kind).reduce((n, x) => n + x[key], 0);
  const overviewStats = [
    { label: "实际加载来源", value: list.filter((s) => s.status === "loaded").length },
    { label: "可执行规则", value: sum("executable_count") },
    { label: "型号字典条目", value: sum("model_count") },
    { label: "已纳入转换条目", value: sum("raw_count") },
    { label: "OUI 条目", value: list.filter((s) => s.kind === "oui").reduce((n, s) => n + s.raw_count, 0) },
    { label: "近 24 小时命中终端", value: coverage.data?.matched_endpoints },
    { label: "命中终端中的冲突", value: coverage.data?.conflict_endpoints },
    { label: "外部域名条目", value: list.filter((s) => s.kind === "domain").reduce((n, s) => n + s.raw_count, 0) },
  ].filter((item): item is { label: string; value: number } => typeof item.value === "number" && item.value !== 0)

  const sourceName = (id: string) => list.find((s) => s.id === id)?.name ?? id;
  const coverageItems = coverage.data?.items ?? [];
  const coveragePageCount = Math.max(1, Math.ceil(coverageItems.length / coveragePageSize));
  const visibleCoveragePage = Math.min(coveragePage, coveragePageCount);
  const visibleCoverage = coverageItems.slice((visibleCoveragePage - 1) * coveragePageSize, visibleCoveragePage * coveragePageSize);
  const shortVersion = (version?: string) => version && version.length > 24 ? `${version.slice(0, 12)}…` : version
  const coverageColumns: ColumnsType<CoverageItem> = [
    { title: "来源", key: "source", width: 180, render: (_, item) => sourceName(item.source_id) },
    { title: "命中终端", dataIndex: "endpoint_count", width: 100, render: (value?: number) => value ?? 0 },
    { title: "规则命中关系", dataIndex: "match_count", width: 120, render: (value?: number) => value ?? 0 },
    { title: "规则匹配次数", dataIndex: "evaluation_match_count", width: 120, render: (value?: number) => value ?? 0 },
    { title: "实时计算", dataIndex: "realtime_match_count", width: 100, render: (value?: number) => value ?? 0 },
    { title: "历史重算", dataIndex: "history_match_count", width: 100, render: (value?: number) => value ?? 0 },
    { title: "冲突终端", dataIndex: "conflict_count", width: 100, render: (value?: number) => value ?? 0 },
    { title: "一致结论", dataIndex: "confirmed_count", width: 100, render: (value?: number) => value ?? 0 },
  ]
  const filter =
    (setter: (v: string | undefined) => void) => (v: string | undefined) => {
      setter(v);
      setPage(1);
    };
  const filters = (
    <AppTableBar
      searchPlaceholder="品牌、型号、规则名称"
      searchValue={searchInput}
      onSearchChange={setSearchInput}
      filters={<>
<Select
        aria-label="指纹来源筛选"
        placeholder="全部来源"
        allowClear
        value={source}
        onChange={filter(setSource)}
        options={list.map((s) => ({ value: s.id, label: s.name }))}
      />
        <Button size="small" type="text" onClick={() => setMoreOpen(value => !value)}>{moreOpen ? '收起筛选' : '更多筛选'}{[protocol, role, status].filter(Boolean).length ? `（${[protocol, role, status].filter(Boolean).length}）` : ''}</Button>
      </>}
      panel={moreOpen ? <div className="app-filter-panel">
<Select
        aria-label="指纹协议筛选"
        placeholder="全部协议"
        allowClear
        value={protocol}
        onChange={filter(setProtocol)}
        options={[...new Set(list.flatMap((s) => s.protocols))]
          .sort()
          .map((v) => ({ value: v, label: v }))}
      />
<Select
        aria-label="指纹品类筛选"
        placeholder="全部品类"
        allowClear
        value={role}
        onChange={filter(setRole)}
        options={[...new Set(list.flatMap((s) => s.categories))]
          .sort()
          .map((v) => ({ value: v, label: label(v) }))}
      />
<Select
        aria-label="规则状态筛选"
        placeholder="全部状态"
        allowClear
        value={status}
        onChange={filter(setStatus)}
        options={(tab === "sources"
          ? ["loaded", "registered", "pending_adapter", "license_required"]
          : [
              "converted",
              "dictionary",
              "duplicate",
              "unsupported_input",
              "unsupported_syntax",
              "invalid_data",
            ]
        ).map((v) => ({ value: v, label: label(v) }))}
      />
      </div> : undefined}
    />
  );
  if (sources.isLoading) return <Skeleton active />;
  if (sources.isError) return failure(sources.error);
  const sourceColumns: ColumnsType<Source> = [
    { title: "来源", key: "name", width: 260, render: (_, source) => <div className="fingerprint-source-name"><strong>{source.name}</strong><span className="fingerprint-ident fingerprint-source-meta" title={[source.license, source.version].filter(Boolean).join(" · ")}>{source.license}{source.version ? ` · ${shortVersion(source.version)}` : ""}</span>{source.reason && <span className="fingerprint-ident fingerprint-source-meta" title={source.reason}>{source.reason}</span>}</div> },
    { title: "状态", dataIndex: "status", width: 120, render: (value: string) => <Tag color={value === "loaded" ? "blue" : "default"}>{label(value)}</Tag> },
    { title: "转换条目", dataIndex: "raw_count", width: 110, render: (value: number) => formatCount(value) },
    { title: "可执行", dataIndex: "executable_count", width: 100, render: (value: number) => formatCount(value) },
    { title: "型号", dataIndex: "model_count", width: 90, render: (value: number) => formatCount(value) },
    { title: "上游", key: "url", width: 100, render: (_, source) => source.url.startsWith("https://") ? <a href={source.url} target="_blank" rel="noreferrer">上游项目</a> : null },
    { title: "操作", key: "actions", width: 200, render: (_, source) => <div className="fingerprint-actions"><Button onClick={() => setSelectedSource(source)}>来源详情</Button><Button disabled={!!source.kind} onClick={() => { setSource(source.id); setStatus(undefined); setPage(1); setTab("rules") }}>{source.kind ? "沿用原引擎" : "查看条目"}</Button></div> },
  ]
  const sourceTable = (items: Source[]) => <div className="list-table-scroll"><AppTable rowKey="id" columns={sourceColumns} dataSource={items} tableLayout="fixed" scroll={{ x: 980 }} /></div>
  const ruleColumns: ColumnsType<Rule> = [
    { title: "规则名称", key: "name", width: 280, render: (_, rule) => <div className="fingerprint-rule-name"><strong className="fingerprint-ident">{rule.name}</strong><Tag color={rule.status === "converted" ? "blue" : "default"}>{label(rule.status)}</Tag>{rule.reason && <span className="fingerprint-ident">{rule.reason}</span>}</div> },
    { title: "来源", key: "source", width: 160, render: (_, rule) => sourceName(rule.source_id) },
    { title: "协议", dataIndex: "protocol", width: 100 },
    { title: "归属", dataIndex: "role", width: 110, render: (value: string) => label(value) },
    { title: "品牌 / 型号", key: "model", render: (_, rule) => `${rule.brand ?? ""} ${rule.model ?? ""}`.trim() + (rule.hardware_version && rule.hardware_version !== "-" ? ` · ${rule.hardware_version}` : "") },
    { title: "操作", key: "actions", width: 120, render: (_, rule) => <Button onClick={() => setSelected(rule)}>条件与依据</Button> },
  ]
  return (
    <section className="fingerprint-catalog" aria-label="多来源设备指纹库">
      <Typography.Title level={4}>多来源设备指纹库</Typography.Title>
      <Typography.Paragraph type="secondary">
        按来源、协议和设备品类查看实际接入能力。库已登记不等于规则已生效，型号字典不作为独立识别证据。
      </Typography.Paragraph>
      <Tabs
        activeKey={tab}
        onChange={(v) => {
          setTab(v);
          setStatus(undefined);
          setPage(1);
        }}
        items={[
          {
            key: "overview",
            label: "总览",
            children: (
              <>
                <div className="fingerprint-overview-stats">
                  {overviewStats.map((stat) => <div className="fingerprint-overview-stat" key={stat.label}><span>{stat.label}</span><strong>{formatCount(stat.value)}</strong></div>)}
                </div>
                {coverage.data?.rebuild && (
                  <Typography.Paragraph>
                    历史重算：
                    {coverage.data.rebuild.complete
                      ? "入队扫描完成"
                      : "正在按字段入队"}{" "}
                    · 已检查 {coverage.data.rebuild.visited ?? 0} · 入队{" "}
                    {coverage.data.rebuild.enqueued ?? 0}
                  </Typography.Paragraph>
                )}
                <AppFactBar label="统计口径" items={['来源条目、匹配条件、去重规则和型号分别计数','上游全部数据与待适配条目不计入可执行规则']}/>
                {sourceTable(list.filter((s) => s.status === "loaded"))}
              </>
            ),
          },
          {
            key: "sources",
            label: "来源目录",
            children: (
              <>
                {filters}
                {sourceTable(list
                    .filter(
                      (s) =>
                        (!source || s.id === source) &&
                        (!protocol || s.protocols.includes(protocol)) &&
                        (!role || s.categories.includes(role)) &&
                        (!status || s.status === status) &&
                        (!search ||
                          `${s.name} ${s.reason}`
                            .toLowerCase()
                            .includes(search.toLowerCase())),
                    )
                    )}
              </>
            ),
          },
          {
            key: "rules",
            label: "规则检索",
            disabled: !canViewRules,
            children: (
              <>
                {filters}
                {rules.isLoading ? (
                  <Skeleton active />
                ) : rules.isError ? (
                  failure(rules.error)
                ) : (
                  <>
                    <AppListHeader title="规则检索" count={`${formatCount(rules.data?.total ?? 0)} 条`} />
                    <div className="list-table-scroll"><AppTable rowKey="id" columns={ruleColumns} dataSource={rules.data?.items ?? []} tableLayout="fixed" scroll={{ x: 1000 }} locale={{ emptyText: "暂无匹配条目" }} /></div>
                    <AppServerPagination page={page} pageSize={pageSize} total={rules.data?.total ?? 0} onChange={(next, size) => { setPage(next); setPageSize(size); }} />
                  </>
                )}
              </>
            ),
          },
          {
            key: "coverage",
            label: "现场覆盖",
            children: coverage.isLoading ? (
              <Skeleton active />
            ) : coverage.isError ? (
              failure(coverage.error)
            ) : (
              <>
                <AppFactBar label="识别结果统计口径" items={['统计每分钟异步更新','匹配次数按成功画像累计，区分实时与历史重算，不是报文次数','异常退出可能丢失尚未刷新的一分钟计数']}/>
                {coverage.data?.as_of && (
                  <Typography.Paragraph type="secondary">
                    统计时间 {formatDateTime(coverage.data.as_of)}
                  </Typography.Paragraph>
                )}
                {coverage.data?.status !== "ready" ? (
                  <AppEmptyState
                    description={
                      coverage.data?.status === "stale"
                        ? "覆盖统计已过期，等待后台刷新"
                        : "覆盖统计正在准备"
                    }
                  />
                ) : (
                  <>
                    <Typography.Paragraph>
                      跨库重叠终端 {coverage.data.overlap_endpoints ?? 0}
                    </Typography.Paragraph>
                    <AppListHeader title="现场覆盖" count={`${coverage.data.items.length} 个来源`} />
                    <div className="list-table-scroll">
                      <AppTable
                        rowKey="source_id"
                        columns={coverageColumns}
                        dataSource={visibleCoverage}
                        tableLayout="fixed"
                        scroll={{ x: 940 }}
                        locale={{ emptyText: "暂无来源命中记录" }}
                      />
                    </div>
                    <AppServerPagination page={visibleCoveragePage} pageSize={coveragePageSize} total={coverageItems.length} onChange={(next, size) => { setCoveragePage(next); setCoveragePageSize(size); }} totalText={`共 ${coverageItems.length} 条`} />
                  </>
                )}
              </>
            ),
          },
        ]}
      />
      <Drawer
        open={!!selected}
        onClose={() => setSelected(undefined)}
        title={selected?.name}
        className="fingerprint-detail"
      >
        <Descriptions
          column={1}
          items={
            selected
              ? [
                  {
                    key: "source",
                    label: "来源",
                    children: sourceName(selected.source_id),
                  },
                  {
                    key: "id",
                    label: "上游标识",
                    children: (
                      <span className="fingerprint-ident">
                        {selected.original_id}
                      </span>
                    ),
                  },
                  {
                    key: "v",
                    label: "版本",
                    children: (
                      <span className="fingerprint-ident">
                        {selected.version}
                      </span>
                    ),
                  },
                  {
                    key: "direction",
                    label: "归属方向",
                    children: label(selected.direction),
                  },
                  {
                    key: "strength",
                    label: "证据性质",
                    children: label(selected.strength),
                  },
                  {
                    key: "state",
                    label: "状态",
                    children: label(selected.status),
                  },
                ]
              : []
          }
        />
        {selected?.reason && <Alert type="info" title={selected.reason} />}
        <Typography.Title level={5}>匹配条件（同时满足）</Typography.Title>
        {selected?.conditions.map((c, i) => (
          <pre className="fingerprint-code" key={i}>
            {c.field} · {c.operator}
            {"\n"}
            {c.value}
          </pre>
        ))}
        <Typography.Title level={5}>回放样例</Typography.Title>
        {selected?.examples.map((e, i) => (
          <pre className="fingerprint-code" key={i}>
            {e.match ? "应命中" : "不应命中"}
            {"\n"}
            {JSON.stringify(e.values, null, 2)}
          </pre>
        ))}
      </Drawer>
      <Drawer
        open={!!selectedSource}
        onClose={() => setSelectedSource(undefined)}
        title={selectedSource?.name}
        className="fingerprint-detail"
      >
        <Descriptions
          column={1}
          items={
            selectedSource
              ? [
                  {
                    key: "version",
                    label: "版本",
                    children: (
                      <span className="fingerprint-ident">
                        {selectedSource.version}
                      </span>
                    ),
                  },
                  {
                    key: "checksum",
                    label: "快照校验",
                    children: (
                      <span className="fingerprint-ident">
                        {selectedSource.checksum}
                      </span>
                    ),
                  },
                  {
                    key: "license",
                    label: "许可证",
                    children: selectedSource.license,
                  },
                  {
                    key: "converter",
                    label: "转换器",
                    children: selectedSource.converter_version,
                  },
                  {
                    key: "upstream",
                    label: "上游原始条目",
                    children: selectedSource.upstream_count,
                  },
                  {
                    key: "count",
                    label: "匹配条件数",
                    children: selectedSource.condition_count,
                  },
                ]
              : []
          }
        />
        {Object.entries(selectedSource?.dispositions ?? {}).map(([k, v]) => (
          <Typography.Paragraph key={k}>
            {label(k)}：{v}
          </Typography.Paragraph>
        ))}
      </Drawer>
    </section>
  );
}
