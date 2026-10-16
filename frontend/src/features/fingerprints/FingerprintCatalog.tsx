import { Notice as Alert } from '../../shared/ui/Notice'
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {Button,
  Card,
  Descriptions,
  Drawer,
  Empty,
  Input,
  Pagination,
  Select,
  Skeleton,
  Statistic,
  Tabs,
  Tag,
  Typography} from "antd";
import { request } from "../../shared/api/client";
import type { components } from "../../shared/api/generated";
import { AppFactBar } from '../../shared/ui'

type Source = components["schemas"]["FingerprintSource"];
type Rule = components["schemas"]["FingerprintSourceRule"];
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
  host: "设备自报",
  self_report: "设备自报",
  auxiliary: "辅助线索",
};
const label = (s?: string) => (s ? (labels[s] ?? s) : "");
const failure = (error: Error | null) => (
  <Alert
    type="error"
    showIcon
    title="指纹目录读取失败"
    description={error?.message}
  />
);

export function FingerprintCatalog() {
  const [tab, setTab] = useState("overview");
  const [source, setSource] = useState<string>();
  const [status, setStatus] = useState<string>();
  const [protocol, setProtocol] = useState<string>();
  const [role, setRole] = useState<string>();
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
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
    page_size: "25",
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
    enabled: tab === "rules",
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
  const sourceName = (id: string) => list.find((s) => s.id === id)?.name ?? id;
  const filter =
    (setter: (v: string | undefined) => void) => (v: string | undefined) => {
      setter(v);
      setPage(1);
    };
  const filters = (
    <div className="fingerprint-toolbar">
      <Input.Search
        aria-label="搜索指纹规则"
        placeholder="品牌、型号、规则名称"
        allowClear
        onSearch={(v) => {
          setSearch(v);
          setPage(1);
        }}
      />
      <Select
        aria-label="指纹来源筛选"
        placeholder="全部来源"
        allowClear
        value={source}
        onChange={filter(setSource)}
        options={list.map((s) => ({ value: s.id, label: s.name }))}
      />
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
    </div>
  );
  if (sources.isLoading) return <Skeleton active />;
  if (sources.isError) return failure(sources.error);
  const sourceCard = (s: Source) => (
    <Card
      key={s.id}
      size="small"
      className="fingerprint-source-card"
      title={
        <div className="fingerprint-card-heading">
          <span>{s.name}</span>
          <Tag color={s.status === "loaded" ? "blue" : "default"}>
            {label(s.status)}
          </Tag>
        </div>
      }
    >
      <div className="fingerprint-source-metrics">
        <span>
          转换条目 <strong>{s.raw_count.toLocaleString()}</strong>
        </span>
        <span>
          可执行 <strong>{s.executable_count.toLocaleString()}</strong>
        </span>
        <span>
          型号 <strong>{s.model_count.toLocaleString()}</strong>
        </span>
      </div>
      <Typography.Paragraph type="secondary" className="fingerprint-ident">
        {s.license}
        {s.version ? ` · ${s.version}` : ""}
      </Typography.Paragraph>
      {s.reason && (
        <Typography.Paragraph type="secondary">{s.reason}</Typography.Paragraph>
      )}
      <div className="fingerprint-actions">
        <Button onClick={() => setSelectedSource(s)}>来源详情</Button>
        <Button
          disabled={!!s.kind}
          onClick={() => {
            setSource(s.id);
            setStatus(undefined);
            setPage(1);
            setTab("rules");
          }}
        >
          {s.kind ? "沿用原引擎" : "查看条目"}
        </Button>
        {s.url.startsWith("https://") && (
          <a href={s.url} target="_blank" rel="noreferrer">
            上游项目
          </a>
        )}
      </div>
    </Card>
  );
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
                <div className="fingerprint-stats">
                  <Card>
                    <Statistic
                      title="实际加载来源"
                      value={list.filter((s) => s.status === "loaded").length}
                    />
                  </Card>
                  <Card>
                    <Statistic
                      title="可执行规则"
                      value={sum("executable_count")}
                    />
                  </Card>
                  <Card>
                    <Statistic
                      title="型号字典条目"
                      value={sum("model_count")}
                    />
                  </Card>
                  <Card>
                    <Statistic
                      title="已纳入转换条目"
                      value={sum("raw_count")}
                    />
                  </Card>
                  <Card>
                    <Statistic
                      title="OUI 条目"
                      value={list
                        .filter((s) => s.kind === "oui")
                        .reduce((n, s) => n + s.raw_count, 0)}
                    />
                  </Card>
                  <Card>
                    <Statistic
                      title="近 24 小时命中终端"
                      value={coverage.data?.matched_endpoints ?? ""}
                    />
                  </Card>
                  <Card>
                    <Statistic
                      title="命中终端中的冲突"
                      value={coverage.data?.conflict_endpoints ?? ""}
                    />
                  </Card>
                  <Card>
                    <Statistic
                      title="外部域名条目"
                      value={list
                        .filter((s) => s.kind === "domain")
                        .reduce((n, s) => n + s.raw_count, 0)}
                    />
                  </Card>
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
                <div className="fingerprint-source-grid">
                  {list.filter((s) => s.status === "loaded").map(sourceCard)}
                </div>
              </>
            ),
          },
          {
            key: "sources",
            label: "来源目录",
            children: (
              <>
                {filters}
                <div className="fingerprint-source-grid">
                  {list
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
                    .map(sourceCard)}
                </div>
              </>
            ),
          },
          {
            key: "rules",
            label: "规则检索",
            children: (
              <>
                {filters}
                {rules.isLoading ? (
                  <Skeleton active />
                ) : rules.isError ? (
                  failure(rules.error)
                ) : (
                  <>
                    <div className="fingerprint-rules">
                      {rules.data?.items.map((r) => (
                        <Card key={r.id} size="small">
                          <div className="fingerprint-card-heading">
                            <Typography.Text
                              strong
                              className="fingerprint-ident"
                            >
                              {r.name}
                            </Typography.Text>
                            <Tag
                              color={
                                r.status === "converted" ? "blue" : "default"
                              }
                            >
                              {label(r.status)}
                            </Tag>
                          </div>
                          <div className="fingerprint-rule-meta">
                            <span>{sourceName(r.source_id)}</span>
                            <span>{r.protocol}</span>
                            <span>{label(r.role)}</span>
                            <span>
                              {r.brand} {r.model}
                              {r.hardware_version && r.hardware_version !== "-"
                                ? ` · ${r.hardware_version}`
                                : ""}
                            </span>
                          </div>
                          {r.reason && (
                            <Typography.Paragraph type="secondary">
                              {r.reason}
                            </Typography.Paragraph>
                          )}
                          <Button onClick={() => setSelected(r)}>
                            条件与依据
                          </Button>
                        </Card>
                      ))}
                    </div>
                    {rules.data?.total === 0 ? (
                      <Empty description="没有匹配条目" />
                    ) : (
                      <Pagination
                        current={page}
                        pageSize={25}
                        total={rules.data?.total ?? 0}
                        onChange={setPage}
                        showSizeChanger={false}
                        showTotal={(n) => `共 ${n.toLocaleString()} 条`}
                      />
                    )}
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
                    统计时间 {new Date(coverage.data.as_of).toLocaleString()}
                  </Typography.Paragraph>
                )}
                {coverage.data?.status !== "ready" ? (
                  <Empty
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
                    <div className="fingerprint-source-grid">
                      {coverage.data.items.map((x) => (
                        <Card key={x.source_id} title={sourceName(x.source_id)}>
                          <Descriptions
                            column={1}
                            items={[
                              {
                                key: "e",
                                label: "命中终端",
                                children: x.endpoint_count,
                              },
                              {
                                key: "m",
                                label: "当前规则命中关系",
                                children: x.match_count,
                              },
                              { key: "evaluations", label: "规则匹配次数（画像计算）", children: x.evaluation_match_count },
                              { key: "realtime", label: "实时计算匹配", children: x.realtime_match_count },
                              { key: "history", label: "历史重算匹配", children: x.history_match_count },
                              {
                                key: "c",
                                label: "冲突终端",
                                children: x.conflict_count,
                              },
                              {
                                key: "confirmed",
                                label: "与自报证据一致的结论",
                                children: x.confirmed_count,
                              },
                            ]}
                          />
                        </Card>
                      ))}
                    </div>
                    {coverage.data.items.length === 0 && (
                      <Empty description="当前没有来源命中记录" />
                    )}
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
