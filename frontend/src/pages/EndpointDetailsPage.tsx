import {
  Notice as Alert } from '../shared/ui/Notice'
import { detailPath,
  safeReturnTo } from '../app/navigation'
import { DiscoveryEvidence } from "../entities/device/DiscoveryEvidence"
import { DeviceBrandSummary, deviceTypeLabel } from '../entities/device/DeviceInventoryCells'
import { DeviceNamePanel, DeviceNameView } from '../entities/device/DeviceNameView'
import { BrandInferenceDetails } from '../entities/device/BrandInferenceView';
import { useEffect, useState } from "react";
import { AssociationOverview,
  EndpointTracePanel } from '../entities/device/EndpointTracePanel'
import { Link,
  useParams,
  useSearchParams } from "react-router-dom";
import {App as AntApp,
  Button,
  Descriptions,
  Form,
  Input,
  Progress,
  Select,
  Skeleton,
  Space,
  Tabs,
  Tag,
  Typography,
} from "antd";
import type { ColumnsType } from "antd/es/table";

import {
  useInventoryDetail,
  useDeviceSignals,
  useEndpointIdentity,
  useSession,
  useUpdateEndpointRegistration,
} from "../shared/api/queries";
import type {
  DeviceSignal,
  EndpointDomainEvidence,
  EndpointIdentityProfile,
  UpdateEndpointRegistrationRequest,
} from "../shared/api/types";
import { can } from "../shared/auth/permissions";
import { AppErrorAlert, AppFactBar, AppServerPagination, AppTable, formatDateTime } from '../shared/ui'
import { EndpointTrafficPanel } from './EndpointTrafficPanel'

const ecosystemColumns: ColumnsType<EndpointDomainEvidence> = [
  {
    title: "生态",
    dataIndex: "ecosystem",
    width: 130,
    render: (value: string) => <Tag>{value}</Tag>,
  },
  {
    title: "命中域名",
    dataIndex: "domain",
    width: 250,
    render: (value: string) => (
      <Typography.Text className="list-cell-nowrap mono" copyable title={value}>
        {value}
      </Typography.Text>
    ),
  },
  {
    title: "事件 / 归属",
    key: "source",
    width: 210,
    render: (_, row) => (
      <Typography.Text
        className="list-cell-nowrap"
        title={`${row.event_source} / ${row.attribution_method}`}
      >
        {row.event_source} / {attributionText(row.attribution_method)}
      </Typography.Text>
    ),
  },
  {
    title: "规则来源",
    key: "rule",
    width: 220,
    render: (_, row) => (
      <Typography.Text
        className="list-cell-nowrap mono"
        title={`${row.rule_source} / ${row.rule_version}`}
      >
        {row.rule_source} / {row.rule_version}
      </Typography.Text>
    ),
  },
  { title: "次数", dataIndex: "count", width: 80 },
  {
    title: "首次 / 最近",
    key: "seen",
    width: 280,
    render: (_, row) => (
      <Typography.Text className="list-cell-nowrap">
        {formatTime(row.first_seen)} / {formatTime(row.last_seen)}
      </Typography.Text>
    ),
  },
];

function attributionText(value: string) {
  return value === "explicit_endpoint"
    ? "事件显式终端"
    : value === "active_auth_session"
      ? "有效认证会话"
      : value === "identity_history"
        ? "唯一身份历史"
        : value;
}

const recognitionStages: Record<string, string> = {
  vendor: '厂商线索', brand: '品牌', device_type: '设备类型', model: '型号', os_family: '系统线索',
};
const recognitionReasons: Record<string, string> = {
  no_current_signal: '当前没有可用设备信号',
  unattributed: '协议信号无法可靠归属到此终端',
  insufficient_specificity: '现有信号不足以确认更具体的设备信息',
  conflict: '不同来源的设备证据存在冲突',
  processing: '识别处理中',
  stale: '识别结果已过期',
};

export function EndpointDetailsPage() {
  const [params,setParams]=useSearchParams()
  const returnTo=params.get('return_to')||''
  const back=safeReturnTo(returnTo,'/devices')
  const rawEndpointId = useParams().endpointId ?? "";
  const endpointId = decodeURIComponent(rawEndpointId);
  const { message } = AntApp.useApp();
  const [registrationForm] = Form.useForm<UpdateEndpointRegistrationRequest>();
  const activeTab = params.get("tab") || "overview";
  const [signalPage,setSignalPage]=useState(1);const [signalPageSize,setSignalPageSize]=useState(20)
  const [ecosystemPage,setEcosystemPage]=useState(1);const [ecosystemPageSize,setEcosystemPageSize]=useState(20)
  const setActiveTab=(tab:string)=>setParams(current=>{const next=new URLSearchParams(current);next.set("tab",tab);return next},{replace:true});
  const detail = useInventoryDetail(endpointId);
  const identity = {...detail,data:detail.data?.profile};
  const recognitionEvidence=useEndpointIdentity(endpointId,{limit:20},activeTab==='recognition');
  const session = useSession();
  const updateRegistration = useUpdateEndpointRegistration();

  const profile = identity.data ?? fallbackEndpointProfile(endpointId);
  const canUpdateRegistration = can(session.data, "endpoints:write");
  const mergeStatus = Form.useWatch("merge_status", registrationForm);
  const latestIP = profile?.recognition?.current_ip ?? profile?.ip_history?.[0]?.ip ?? "";
  const latestAccess = profile?.recognition?.current_access_id ?? "";
  // 旧终端信号只按 IP 有界匹配。MAC 证据由上方流量观测独立查询。
  const signals = useDeviceSignals(
    {
      window: "24h",
      ip: latestIP,
      include_weak: true,
      limit: 50,
    },
    activeTab === "signals" && Boolean(latestIP),
  );
  const signalItems = signals.data?.items ?? [];
  const signalPageCount=Math.max(1,Math.ceil(signalItems.length/signalPageSize))
  const visibleSignalPage=Math.min(signalPage,signalPageCount)
  const visibleSignals=signalItems.slice((visibleSignalPage-1)*signalPageSize,visibleSignalPage*signalPageSize)
  const ecosystemItems=recognitionEvidence.data?.ecosystem_evidence??[]
  const ecosystemPageCount=Math.max(1,Math.ceil(ecosystemItems.length/ecosystemPageSize))
  const visibleEcosystemPage=Math.min(ecosystemPage,ecosystemPageCount)
  const visibleEcosystem=ecosystemItems.slice((visibleEcosystemPage-1)*ecosystemPageSize,visibleEcosystemPage*ecosystemPageSize)
  const recognition = recognitionEvidence.data?.recognition ?? profile.recognition;
  const knownRecognition = (value?: string) => Boolean(value && !/^(unknown|未知|未识别)$/i.test(value.trim()))
  const recognitionType = knownRecognition(recognition?.device_type) ? recognition!.device_type! : ''
  const tentativeBrand = knownRecognition(recognition?.brand) && (recognition?.brand_confidence ?? 0) < 0.8 ? recognition!.brand! : ''
  const tentativeModel = knownRecognition(recognition?.model) && (recognition?.model_confidence ?? 0) < 0.8 ? recognition!.model! : ''
  const hasRecognition = Boolean(recognitionType || knownRecognition(recognition?.brand) || knownRecognition(recognition?.model) || knownRecognition(recognition?.os_family) || recognition?.brand_inference?.brand || recognition?.brand_reference?.brand || recognition?.discovery?.capabilities?.length || recognition?.recognition_conflict)
  const associationCounts=detail.data?.state.complete?detail.data.association_counts:undefined;

  useEffect(() => {
    if (!identity.data) {
      return;
    }
    const endpoint = identity.data.endpoint;
    registrationForm.setFieldsValue({
      registration_status: endpoint.registration_status,
      owner_account: endpoint.owner_account ?? "",
      owner_name: endpoint.owner_name ?? "",
      owner_department: endpoint.owner_department ?? "",
      asset_tag: endpoint.asset_tag ?? "",
      ownership_class: endpoint.ownership_class ?? "unknown",
      registration_note: endpoint.registration_note ?? "",
      merge_status: endpoint.merge_status ?? "active",
      merged_into_endpoint_id: endpoint.merged_into_endpoint_id ?? "",
      split_from_endpoint_id: endpoint.split_from_endpoint_id ?? "",
    });
  }, [identity.data, registrationForm]);

  if (identity.isLoading) {
    return <Skeleton active />;
  }
  if(identity.isError&&!identity.data)return <main className="page"><AppErrorAlert title="终端摘要读取失败" message={identity.error.message} /><Button onClick={()=>void identity.refetch()}>重试</Button><Link to={back}>返回终端列表</Link></main>

  return (
    <main className="page endpoint-details-page">
      <div className="page-header">
        <div>
          <Typography.Title className="page-title mono" level={3}>
            {[profile.device_names_disabled ? '' : profile.device_name?.value,latestIP].filter(Boolean).join(' · ') || profile.endpoint.primary_mac || '终端详情'}
          </Typography.Title>
          <Typography.Text type="secondary">
            终端登记、账号历史、IP 历史、接入位置和终端信号。
          </Typography.Text>
        </div>
        <Space wrap>
          <Link to={back}>返回终端列表</Link>
          <Tag
            color={registrationStatusColor(
              profile.endpoint.registration_status,
            )}
          >
            {registrationStatusText(profile.endpoint.registration_status)}
          </Tag>
          {profile.recognition?.current_account_conflict&&<Tag color="orange">最新关联账号冲突</Tag>}
        </Space>
      </div>


      {activeTab!=='identity'&&<section className="surface endpoint-summary" aria-label="终端关联摘要">
        <div className="endpoint-summary-item">
          <span>关联账号</span>
          <strong>{associationCounts?.account ?? (detail.data?.state.complete ? 0 : '')}</strong>
        </div>
        <div className="endpoint-summary-item">
          <span>历史 IP</span>
          <strong>{associationCounts?.ip ?? (detail.data?.state.complete ? 0 : '')}</strong>
        </div>
        <div className="endpoint-summary-item">
          <span>接入位置</span>
          <strong>{associationCounts?.access ?? (detail.data?.state.complete ? 0 : '')}</strong>
        </div>
        <div className="endpoint-summary-item endpoint-summary-confidence">
          <span>身份置信度</span>
          <strong>{Math.round(profile.endpoint.identity_confidence * 100)}%</strong>
          <Progress percent={Math.round(profile.endpoint.identity_confidence * 100)} size="small" showInfo={false} />
        </div>
      </section>}

      <section className="surface details-tab-shell">
        <Tabs
          activeKey={activeTab}
          onChange={setActiveTab}
          items={[
            { key: "overview", label: "概览" },
            { key: "recognition", label: "终端识别" },
            { key: "signals", label: "技术信号" },
            { key: "identity", label: "身份溯源" },
            { key: "registration", label: "登记管理" },
          ]}
        />
      </section>


      {activeTab === "overview" && (
        <>
          {identity.isError && (
            <Alert
              className="endpoint-detail-alert"
              showIcon
              title="终端身份历史暂不可用，当前展示最小 endpoint 视图"
              type="warning"
            />
          )}
          <section className="endpoint-overview-grid">
            <section className="surface endpoint-overview-card">
              <div className="endpoint-overview-card-head"><Typography.Title level={4}>终端识别</Typography.Title><Button type="link" onClick={()=>setActiveTab('recognition')}>查看识别依据</Button></div>
              {!profile.device_names_disabled&&profile.device_name?.value&&<div className="endpoint-recognition-name"><span>设备名称</span><DeviceNameView name={profile.device_name}/></div>}
              {recognition&&<DeviceBrandSummary device={recognition}/>}
              {recognition&&hasRecognition&&<Descriptions column={1} size="small" className="endpoint-recognition-facts">
                {recognitionType&&<Descriptions.Item label="类型">{deviceTypeLabel(recognitionType)}{(recognition.device_type_confidence??0)<.8&&<Tag className="device-inference-tag">类型线索</Tag>}</Descriptions.Item>}
                {tentativeBrand&&<Descriptions.Item label="品牌">{tentativeBrand}<Tag className="device-inference-tag">品牌线索 {Math.round((recognition.brand_confidence??0)*100)}%</Tag></Descriptions.Item>}
                {tentativeModel&&<Descriptions.Item label="型号">{tentativeModel}<Tag className="device-inference-tag">型号线索 {Math.round((recognition.model_confidence??0)*100)}%</Tag></Descriptions.Item>}
                {(recognition.recognition_confidence ?? 0) > 0 && <Descriptions.Item label="识别置信度">{Math.round(recognition.recognition_confidence*100)}%</Descriptions.Item>}
                {recognition.vendor&&<Descriptions.Item label="注册厂商">{recognition.vendor}</Descriptions.Item>}
                {recognition.ecosystem_hint&&<Descriptions.Item label="生态线索">{recognition.ecosystem_hint}{recognition.ecosystem_confidence!==undefined&&` · ${Math.round(recognition.ecosystem_confidence*100)}%`}</Descriptions.Item>}
                {recognition.recognition_source&&<Descriptions.Item label="识别来源">{recognitionSourceText(recognition.recognition_source)}</Descriptions.Item>}
                {recognition.fingerprint_version&&<Descriptions.Item label="规则版本">{recognition.fingerprint_version}</Descriptions.Item>}
              </Descriptions>}
              {!hasRecognition&&<Typography.Text type="secondary">尚无足够识别结果，可查看识别依据或技术信号。</Typography.Text>}
            </section>
            <section className="surface endpoint-overview-card">
              <div className="endpoint-overview-card-head"><Typography.Title level={4}>观测摘要</Typography.Title></div>
              <Descriptions column={1} size="small">
                {profile.endpoint.primary_mac && <Descriptions.Item label="MAC">{profile.endpoint.primary_mac}</Descriptions.Item>}
                {(profile.recognition?.current_account || profile.recognition?.current_account_conflict) && <Descriptions.Item label="最新观测账号">
                  {profile.recognition?.current_account || ''}
                  {profile.recognition?.current_account_conflict&&<><Tag color="orange">同时间多账号冲突</Tag>{(profile.recognition.current_account_candidates??[]).join(' / ')}</>}
                </Descriptions.Item>}
                {latestIP && <Descriptions.Item label="最近观测 IP">
                  <Link className="mono" to={detailPath(`/ips/${encodeURIComponent(latestIP)}`,`/devices/${encodeURIComponent(endpointId)}?${params.toString()}`)}>{latestIP}</Link>
                </Descriptions.Item>}
                {latestAccess && <Descriptions.Item label="最近观测接入">{latestAccess}</Descriptions.Item>}
                {formatTime(profile.first_seen) && <Descriptions.Item label="首次发现">{formatTime(profile.first_seen)}</Descriptions.Item>}
                {formatTime(profile.last_seen) && <Descriptions.Item label="最近观测">{formatTime(profile.last_seen)}</Descriptions.Item>}
              </Descriptions>
            </section>
            <section className="surface endpoint-overview-card endpoint-registration-summary">
              <div className="endpoint-overview-card-head"><Typography.Title level={4}>登记信息</Typography.Title>{profile.endpoint.registration_status !== 'registered' && <Button type="link" className="endpoint-registration-link" onClick={()=>setActiveTab('registration')}>补充登记</Button>}</div>
              <Descriptions column={1} size="small">
                <Descriptions.Item label="登记状态">
                  {registrationStatusText(profile.endpoint.registration_status)}
                </Descriptions.Item>
                {profile.endpoint.owner_account && <Descriptions.Item label="责任账号">{profile.endpoint.owner_account}</Descriptions.Item>}
                {profile.endpoint.owner_name && <Descriptions.Item label="责任人">{profile.endpoint.owner_name}</Descriptions.Item>}
                {profile.endpoint.owner_department && <Descriptions.Item label="部门">{profile.endpoint.owner_department}</Descriptions.Item>}
                {profile.endpoint.asset_tag && <Descriptions.Item label="资产编号">{profile.endpoint.asset_tag}</Descriptions.Item>}
                {ownershipClassText(profile.endpoint.ownership_class) && <Descriptions.Item label="终端归属">{ownershipClassText(profile.endpoint.ownership_class)}</Descriptions.Item>}
                <Descriptions.Item label="合并状态">{mergeStatusText(profile.endpoint.merge_status)}</Descriptions.Item>
                {profile.endpoint.registration_note && <Descriptions.Item label="备注">{profile.endpoint.registration_note}</Descriptions.Item>}
              </Descriptions>
            </section>
          </section>
          <AssociationOverview detail={detail.data}/>
        </>
      )}

      {activeTab === "recognition" && (
        <>
      {profile.discovery && <DiscoveryEvidence endpointId={endpointId} />}
      {!profile.device_names_disabled && <DeviceNamePanel endpointId={endpointId} name={profile.device_name} canEdit={canUpdateRegistration} />}
          <BrandInferenceDetails value={profile.brand_inference ?? recognition?.brand_inference} />
          {!!recognition?.source_matches?.length && <section className="surface"><Typography.Title level={4}>多来源指纹依据</Typography.Title><Typography.Paragraph type="secondary">同一协议证据的跨库命中不重复增加置信度；辅助线索不单独确认设备类型。</Typography.Paragraph><div className="endpoint-scroll-list">{recognition.source_matches.map(m=><details key={`${m.source_id}:${m.rule_id}`} className="fingerprint-evidence"><summary>{m.name} · {m.source_id}{m.strength==='auxiliary'?' · 辅助线索':''}</summary><Descriptions column={1} items={[{key:'rule',label:'规则',children:<span className="fingerprint-ident">{m.rule_id}</span>},{key:'version',label:'版本',children:<span className="fingerprint-ident">{m.version}</span>},{key:'fields',label:'依据字段',children:m.fields.join('、')},{key:'observed',label:'匹配内容节选',children:Object.entries(m.observed??{}).map(([field,value])=><div key={field} className="fingerprint-ident">{field}：{value}</div>)},{key:'side',label:'归属',children:m.direction==='server'?'服务端':m.direction==='client'?'客户端':'终端'}]}/></details>)}</div></section>}
          <section className="surface">
            <Typography.Title level={4}>终端识别</Typography.Title>
            <AppFactBar label="生态线索口径" items={['生态线索表示终端访问过相关厂商服务','不代表硬件品牌、型号或设备类型已确认']}/>
            <Descriptions column={{ xs: 1, md: 2 }} size="small">
              <Descriptions.Item label="识别摘要">{recognition&&<DeviceBrandSummary device={recognition}/>}</Descriptions.Item>
              {recognition?.vendor&&<Descriptions.Item label="MAC 注册厂商">{recognition.vendor}</Descriptions.Item>}
              {recognition?.brand_reference&&<Descriptions.Item label="MAC 品牌参考">{recognition.brand_reference.explanation}</Descriptions.Item>}
              <Descriptions.Item label="终端 ID"><Typography.Text className="detail-value-wrap" copyable>{profile.endpoint_id}</Typography.Text></Descriptions.Item>
              <Descriptions.Item label="规则版本">
                <Typography.Text className="mono list-cell-nowrap">
                  {recognition?.fingerprint_version || ""}
                </Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="随机 MAC">
                {recognition?.randomized_mac ? "是；不使用 OUI 判断厂商" : "否"}
              </Descriptions.Item>
              <Descriptions.Item label="识别冲突">
                {recognition?.recognition_conflict
                  ? "是；请核对冲突证据"
                  : "否"}
              </Descriptions.Item>
              <Descriptions.Item label="生态线索">
                {recognition?.ecosystem_conflict
                  ? "存在冲突"
                  : recognition?.ecosystem_hint || ""}
                {recognition?.ecosystem_hint && `（${confidenceText(recognition?.ecosystem_confidence)}）`}
              </Descriptions.Item>
              <Descriptions.Item label="识别证据">
                {recognition?.recognition_evidence?.join("；") || ""}
              </Descriptions.Item>
              {recognition?.recognition_diagnostics?.stage && recognition.recognition_diagnostics.stage !== 'none' && <Descriptions.Item label="识别层级">{recognitionStages[recognition.recognition_diagnostics.stage] ?? recognition.recognition_diagnostics.stage}</Descriptions.Item>}
              {recognition?.recognition_diagnostics?.reason && <Descriptions.Item label="当前识别状态">{recognitionReasons[recognition.recognition_diagnostics.reason] ?? recognition.recognition_diagnostics.reason}</Descriptions.Item>}
              {!!recognition?.conflict_dimensions?.length && <Descriptions.Item label="冲突字段">{recognition.conflict_dimensions.map(field => recognitionStages[field] ?? field).join('、')}</Descriptions.Item>}
              {!!recognition?.recognition_diagnostics?.protocols?.length && <Descriptions.Item label="可用协议">{recognition.recognition_diagnostics.protocols.join('、')}</Descriptions.Item>}
              {recognition?.recognition_diagnostics && <Descriptions.Item label="分层处理">有效信号 {recognition.recognition_diagnostics.accepted_signals} 条 · 候选规则 {recognition.recognition_diagnostics.candidate_rules} 条</Descriptions.Item>}
              {!!recognition?.evidence_refs?.length && <Descriptions.Item label="可用信号事件">{recognition.evidence_refs.map(ref=><div className="fingerprint-ident" key={`${ref.event_id}:${ref.field}`}>{ref.protocol} · {ref.field} · {ref.event_id}</div>)}</Descriptions.Item>}
            </Descriptions>
          </section>
          <section className="surface">
            <div className="surface-title-row">
              <Typography.Title className="surface-title" level={4}>
                生态线索证据
              </Typography.Title>
              <Typography.Text className="surface-subtitle" type="secondary">
                仅展示可审计的标准事件命中，不作为单独定性依据
              </Typography.Text>
            </div>
            <div className="endpoint-tab-table-wrap">
              <AppTable<EndpointDomainEvidence>
                className="compact-list-table"
                columns={ecosystemColumns}
                dataSource={visibleEcosystem}
                locale={{ emptyText: "暂无可归属的生态线索" }}
                pagination={false}
                rowKey={(row) =>
                  `${row.rule_version}:${row.domain}:${row.event_source}`
                }
                scroll={{ x: 1100 }}
              />
            </div>
            {ecosystemItems.length>0&&<AppServerPagination page={visibleEcosystemPage} pageSize={ecosystemPageSize} total={ecosystemItems.length} onChange={(nextPage,nextSize)=>{setEcosystemPageSize(nextSize);setEcosystemPage(nextPage)}} totalText={`共 ${ecosystemItems.length} 条`} />}
          </section>
        </>
      )}

      {activeTab === "registration" && (
        <section className="surface endpoint-registration-editor">
          <div className="surface-title-row">
            <Typography.Title className="surface-title" level={4}>
              更新终端登记
            </Typography.Title>
            <Typography.Text className="surface-subtitle" type="secondary">
              保存后记录操作者、时间和审计日志
            </Typography.Text>
          </div>
          {!canUpdateRegistration && (
            <Alert
              showIcon
              title="当前会话没有 endpoints:write 权限，登记表单只读"
              type="warning"
            />
          )}
          <Form<UpdateEndpointRegistrationRequest>
            className="endpoint-registration-form"
            disabled={!canUpdateRegistration}
            form={registrationForm}
            layout="vertical"
            onFinish={(payload) => {
              updateRegistration.mutate(
                { endpointId, payload },
                {
                  onError: (error) => message.error(error.message),
                  onSuccess: () => message.success("终端登记已更新"),
                },
              );
            }}
          >
            <div className="endpoint-registration-grid">
              <Form.Item
                label="登记状态"
                name="registration_status"
                rules={[{ required: true }]}
              >
                <Select
                  options={[
                    { label: "未登记", value: "unregistered" },
                    { label: "已登记", value: "registered" },
                    { label: "已忽略", value: "ignored" },
                    { label: "已退役", value: "retired" },
                  ]}
                />
              </Form.Item>
              <Form.Item label="责任账号" name="owner_account">
                <Input placeholder="账号或工号" />
              </Form.Item>
              <Form.Item
                dependencies={[
                  "registration_status",
                  "owner_account",
                  "asset_tag",
                ]}
                label="责任人"
                name="owner_name"
                rules={[
                  ({ getFieldValue }) => ({
                    validator: (_, value) => {
                      if (
                        getFieldValue("registration_status") !== "registered" ||
                        value ||
                        getFieldValue("owner_account") ||
                        getFieldValue("asset_tag")
                      ) {
                        return Promise.resolve();
                      }
                      return Promise.reject(
                        new Error(
                          "已登记终端至少填写责任账号、责任人或资产编号之一",
                        ),
                      );
                    },
                  }),
                ]}
              >
                <Input placeholder="人工确认的责任人" />
              </Form.Item>
              <Form.Item label="部门" name="owner_department">
                <Input placeholder="部门或管理单位" />
              </Form.Item>
              <Form.Item label="资产编号" name="asset_tag">
                <Input placeholder="资产编号" />
              </Form.Item>
              <Form.Item
                label="终端归属"
                name="ownership_class"
                rules={[{ required: true }]}
              >
                <Select
                  options={[
                    { label: "空值", value: "unknown" },
                    { label: "个人终端（BYOD）", value: "byod" },
                    { label: "学校资产", value: "school_asset" },
                    { label: "公共终端", value: "public_terminal" },
                    { label: "基础设施", value: "infrastructure" },
                  ]}
                />
              </Form.Item>
              <Form.Item
                label="合并状态"
                name="merge_status"
                rules={[{ required: true }]}
              >
                <Select
                  options={[
                    { label: "正常", value: "active" },
                    { label: "已合并", value: "merged" },
                    { label: "拆分来源", value: "split" },
                  ]}
                />
              </Form.Item>
              {mergeStatus === "merged" && (
                <Form.Item
                  label="合并到 Endpoint"
                  name="merged_into_endpoint_id"
                  rules={[
                    { required: true, message: "请填写合并目标 Endpoint" },
                  ]}
                >
                  <Input className="mono" placeholder="mac:xx:xx:xx:xx:xx:xx" />
                </Form.Item>
              )}
              {mergeStatus === "split" && (
                <Form.Item
                  label="拆分自 Endpoint"
                  name="split_from_endpoint_id"
                >
                  <Input className="mono" placeholder="原 Endpoint ID" />
                </Form.Item>
              )}
              <Form.Item
                className="endpoint-registration-note"
                label="登记备注"
                name="registration_note"
              >
                <Input.TextArea
                  placeholder="记录人工确认依据、终端类型或例外原因"
                  rows={3}
                />
              </Form.Item>
            </div>
            <div className="endpoint-registration-actions">
              <Button
                htmlType="submit"
                loading={updateRegistration.isPending}
                type="primary"
              >
                保存登记
              </Button>
            </div>
          </Form>
        </section>
      )}

      {activeTab === "identity" && <EndpointTracePanel endpointId={endpointId}/>}

      {activeTab === "signals" && (
        <>
        {can(session.data, 'events:read') && <EndpointTrafficPanel recentIP={latestIP} primaryMac={profile.endpoint.primary_mac} identityLastSeen={profile.last_seen} />}
        {latestIP && <section className="surface">
          <div className="surface-title-row">
            <Typography.Title className="surface-title" level={4}>
              终端信号
            </Typography.Title>
            <Typography.Text className="surface-subtitle" type="secondary">
              按最近观测 IP 查询近 24 小时的 DHCP、TLS/HTTP 握手、指纹等线索
            </Typography.Text>
          </div>
          {signals.isError ? (
            <Alert showIcon title="终端信号读取失败" type="warning" />
          ) : (
            <>
              <div className="endpoint-tab-table-wrap">
                <AppTable<DeviceSignal>
                  columns={signalColumns}
                  dataSource={visibleSignals}
                  loading={signals.isFetching}
                  locale={{ emptyText: "近 24 小时暂无该 IP 的终端信号，可在身份溯源中查看历史关联" }}
                  pagination={false}
                  rowKey="signal_id"
                  scroll={{ x: 920 }}
                />
              </div>
              {signalItems.length>0&&<AppServerPagination page={visibleSignalPage} pageSize={signalPageSize} total={signalItems.length} onChange={(nextPage,nextSize)=>{setSignalPageSize(nextSize);setSignalPage(nextPage)}} totalText={`共 ${signalItems.length} 条`} />}
            </>
          )}
        </section>}
        </>
      )}
    </main>
  );
}


const signalColumns: ColumnsType<DeviceSignal> = [
  { title: "来源", dataIndex: "source", width: 130 },
  { title: "类型", dataIndex: "kind", width: 150 },
  {
    title: "值",
    dataIndex: "value",
    minWidth: 260,
    render: (value: string) => (
      <Typography.Text className="wrap-text">{value}</Typography.Text>
    ),
  },
  {
    title: "强度",
    dataIndex: "strength",
    width: 100,
    render: (value: string) => (
      <Tag color={signalStrengthColor(value)}>{value}</Tag>
    ),
  },
  {
    title: "置信度",
    dataIndex: "confidence",
    width: 130,
    render: (value: number) => (
      <Progress percent={Math.round(value * 100)} size="small" />
    ),
  },
  { title: "最近出现", dataIndex: "last_seen", width: 180, render: formatTime },
];

function registrationStatusText(status?: string) {
  switch (status) {
    case "registered":
      return "已登记";
    case "ignored":
      return "已忽略";
    case "retired":
      return "已退役";
    default:
      return "未登记";
  }
}

function registrationStatusColor(status?: string) {
  switch (status) {
    case "registered":
      return "green";
    case "ignored":
      return "default";
    case "retired":
      return "red";
    default:
      return "orange";
  }
}

function recognitionSourceText(value: string) {
  return ({ dhcp_hostname_hint: 'DHCP 主机名线索', passive_discovery: '被动发现', ieee_oui: 'MAC 厂商库', fingerprint: '指纹库', fixture: '测试数据' } as Record<string, string>)[value] ?? value
}

function mergeStatusText(value?: string) {
  return ({ active: '正常', merged: '已合并', split: '已拆分' } as Record<string, string>)[value ?? 'active'] ?? ''
}

function ownershipClassText(value?: string) {
  return (
    (
      {
        byod: "个人终端（BYOD）",
        school_asset: "学校资产",
        public_terminal: "公共终端",
        infrastructure: "基础设施",
        unknown: "",
      } as Record<string, string>
    )[value ?? "unknown"] ?? ""
  );
}

function confidenceText(value?: number) {
  return `${Math.round((value ?? 0) * 100)}%`;
}

function signalStrengthColor(value: string) {
  switch (value) {
    case "strong":
      return "green";
    case "medium":
      return "blue";
    default:
      return "default";
  }
}

function formatTime(value?: string) {
  return formatDateTime(value);
}


function fallbackEndpointProfile(endpointId: string): EndpointIdentityProfile {
  const now = new Date().toISOString();
  return {
    endpoint_id: endpointId,
    summary: `终端 ${endpointId} 暂无完整身份历史`,
    endpoint: {
      endpoint_id: endpointId,
      entity_role: "endpoint",
      first_seen: now,
      last_seen: now,
      identity_confidence: 0,
      attributes: {},
      registration_status: "unregistered",
      ownership_class: "unknown",
      merge_status: "active",
    },
    accounts: [],
    sessions: [],
    ip_history: [],
    access_history: [],
    first_seen: now,
    last_seen: now,
  };
}
