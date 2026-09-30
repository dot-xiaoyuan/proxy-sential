import { useState } from 'react'
import { Link,useLocation } from 'react-router-dom'
import { Button,Table,Typography } from 'antd'
import { SearchOutlined } from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import { RiskLevelTag } from '../entities/risk/RiskLevelTag'
import { RiskScore } from '../entities/risk/RiskScore'
import { FlowInspectorDrawer } from '../features/dpi/FlowInspectorDrawer'
import { detailPath } from '../app/navigation'
import type { ActivityCount,ActivityIpSummary } from '../shared/api/types'
import type { ReportWindow } from '../shared/ui'
export function ActiveRiskIps({items}:{items:ActivityIpSummary[]}){
 const [inspectIp,setInspectIp]=useState<string|null>(null);const location=useLocation();
  const riskColumns: ColumnsType<ActivityIpSummary> = [
    {
      title: "IP 地址",
      dataIndex: "ip",
      width: 150,
      render: (value: string) => (
        <Link
          className="mono wrap-text"
          to={detailPath(`/ips/${encodeURIComponent(value)}`,location.pathname+location.search)}
        >
          {value}
        </Link>
      ),
    },
    {
      title: "风险等级",
      dataIndex: "risk_level",
      width: 85,
      render: (value: ActivityIpSummary["risk_level"]) => (
        <RiskLevelTag level={value} />
      ),
    },
    {
      title: "综合评分",
      dataIndex: "score",
      width: 75,
      render: (value: number) => <RiskScore score={value} />,
    },
    { title: "DPI 事件数", dataIndex: "event_count", width: 85 },
    {
      title: "Top 访问对象 (DNS/SNI/Host)",
      dataIndex: "top_domains",
      render: (items: ActivityCount[]) =>
        renderCountTokens(items, "暂无域名对象"),
    },
    {
      title: "最后抓包时间",
      dataIndex: "last_seen",
      width: 150,
      render: (value?: string) =>
        value ? <span className="nowrap-cell" title={new Date(value).toLocaleString('zh-CN')}>{new Date(value).toLocaleString('zh-CN',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false})}</span> : "",
    },
    {
      title: "快捷追查",
      key: "action",
      width: 160,
      fixed: 'right',
      render: (_, record) => (
        <Button
          className="dpi-badge-tag"
          icon={<SearchOutlined />}
          onClick={() => setInspectIp(record.ip)}
          size="small"
          type="link"
        >
          DPI Flow 样本
        </Button>
      ),
    },
  ];

return <>          <div className="activity-tab-panel">
            <div className="surface-title-row">
              <Typography.Title className="surface-title" level={4}>
                活跃共享风险 IP
              </Typography.Title>
              <Typography.Text className="surface-subtitle" type="secondary">
                点击 DPI Flow 样本展开追查抽屉
              </Typography.Text>
            </div>
            <Table<ActivityIpSummary> className="compact-list-table"
              tableLayout="fixed"
            columns={riskColumns}
              dataSource={items}
              pagination={false}
              rowKey="ip"
              scroll={{ x: 960 }}
              size="small"
            />
          </div>
<FlowInspectorDrawer context={{window:(new URLSearchParams(location.search).get('window')||'1h') as ReportWindow,sensor_id:new URLSearchParams(location.search).get('sensor_id')||undefined,campus_id:new URLSearchParams(location.search).get('campus_id')||undefined}} ip={inspectIp} open={!!inspectIp} onClose={()=>setInspectIp(null)}/></>;
}
function renderCountTokens(items:ActivityCount[],_empty:string){const text=items.map(item=>`${item.value} ×${item.count}`).join('、');return <span className="ellipsis-cell" title={text}>{text}</span>}
