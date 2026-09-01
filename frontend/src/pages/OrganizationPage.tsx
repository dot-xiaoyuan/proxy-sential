import { ApartmentOutlined, EnvironmentOutlined, WifiOutlined } from '@ant-design/icons'
import { Card, Col, Empty, List, Row, Statistic, Tag, Typography } from 'antd'

import { useOrganization } from '../shared/api/queries'
import { AppErrorAlert, AppLoadingState, AppPageHeader } from '../shared/ui'

export function OrganizationPage(){
  const query=useOrganization();if(query.isLoading)return <AppLoadingState rows={6}/>;if(query.isError||!query.data)return <AppErrorAlert title="校园组织与网络区域加载失败"/>
  const data=query.data
  return <main className="page"><AppPageHeader title="校区与网络区域" subtitle="维护单校多校区、楼宇、网络区域和接入设备映射" loading={query.isFetching} onRefresh={()=>void query.refetch()}/>
    <Row gutter={[16,16]}><Col xs={24} md={8}><Card><Statistic prefix={<EnvironmentOutlined/>} title="校区" value={data.campuses.length}/></Card></Col><Col xs={24} md={8}><Card><Statistic prefix={<ApartmentOutlined/>} title="楼宇" value={data.buildings.length}/></Card></Col><Col xs={24} md={8}><Card><Statistic prefix={<WifiOutlined/>} title="接入点/NAS" value={data.access_points.length}/></Card></Col></Row>
    <section className="organization-grid margin-top-md"><Card title="校区与楼宇">{data.campuses.length===0?<Empty description="尚未导入校园组织数据"/>:<List dataSource={data.campuses} renderItem={campus=><List.Item><List.Item.Meta title={<span className="nowrap-cell">{campus.name} <Tag>{campus.code}</Tag></span>} description={`${data.buildings.filter(item=>item.campus_id===campus.campus_id).length} 栋楼宇`} /></List.Item>}/>}</Card><Card title="网络区域">{data.network_zones.length===0?<Empty description="尚未配置 VLAN、SSID 或网段映射"/>:<List dataSource={data.network_zones} renderItem={zone=><List.Item><List.Item.Meta title={zone.name} description={<Typography.Text type="secondary">SSID {zone.ssids.join('、')||'-'} · VLAN {zone.vlans.join('、')||'-'}</Typography.Text>}/></List.Item>}/>}</Card></section>
  </main>
}
