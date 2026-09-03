import ReactECharts from 'echarts-for-react'
import { Card, Typography } from 'antd'

import type { ActivityReport } from '../../shared/api/types'

export function EChartsTopReport({ title, report, kind, note, onSelect }: { title:string;report?:ActivityReport;kind:'bar'|'donut';note?:string;onSelect?:(key:string)=>void }) {
	const items = report?.items ?? []
	const option = kind === 'bar' ? {
		animation: false,
		grid: { left: 12, right: 26, top: 8, bottom: 8, containLabel: true },
		xAxis: { type: 'value', axisLabel: { color: '#64748b' }, splitLine: { lineStyle: { color: '#f1f5f9' } } },
		yAxis: { type: 'category', inverse: true, data: items.map(item=>item.label), axisLabel: { width: 210, overflow: 'truncate', color: '#334155' } },
		tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
		series: [{ type: 'bar', data: items.map(item=>({value:item.count,name:item.key})), barMaxWidth: 18, itemStyle: { color: '#2563eb', borderRadius: [0,4,4,0] } }],
	} : {
		animation: false,
		tooltip: { trigger: 'item', formatter: '{b}<br/>{c}（{d}%）' },
		legend: { type: 'scroll', bottom: 0, textStyle: { color: '#475569' } },
		series: [{ type: 'pie', radius: ['48%','70%'], center: ['50%','43%'], label: { show: false }, data: donutData(items) }],
	}
	return <Card className="report-chart-card" size="small" title={title}>
		{items.length === 0 ? <Typography.Text type="secondary">暂无可报表化数据</Typography.Text> : <ReactECharts className="report-chart" option={option} onEvents={onSelect?{click:(params:{name:string})=>onSelect(params.name)}:undefined} />}
		{note && <Typography.Text className="report-chart-note" type="secondary">{note}</Typography.Text>}
	</Card>
}

function donutData(items:ActivityReport['items']) {
	const visible=items.slice(0,6).map(item=>({name:item.label,value:item.count}))
	const other=items.slice(6).reduce((sum,item)=>sum+item.count,0)
	if(other>0)visible.push({name:'其他',value:other})
	return visible
}
