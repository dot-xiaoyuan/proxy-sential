import ReactECharts from 'echarts-for-react'
import { Card, Typography } from 'antd'

interface DistributionData {
  name: string
  value: number
  color?: string
}

interface EChartsDistributionPieProps {
  title: string
  data: DistributionData[]
  subtext?: string
}

const defaultColors = ['#dc2626', '#ea580c', '#d97706', '#16a34a', '#0284c7', '#8b5cf6']

export function EChartsDistributionPie({ title, data, subtext }: EChartsDistributionPieProps) {
  const formattedData = data.map((item, idx) => ({
    name: item.name,
    value: item.value,
    itemStyle: { color: item.color || defaultColors[idx % defaultColors.length] },
  }))

  const option = {
    tooltip: {
      trigger: 'item',
      formatter: '{b}: <b>{c}</b> ({d}%)',
    },
    legend: {
      orient: 'vertical',
      right: 10,
      top: 'center',
      textStyle: { color: '#475569', fontSize: 12 },
    },
    series: [
      {
        name: title,
        type: 'pie',
        radius: ['45%', '72%'],
        center: ['38%', '50%'],
        avoidLabelOverlap: false,
        itemStyle: {
          borderRadius: 6,
          borderColor: '#ffffff',
          borderWidth: 2,
        },
        label: {
          show: false,
        },
        emphasis: {
          label: {
            show: true,
            fontSize: 13,
            fontWeight: 'bold',
          },
        },
        data: formattedData,
      },
    ],
  }

  return (
    <Card className="surface-card chart-card-full-height" size="small">
      <div className="dpi-card-header">
        <div className="dpi-card-title">
          <span>{title}</span>
        </div>
        {subtext && (
          <Typography.Text className="dpi-card-hint" type="secondary">
            {subtext}
          </Typography.Text>
        )}
      </div>

      <ReactECharts className="distribution-echart" option={option} />
    </Card>
  )
}
