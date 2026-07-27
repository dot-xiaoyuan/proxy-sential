import { Progress, Space, Typography } from 'antd'

export function RiskScore({ score }: { score: number }) {
  const strokeColor = score >= 80 ? '#d4380d' : score >= 60 ? '#fa8c16' : score >= 30 ? '#d4b106' : '#389e0d'

  return (
    <Space className="risk-score" size={10}>
      <Progress
        aria-label={`风险分 ${score}`}
        percent={score}
        size={42}
        type="circle"
        strokeColor={strokeColor}
        format={(value) => value}
      />
      <Typography.Text type="secondary">/100</Typography.Text>
    </Space>
  )
}
