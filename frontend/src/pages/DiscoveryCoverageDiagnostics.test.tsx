import { render, screen, fireEvent } from '@testing-library/react'
import { expect, it } from 'vitest'
import { DiscoveryCoverageDiagnostics } from './DiscoveryCoverageDiagnostics'

it('explains the four stages and keeps fact rows auditable', () => {
  render(<DiscoveryCoverageDiagnostics />)
  const report = screen.getByLabelText('设备事实原因分析')
  expect(report).toHaveTextContent('当次窗口缺镜像地址')
  expect(report).toHaveTextContent('有流量，缺设备身份')
  expect(report).toHaveTextContent('有身份，缺类型结论')
  expect(report).toHaveTextContent('购买不能确保这些地址形成设备类型')
  expect(report).toHaveTextContent('10.161.8.0/24')
  expect(report).toHaveTextContent('发现处理水位 2026/11/15 20:01:30')
  fireEvent.change(screen.getByRole('searchbox', {name:'搜索 IP 段或原因'}), {target:{value:'10.126.1.250'}})
  expect(report.querySelectorAll('tbody tr')).toHaveLength(2)
  expect(report).toHaveTextContent('Host/SNI')
})
