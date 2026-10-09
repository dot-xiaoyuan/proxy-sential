import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, expect, it } from 'vitest'
import type { RootFilesystemStatus } from '../../shared/api/types'
import { RootFilesystemCapacity, RootFilesystemWarning } from './RootFilesystemCapacity'

afterEach(cleanup)
const root: RootFilesystemStatus = { path: '/', total_bytes: 200 * 1024 ** 3, used_bytes: 190 * 1024 ** 3, available_bytes: 8 * 1024 ** 3, used_percent: 190 / 198 * 100 }

it('存储连接正常时仍独立显示真实容量压力', () => {
  render(<><RootFilesystemWarning status={root} /><RootFilesystemCapacity status={root} /></>)
  expect(screen.getByText('根盘空间紧张')).toBeInTheDocument()
  expect(screen.getByText('可用 8.0 GB')).toBeInTheDocument()
  expect(screen.getByText('已用 96.0%')).toBeInTheDocument()
  expect(screen.queryByText(/inode/)).toBeNull()
})
it('容量缺省时省略内容和告警', () => {
  const { container } = render(<><RootFilesystemWarning /><RootFilesystemCapacity /></>)
  expect(container).toBeEmptyDOMElement()
})
it('字节容量充足时仍显示 inode 用尽', () => {
  render(<RootFilesystemWarning status={{ ...root, available_bytes: 100 * 1024 ** 3, used_percent: 50, inodes_total: 100000, inodes_free: 0, inodes_used_percent: 100 }} />)
  expect(screen.getByText('根盘 inode 不足')).toBeInTheDocument()
})
it('读取失败保留真实错误并避免伪造零可用容量', () => {
  render(<RootFilesystemCapacity error="permission denied" />)
  expect(screen.getByText('根盘容量读取失败')).toBeInTheDocument()
  expect(screen.getByText('permission denied')).toBeInTheDocument()
  expect(screen.queryByText(/可用/)).toBeNull()
})
it('真实零容量明确展示并告警', () => {
  render(<><RootFilesystemWarning status={{ ...root, available_bytes: 0, used_percent: 100 }} /><RootFilesystemCapacity status={{ ...root, available_bytes: 0, used_percent: 100 }} /></>)
  expect(screen.getByText('根盘空间不足')).toBeInTheDocument()
  expect(screen.getByText('可用 0 B')).toBeInTheDocument()
})
