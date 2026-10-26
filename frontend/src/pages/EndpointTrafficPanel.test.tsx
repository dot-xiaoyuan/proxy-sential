import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { EndpointTrafficPanel } from './EndpointTrafficPanel'

vi.mock('../widgets/IpTrafficObservations', () => ({ IpTrafficObservations: ({ ip, contextMac }: { ip: string; contextMac?: string }) => <output data-testid="traffic-observations">{ip} / {contextMac}</output> }))

afterEach(cleanup)
function Location() { return <output data-testid="location">{useLocation().search}</output> }
function setup(url: string, recentIP = '') {
  render(<MemoryRouter initialEntries={[url]}><EndpointTrafficPanel recentIP={recentIP} primaryMac="90:fb:5d:a7:40:4b" identityLastSeen="2026-10-25T15:51:00Z" /><Location /></MemoryRouter>)
}

it('在终端技术信号中按显式 IP 展示观测并区分归属', () => {
  setup('/devices/mac%3A90%3Afb%3A5d%3Aa7%3A40%3A4b?tab=signals&ip=10.157.2.191')
  expect(screen.getByTestId('traffic-observations')).toHaveTextContent('10.157.2.191 / 90:fb:5d:a7:40:4b')
  expect(screen.getByText(/身份摘要中没有该 IP 的地址关联/)).toBeInTheDocument()
})

it('没有地址关联时允许核查 IP，但非法地址不发起查询', () => {
  setup('/devices/mac%3A90%3Afb%3A5d%3Aa7%3A40%3A4b?tab=signals')
  expect(screen.queryByTestId('traffic-observations')).not.toBeInTheDocument()
  fireEvent.change(screen.getByRole('textbox', { name: '流量观测 IP' }), { target: { value: 'not-an-ip' } })
  fireEvent.click(screen.getByRole('button', { name: '查询此 IP' }))
  expect(screen.getByRole('alert')).toHaveTextContent('请输入完整有效的 IPv4 或 IPv6 地址')
  fireEvent.change(screen.getByRole('textbox', { name: '流量观测 IP' }), { target: { value: '10.157.2.191' } })
  fireEvent.click(screen.getByRole('button', { name: '查询此 IP' }))
  expect(screen.getByTestId('location')).toHaveTextContent('ip=10.157.2.191')
  expect(screen.getByTestId('traffic-observations')).toHaveTextContent('10.157.2.191')
})

it('有最近观测地址时默认查询该地址', () => {
  setup('/devices/mac%3A90%3Afb%3A5d%3Aa7%3A40%3A4b?tab=signals', '10.157.2.191')
  expect(screen.getByTestId('traffic-observations')).toHaveTextContent('10.157.2.191')
  expect(screen.queryByText(/身份摘要中没有该 IP 的地址关联/)).not.toBeInTheDocument()
})
