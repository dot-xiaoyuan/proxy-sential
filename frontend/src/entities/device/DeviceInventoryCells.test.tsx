import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { domainOnlyDevice, domainOnlyInference } from '../../mocks/brandInference'
import { DeviceBrandSummary, DeviceMAC, virtualPlatform } from './DeviceInventoryCells'

afterEach(cleanup)

describe('terminal recognition summary', () => {
  it('shows a confirmed brand and only a sufficiently supported model', () => {
    const { rerender } = render(<DeviceBrandSummary device={{ ...domainOnlyDevice, brand: 'Dell', brand_confidence: .9, model: 'Latitude 7440', model_confidence: .9 }} />)
    expect(screen.getByText('戴尔')).toBeVisible()
    expect(screen.getByText('Latitude 7440')).toBeVisible()
    expect(screen.queryByText('推测')).not.toBeInTheDocument()
    rerender(<DeviceBrandSummary device={{ ...domainOnlyDevice, brand: 'Dell', brand_confidence: .9, model: 'Latitude 7440', model_confidence: .5 }} />)
    expect(screen.queryByText('Latitude 7440')).not.toBeInTheDocument()
  })
  it('marks an inferred brand without putting scores into the main list', () => {
    render(<DeviceBrandSummary device={domainOnlyDevice} />)
    expect(screen.getByText('苹果')).toBeVisible()
    expect(screen.getByText('域名推测')).toBeVisible()
    expect(screen.queryByText(/评分/)).not.toBeInTheDocument()
  })
  it('does not show a confident hardware brand when recognition conflicts', () => {
    render(<DeviceBrandSummary device={{ ...domainOnlyDevice, brand: 'Dell', brand_confidence: .9, recognition_conflict: true, brand_inference: { ...domainOnlyInference, status: 'conflict' } }} />)
    expect(screen.queryByText('—')).not.toBeInTheDocument()
    expect(screen.getByText('线索冲突')).toBeVisible()
    expect(screen.queryByText('戴尔')).not.toBeInTheDocument()
  })
  it('keeps insufficient evidence quiet and unknown manufacturer text intact', () => {
    const { rerender } = render(<DeviceBrandSummary device={{ ...domainOnlyDevice, brand: 'Dell', brand_confidence: .5, brand_inference: undefined }} />)
    expect(screen.queryByText('—')).not.toBeInTheDocument()
    expect(screen.queryByText('戴尔')).not.toBeInTheDocument()
    rerender(<DeviceBrandSummary device={{ ...domainOnlyDevice, brand: 'New manufacturer', brand_confidence: .9, brand_inference: undefined }} />)
    expect(screen.getByText('New manufacturer')).toBeVisible()
  })
  it('keeps a MAC manufacturer out of the hardware brand', () => {
    const device = { ...domainOnlyDevice, brand: '', brand_inference: undefined, vendor: 'Intel Corporation', vendor_confidence: .9 }
    render(<MemoryRouter><DeviceBrandSummary device={device} /><DeviceMAC device={device} /></MemoryRouter>)
    expect(screen.queryByText('—')).not.toBeInTheDocument()
    expect(screen.getByRole('link')).toHaveAttribute('title', expect.stringContaining('Intel Corporation'))
    expect(screen.queryByText('厂商')).not.toBeInTheDocument()
  })
  it('displays macOS as an independent operating system clue', () => {
    render(<DeviceBrandSummary device={{ ...domainOnlyDevice, brand: '', brand_inference: undefined, os_family: 'macOS', os_family_confidence: .65 }} />)
    expect(screen.getByText('macOS')).toBeVisible()
    expect(screen.getByText('系统推测')).toBeVisible()
    expect(screen.queryByText('—')).not.toBeInTheDocument()
  })
  it('shows a device manufacturer reference with its distinct source label', () => {
    render(<DeviceBrandSummary device={{ ...domainOnlyDevice, brand_inference: undefined, brand_reference: { brand: 'Huawei', vendor: 'Huawei Technologies Co.,Ltd.', source: 'mac_vendor', confidence: .6, explanation: '仅作参考' } }} />)
    expect(screen.getByText('华为')).toBeVisible()
    expect(screen.getByText('MAC 厂商线索')).toBeVisible()
    expect(screen.queryByText('推测')).not.toBeInTheDocument()
  })
  it('uses MAC as the detail link and does not expose endpoint IDs as labels', () => {
    render(<MemoryRouter><DeviceMAC device={domainOnlyDevice} /></MemoryRouter>)
    expect(screen.getByRole('link')).toHaveTextContent(domainOnlyDevice.primary_mac!)
    expect(screen.getByRole('link')).toHaveAttribute('href', `/devices/${encodeURIComponent(domainOnlyDevice.endpoint_id)}`)
    expect(screen.queryByText(domainOnlyDevice.endpoint_id)).not.toBeInTheDocument()
  })
  it('links an associated router observation without changing the endpoint identity', () => {
    render(<MemoryRouter><DeviceBrandSummary device={{ ...domainOnlyDevice, router_observation: { assessment_id: 'router-huawei-ar-001', role: 'router', status: 'confirmed', confidence: 95, independent_sources: 2, sources: ['dhcp', 'lldp'], infrastructure: false, brand_reference_only: false, association_quality: 'mac', ambiguous: false, confirmed_router: true, rule_version: 'router-rules-2026.09.1', first_seen: '2026-09-24T08:00:00Z', last_seen: '2026-09-24T09:00:00Z', expires_at: '2026-09-25T09:00:00Z', conflicts: [], score_components: [] } }} /></MemoryRouter>)
    const link = screen.getByRole('link', { name: '路由观察 · 已确认 · 95' })
    expect(link).toHaveAttribute('href', '/discovery/routers/router-huawei-ar-001')
  })
})

it('preserves matching MAC evidence alongside domain inference', () => {
 render(<DeviceBrandSummary device={{...domainOnlyDevice,brand_reference:{brand:'Apple',vendor:'Apple, Inc.',source:'mac_vendor',confidence:.6,explanation:'MAC evidence'}}}/> )
 expect(screen.getByText('品牌线索')).toBeVisible()
 expect(screen.queryByText('域名推测')).not.toBeInTheDocument()
})
it('shows VMware independently from hardware brand and rejects weak or randomized MAC clues', () => {
 const device={...domainOnlyDevice,primary_mac:'00:0c:29:2f:fe:f6',vendor:'VMware, Inc.',vendor_confidence:.9,randomized_mac:false}
 render(<DeviceBrandSummary device={device}/> )
 expect(screen.getByText('VMware')).toBeVisible()
 expect(document.querySelector('.brand-logo-vmware svg path')).not.toBeNull()
 expect(screen.getByText('虚拟机线索')).toBeVisible()
 expect(screen.getByText('苹果')).toBeVisible()
 for(const candidate of [{...device,primary_mac:'02:0c:29:2f:fe:f6'},{...device,vendor_confidence:.5},{...device,randomized_mac:true},{...device,vendor:'Intel Corporation'}]) expect(virtualPlatform(candidate)).toBeUndefined()
})
