import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { domainOnlyDevice, domainOnlyInference } from '../../mocks/brandInference'
import { DeviceBrandSummary, DeviceIdentityCell, DeviceLedgerIdentity, DeviceLedgerRecognition, DeviceLedgerOS, DeviceSemanticIcon, DeviceMAC, virtualPlatform } from './DeviceInventoryCells'

afterEach(cleanup)

it('ledger identity always locates an unnamed device by IP and MAC',()=>{
 render(<MemoryRouter><DeviceLedgerIdentity device={domainOnlyDevice} href="/devices/test?return_to=inventory"/></MemoryRouter>)
 expect(screen.getByRole('link',{name:'198.18.90.8'})).toHaveAttribute('href','/devices/test?return_to=inventory')
 expect(screen.getByRole('link',{name:'02:00:00:00:90:08'})).toBeVisible()
})
it('ledger prioritizes confident recognition and keeps weak OS out of the OS column',()=>{
 const device={...domainOnlyDevice,device_type:'laptop',device_type_confidence:.95,brand:'Dell',brand_confidence:.95,model:'Latitude',model_confidence:.9,os_family:'Windows',os_family_confidence:.6}
 render(<><DeviceLedgerRecognition device={device}/><DeviceLedgerOS device={device}/></>)
 expect(screen.getByText('笔记本电脑')).toBeVisible()
 expect(screen.getByText('戴尔 · Latitude')).toBeVisible()
 expect(screen.queryByText('Windows')).not.toBeInTheDocument()
 expect(screen.getByText('识别依据')).toBeVisible()
})
it('ledger keeps VMware as a virtual clue and does not render its logo or hardware brand',()=>{
 const device={...domainOnlyDevice,primary_mac:'00:0c:29:2f:fe:f6',vendor:'VMware, Inc.',vendor_confidence:.9,randomized_mac:false,brand:'VMware',brand_confidence:.9}
 render(<DeviceLedgerRecognition device={device}/>)
 expect(screen.getByText('VMware 虚拟平台线索')).toBeVisible()
 expect(document.querySelector('.brand-logo-vmware')).toBeNull()
 expect(screen.queryByText('VMware',{exact:true})).not.toBeInTheDocument()
})
it('neutral icon does not promote low-confidence desktop recognition',()=>{
 render(<DeviceSemanticIcon device={{...domainOnlyDevice,device_type:'desktop',device_type_confidence:.5,os_family:'Windows',os_family_confidence:.5}}/>)
 expect(document.querySelector('[data-icon="deployment-unit"]')).not.toBeNull()
 expect(document.querySelector('[data-icon="desktop"]')).toBeNull()
})
it('ledger suppresses empty recognition placeholders and preserves conflicts',()=>{
 render(<DeviceLedgerRecognition device={{...domainOnlyDevice,brand:'unknown',device_type:'unknown',os_family:'unknown',model:'unknown',brand_confidence:1,model_confidence:1,device_type_confidence:1,os_family_confidence:1,brand_inference:undefined,recognition_conflict:true}}/>)
 expect(screen.getByText('线索冲突')).toBeVisible()
 expect(screen.queryByText(/unknown|未知|未识别|—/)).not.toBeInTheDocument()
})

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
it('uses a uniform semantic glyph and text-only VMware clue in the list identity', () => {
 const device={...domainOnlyDevice,primary_mac:'00:0c:29:2f:fe:f6',vendor:'VMware, Inc.',vendor_confidence:.9,randomized_mac:false}
 render(<MemoryRouter><DeviceIdentityCell device={device}/></MemoryRouter>)
 expect(document.querySelector('.device-semantic-icon')).not.toBeNull()
 expect(screen.getByText('VMware 虚拟平台线索')).toBeVisible()
 expect(document.querySelector('.brand-logo-vmware')).toBeNull()
 expect(screen.getByText(/品牌推测/)).toBeVisible()
})
