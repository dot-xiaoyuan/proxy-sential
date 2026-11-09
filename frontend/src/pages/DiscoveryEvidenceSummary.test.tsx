import {cleanup,fireEvent,render,screen} from '@testing-library/react'
import {afterEach,expect,it} from 'vitest'
import {DiscoveryEvidenceSummary} from './DiscoveryEvidenceSummary'
import type {EvidenceObservation} from './discoveryEvidenceGroups'
const record={id:'a',event_id:'event-a',origin:'dns_sd',source_id:'mirror',observed_at:'2026-11-06T00:00:00Z',valid_until:'2099-01-01T00:00:00Z',explanation:'服务响应',evidence:{payload:{service_type:'_ipp._tcp',service_target:'printer.local'}}}
afterEach(cleanup)
it('shows one protocol summary with distinct services, compact repeats, and expandable original references',()=>{
 render(<DiscoveryEvidenceSummary observations={[record,{...record,id:'b',event_id:'event-b',observed_at:'2026-11-06T00:01:00Z'},{...record,id:'scan',event_id:'event-scan',evidence:{payload:{service_type:'_uscan._tcp'}}}]}/>)
 expect(screen.getByText(/本次摘要 3 条，按内容归并为 2 组/)).toBeVisible()
 expect(screen.getByText('DNS-SD 服务公告')).toBeVisible()
 expect(screen.getAllByText('IPP 打印')[0]).toBeVisible()
 expect(screen.getAllByText('扫描')[0]).toBeVisible()
 expect(screen.getByText('event-a')).not.toBeVisible()
 fireEvent.click(screen.getByText('DNS-SD 服务公告'))
 expect(screen.getByText('相同内容 2 条')).toBeVisible()
 fireEvent.click(screen.getByText('原始引用（2）'))
 expect(screen.getByText('event-a')).toBeVisible()
 expect(screen.getByText('event-b')).toBeVisible()
})
it('shows SIP and RTSP identity clues', () => {
  const now = new Date().toISOString()
  const observations = [
    { id: 'sip-1', origin: 'sip', observed_at: now, valid_until: now, explanation: 'SIP 话机自报标识', evidence: { payload: { user_agent: 'Huawei eSpace 7910 V200R003C00', method: 'REGISTER' } } },
    { id: 'rtsp-1', origin: 'rtsp', observed_at: now, valid_until: now, explanation: 'RTSP 服务端自报标识', evidence: { payload: { server: 'Hikvision', method: 'DESCRIBE' } } },
  ] as unknown as EvidenceObservation[]
  render(<DiscoveryEvidenceSummary observations={observations} />)
  expect(screen.getByText('话机标识 Huawei eSpace 7910 V200R003C00')).toBeInTheDocument()
  expect(screen.getByText('服务端标识 Hikvision')).toBeInTheDocument()
})
