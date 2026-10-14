import { afterEach,expect,it,vi } from 'vitest'
import { cleanup,render,screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { AssociationOverview,EndpointTracePanel } from './EndpointTracePanel'
const fixture=vi.hoisted(()=>({data:{items:[] as object[]|null,state:{complete:true,updating:false,as_of:'2026-10-12T12:00:00Z'}},refetch:vi.fn()}))
vi.mock('../../shared/api/queries',()=>({useEndpointObservations:()=>({data:fixture.data,isFetching:false,isError:false,refetch:fixture.refetch})}))
afterEach(()=>{cleanup();fixture.data.items=[];fixture.data.state.complete=true})
it('does not present incomplete coverage as zero observations',()=>{fixture.data.state.complete=false;render(<MemoryRouter><EndpointTracePanel endpointId="test"/></MemoryRouter>);expect(screen.getByText('历史覆盖回填中')).toBeInTheDocument();expect(screen.queryByText('所选条件没有观测记录')).not.toBeInTheDocument()})
it('handles null arrays without crashing',()=>{fixture.data.items=null;render(<MemoryRouter><EndpointTracePanel endpointId="test"/></MemoryRouter>);expect(screen.getByText('所选条件没有观测记录')).toBeInTheDocument()})
it('keeps retained observations after raw payload expiry and invents no interval',()=>{fixture.data.items=[{record_id:'ip:1',kind:'ip',value:'192.0.2.1',source:'dhcp',observed_at:'2026-09-01T00:00:00Z',confidence:.9,event_id:'retained-fact',evidence_state:'outside_retention'}];render(<MemoryRouter><EndpointTracePanel endpointId="test"/></MemoryRouter>);expect(screen.getByText('192.0.2.1')).toBeInTheDocument();expect(screen.getByText('原始事件超出 7 天保留期')).toBeInTheDocument();expect(screen.queryByText(/会话起点/)).not.toBeInTheDocument()})
it('distinguishes observation summaries from continuous occupancy',()=>{render(<AssociationOverview/>);expect(screen.getByText('关联概览回填中')).toBeInTheDocument();expect(screen.queryByText('0')).not.toBeInTheDocument()})
