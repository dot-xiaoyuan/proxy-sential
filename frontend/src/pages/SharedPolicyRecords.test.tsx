import { render, screen, waitFor, cleanup } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { SharedPolicyRecords, sharedReason } from './SharedPolicyRecords'
import { sharedDecisionFixture } from '../mocks/sharedPolicyRecords'
import { request } from '../shared/api/client'
vi.mock('../shared/api/client', () => ({ request: vi.fn() }))
vi.mock('../shared/api/queries', () => ({ useSession: () => ({ data: { permissions: [] } }) }))
afterEach(() => { cleanup(); vi.clearAllMocks() })
function setup(url = '/shared-access?tab=decisions') {const client = new QueryClient({defaultOptions:{queries:{retry:false}}});return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[url]}><SharedPolicyRecords /></MemoryRouter></QueryClientProvider>)}
describe('共享策略仅记录', () => {
 it('重复采集原因合并，长原因列表默认折叠', async () => {
  vi.mocked(request).mockResolvedValue({items:[{...sharedDecisionFixture,reasons:[...Array(500).fill('feature_value_limit'),'incomplete_shared_observation_window']}],next_cursor:''});setup()
  await screen.findByText('campus-student-001')
  ;(document.querySelector('.ant-table-row-expand-icon') as HTMLElement).click()
  expect(await screen.findByText('特征数量达到采集上限')).toBeInTheDocument()
  expect(screen.getByText('共 500 次')).toBeInTheDocument()
  expect(screen.queryByText('feature_value_limit')).toBeNull()
  expect(document.querySelectorAll('.shared-record-reason')).toHaveLength(2)
 })
 it('无效 URL 时间显示校验提示且不发送查询', () => {
  setup('/shared-access?tab=decisions&decision_from=invalid-date')
  expect(screen.getByText('请填写有效时间，且结束时间晚于开始时间')).toBeInTheDocument()
  expect(request).not.toHaveBeenCalled()
 })
 it('默认查询命中并展示证据与仅记录说明，始终没有执行入口', async () => {
  vi.mocked(request).mockResolvedValue({items:[sharedDecisionFixture],next_cursor:''});setup()
  expect(await screen.findByText('campus-student-001')).toBeInTheDocument()
  expect(screen.getAllByText('仅记录，未执行')).toHaveLength(2)
  expect(screen.getByText('命中后不会下线或发送请求')).toBeInTheDocument()
  expect(screen.queryByRole('button',{name:/确认执行|下线|撤销/})).toBeNull()
  expect(vi.mocked(request).mock.calls.every(([url])=>!String(url).includes('include_processing'))).toBe(true)
  ;(document.querySelector('.ant-table-row-expand-icon') as HTMLElement).click()
  expect(await screen.findByText('证据版本')).toBeInTheDocument()
  expect(screen.getByText(sharedDecisionFixture.evidence_version)).toBeInTheDocument()
  await waitFor(() => expect(request).toHaveBeenCalledWith(expect.stringContaining('result=matched')))
 })
 it('关联观察和不足原因可查询，空结果不表示没有共享', async () => {
  vi.mocked(request).mockResolvedValue({items:[],next_cursor:''});setup('/shared-access?tab=decisions&decision_result=insufficient&observation_id=raw-proof')
  expect(await screen.findByText(/当前筛选下暂无评估记录/)).toBeInTheDocument()
  expect(request).toHaveBeenCalledWith(expect.stringContaining('observation_id=raw-proof'))
  expect(sharedReason('capture_interval_incomplete:handshake-sidecar')).toContain('采集时间段覆盖不足')
 })
})
