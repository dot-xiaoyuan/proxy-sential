import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { CaseHistoryList } from './CaseHistoryList'
import { api } from '../shared/api/client'
vi.mock('../shared/api/client',()=>({api:{caseHistory:vi.fn()}}))
afterEach(()=>{cleanup();vi.clearAllMocks()})
it('案件历史使用准确统计、数字跳页和20/50页长，每次只读取目标页',async()=>{
 vi.mocked(api.caseHistory).mockImplementation(async(_id,_kind,cursor,limit)=>({items:[{comment_id:`record-${cursor}`,created_at:'2026-11-06T00:00:00Z',author_id:'admin',body:`记录${cursor}`}],page:{total:61,limit:limit??20,next_cursor:null}}))
 render(<QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}><CaseHistoryList caseId="case-204" kind="comments" total={61}/></QueryClientProvider>)
 expect(api.caseHistory).not.toHaveBeenCalled()
 fireEvent.click(screen.getByRole('button',{name:'查看调查记录（61）'}))
 await screen.findByText('共 61 条')
 fireEvent.click(screen.getByTitle('4'))
 await screen.findByText('admin · 记录60')
 expect(api.caseHistory).toHaveBeenLastCalledWith('case-204','comments','60',20)
 expect(api.caseHistory).toHaveBeenCalledTimes(2)
 fireEvent.mouseDown(screen.getByRole('combobox'))
 fireEvent.click(screen.getByText('50 / page'))
 await waitFor(()=>expect(api.caseHistory).toHaveBeenLastCalledWith('case-204','comments','0',50))
 await waitFor(()=>expect(screen.getByTitle('1')).toHaveClass('ant-pagination-item-active'))
})
