import { http, HttpResponse } from 'msw'

const observedAt = '2026-10-22T09:00:00Z'
const sampleCase = {case_id:'violation:router-observation-1:student-1',account_id:'student-1',assessment_id:'router-observation-1',status:'open',first_seen:'2026-10-16T09:00:00Z',last_seen:observedAt,simulated_notice_times:['2026-10-16T09:00:00Z','2026-10-18T09:00:00Z','2026-10-20T09:00:00Z']}

export const violationHandlers = [
  http.get('/api/v1/violation-dashboard',()=>HttpResponse.json({window:'7d',counts:{'拟核实提醒':1,'拟提醒':3,'拟封禁':1},observation_only:true})),
  http.get('/api/v1/violation-cases',({request})=>{const account=new URL(request.url).searchParams.get('account_id');return HttpResponse.json({items:!account||sampleCase.account_id.includes(account)?[sampleCase]:[],next_cursor:'',observation_only:true})}),
  http.get('/api/v1/violation-cases/:caseId/timeline',()=>HttpResponse.json({items:[{observation_key:'notice-1',kind:'拟提醒',observed_at:observedAt,facts:{sequence:1}}],observation_only:true})),
  http.get('/api/v1/violation-observations',()=>HttpResponse.json({items:[{observation_key:'notice-1',kind:'拟提醒',target:'student-1',observed_at:observedAt,facts:{reason:'observation_only'}}],next_cursor:'',observation_only:true})),
]
