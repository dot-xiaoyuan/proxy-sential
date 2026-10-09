import { Tabs } from 'antd'
import { AppPageHeader } from '../shared/ui'
import { useUrlState } from '../shared/ui/useUrlState'
import { ActionHistory } from './ActionHistory'
import { PolicyExecutions } from './PolicyExecutions'
import { useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'
export function ActionRecordsPage(){
const session=useSession();const [tab,setTab]=useUrlState('tab','executions',['executions','actions']);
return <main className="page action-records-page"><AppPageHeader title="处置记录" subtitle="查看策略执行、人工审批、处置动作与撤销记录"/><section className="surface operations-tabs-surface"><Tabs activeKey={tab} onChange={setTab} destroyOnHidden items={[{key:'executions',label:'策略执行',disabled:!can(session.data,'policies:read')},{key:'actions',label:'处置动作',disabled:!can(session.data,'actions:read')}]}/>{tab==='actions'?<ActionHistory/>:<PolicyExecutions/>}</section></main>
}
