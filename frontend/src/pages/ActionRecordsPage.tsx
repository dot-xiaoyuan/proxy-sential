import { Tabs } from 'antd'
import { AppPageHeader } from '../shared/ui'
import { useUrlState } from '../shared/ui/useUrlState'
import { ActionHistory } from './ActionHistory'
import { SharedPolicyRecords } from './SharedPolicyRecords'
import { BehaviorReportRecords } from './BehaviorReportsPage'
import { useSession } from '../shared/api/queries'
import { can } from '../shared/auth/permissions'
export function ActionRecordsPage(){
const session=useSession();const [tab,setTab]=useUrlState('tab','decisions',['decisions','actions','reports']);
return <main className="page action-records-page"><AppPageHeader/><section className="surface operations-tabs-surface"><Tabs activeKey={tab} onChange={setTab} destroyOnHidden items={[{key:'decisions',label:'策略执行',disabled:!can(session.data,'policies:read')},{key:'actions',label:'处置动作',disabled:!can(session.data,'actions:read')},{key:'reports',label:'上报记录',disabled:!can(session.data,'behavior-reports:read')}]}/>{tab==='actions'?<ActionHistory/>:tab==='reports'?<BehaviorReportRecords recordOnly/>:<SharedPolicyRecords/>}</section></main>
}
