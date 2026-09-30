import { Tabs } from 'antd'
import { useUrlState } from '../shared/ui/useUrlState'
import { IngestPage } from './IngestPage'
import { DiscoveryPage } from './DiscoveryPage'
export function SourcesPage(){
 const [tab,setTab]=useUrlState('tab','diagnostics',['diagnostics','sources','scan','tasks']);
 return <div className="sources-page"><section className="surface"><Tabs activeKey={tab} onChange={setTab} items={[{key:'diagnostics',label:'采集诊断'},{key:'sources',label:'基础设施接入'},{key:'scan',label:'主动发现'},{key:'tasks',label:'发现任务'}]}/></section>{tab==='diagnostics'?<IngestPage/>:<DiscoveryPage configuration/>}</div>
}
