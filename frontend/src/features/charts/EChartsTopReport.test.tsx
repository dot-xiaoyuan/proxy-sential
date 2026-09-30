import { render } from '@testing-library/react'
import { it,expect,vi } from 'vitest'
import { EChartsTopReport } from './EChartsTopReport'
import type { ActivityReport } from '../../shared/api/types'
const captured=vi.hoisted(()=>({props:{} as {onEvents?:{click:(p:{data:{key?:string}})=>void};option?:{series:{data:{key?:string;name:string}[]}[]}}}))
vi.mock('echarts-for-react',()=>({default:(props:typeof captured.props)=>{captured.props=props;return <div/>}}))
it('drills down using stable keys and makes the aggregate other item inert',()=>{
 const onSelect=vi.fn();const report={items:Array.from({length:8},(_,i)=>({key:`id-${i}`,label:`展示名称 ${i}`,count:8-i,share:.1})),total:36,dimension:'domain',classified_count:36,unknown_count:0} as ActivityReport
 render(<EChartsTopReport title="排行" kind="donut" report={report} onSelect={onSelect}/>)
 const data=captured.props.option!.series[0].data
 captured.props.onEvents!.click({data:data[0]});expect(onSelect).toHaveBeenCalledWith('id-0')
 captured.props.onEvents!.click({data:data.at(-1)!});expect(onSelect).toHaveBeenCalledTimes(1)
})
