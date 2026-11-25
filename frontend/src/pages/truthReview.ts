import type {CSVTable} from './censusComparison'

export const reviewColumns = ['核实标识', '样本来源', '系统确认类型', '系统型号', '证据状态', '人工核实类型', '人工核实型号', '实物或台账依据', '镜像覆盖核对', '核实时间', '核实人'] as const
export const metricNames = {visible:'可观测率', precision:'品类准确率', recall:'召回', model:'型号覆盖', conflict:'冲突率', insufficient:'证据不足比例'}
type Fraction = [number, number]
type Metrics = Record<keyof typeof metricNames, Fraction> & {type:string}
function count(fraction: Fraction, success: boolean) {
  fraction[1]++
  if (success) fraction[0]++
}

export function evaluateTruth(tables: CSVTable[]) {
  const metrics = new Map<string, Metrics>()
  const devices = new Map<string, string>()
  const entries = new Set<string>()
  const group = (type: string) => {
    let item = metrics.get(type)
    if (!item) {
      item = {type, visible:[0,0], precision:[0,0], recall:[0,0], model:[0,0], conflict:[0,0], insufficient:[0,0]}
      metrics.set(type, item)
    }
    return item
  }
  let conflictingReviews = 0, pending = 0, hasIndependent = false
  for (const table of tables) {
    const columns = reviewColumns.map(name => {
      const index = table.headers.indexOf(name)
      if (index < 0 || index !== table.headers.lastIndexOf(name)) throw new Error('请检查列名「' + name + '」')
      return index
    })
    for (const [index, row] of table.rows.entries()) {
      const [id, cohort, predicted, model, status, truth, actualModel, basis, coverage, date, reviewer] = columns.map(col => row[col]?.trim() || '')
      if (!id && !truth && !basis && !coverage && !reviewer) continue
      const fail = (message: string): never => {throw new Error('第 ' + (index+2) + ' 行' + message)}
      if (basis === '台账与实物冲突') { conflictingReviews++; continue }
      if (!truth || !basis || !coverage || !date || !reviewer) { pending++; continue }
      if (!id || !['独立台账','系统抽样'].includes(cohort)) fail('需填写核实标识和样本来源')
      if (!['是','否'].includes(coverage)) fail('的镜像覆盖核对请填是或否')
      const observed = coverage === '是'
      if (observed && !['已确认','冲突','证据不足','已撤销'].includes(status)) fail('的已观测设备需填写证据状态')
      if ((!observed && (predicted || model || status)) || (status === '已确认') !== Boolean(predicted)) fail('的系统确认类型、证据状态和镜像覆盖互相矛盾')
      const key = JSON.stringify([cohort,id])
      if (entries.has(key)) fail('在同一抽样来源重复')
      entries.add(key)
      const assessment = JSON.stringify([predicted,model,status,truth,actualModel,observed])
      const previous = devices.get(id)
      if (previous && previous !== assessment) fail('与同标识的另一份核实结论冲突')
      devices.set(id,assessment)
      const item = group(truth)
      const correct = observed && status === '已确认' && predicted === truth
      if (cohort === '独立台账') {
        hasIndependent = true
        count(item.visible, observed)
        count(item.recall, correct)
      } else if (predicted) count(group(predicted).precision, correct)
      if (observed && !previous) {
        count(item.model, Boolean(actualModel && model && actualModel.toLowerCase() === model.toLowerCase()))
        count(item.conflict, status === '冲突')
        count(item.insufficient, status === '证据不足')
      }
    }
  }
  return {metrics:[...metrics.values()].sort((a,b)=>a.type.localeCompare(b.type,'zh-CN')), conflictingReviews, pending, hasIndependent}
}
