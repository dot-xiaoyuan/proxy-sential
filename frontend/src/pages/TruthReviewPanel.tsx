import {useRef, useState} from 'react'
import {readComparisonCSV} from './censusComparison'
import {evaluateTruth, metricNames} from './truthReview'

export function TruthReviewPanel() {
  const [report,setReport] = useState<ReturnType<typeof evaluateTruth>>()
  const [error,setError] = useState('')
  const generation = useRef(0)
  async function read(files: File[]) {
    const current = ++generation.current
    setReport(undefined)
    setError('')
    if (!files.length) return
    try {
      if (files.length > 2) throw new Error('请选择同一快照的系统抽样和独立台账，最多两个 CSV 文件')
      const result = evaluateTruth(await Promise.all(files.map(readComparisonCSV)))
      if (generation.current === current) setReport(result)
    } catch (err) {
      if (generation.current === current) setError(err instanceof Error ? err.message : '文件读取失败')
    }
  }
  return <section className="coverage-panel truth-review">
    <h2>人工核实结果</h2>
    <p>将同一快照的核实工作表另存为 UTF-8 CSV。可同时选择系统抽样和独立台账，文件仅在本浏览器读取。</p>
    <label>核实表 CSV <input type="file" multiple accept=".csv,text/csv" onChange={e=>void read(Array.from(e.target.files ?? []))}/></label>
    {error && <p role="alert">{error}</p>}
    {report && <>
      <p role="status">纳入 {report.metrics.length} 个品类。待填写 {report.pending} 行，台账与实物冲突 {report.conflictingReviews} 行。</p>
      {!report.hasIndependent && <p>可观测率和召回需要已核实的独立台账样本。</p>}
      {report.metrics.map(row=><section key={row.type}><h3>{row.type}</h3><dl>{(Object.keys(metricNames) as (keyof typeof metricNames)[]).filter(k=>report.hasIndependent || (k !== 'visible' && k !== 'recall')).map(k=>{
        const [num,den] = row[k]
        return <div key={k}><dt>{metricNames[k]}</dt><dd>{num} / {den}{den > 0 && '（'+(100*num/den).toFixed(1)+'%）'}</dd></div>
      })}</dl></section>)}
    </>}
  </section>
}
