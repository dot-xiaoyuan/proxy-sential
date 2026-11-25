import {expect, it} from 'vitest'
import {evaluateTruth, reviewColumns} from './truthReview'

const row = (id: string, cohort = '系统抽样', observed = '是', predicted = '打印机', state = '已确认', evidence = '实物') =>
  [id, cohort, predicted, predicted ? 'M1' : '', state, '打印机', 'M1', evidence, observed, '2026-11-25', '核实员']
const table = (...rows: string[][]) => ({headers: [...reviewColumns], rows})

it('uses separate sampling frames and counts overlapping devices once in observed metrics', () => {
  const report = evaluateTruth([table(row('A'), row('A', '独立台账'), row('B', '独立台账', '否', '', ''), row('C', '系统抽样', '是', '', '冲突'))])
  expect(report.metrics[0]).toMatchObject({type:'打印机', visible:[1,2], precision:[1,1], recall:[1,2], model:[1,2], conflict:[1,2], insufficient:[0,2]})
})
it('excludes unresolved or incomplete reviews and suppresses independent metrics', () => {
  const report=evaluateTruth([table(row('A'),row('B','独立台账','是','打印机','已确认','台账与实物冲突'),[...row('C').slice(0,5), '', '', '', '', '', ''])])
  expect(report.metrics[0].recall).toEqual([0,0])
  expect(report.hasIndependent).toBe(false)
  expect(evaluateTruth([table(['','独立台账','','','','','','','','',''])]).pending).toBe(0)
  expect([report.conflictingReviews,report.pending]).toEqual([1,1])
})
it('rejects inconsistent identities, invalid coverage, and duplicate cohort entries', () => {
  expect(()=>evaluateTruth([table(row('A'),row('A'))])).toThrow()
  expect(()=>evaluateTruth([table(row('A'),row('A','独立台账','否','',''))])).toThrow()
  expect(()=>evaluateTruth([table(row('A','系统抽样','待定'))])).toThrow()
})
