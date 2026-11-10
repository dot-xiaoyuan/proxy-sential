import type { components } from '../shared/api/generated'
import { csvCell } from './discoveryExport'

type Summary = components['schemas']['DeviceRecognitionSummary']
type Trends = components['schemas']['DiscoveryTrends']

function percent(value: number | undefined): string {
  return `${Math.round((value ?? 0) * 100)}%`
}

export function qualityReportCSV(summary: Summary, trends: Trends | undefined, types: Record<string, string>): string {
  const rows: string[][] = []
  rows.push(['识别质量报告'])
  rows.push(['生成时间', new Date().toISOString()])
  rows.push(['说明', '全局识别画像，不随列表筛选变化'])
  rows.push([])
  rows.push(['指标', '已知', '总数', '覆盖率'])
  rows.push(['类型覆盖', String(summary.coverage?.device_type?.known ?? ''), String(summary.total_endpoints ?? ''), percent(summary.coverage?.device_type?.rate)])
  rows.push(['品牌覆盖', String(summary.coverage?.brand?.known ?? ''), String(summary.total_endpoints ?? ''), percent(summary.coverage?.brand?.rate)])
  rows.push(['型号覆盖', String(summary.coverage?.model?.known ?? ''), String(summary.total_endpoints ?? ''), percent(summary.coverage?.model?.rate)])
  rows.push(['系统覆盖', String(summary.coverage?.os_family?.known ?? ''), String(summary.total_endpoints ?? ''), percent(summary.coverage?.os_family?.rate)])
  rows.push(['链路层归属', '', '', percent(summary.mac_attribution_rate)])
  rows.push(['事件归属', '', '', percent(summary.event_attribution_rate)])
  rows.push([])
  rows.push(['厂商 Top', '数量'])
  for (const item of summary.top_brands ?? []) rows.push([item.brand, String(item.count)])
  rows.push([])
  rows.push(['类型厂商', '数量'])
  for (const item of summary.top_type_brands ?? []) rows.push([`${types[item.device_type] ?? item.device_type} · ${item.brand}`, String(item.count)])
  rows.push([])
  rows.push(['型号 Top', '数量'])
  for (const item of summary.top_models ?? []) rows.push([`${item.brand ? item.brand + ' · ' : ''}${item.model}`, String(item.count)])
  rows.push([])
  rows.push(['系统 Top', '数量'])
  for (const item of summary.top_os ?? []) rows.push([item.os, String(item.count)])
  rows.push([])
  rows.push(['未识别原因', '数量'])
  for (const item of summary.untyped_reasons ?? []) rows.push([item.reason, String(item.count)])
  if (trends?.days?.length) {
    rows.push([])
    rows.push(['近 7 天新增', '明确类型'])
    for (const day of trends.days) rows.push([day.date, String(day.new), String(day.typed)])
  }
  return rows.map(row => row.map(csvCell).join(',')).join('\r\n') + '\r\n'
}
