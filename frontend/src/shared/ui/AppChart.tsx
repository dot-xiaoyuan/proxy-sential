import { useEffect, useRef } from 'react'
import * as echarts from 'echarts/core'
import type { ComposeOption } from 'echarts/core'
import { BarChart, LineChart, type BarSeriesOption, type LineSeriesOption } from 'echarts/charts'
import {
  AriaComponent,
  GridComponent,
  LegendComponent,
  TooltipComponent,
  type AriaComponentOption,
  type GridComponentOption,
  type LegendComponentOption,
  type TooltipComponentOption,
} from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'

// 仅注册实际使用的图表与组件，避免打入全量 ECharts 产物。
echarts.use([
  BarChart,
  LineChart,
  GridComponent,
  TooltipComponent,
  LegendComponent,
  AriaComponent,
  CanvasRenderer,
])

export type AppChartOption = ComposeOption<
  | BarSeriesOption
  | LineSeriesOption
  | GridComponentOption
  | TooltipComponentOption
  | LegendComponentOption
  | AriaComponentOption
>

export interface AppChartProps {
  option: AppChartOption
  className?: string
  ariaLabel?: string
}

export function AppChart({ option, className, ariaLabel }: AppChartProps) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const chartRef = useRef<echarts.ECharts | null>(null)

  useEffect(() => {
    const element = containerRef.current
    if (!element) return

    let chart: echarts.ECharts | null = null
    try {
      chart = echarts.getInstanceByDom(element) ?? echarts.init(element)
      chartRef.current = chart
    } catch {
      // jsdom 等无完整 Canvas 实现的测试环境下安全跳过绘制。
      return
    }

    let timer: ReturnType<typeof globalThis.setTimeout> | undefined
    const scheduleResize = () => {
      if (timer) globalThis.clearTimeout(timer)
      timer = globalThis.setTimeout(() => {
        chartRef.current?.resize()
      }, 80)
    }

    const observer =
      typeof ResizeObserver !== 'undefined' ? new ResizeObserver(scheduleResize) : null
    observer?.observe(element)

    return () => {
      if (timer) globalThis.clearTimeout(timer)
      observer?.disconnect()
      chart?.dispose()
      chartRef.current = null
    }
  }, [])

  useEffect(() => {
    const chart = chartRef.current
    if (!chart) return
    chart.setOption(option, { notMerge: true, lazyUpdate: true })
  }, [option])

  return (
    <div
      ref={containerRef}
      className={className ? `app-chart ${className}` : 'app-chart'}
      role="img"
      aria-label={ariaLabel}
    />
  )
}
