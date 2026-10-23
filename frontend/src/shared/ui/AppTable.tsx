import { Table } from 'antd'
import type { TableProps } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import type { TdHTMLAttributes } from 'react'

type LabeledCell = TdHTMLAttributes<HTMLTableCellElement> & { 'data-label'?: string }

/**
 * 窄屏下表格会变成卡片（见 index.css 的 compact-list-table），表头被隐藏，
 * 因此把列标题写进单元格的 data-label，由 CSS 以“字段：值”的形式补回来。
 */
function withCellLabels<RecordType extends object>(columns: ColumnsType<RecordType>): ColumnsType<RecordType> {
  return columns.map((column) => {
    const title = typeof column.title === 'string' ? column.title : undefined
    const children = 'children' in column && column.children
      ? withCellLabels(column.children as ColumnsType<RecordType>)
      : undefined
    if (!title && !children) return column
    return {
      ...column,
      ...(children ? { children } : {}),
      ...(title ? {
        onCell: (record: RecordType, index?: number) => {
          const base = typeof column.onCell === 'function' ? column.onCell(record, index) ?? {} : {}
          return { ...base, 'data-label': title } as LabeledCell
        },
      } : {}),
    }
  })
}

/**
 * 列表页统一表格：固定紧凑样式与不分页（分页交给 AppServerPagination），
 * 调用方只描述列和数据，避免每个页面各写一套 size / className / pagination。
 */
export function AppTable<RecordType extends object = object>({ className, ...props }: TableProps<RecordType>) {
  return (
    <Table<RecordType>
      className={['compact-list-table', className].filter(Boolean).join(' ')}
      size="small"
      pagination={false}
      {...props}
      columns={props.columns ? withCellLabels(props.columns) : undefined}
    />
  )
}
