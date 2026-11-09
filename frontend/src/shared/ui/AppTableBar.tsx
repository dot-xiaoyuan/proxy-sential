import type { ReactNode } from 'react'
import { ClearOutlined, LoadingOutlined, SearchOutlined } from '@ant-design/icons'
import { Button, Input, Space, Tag, Typography } from 'antd'

interface FilterOption {
  key: string
  label: string
  active: boolean
}

interface AppTableBarProps {
  searchValue: string
  onSearchChange: (value: string) => void
  onSearch?: (value: string) => void
  searchPlaceholder?: string
  searchAriaLabel?: string
  /** 搜索请求进行中：在输入框内显示加载指示，避免结果返回前没有任何反馈 */
  searching?: boolean
  filters?: ReactNode
  filterOptions?: FilterOption[]
  onFilterToggle?: (key: string) => void
  onClearFilters?: () => void
  totalCount?: number
  extra?: ReactNode
  /** 展开后显示在工具条下方的整行面板（更多筛选等） */
  panel?: ReactNode
}

export function AppTableBar({
  searchValue,
  onSearchChange,
  onSearch,
  searchPlaceholder = '关键字快速检索 (IP / 域名 / ID / 摘要)...',
  searchAriaLabel,
  searching = false,
  filters,
  filterOptions = [],
  onFilterToggle,
  onClearFilters,
  totalCount,
  extra,
  panel,
}: AppTableBarProps) {
  const hasActiveFilters = filterOptions.some((f) => f.active) || searchValue.length > 0

  return (
    <div className="app-table-bar">
      <Space className="app-table-bar-main" size="middle" wrap>
        <Input
          allowClear
          aria-label={searchAriaLabel ?? searchPlaceholder}
          onChange={(e) => onSearchChange(e.target.value)}
          onPressEnter={() => onSearch?.(searchValue)}
          placeholder={searchPlaceholder}
          prefix={<SearchOutlined className="search-prefix-icon" />}
          suffix={searching ? <LoadingOutlined aria-label="正在加载" className="app-table-search-spinner" spin /> : undefined}
          aria-busy={searching}
          className={searching ? 'app-table-search is-searching' : 'app-table-search'}
          value={searchValue}
        />

        {filters && <div className="app-table-filters">{filters}</div>}

        {filterOptions.length > 0 && (
          <Space className="app-table-filter-group" size="small" wrap>
            <Typography.Text className="app-table-filter-label" type="secondary">
              快捷筛选:
            </Typography.Text>
            {filterOptions.map((opt) => (
              <Tag.CheckableTag
                className="app-table-filter-tag"
                checked={opt.active}
                key={opt.key}
                onChange={() => onFilterToggle?.(opt.key)}
              >
                {opt.label}
              </Tag.CheckableTag>
            ))}
          </Space>
        )}

        {hasActiveFilters && onClearFilters && (
          <Button
            className="dpi-badge-tag"
            icon={<ClearOutlined />}
            onClick={onClearFilters}
            size="small"
            type="text"
          >
            清空筛选
          </Button>
        )}
      </Space>

      <Space className="app-table-bar-extra" size="middle">
        {totalCount !== undefined && (
          <Typography.Text className="app-table-filter-label" type="secondary">
            已筛选 <Typography.Text strong>{totalCount}</Typography.Text> 条记录
          </Typography.Text>
        )}
        {extra}
      </Space>

      {panel && <div className="app-table-bar-panel">{panel}</div>}
    </div>
  )
}
