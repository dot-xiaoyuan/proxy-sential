import type { ReactNode } from 'react'
import { LeftOutlined, RightOutlined, ExportOutlined } from '@ant-design/icons'
import { Button, Drawer } from 'antd'
import { Link } from 'react-router-dom'

import { useMediaQuery } from './useMediaQuery'

export interface AppDetailDrawerProps {
  open: boolean
  title: ReactNode
  subtitle?: ReactNode
  badges?: ReactNode
  detailHref?: string
  detailLabel?: string
  hasPrev?: boolean
  hasNext?: boolean
  onPrev?: () => void
  onNext?: () => void
  onClose: () => void
  extra?: ReactNode
  children: ReactNode
}

// 统一右侧快速研判抽屉：支持不离列表连续翻看，并可一键进入独立详情页深度溯源。
export function AppDetailDrawer({
  open,
  title,
  subtitle,
  badges,
  detailHref,
  detailLabel = '完整详情',
  hasPrev,
  hasNext,
  onPrev,
  onNext,
  onClose,
  extra,
  children,
}: AppDetailDrawerProps) {
  const isMobile = useMediaQuery('(max-width: 640px)')

  return (
    <Drawer
      rootClassName="app-detail-drawer"
      open={open}
      onClose={onClose}
      placement="right"
      size={isMobile ? '100%' : 620}
      destroyOnHidden
      title={
        <div className="app-detail-drawer-head">
          <div className="app-detail-drawer-title-group">
            <h2 className="app-detail-drawer-title">{title}</h2>
            {subtitle && <span className="app-detail-drawer-subtitle">{subtitle}</span>}
            {badges}
          </div>
          <div className="app-detail-drawer-nav">
            {(onPrev || onNext) && (
              <>
                <Button
                  size="small"
                  aria-label="上一条"
                  icon={<LeftOutlined />}
                  disabled={!hasPrev}
                  onClick={onPrev}
                />
                <Button
                  size="small"
                  aria-label="下一条"
                  icon={<RightOutlined />}
                  disabled={!hasNext}
                  onClick={onNext}
                />
              </>
            )}
            {detailHref && (
              <Link className="ant-btn ant-btn-default ant-btn-sm" to={detailHref}>
                <ExportOutlined /> <span>{detailLabel}</span>
              </Link>
            )}
            {extra}
          </div>
        </div>
      }
    >
      <div className="app-detail-drawer-body">{children}</div>
    </Drawer>
  )
}
