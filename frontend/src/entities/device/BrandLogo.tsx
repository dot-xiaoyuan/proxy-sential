import type { FC } from 'react'
import { Typography } from 'antd'
import {
  AndroidOutlined,
  DesktopOutlined,
  MobileOutlined,
  WindowsOutlined,
} from '@ant-design/icons'
import { resolveDeviceBrand } from './brandMatcher'

interface BrandLogoProps {
  brandKey?: string
  device?: {
    brand?: string
    vendor?: string
    summary?: string
    endpoint_id?: string
    model?: string
  }
  size?: number
  showName?: boolean
}

export const BrandLogo: FC<BrandLogoProps> = ({ brandKey, device, showName = true }) => {
  const brandInfo = device ? resolveDeviceBrand(device) : resolveDeviceBrand({ brand: brandKey })

  if (brandInfo.key === 'unknown') {
    return <Typography.Text type="secondary">-</Typography.Text>
  }

  return (
    <div className={`brand-logo-tag brand-logo-${brandInfo.key}`}>
      <span className="brand-logo-icon">
        {renderBrandSvg(brandInfo.key)}
      </span>
      {showName && (
        <span className="brand-logo-text">
          <span className="brand-name-cn">{brandInfo.name}</span>
        </span>
      )}
    </div>
  )
}

function renderBrandSvg(key: string) {
  switch (key) {
    case 'apple':
      return (
        <svg className="brand-logo-svg-inline" fill="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M15.97 4.03c.6-0.74 1.01-1.77.9-2.81-.88.04-1.95.59-2.58 1.32-.56.65-.96 1.7-0.83 2.72 0.99.08 1.99-.48 2.51-1.23z" />
        </svg>
      )
    case 'xiaomi':
      return (
        <svg className="brand-logo-svg-inline" fill="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm3.75 14.5h-2.25v-5.25c0-.69-.56-1.25-1.25-1.25s-1.25.56-1.25 1.25v5.25H9v-5.25c0-1.93 1.57-3.5 3.5-3.5s3.5 1.57 3.5 3.5v5.25zM6.5 8h2.25v8.5H6.5V8z" />
        </svg>
      )
    case 'huawei':
      return (
        <svg className="brand-logo-svg-inline" fill="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path d="M12 2L9.5 8.5h5L12 2zm-5 4.5L5 12.5h3.5L7 6.5zm10 0l-1.5 6H19l-2-6zM3.5 12L2 17.5h3L3.5 12zm17 0l-1.5 5.5h3L20.5 12zM6 16.5L4.5 22h3L6 16.5zm12 0l-1.5 5.5h3L18 16.5zm-6 0l-1.5 5.5h3.5L12 16.5z" />
        </svg>
      )
    case 'microsoft':
      return <WindowsOutlined className="brand-logo-ant-icon" />
    case 'lenovo':
      return (
        <svg className="brand-logo-svg-inline" fill="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path d="M3 6h3v12H3V6zm5 0h13v3H8V6zm0 4.5h10v3H8v-3zm0 4.5h13v3H8v-3z" />
        </svg>
      )
    case 'dell':
      return (
        <svg className="brand-logo-svg-inline" fill="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-5 13.5V8.5h2.5c1.38 0 2.5 1.12 2.5 2.5s-1.12 2.5-2.5 2.5H7zm7.5 0V8.5H18v1.8h-2v1.5h1.8v1.8H16v1.9h2.5v1.8h-4z" />
        </svg>
      )
    case 'hp':
      return (
        <svg className="brand-logo-svg-inline" fill="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path d="M9.5 4l-4 16h3l4-16h-3zm6 0l-4 16h3l4-16h-3z" />
        </svg>
      )
    case 'samsung':
      return (
        <svg className="brand-logo-svg-inline" fill="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path d="M20.5 9.5c0-1.93-3.81-3.5-8.5-3.5s-8.5 1.57-8.5 3.5 3.81 3.5 8.5 3.5 8.5-1.57 8.5-3.5zM12 11c-3.58 0-6.5-.9-6.5-2s2.92-2 6.5-2 6.5.9 6.5 2-2.92 2-6.5 2z" />
        </svg>
      )
    case 'cisco':
      return (
        <svg className="brand-logo-svg-inline" fill="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path d="M4 14h2v4H4v-4zm4-4h2v8H8v-8zm4-4h2v12h-2V6zm4 4h2v8h-2v-8zm4 4h2v4h-2v-4z" />
        </svg>
      )
    case 'asus':
      return <DesktopOutlined className="brand-logo-ant-icon" />
    case 'android':
      return <AndroidOutlined className="brand-logo-ant-icon" />
    case 'linux':
      return <MobileOutlined className="brand-logo-ant-icon" />
    default:
      return null
  }
}
