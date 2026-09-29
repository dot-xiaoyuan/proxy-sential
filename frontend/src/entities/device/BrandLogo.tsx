import type { FC } from 'react'
import { DesktopOutlined } from '@ant-design/icons'
import { resolveDeviceBrand } from './brandMatcher'
import { brandIconPaths } from './brandIcons'

interface BrandLogoProps {
  brandKey?: string
  device?: { brand?: string; vendor?: string; summary?: string; endpoint_id?: string; model?: string }
  showName?: boolean
}

export const BrandLogo: FC<BrandLogoProps> = ({ brandKey, device, showName = true }) => {
  const brand = resolveDeviceBrand(device ?? { brand: brandKey })
  const paths = brandIconPaths[brand.key]
  return (
    <span className={`brand-logo-tag brand-logo-${brand.key}`} title={brand.nameEn} aria-label={showName ? undefined : brand.nameEn}>
      <span className="brand-logo-icon" aria-hidden="true">
        {paths ? <svg className="brand-logo-svg-inline" fill="currentColor" viewBox={brand.key === 'realme' ? '0 0 80 24' : '0 0 24 24'} xmlns="http://www.w3.org/2000/svg">
          {paths.map((path, index) => <path key={index} d={path} />)}
        </svg> : <DesktopOutlined className="brand-logo-ant-icon" />}
      </span>
      {showName && <span className="brand-logo-text"><span className="brand-name-cn">{brand.name}</span></span>}
    </span>
  )
}
