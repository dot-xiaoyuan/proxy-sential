import { brandIconPaths } from './brandIcons'

// Use only the reported OS family; never infer hardware brand from an OS icon.
export function OperatingSystemLabel({ family, confirmed = false }: { family: string; confirmed?: boolean }) {
  const value = family.trim().toLowerCase()
  if (!value || value === 'unknown') return null
  const key = /^(microsoft )?windows\b/.test(value) ? 'microsoft'
    : /^(macos|mac os|os x|ios|ipados)\b/.test(value) ? 'apple'
    : /^android\b/.test(value) ? 'android'
    : /^(linux|ubuntu|debian|centos|fedora|openwrt)\b/.test(value) ? 'linux' : undefined
  const paths = key ? brandIconPaths[key] : undefined
  return <span className={`device-os-label${confirmed ? ' device-os-confirmed' : ''}`}>
    {paths && <svg className="device-os-icon" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">{paths.map((path, index) => <path key={index} d={path} />)}</svg>}
    <span>{family}</span>
  </span>
}
