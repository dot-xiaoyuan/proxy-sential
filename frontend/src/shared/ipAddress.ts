export function isIPAddress(value: string): boolean {
  const ip = value.trim()
  const octet = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)'
  if (new RegExp(`^${octet}(?:\\.${octet}){3}$`).test(ip)) return true
  if (!ip.includes(':') || ip.includes('%') || ip.includes('/')) return false
  try {
    return new URL(`http://[${ip}]/`).hostname.startsWith('[')
  } catch {
    return false
  }
}
