export function formatBytes(value?: number) {
  if (value === undefined) return ''
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let unitIndex = 0
  let result = value
  while (result >= 1024 && unitIndex < units.length - 1) {
    result /= 1024
    unitIndex += 1
  }
  return `${result >= 10 || unitIndex === 0 ? result.toFixed(0) : result.toFixed(1)} ${units[unitIndex]}`
}
