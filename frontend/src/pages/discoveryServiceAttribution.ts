type DeviceAddress = { name?: string; primary_ip?: string; current_addresses?: string[] }
type ServiceOrigin = { source_ip?: string; service_target?: string }
type FlowDevice = DeviceAddress & { sensor_id?: string }

function hostName(value: string) {
  return value.trim().toLowerCase().replace(/\.+$/, '').replace(/\.local$/, '')
}

// A routed mirror may report the gateway's Ethernet MAC for many hosts.
// Associate an announcement only through its source IP or an exact target name.
export function serviceBelongsToDevice(device: DeviceAddress, clue: ServiceOrigin) {
  const addresses = device.current_addresses ?? (device.primary_ip ? [device.primary_ip] : [])
  if (clue.source_ip) return addresses.includes(clue.source_ip)
  const name = hostName(device.name ?? '')
  return name !== '' && hostName(clue.service_target ?? '') === name
}

export function signalAddressMatchesDevice(device: DeviceAddress, signal: { ip?: string }) {
  if (!signal.ip) return true
  const addresses = device.current_addresses ?? (device.primary_ip ? [device.primary_ip] : [])
  return addresses.includes(signal.ip)
}

// A current row can arrive before its descriptive projection. Missing sensor
// scope must never become a literal "undefined" target or an unscoped IP lookup.
export function currentFlowTargets(devices: FlowDevice[]) {
  return [...new Set(devices.flatMap(device => {
    if (typeof device.sensor_id !== 'string' || !device.sensor_id.trim()) return []
    return (device.current_addresses ?? [])
      .filter(ip => typeof ip === 'string' && ip.trim() !== '')
      .map(ip => `${device.sensor_id}|${ip}`)
  }))].sort()
}

export function flowBelongsToDevice(device: FlowDevice, clue: { sensor_id: string; src_ip: string }) {
  return typeof device.sensor_id === 'string' && device.sensor_id.trim() !== '' &&
    clue.sensor_id === device.sensor_id && (device.current_addresses ?? []).includes(clue.src_ip)
}
