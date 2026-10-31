type DeviceAddress = { name?: string; primary_ip?: string; current_addresses?: string[] }
type ServiceOrigin = { source_ip?: string; service_target?: string }

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
