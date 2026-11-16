// The U/L bit identifies local administration, not how the address was made.
export function isLocallyAdministeredMAC(mac?: string): boolean {
  if (!mac) return false
  const octets = mac.trim().split(/[:-]/)
  if (octets.length < 1) return false
  const first = Number.parseInt(octets[0], 16)
  return Number.isFinite(first) && first >= 0 && first <= 255 && (first & 0x02) === 0x02
}
