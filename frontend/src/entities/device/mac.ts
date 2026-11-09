// A locally administered MAC (second-least-significant bit of the first
// octet) is how phones and laptops hide their hardware address.
export function isRandomizedMAC(mac?: string): boolean {
  if (!mac) return false
  const octets = mac.trim().split(/[:-]/)
  if (octets.length < 1) return false
  const first = Number.parseInt(octets[0], 16)
  return Number.isFinite(first) && first >= 0 && first <= 255 && (first & 0x02) === 0x02
}
