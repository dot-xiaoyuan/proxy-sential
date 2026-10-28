// Older results have only a global flag and retain the conservative fallback.
export function recognitionDimensionConflict(device: { recognition_conflict?: boolean; conflict_dimensions?: string[] }, dimension: string): boolean {
  return device.conflict_dimensions?.length ? device.conflict_dimensions.includes(dimension) : Boolean(device.recognition_conflict)
}
