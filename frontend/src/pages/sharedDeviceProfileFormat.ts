export function formatDeviceName(brand?: string, model?: string, fallback?: string) {
  const normalizedBrand = brand?.trim() || ''
  const normalizedModel = model?.trim() || ''
  if (!normalizedBrand) return normalizedModel || fallback || ''
  if (!normalizedModel) return normalizedBrand

  const escapedBrand = normalizedBrand.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const modelAlreadyIncludesBrand = new RegExp(`^${escapedBrand}(?:[\\s/_-]+|$)`, 'i').test(normalizedModel)
  return modelAlreadyIncludesBrand ? normalizedModel : `${normalizedBrand} ${normalizedModel}`
}
