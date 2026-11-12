package store

import (
	"sort"
	"strings"
)

// This calculation runs once when the existing recognition catalog refreshes.
// HTTP statistics readers receive only its compact result and never traverse
// every endpoint to answer a single request.
func summarizeRecognitionCatalog(items []EndpointDeviceInventory) DeviceRecognitionSummary {
	result := DeviceRecognitionSummary{Coverage: map[string]RecognitionCoverage{}, TotalEndpoints: len(items)}
	counts := map[string]int{}
	for _, item := range items {
		for key, value := range map[string]struct {
			text  string
			score float64
		}{"vendor": {item.Vendor, item.VendorConfidence}, "brand": {item.Brand, item.BrandConfidence},
			"model": {item.Model, item.ModelConfidence}, "device_type": {item.DeviceType, item.DeviceTypeConfidence},
			"os_family": {item.OSFamily, item.OSFamilyConfidence}} {
			if !deviceDimensionConflict(item, key) && value.text != "" && value.text != "unknown" && value.score >= .8 {
				counts[key]++
			}
		}
		if item.EcosystemHint != "" && !item.EcosystemConflict {
			counts["ecosystem"]++
		}
		if item.EcosystemConflict {
			result.EcosystemConflicts++
		}
		if item.BrandInference != nil {
			if item.BrandInference.Status == "inferred" {
				counts["brand_inferred"]++
			}
			if item.BrandInference.Status == "conflict" {
				result.BrandInferenceConflicts++
			}
		}
	}
	for _, key := range []string{"vendor", "brand", "model", "device_type", "os_family", "ecosystem", "brand_inferred"} {
		result.Coverage[key] = coverage(counts[key], result.TotalEndpoints)
	}
	untypedReasons := map[string]int{}
	for _, item := range items {
		typed := item.DeviceType != "" && item.DeviceType != "unknown" && item.DeviceTypeConfidence >= .8 && !deviceDimensionConflict(item, "device_type")
		if typed {
			continue
		}
		switch {
		case strings.EqualFold(item.OSFamily, "Apple OS") || strings.EqualFold(item.OSFamily, "iOS") || strings.EqualFold(item.OSFamily, "iPadOS") || strings.EqualFold(item.OSFamily, "macOS"):
			untypedReasons["Apple 系统线索"]++
		case item.OSFamily != "" && item.OSFamily != "unknown":
			untypedReasons["其他系统线索"]++
		case item.Brand != "" || item.Vendor != "":
			untypedReasons["仅品牌线索"]++
		default:
			untypedReasons["缺少系统与品牌线索"]++
		}
	}
	for reason, count := range untypedReasons {
		result.UntypedReasons = append(result.UntypedReasons, RecognitionUntypedReason{Reason: reason, Count: count})
	}
	sort.Slice(result.UntypedReasons, func(i, j int) bool {
		if result.UntypedReasons[i].Count == result.UntypedReasons[j].Count {
			return result.UntypedReasons[i].Reason < result.UntypedReasons[j].Reason
		}
		return result.UntypedReasons[i].Count > result.UntypedReasons[j].Count
	})
	result.TopModels = topModels(items)
	result.TopOS = topOSFamilies(items)
	typeBrandCounts := map[[2]string]int{}
	typeTotals := map[string]int{}
	for _, item := range items {
		if item.DeviceType == "" || item.DeviceType == "unknown" || deviceDimensionConflict(item, "device_type") || item.DeviceTypeConfidence < .8 {
			continue
		}
		if item.Brand == "" || item.Brand == "unknown" || deviceDimensionConflict(item, "brand") || item.BrandConfidence < .8 {
			continue
		}
		typeBrandCounts[[2]string{item.DeviceType, item.Brand}]++
		typeTotals[item.DeviceType]++
	}
	typeBrandPairs := make([][3]any, 0, len(typeBrandCounts))
	for key, count := range typeBrandCounts {
		typeBrandPairs = append(typeBrandPairs, [3]any{key[0], key[1], count})
	}
	sort.Slice(typeBrandPairs, func(i, j int) bool {
		left, right := typeBrandPairs[i], typeBrandPairs[j]
		lt, lb, lc := left[0].(string), left[1].(string), left[2].(int)
		rt, rb, rc := right[0].(string), right[1].(string), right[2].(int)
		if typeTotals[lt] != typeTotals[rt] {
			return typeTotals[lt] > typeTotals[rt]
		}
		if lt != rt {
			return lt < rt
		}
		if lc != rc {
			return lc > rc
		}
		return lb < rb
	})
	perType := map[string]int{}
	for _, pair := range typeBrandPairs {
		deviceType, brand, count := pair[0].(string), pair[1].(string), pair[2].(int)
		if len(result.TopTypeBrands) >= 12 || perType[deviceType] >= 3 {
			continue
		}
		perType[deviceType]++
		result.TopTypeBrands = append(result.TopTypeBrands, RecognitionTypeBrandCount{DeviceType: deviceType, Brand: brand, Count: count})
	}
	brandCounts := map[string]int{}
	for _, item := range items {
		brand := item.Brand
		if brand == "" || brand == "unknown" || deviceDimensionConflict(item, "brand") || item.BrandConfidence < .8 {
			continue
		}
		brandCounts[brand]++
	}
	for brand, count := range brandCounts {
		result.TopBrands = append(result.TopBrands, RecognitionBrandCount{Brand: brand, Count: count})
	}
	sort.Slice(result.TopBrands, func(i, j int) bool {
		if result.TopBrands[i].Count == result.TopBrands[j].Count {
			return result.TopBrands[i].Brand < result.TopBrands[j].Brand
		}
		return result.TopBrands[i].Count > result.TopBrands[j].Count
	})
	if len(result.TopBrands) > 8 {
		result.TopBrands = result.TopBrands[:8]
	}
	return result
}
