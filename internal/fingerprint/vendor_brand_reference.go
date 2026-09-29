package fingerprint

import "strings"

// BrandReference is an interface-manufacturer clue, independent of device and domain recognition.
type BrandReference struct {
	Brand       string  `json:"brand"`
	Vendor      string  `json:"vendor"`
	Source      string  `json:"source"`
	Confidence  float64 `json:"confidence"`
	Explanation string  `json:"explanation"`
}

// Only named device manufacturers are eligible. Component and virtual-interface
// vendors must never become hardware brands through a generic alias fallback.
func MACVendorBrandReference(mac, vendor string, confidence float64) *BrandReference {
	if len(normalizeMAC(mac)) != 12 || IsRandomizedMAC(mac) || confidence < .8 {
		return nil
	}
	value := strings.ToLower(strings.TrimSpace(vendor))
	value = strings.NewReplacer(",", " ", ".", " ", "-", " ", "_", " ").Replace(value)
	value = strings.Join(strings.Fields(value), " ")
	groups := []struct {
		brand   string
		aliases []string
	}{
		{"Huawei", []string{"huawei", "华为"}}, {"Vivo", []string{"vivo", "维沃"}},
		{"OPPO", []string{"oppo", "guangdong oppo", "广东欧珀"}}, {"Honor", []string{"honor", "荣耀"}},
		{"Xiaomi", []string{"xiaomi", "beijing xiaomi", "小米"}}, {"Apple", []string{"apple", "苹果"}},
		{"Samsung", []string{"samsung electronics", "三星电子"}}, {"Realme", []string{"realme", "真我"}},
		{"OnePlus", []string{"oneplus", "one plus", "一加"}},
		{"Dell", []string{"dell"}}, {"Lenovo", []string{"lenovo", "联想"}},
		{"HP", []string{"hp inc", "hewlett packard"}}, {"ASUS", []string{"asustek", "asus"}},
		{"Acer", []string{"acer"}}, {"Sony", []string{"sony"}}, {"Nokia", []string{"nokia"}},
	}
	for _, group := range groups {
		for _, alias := range group.aliases {
			if value == alias || strings.HasPrefix(value, alias+" ") {
				return &BrandReference{Brand: group.brand, Vendor: vendor, Source: "mac_vendor", Confidence: .6, Explanation: "MAC 注册厂商与设备厂商名称对应，仅作品牌参考，不确认整机品牌、型号或操作系统"}
			}
		}
	}
	return nil
}
