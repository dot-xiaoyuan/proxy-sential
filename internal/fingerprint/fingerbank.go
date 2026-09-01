package fingerprint

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type DHCPFingerprint struct {
	RequestedOptions string   `json:"requested_options"`
	VendorClasses    []string `json:"vendor_classes,omitempty"`
	DeviceType       string   `json:"device_type,omitempty"`
	OSFamily         string   `json:"os_family,omitempty"`
	Description      string   `json:"description"`
	Confidence       float64  `json:"confidence"`
}

type fingerbankSection struct {
	kind, id, description string
	values                map[string][]string
}

func FingerbankFromLegacy(data []byte) ([]byte, error) {
	sections := []fingerbankSection{}
	var current *fingerbankSection
	var multiline string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if multiline != "" {
			if line == "EOT" {
				multiline = ""
				continue
			}
			current.values[multiline] = append(current.values[multiline], line)
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			parts := strings.Fields(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			if len(parts) != 2 {
				current = nil
				continue
			}
			sections = append(sections, fingerbankSection{kind: parts[0], id: parts[1], values: map[string][]string{}})
			current = &sections[len(sections)-1]
			continue
		}
		if current == nil {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if value == "<<EOT" {
			multiline = key
			continue
		}
		if key == "description" {
			current.description = value
		} else {
			current.values[key] = append(current.values[key], value)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	classByOS := map[int]string{}
	for _, section := range sections {
		if section.kind != "class" {
			continue
		}
		for _, expression := range section.values["members"] {
			for _, part := range strings.Split(expression, ",") {
				bounds := strings.Split(strings.TrimSpace(part), "-")
				start, err := strconv.Atoi(bounds[0])
				if err != nil {
					continue
				}
				end := start
				if len(bounds) == 2 {
					end, _ = strconv.Atoi(bounds[1])
				}
				for id := start; id <= end && id-start < 1000; id++ {
					classByOS[id] = section.description
				}
			}
		}
	}
	items := []DHCPFingerprint{}
	for _, section := range sections {
		if section.kind != "os" {
			continue
		}
		id, _ := strconv.Atoi(section.id)
		deviceType, osFamily := normalizeFingerbankClass(classByOS[id], section.description)
		for _, options := range section.values["fingerprints"] {
			options = normalizeDHCPOptions(options)
			if options == "" {
				continue
			}
			items = append(items, DHCPFingerprint{RequestedOptions: options, VendorClasses: section.values["vendor_id"], DeviceType: deviceType, OSFamily: osFamily, Description: section.description, Confidence: 0.84})
		}
	}
	if len(items) < 10 {
		return nil, fmt.Errorf("Fingerbank snapshot produced too few DHCP fingerprints: %d", len(items))
	}
	return json.Marshal(items)
}

func normalizeDHCPOptions(value string) string {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == ';' })
	return strings.Join(parts, ",")
}

func normalizeFingerbankClass(class, description string) (string, string) {
	text := strings.ToLower(class + " " + description)
	switch {
	case strings.Contains(text, "windows"):
		return "desktop", "Windows"
	case strings.Contains(text, "macintosh") || strings.Contains(text, "mac os"):
		return "desktop", "macOS"
	case strings.Contains(text, "smartphone") || strings.Contains(text, "android") || strings.Contains(text, "iphone"):
		return "mobile", firstMatching(text, map[string]string{"android": "Android", "iphone": "iOS"})
	case strings.Contains(text, "printer"):
		return "printer", ""
	case strings.Contains(text, "router") || strings.Contains(text, "switch") || strings.Contains(text, "network"):
		return "network", ""
	case strings.Contains(text, "audio") || strings.Contains(text, "video"):
		return "media", ""
	case strings.Contains(text, "linux"):
		return "desktop", "Linux"
	case strings.Contains(text, "bsd"):
		return "desktop", "BSD"
	default:
		return "", ""
	}
}

func firstMatching(value string, candidates map[string]string) string {
	for needle, result := range candidates {
		if strings.Contains(value, needle) {
			return result
		}
	}
	return ""
}
