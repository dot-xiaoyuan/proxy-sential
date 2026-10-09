package sharedaccess

import (
	"strconv"
	"strings"
)

// TTLPathFamily decodes our feature keys. The initial TTL is an estimate, not
// an operating-system or physical-device identity. Hop variation stays in the
// raw key but must not create another independent host family.
func TTLPathFamily(path string) (direction string, initial int, ok bool) {
	direction = "unknown"
	path = strings.TrimSpace(path)
	if strings.Contains(path, "=") {
		seen := map[string]bool{}
		for _, part := range strings.Split(path, ",") {
			key, value, found := strings.Cut(strings.TrimSpace(part), "=")
			if !found {
				return "", 0, false
			}
			if key != "initial" && key != "direction" {
				continue
			}
			if seen[key] {
				return "", 0, false
			}
			seen[key] = true
			if key == "initial" {
				number, err := strconv.Atoi(value)
				if err != nil {
					return "", 0, false
				}
				initial = number
			} else {
				direction = value
			}
		}
	} else if parts := strings.Split(path, ":"); len(parts) == 3 {
		direction = parts[0]
		number, err := strconv.Atoi(parts[1])
		if err != nil {
			return "", 0, false
		}
		initial = number
	} else {
		value, err := strconv.Atoi(path)
		if err != nil || value < 1 || value > 255 {
			return "", 0, false
		}
		for _, candidate := range []int{32, 64, 128, 255} {
			if value <= candidate {
				initial = candidate
				break
			}
		}
	}
	switch direction {
	case "out":
		direction = "outbound"
	case "in":
		direction = "inbound"
	case "unknown", "outbound", "inbound":
	default:
		return "", 0, false
	}
	switch initial {
	case 32, 64, 128, 255:
		return direction, initial, true
	default:
		return "", 0, false
	}
}

func ttlHostDiversity(paths []string) bool {
	byDirection := map[string]int{}
	for _, path := range paths {
		direction, initial, ok := TTLPathFamily(path)
		if !ok {
			continue
		}
		if previous, found := byDirection[direction]; found && previous != initial {
			return true
		}
		byDirection[direction] = initial
	}
	return false
}
