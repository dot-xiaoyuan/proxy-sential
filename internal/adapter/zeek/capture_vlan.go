package zeek

import (
	"fmt"
	"strconv"
	"strings"
)

// The VLAN-aware conn key logs tags under id.ctx rather than vlan. Retain
// both tags in order; conflicting encodings must never silently select one.
func retainConnectionVLAN(fields map[string]string) error {
	outer, inner := first(fields, "id.ctx.vlan"), first(fields, "id.ctx.inner_vlan")
	if outer == "" && inner == "" {
		if capture := first(fields, "capture_vlan"); capture != "" {
			parts := strings.Split(capture, "/")
			if len(parts) > 2 {
				return fmt.Errorf("invalid capture VLAN depth")
			}
			for _, part := range parts {
				n, err := strconv.Atoi(part)
				if err != nil || n < 0 || n > 4094 {
					return fmt.Errorf("invalid capture VLAN")
				}
			}
			if existing := first(fields, "vlan"); existing != "" && existing != capture {
				return fmt.Errorf("conflicting capture VLAN")
			}
			fields["vlan"] = capture
		}
		return nil
	}
	if outer == "" {
		return fmt.Errorf("inner connection VLAN without outer VLAN")
	}
	for _, value := range []string{outer, inner} {
		if value == "" {
			continue
		}
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 || n > 4094 {
			return fmt.Errorf("invalid connection VLAN")
		}
	}
	vlan := outer
	if inner != "" {
		vlan += "/" + inner
	}
	if existing := first(fields, "vlan", "capture_vlan"); existing != "" && existing != vlan {
		return fmt.Errorf("conflicting capture and connection VLAN")
	}
	fields["vlan"] = vlan
	return nil
}
