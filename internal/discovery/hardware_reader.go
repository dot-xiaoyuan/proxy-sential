package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

func indexedTypesProjection(v2 bool) string {
	if !v2 {
		return "SELECT *," + indexedEffectiveTypesSQL + " effective_types FROM candidate_grouped"
	}
	return `SELECT g.*,CASE WHEN h.hardware_type_status='identified' THEN ARRAY[h.hardware_type] ELSE '{}'::text[] END effective_types,
 h.hardware_type projection_type,h.hardware_type_status projection_status,h.first_seen projection_first_seen,h.type_changed_at,h.address_only_since
 FROM candidate_grouped g LEFT JOIN passive_hardware_current h USING(identity_key)`
}
func indexedClassificationProjection(v2 bool) string {
	if !v2 {
		return indexedClassificationStateSQL
	}
	return `CASE WHEN projection_status='revoked' THEN 'expired' ELSE coalesce(projection_status,'candidate') END`
}
func hardwareReviewPredicate(reason string, at ...string) (string, error) {
	clock := "now()"
	if len(at) > 0 {
		clock = at[0] + "::timestamptz"
	}
	switch reason {
	case "":
		return "", nil
	case "conflict":
		return "classification_status='conflict'", nil
	case "new_priority":
		return `classification_status='identified' AND effective_types[1] IN ('printer','camera','recorder','access_control','voip_phone','environment_monitor','ups','pdu') AND projection_first_seen>=` + clock + `-interval '7 days' AND projection_first_seen<=` + clock, nil
	case "type_change":
		return `type_changed_at>=` + clock + `-interval '7 days' AND type_changed_at<=` + clock, nil
	case "address_only":
		return `classification_status='candidate' AND address_only_since<=` + clock + `-interval '7 days'`, nil
	default:
		return "", fmt.Errorf("invalid discovery review reason")
	}
}

func attachHardwareCurrent(ctx context.Context, db indexedQueryer, items []DeviceView, now time.Time) error {
	if len(items) == 0 {
		return nil
	}
	keys := make([]string, 0, len(items))
	for _, item := range items {
		keys = append(keys, item.indexedIdentityKey)
	}
	rows, err := db.QueryContext(ctx, `SELECT identity_key,data FROM passive_hardware_current WHERE identity_key=ANY($1::text[])`, keys)
	if err != nil {
		return err
	}
	defer rows.Close()
	current := map[string]HardwareState{}
	for rows.Next() {
		var key string
		var raw []byte
		var s HardwareState
		if err = rows.Scan(&key, &raw); err != nil {
			return err
		}
		if err = json.Unmarshal(raw, &s); err != nil {
			return err
		}
		current[key] = s
	}
	if err = rows.Err(); err != nil {
		return err
	}
	for i := range items {
		v := &items[i]
		s, ok := current[v.indexedIdentityKey]
		v.HardwareDetails = HardwareDetails{HardwareTypeStatus: "candidate", ClassificationVersion: "passive-hardware/v2", ActivityStatus: "stale"}
		if v.Current {
			v.ActivityStatus = "active"
		}
		v.DeviceType = ""
		v.ModelName = ""
		v.LastDeviceType = ""
		v.LastProductType = ""
		v.LastProductAt = nil
		v.ClassificationStatus = "candidate"
		v.Category = "identity_only"
		if !ok {
			continue
		}
		v.HardwareDetails = s.HardwareDetails
		v.ActivityStatus = "stale"
		if s.ActiveUntil.After(now) {
			v.ActivityStatus = "active"
		}
		v.FirstSeen = s.FirstSeen
		v.reviewProjectionAt = s.TypeChangedAt
		v.ClassificationStatus = s.HardwareTypeStatus
		if s.HardwareTypeStatus == "identified" {
			v.DeviceType = s.HardwareType
			v.Category = deviceCategory(s.HardwareType)
			v.Confidence = "strong"
		}
		if s.HardwareTypeStatus == "revoked" {
			v.ClassificationStatus = "expired"
			v.LastDeviceType = s.HardwareType
		}
		if s.HardwareModelStatus != "conflict" {
			v.ModelName = s.HardwareModel
		}
		if s.Manufacturer != "" {
			v.Manufacturer = s.Manufacturer
		}
	}
	return nil
}
