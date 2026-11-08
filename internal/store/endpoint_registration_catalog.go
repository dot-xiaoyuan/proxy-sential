package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type EndpointRegistrationQuery struct {
	Search, Status, DeviceType, OwnershipClass, MAC, Cursor string
	Limit                                                   int
}

type EndpointRegistrationRecord struct {
	EndpointID            string                      `json:"endpoint_id"`
	PrimaryMAC            string                      `json:"primary_mac"`
	RegistrationStatus    string                      `json:"registration_status"`
	OwnerAccount          string                      `json:"owner_account"`
	OwnerName             string                      `json:"owner_name"`
	OwnerDepartment       string                      `json:"owner_department"`
	AssetTag              string                      `json:"asset_tag"`
	OwnershipClass        string                      `json:"ownership_class"`
	RegistrationNote      string                      `json:"registration_note"`
	RegistrationUpdatedAt string                      `json:"registration_updated_at"`
	RegistrationUpdatedBy string                      `json:"registration_updated_by"`
	RegisteredAt          string                      `json:"registered_at"`
	LastSeen              string                      `json:"last_seen"`
	MergeStatus           string                      `json:"merge_status"`
	MergedIntoEndpointID  string                      `json:"merged_into_endpoint_id"`
	SplitFromEndpointID   string                      `json:"split_from_endpoint_id"`
	Source                string                      `json:"source"`
	RegistrationDetails   EndpointRegistrationDetails `json:"registration_details"`
}

type EndpointRegistrationPage struct {
	Items      []EndpointRegistrationRecord `json:"items"`
	NextCursor string                       `json:"next_cursor"`
	HasMore    bool                         `json:"has_more"`
	Limit      int                          `json:"limit"`
	AsOf       string                       `json:"as_of"`
}

type EndpointRegistrationMetadata struct {
	Total int    `json:"total"`
	AsOf  string `json:"as_of"`
}

type EndpointRegistrationCatalogReader interface {
	ListEndpointRegistrations(context.Context, EndpointRegistrationQuery) (EndpointRegistrationPage, error)
	EndpointRegistrationMetadata(context.Context, EndpointRegistrationQuery) (EndpointRegistrationMetadata, error)
}

type registrationCursor struct {
	Version    int    `json:"v"`
	Signature  string `json:"s"`
	EndpointID string `json:"id"`
}

func registrationQuerySignature(q EndpointRegistrationQuery) string {
	data, _ := json.Marshal([]string{q.Search, q.Status, q.DeviceType, q.OwnershipClass, q.MAC})
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func NormalizeEndpointRegistrationQuery(q EndpointRegistrationQuery) (EndpointRegistrationQuery, error) {
	q.Search = strings.TrimSpace(q.Search)
	q.Status = strings.TrimSpace(q.Status)
	q.DeviceType = strings.TrimSpace(q.DeviceType)
	q.OwnershipClass = strings.TrimSpace(q.OwnershipClass)
	if strings.TrimSpace(q.MAC) != "" {
		if q.MAC = validPassiveMAC(q.MAC); q.MAC == "" {
			return q, fmt.Errorf("invalid registration MAC")
		}
	} else {
		q.MAC = ""
	}
	if q.Limit == 0 {
		q.Limit = 20
	}
	if q.Limit < 1 || q.Limit > 200 {
		return q, fmt.Errorf("limit must be between 1 and 200")
	}
	if len([]rune(q.Search)) > 200 || len([]rune(q.DeviceType)) > 200 {
		return q, fmt.Errorf("registration search exceeds 200 characters")
	}
	switch q.Status {
	case "", "registered", "unregistered", "ignored", "retired":
	default:
		return q, fmt.Errorf("invalid registration status")
	}
	switch q.OwnershipClass {
	case "", "unknown", "byod", "school_asset", "public_terminal", "infrastructure":
	default:
		return q, fmt.Errorf("invalid ownership class")
	}
	if q.Cursor != "" {
		if len(q.Cursor) > 4096 {
			return q, fmt.Errorf("invalid registration cursor")
		}
		if _, err := decodeRegistrationCursor(q); err != nil {
			return q, err
		}
	}
	return q, nil
}

func encodeRegistrationCursor(q EndpointRegistrationQuery, endpointID string) string {
	raw, _ := json.Marshal(registrationCursor{Version: 1, Signature: registrationQuerySignature(q), EndpointID: endpointID})
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeRegistrationCursor(q EndpointRegistrationQuery) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(q.Cursor)
	var cursor registrationCursor
	if err != nil || json.Unmarshal(raw, &cursor) != nil || cursor.Version != 1 || cursor.EndpointID == "" || len(cursor.EndpointID) > 512 || cursor.Signature != registrationQuerySignature(q) {
		return "", fmt.Errorf("registration cursor does not match query")
	}
	return cursor.EndpointID, nil
}

// Registration catalog reads current operator-maintained facts only. It does
// not rebuild identities, scan historical evidence, or resolve registered IPs
// into observed addresses. Primary-key pagination bounds each returned page.
func registrationCatalogWhere(q EndpointRegistrationQuery) (string, []any) {
	where := []string{"entity_role='endpoint'", "registration_updated_at IS NOT NULL"}
	args := []any{}
	add := func(v any) string { args = append(args, v); return fmt.Sprintf("$%d", len(args)) }
	if q.Status != "" {
		where = append(where, "registration_status="+add(q.Status))
	}
	if q.DeviceType != "" {
		where = append(where, "attributes->'manual_registration'->>'device_type'="+add(q.DeviceType))
	}
	if q.OwnershipClass != "" {
		where = append(where, "ownership_class="+add(q.OwnershipClass))
	}
	if q.MAC != "" {
		where = append(where, "primary_mac="+add(q.MAC))
	}
	if q.Search != "" {
		pattern := "%" + strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(strings.ToLower(q.Search)) + "%"
		where = append(where, `lower(concat_ws(' ',primary_mac,owner_account,owner_name,owner_department,asset_tag,attributes->'manual_registration'->>'name',attributes->'manual_registration'->>'registered_ip',attributes->'manual_registration'->>'serial_number',attributes->'manual_registration'->>'location')) LIKE `+add(pattern)+` ESCAPE '\'`)
	}
	return strings.Join(where, " AND "), args
}

func (s *PostgresStore) ListEndpointRegistrations(ctx context.Context, query EndpointRegistrationQuery) (EndpointRegistrationPage, error) {
	q, err := NormalizeEndpointRegistrationQuery(query)
	page := EndpointRegistrationPage{Items: []EndpointRegistrationRecord{}, Limit: q.Limit, AsOf: time.Now().UTC().Format(time.RFC3339Nano)}
	if err != nil {
		return page, err
	}
	where, args := registrationCatalogWhere(q)
	if q.Cursor != "" {
		id, _ := decodeRegistrationCursor(q)
		args = append(args, id)
		where += fmt.Sprintf(" AND endpoint_id>$%d", len(args))
	}
	args = append(args, q.Limit+1)
	rows, err := s.db.QueryContext(ctx, `SELECT endpoint_id,coalesce(primary_mac,''),registration_status,
coalesce(owner_account,''),coalesce(owner_name,''),coalesce(owner_department,''),coalesce(asset_tag,''),ownership_class,
coalesce(registration_note,''),registration_updated_at,coalesce(registration_updated_by,''),registered_at,last_seen,
merge_status,coalesce(merged_into_endpoint_id,''),coalesce(split_from_endpoint_id,''),
coalesce(attributes->'manual_registration','{}'::jsonb)
FROM endpoint_entities WHERE `+where+fmt.Sprintf(" ORDER BY endpoint_id LIMIT $%d", len(args)), args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var item EndpointRegistrationRecord
		var updated, registered, lastSeen sql.NullTime
		var details []byte
		if err = rows.Scan(&item.EndpointID, &item.PrimaryMAC, &item.RegistrationStatus, &item.OwnerAccount, &item.OwnerName, &item.OwnerDepartment, &item.AssetTag, &item.OwnershipClass, &item.RegistrationNote, &updated, &item.RegistrationUpdatedBy, &registered, &lastSeen, &item.MergeStatus, &item.MergedIntoEndpointID, &item.SplitFromEndpointID, &details); err != nil {
			return page, err
		}
		if err = json.Unmarshal(details, &item.RegistrationDetails); err != nil {
			return page, err
		}
		if updated.Valid {
			item.RegistrationUpdatedAt = updated.Time.UTC().Format(time.RFC3339Nano)
		}
		if registered.Valid {
			item.RegisteredAt = registered.Time.UTC().Format(time.RFC3339Nano)
		}
		if lastSeen.Valid {
			item.LastSeen = lastSeen.Time.UTC().Format(time.RFC3339Nano)
		}
		item.Source = "local"
		page.Items = append(page.Items, item)
	}
	if err = rows.Err(); err != nil {
		return page, err
	}
	page.HasMore = len(page.Items) > q.Limit
	if page.HasMore {
		page.Items = page.Items[:q.Limit]
		page.NextCursor = encodeRegistrationCursor(q, page.Items[len(page.Items)-1].EndpointID)
	}
	return page, nil
}

// Counts are independently requested and never force the cursor list to load
// all rows or historical observations. Both endpoints read the same filters.
func (s *PostgresStore) EndpointRegistrationMetadata(ctx context.Context, query EndpointRegistrationQuery) (EndpointRegistrationMetadata, error) {
	query.Cursor = ""
	q, err := NormalizeEndpointRegistrationQuery(query)
	result := EndpointRegistrationMetadata{AsOf: time.Now().UTC().Format(time.RFC3339Nano)}
	if err != nil {
		return result, err
	}
	where, args := registrationCatalogWhere(q)
	err = s.db.QueryRowContext(ctx, "SELECT count(*) FROM endpoint_entities WHERE "+where, args...).Scan(&result.Total)
	return result, err
}

func (s *DBStore) ListEndpointRegistrations(ctx context.Context, q EndpointRegistrationQuery) (EndpointRegistrationPage, error) {
	return s.pg.ListEndpointRegistrations(ctx, q)
}
func (s *DBStore) EndpointRegistrationMetadata(ctx context.Context, q EndpointRegistrationQuery) (EndpointRegistrationMetadata, error) {
	return s.pg.EndpointRegistrationMetadata(ctx, q)
}
