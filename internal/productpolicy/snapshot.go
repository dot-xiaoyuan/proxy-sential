package productpolicy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const SchemaVersion = "srun-business-policy/v1"

type Product struct {
	ID         string   `json:"product_id"`
	Name       string   `json:"name"`
	Manager    string   `json:"manager,omitempty"`
	ControlIDs []string `json:"control_ids"`
}

type Control struct {
	ID               string            `json:"control_id"`
	Name             string            `json:"name"`
	MaxOnlineNum     int               `json:"max_online_num"`
	DisableProxy     int               `json:"disable_proxy"`
	ProxyTimes       int               `json:"proxy_times"`
	ProxyDisableTime int               `json:"proxy_disable_time"`
	Reference        map[string]string `json:"reference,omitempty"`
}

// AntiProxyProfile is optional. It is intentionally separate from the 4K
// control strategy because concurrent authentication sessions and independently
// identified devices are different business facts.
type AntiProxyProfile struct {
	ExternalID      string   `json:"external_id"`
	Name            string   `json:"name"`
	TargetType      string   `json:"target_type"`
	TargetIDs       []string `json:"target_ids"`
	Total           *int     `json:"total,omitempty"`
	Mobile          *int     `json:"mobile,omitempty"`
	PC              *int     `json:"pc,omitempty"`
	CooldownSeconds int      `json:"cooldown_seconds,omitempty"`
	Unsupported     []string `json:"unsupported,omitempty"`
}

type Snapshot struct {
	SchemaVersion     string             `json:"schema_version"`
	Source            string             `json:"source"`
	InstanceID        string             `json:"instance_id"`
	ObservedAt        time.Time          `json:"observed_at"`
	Complete          bool               `json:"complete"`
	Products          []Product          `json:"products"`
	Controls          []Control          `json:"controls"`
	AntiProxyProfiles []AntiProxyProfile `json:"anti_proxy_profiles,omitempty"`
	ContentHash       string             `json:"content_hash"`
}

func (s *Snapshot) NormalizeAndValidate(now time.Time) error {
	if err := s.validateVolume(); err != nil {
		return err
	}
	if s.SchemaVersion != SchemaVersion || strings.TrimSpace(s.Source) != s.Source || s.Source == "" || len(s.Source) > 200 || strings.TrimSpace(s.InstanceID) == "" || !s.Complete {
		return fmt.Errorf("complete %s snapshot with source and instance_id required", SchemaVersion)
	}
	if s.ObservedAt.IsZero() || s.ObservedAt.After(now.Add(time.Second)) || s.ObservedAt.Before(now.Add(-7*24*time.Hour)) || s.ObservedAt.Nanosecond()%1000 != 0 {
		return fmt.Errorf("observed_at must be within seven days and microsecond aligned")
	}
	if len(s.Products) > 10000 || len(s.Controls) > 10000 || len(s.AntiProxyProfiles) > 10000 {
		return fmt.Errorf("snapshot exceeds bounded catalog size")
	}
	productIDs := map[string]bool{}
	for i := range s.Products {
		p := &s.Products[i]
		p.ID, p.Name, p.Manager = strings.TrimSpace(p.ID), strings.TrimSpace(p.Name), strings.TrimSpace(p.Manager)
		if p.ID == "" || p.Name == "" || productIDs[p.ID] || len(p.ID) > 200 || len(p.Name) > 500 {
			return fmt.Errorf("invalid or duplicate product")
		}
		productIDs[p.ID] = true
		p.ControlIDs = normalizedIDs(p.ControlIDs)
	}
	controlIDs := map[string]bool{}
	for i := range s.Controls {
		c := &s.Controls[i]
		c.ID, c.Name = strings.TrimSpace(c.ID), strings.TrimSpace(c.Name)
		if c.ID == "" || c.Name == "" || controlIDs[c.ID] || len(c.ID) > 200 || len(c.Name) > 500 || c.DisableProxy < 0 || c.ProxyTimes < 0 || c.ProxyDisableTime < 0 {
			return fmt.Errorf("invalid or duplicate control")
		}
		if len(c.Reference) > 256 {
			return fmt.Errorf("control reference exceeds bounded field count")
		}
		for key, value := range c.Reference {
			trimmed := strings.TrimSpace(key)
			if trimmed == "" || trimmed != key || len(key) > 200 || len(value) > 10000 {
				return fmt.Errorf("invalid control reference")
			}
		}
		controlIDs[c.ID] = true
	}
	for _, p := range s.Products {
		for _, id := range p.ControlIDs {
			if !controlIDs[id] {
				return fmt.Errorf("product %s references missing control %s", p.ID, id)
			}
		}
	}
	profileIDs := map[string]bool{}
	for i := range s.AntiProxyProfiles {
		p := &s.AntiProxyProfiles[i]
		p.ExternalID, p.Name, p.TargetType = strings.TrimSpace(p.ExternalID), strings.TrimSpace(p.Name), strings.TrimSpace(p.TargetType)
		p.TargetIDs = normalizedIDs(p.TargetIDs)
		p.Unsupported = normalizedIDs(p.Unsupported)
		if p.ExternalID == "" || p.Name == "" || profileIDs[p.ExternalID] || (p.TargetType != "product" && p.TargetType != "group") || len(p.TargetIDs) == 0 || p.CooldownSeconds < 0 {
			return fmt.Errorf("invalid anti-proxy profile")
		}
		for _, limit := range []*int{p.Total, p.Mobile, p.PC} {
			if limit != nil && *limit < 0 {
				return fmt.Errorf("negative anti-proxy quota")
			}
		}
		profileIDs[p.ExternalID] = true
	}
	sort.Slice(s.Products, func(i, j int) bool { return s.Products[i].ID < s.Products[j].ID })
	sort.Slice(s.Controls, func(i, j int) bool { return s.Controls[i].ID < s.Controls[j].ID })
	sort.Slice(s.AntiProxyProfiles, func(i, j int) bool { return s.AntiProxyProfiles[i].ExternalID < s.AntiProxyProfiles[j].ExternalID })
	canonical := *s
	canonical.ContentHash = ""
	raw, err := json.Marshal(canonical)
	if err != nil {
		return err
	}
	// Replacing the empty canonical content_hash with its hex digest adds 64
	// bytes to the transmitted document, which must fit the same HTTP bound.
	if len(raw) > MaxSnapshotBytes-sha256.Size*2 {
		return ErrCatalogResourceLimit
	}
	sum := sha256.Sum256(raw)
	want := hex.EncodeToString(sum[:])
	if s.ContentHash != "" && !strings.EqualFold(s.ContentHash, want) {
		return fmt.Errorf("content_hash mismatch")
	}
	s.ContentHash = want
	return nil
}

func (s Snapshot) Hash() (string, error) {
	s.ContentHash = ""
	raw, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func normalizedIDs(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func parseNonNegative(raw any, field string) (int, error) {
	if raw == nil || raw == "" {
		return 0, nil
	}
	value, ok := raw.(string)
	if !ok {
		return 0, fmt.Errorf("invalid %s", field)
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid %s", field)
	}
	return n, nil
}

func parseInteger(raw any, field string) (int, error) {
	if raw == nil || raw == "" {
		return 0, nil
	}
	value, ok := raw.(string)
	if !ok {
		return 0, fmt.Errorf("invalid %s", field)
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s", field)
	}
	return n, nil
}

// ErrRedisCatalogChanged identifies a retryable observation conflict, rather
// than failed source connectivity. No partial catalog may be published.
var ErrRedisCatalogChanged = errors.New("Redis catalog membership or relations changed; retry entire snapshot")

func validateCatalogMembers(ids []string) error {
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if len(id) > 200 {
			return ErrCatalogResourceLimit
		}
		if id == "" || strings.TrimSpace(id) != id || len(id) > 200 {
			return fmt.Errorf("invalid catalog list member")
		}
		if _, duplicate := seen[id]; duplicate {
			return fmt.Errorf("duplicate catalog list member")
		}
		seen[id] = struct{}{}
	}
	return nil
}

// ReadRedisSnapshot reads only documented product/control keys. Membership and
// every product-to-control relation are re-read in one MULTI/EXEC; a concurrent
// change rejects the whole snapshot instead of emitting a partial catalog.
func ReadRedisSnapshot(ctx context.Context, client *RedisCatalogClient, source string, maxRecords int) (Snapshot, error) {
	if client == nil || client.Client == nil || !client.Client.Initialized() || strings.TrimSpace(source) == "" || strings.TrimSpace(source) != source || len(source) > 200 || maxRecords < 1 || maxRecords > 10000 {
		return Snapshot{}, fmt.Errorf("redis client, source and bound required")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	endRead, err := client.BeginRead(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	defer endRead()
	products, err := client.LRange(ctx, "list:products", 0, int64(maxRecords)).Result()
	if err != nil {
		return Snapshot{}, err
	}
	controls, err := client.LRange(ctx, "list:control", 0, int64(maxRecords)).Result()
	if err != nil {
		return Snapshot{}, err
	}
	if len(products) > maxRecords || len(controls) > maxRecords {
		return Snapshot{}, ErrCatalogResourceLimit
	}
	if err := validateCatalogMembers(products); err != nil {
		return Snapshot{}, err
	}
	if err := validateCatalogMembers(controls); err != nil {
		return Snapshot{}, err
	}
	preLinks := make(map[string][]string, len(products))
	// Count the whole relation volume before downloading it. Read exactly the
	// counted length plus one sentinel, so growth cannot expand a final reply
	// to maxRecords for every product. The final transaction rechecks lengths
	// and contents together with the hashes.
	counts := make(map[string]*redis.IntCmd, len(products))
	pipe := client.Pipeline()
	for _, id := range products {
		counts[id] = pipe.LLen(ctx, "list:products:control:"+id)
	}
	if _, err = pipe.Exec(ctx); err != nil {
		return Snapshot{}, err
	}
	totalRelations := int64(0)
	for _, id := range products {
		count := counts[id].Val()
		if count < 0 {
			return Snapshot{}, fmt.Errorf("invalid control relation length")
		}
		if count > int64(maxRecords) || count > MaxCatalogRelations-totalRelations {
			return Snapshot{}, ErrCatalogResourceLimit
		}
		totalRelations += count
	}
	linkCommands := make(map[string]*redis.StringSliceCmd, len(products))
	pipe = client.Pipeline()
	for _, id := range products {
		linkCommands[id] = pipe.LRange(ctx, "list:products:control:"+id, 0, counts[id].Val())
	}
	if _, err = pipe.Exec(ctx); err != nil && err != redis.Nil {
		return Snapshot{}, err
	}
	controlSet := map[string]bool{}
	for _, id := range controls {
		controlSet[id] = true
	}
	for _, id := range products {
		preLinks[id] = linkCommands[id].Val()
		if int64(len(preLinks[id])) != counts[id].Val() {
			return Snapshot{}, ErrRedisCatalogChanged
		}
		for _, controlID := range preLinks[id] {
			if len(controlID) > 200 {
				return Snapshot{}, ErrCatalogResourceLimit
			}
			if controlID == "" || strings.TrimSpace(controlID) != controlID || len(controlID) > 200 {
				return Snapshot{}, fmt.Errorf("invalid control relation member")
			}
			// Repeated references retain their existing set semantics. Unlike
			// duplicate catalog members, they identify the same association.
			controlSet[controlID] = true
			if len(controlSet) > maxRecords {
				return Snapshot{}, ErrCatalogResourceLimit
			}
		}
	}
	allControls := make([]string, 0, len(controlSet))
	for id := range controlSet {
		allControls = append(allControls, id)
	}
	sort.Strings(allControls)

	var currentProducts, currentControls *redis.StringSliceCmd
	var info *redis.StringCmd
	var observed *redis.TimeCmd
	productRows := map[string]*redis.SliceCmd{}
	controlRows := map[string]*redis.MapStringStringCmd{}
	currentLinks := map[string]*redis.StringSliceCmd{}
	_, err = client.TxPipelined(ctx, func(tx redis.Pipeliner) error {
		// Timestamp the atomic observation before its reads, conservatively
		// covering values that may expire while the transaction is processed.
		observed = tx.Time(ctx)
		currentProducts = tx.LRange(ctx, "list:products", 0, int64(len(products)))
		currentControls = tx.LRange(ctx, "list:control", 0, int64(len(controls)))
		for _, id := range products {
			productRows[id] = tx.HMGet(ctx, "hash:products:"+id, "products_id", "products_name", "mgr_name")
			currentLinks[id] = tx.LRange(ctx, "list:products:control:"+id, 0, int64(len(preLinks[id])))
		}
		for _, id := range allControls {
			controlRows[id] = tx.HGetAll(ctx, "hash:control:"+id)
		}
		info = tx.Info(ctx, "server")
		return ctx.Err()
	})
	if err != nil {
		return Snapshot{}, err
	}
	if !equalStrings(products, currentProducts.Val()) || !equalStrings(controls, currentControls.Val()) {
		return Snapshot{}, ErrRedisCatalogChanged
	}
	for _, id := range products {
		if !equalStrings(preLinks[id], currentLinks[id].Val()) {
			return Snapshot{}, ErrRedisCatalogChanged
		}
	}
	instance := ""
	for _, line := range strings.Split(info.Val(), "\n") {
		if strings.HasPrefix(line, "run_id:") {
			instance = strings.TrimSpace(strings.TrimPrefix(line, "run_id:"))
		}
	}
	if instance == "" {
		return Snapshot{}, fmt.Errorf("redis source instance unavailable")
	}
	snapshot := Snapshot{SchemaVersion: SchemaVersion, Source: source, InstanceID: instance, ObservedAt: observed.Val().UTC().Truncate(time.Microsecond), Complete: true, Products: []Product{}, Controls: []Control{}}
	for _, id := range products {
		values := productRows[id].Val()
		stringAt := func(index int) string { value, _ := values[index].(string); return value }
		storedID, name, manager := stringAt(0), stringAt(1), stringAt(2)
		if storedID != "" && storedID != id {
			return Snapshot{}, fmt.Errorf("product identity differs from list")
		}
		snapshot.Products = append(snapshot.Products, Product{ID: id, Name: name, Manager: manager, ControlIDs: append([]string{}, preLinks[id]...)})
	}
	for _, id := range allControls {
		values := controlRows[id].Val()
		if len(values) > 256+6 {
			return Snapshot{}, ErrCatalogResourceLimit
		}
		storedID, name := values["control_id"], values["control_name"]
		if storedID != "" && storedID != id {
			return Snapshot{}, fmt.Errorf("control identity differs from list")
		}
		maxOnline, e := parseInteger(values["max_online_num"], "max_online_num")
		if e != nil {
			return Snapshot{}, e
		}
		disableProxy, e := parseNonNegative(values["disable_proxy"], "disable_proxy")
		if e != nil {
			return Snapshot{}, e
		}
		proxyTimes, e := parseNonNegative(values["proxy_times"], "proxy_times")
		if e != nil {
			return Snapshot{}, e
		}
		proxyDisableTime, e := parseNonNegative(values["proxy_disable_time"], "proxy_disable_time")
		if e != nil {
			return Snapshot{}, e
		}
		reference := map[string]string{}
		for key, value := range values {
			switch key {
			case "control_id", "control_name", "max_online_num", "disable_proxy", "proxy_times", "proxy_disable_time":
			default:
				reference[key] = value
			}
		}
		snapshot.Controls = append(snapshot.Controls, Control{ID: id, Name: name, MaxOnlineNum: maxOnline, DisableProxy: disableProxy, ProxyTimes: proxyTimes, ProxyDisableTime: proxyDisableTime, Reference: reference})
	}
	if err = snapshot.NormalizeAndValidate(time.Now().UTC()); err != nil {
		return Snapshot{}, err
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
