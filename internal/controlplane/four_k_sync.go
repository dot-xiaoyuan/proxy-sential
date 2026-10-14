package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/store"
)

const defaultFourKSource = "srun-office"

type fourKDirectoryItem struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	// ParentID and Path are set for the northbound group directory, which is a
	// tree. Groups observed only in identity events carry neither, and the UI
	// must say so rather than present a bare id as a complete entry.
	ParentID string `json:"parent_id,omitempty"`
	Path     string `json:"path,omitempty"`
}

type fourKDirectory struct {
	Source             string               `json:"source"`
	Products           []fourKDirectoryItem `json:"products"`
	Groups             []fourKDirectoryItem `json:"groups"`
	Accounts           []fourKDirectoryItem `json:"accounts"`
	VLANs              []fourKDirectoryItem `json:"vlans"`
	ProductObservedAt  *time.Time           `json:"product_observed_at,omitempty"`
	IdentityObservedAt *time.Time           `json:"identity_observed_at,omitempty"`
	IdentitySessions   int                  `json:"identity_sessions"`
	Controls           int                  `json:"controls"`
	// Warnings explains an empty selector. A blank list otherwise cannot be told
	// apart from a failed directory read.
	Warnings []string `json:"warnings,omitempty"`
}

func fourKSyncPath(path string) (string, bool) {
	path = strings.TrimPrefix(path, "/api/v1")
	parts := strings.Split(strings.Trim(strings.TrimPrefix(path, "/actions/"), "/"), "/")
	if len(parts) == 3 && parts[0] == "connectors" && parts[2] == "4k-sync" {
		return parts[1], true
	}
	return "", false
}

func stringValue(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return strings.TrimSpace(value)
}

func fourKIdentityDirectory(snapshot store.IdentitySnapshot) (accounts, groups, vlans []fourKDirectoryItem) {
	accounts, groups, vlans = []fourKDirectoryItem{}, []fourKDirectoryItem{}, []fourKDirectoryItem{}
	accountSet, groupSet, vlanSet := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, event := range snapshot.Events {
		if value := stringValue(event.Subject, "account_id"); value != "" {
			accountSet[value] = true
		}
		if value := stringValue(event.Payload, "group_id"); value != "" {
			groupSet[value] = true
		}
		if value := stringValue(event.Payload, "vlan"); value != "" {
			vlanSet[value] = true
		}
	}
	for value := range accountSet {
		accounts = append(accounts, fourKDirectoryItem{ID: value})
	}
	for value := range groupSet {
		groups = append(groups, fourKDirectoryItem{ID: value})
	}
	for value := range vlanSet {
		vlans = append(vlans, fourKDirectoryItem{ID: value})
	}
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].ID < accounts[j].ID })
	sort.Slice(groups, func(i, j int) bool { return groups[i].ID < groups[j].ID })
	sort.Slice(vlans, func(i, j int) bool { return vlans[i].ID < vlans[j].ID })
	return accounts, groups, vlans
}

// loadFourKDirectory joins read-only 4K product and identity snapshots. It does
// not translate product control rows into Sentinel strategies or actions: just
// like dpi-analyze, those snapshots only supply match-directory information.
func loadFourKDirectory(ctx context.Context, db *sql.DB, source string) (fourKDirectory, error) {
	return loadFourKDirectoryCatalogScope(ctx, db, source, "")
}

func loadFourKDirectoryCatalogScope(ctx context.Context, db *sql.DB, source, catalogPrefix string) (fourKDirectory, error) {
	return loadFourKDirectoryWithGroupSource(ctx, db, source, catalogPrefix, source)
}

func managedGroupCatalogSource(source string, version int64) string {
	if source == "" || version < 1 {
		return ""
	}
	return fmt.Sprintf("%s:bridge-v%d", source, version)
}

func loadFourKDirectoryWithGroupSource(ctx context.Context, db *sql.DB, source, catalogPrefix, groupSource string) (fourKDirectory, error) {
	directory := fourKDirectory{Source: source, Products: []fourKDirectoryItem{}, Groups: []fourKDirectoryItem{}, Accounts: []fourKDirectoryItem{}, VLANs: []fourKDirectoryItem{}}
	rows, err := db.QueryContext(ctx, `SELECT product_id,name FROM product_catalog WHERE source=$1 AND active AND ($2='' OR snapshot_id LIKE $2) ORDER BY name,product_id`, source, catalogPrefix)
	if err != nil {
		return directory, err
	}
	for rows.Next() {
		var item fourKDirectoryItem
		if err = rows.Scan(&item.ID, &item.Name); err != nil {
			rows.Close()
			return directory, err
		}
		directory.Products = append(directory.Products, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return directory, err
	}
	rows.Close()

	var productObserved time.Time
	err = db.QueryRowContext(ctx, `SELECT observed_at,(SELECT count(*) FROM product_control_catalog WHERE source=$1 AND active AND ($2='' OR snapshot_id LIKE $2)) FROM product_policy_snapshots WHERE source=$1 AND ($2='' OR snapshot_id LIKE $2) ORDER BY observed_at DESC,received_at DESC LIMIT 1`, source, catalogPrefix).Scan(&productObserved, &directory.Controls)
	if err != nil && err != sql.ErrNoRows {
		return directory, err
	}
	if err == nil {
		directory.ProductObservedAt = &productObserved
	}

	// Only scalar columns are read here. The snapshot document is the entire
	// online inventory — tens of thousands of events and several megabytes — so
	// deserializing it to build a selector list made every directory request
	// unusably slow on a production-sized site. The compact group directory is
	// maintained when the snapshot is committed instead.
	var identityObserved time.Time
	err = db.QueryRowContext(ctx, `SELECT observed_at,session_count FROM identity_full_snapshots WHERE source=$1 ORDER BY observed_at DESC,received_at DESC LIMIT 1`, source).Scan(&identityObserved, &directory.IdentitySessions)
	if err != nil && err != sql.ErrNoRows {
		return directory, err
	}
	if err == nil {
		directory.IdentityObservedAt = &identityObserved
	}

	directory.Groups, err = loadGroupDirectory(ctx, db, source, groupSource)
	if err != nil {
		return directory, err
	}
	return directory, nil
}

// loadGroupDirectory merges the named northbound group tree with the groups that
// identity snapshots observed online. Both are keyed by group id. The named,
// parented entry from the northbound catalog always wins: identity only ever
// knows an id, and losing a name or a parent to a weaker observation would make
// the selector show a bare number for a group that has a real name.
func loadGroupDirectory(ctx context.Context, db *sql.DB, source, groupSource string) ([]fourKDirectoryItem, error) {
	rows, err := db.QueryContext(ctx, `SELECT group_id,name,parent_id,path FROM srun4k_group_catalog WHERE active AND source IN ($1,$2,$3) ORDER BY group_id`,
		identityGroupCatalogSource(source), groupSource, source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type groupEntry struct{ name, parentID, path string }
	entries := map[string]groupEntry{}
	strength := func(entry groupEntry) int {
		score := 0
		if entry.name != "" {
			score += 2
		}
		if entry.parentID != "" || entry.path != "" {
			score++
		}
		return score
	}
	for rows.Next() {
		var id string
		var entry groupEntry
		if err = rows.Scan(&id, &entry.name, &entry.parentID, &entry.path); err != nil {
			return nil, err
		}
		if id == "" {
			continue
		}
		existing, ok := entries[id]
		if !ok || strength(entry) > strength(existing) {
			entries[id] = entry
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	items := make([]fourKDirectoryItem, 0, len(entries))
	for id, entry := range entries {
		items = append(items, fourKDirectoryItem{ID: id, Name: entry.name, ParentID: entry.parentID, Path: entry.path})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Name != items[j].Name {
			return items[i].Name < items[j].Name
		}
		return items[i].ID < items[j].ID
	})
	return items, nil
}

// identityGroupCatalogSource namespaces the groups observed in identity
// snapshots. Identity only knows which groups are online, never the complete
// northbound directory, so its entries live under their own key and can never
// deactivate or blank a named catalog.
func identityGroupCatalogSource(source string) string {
	if source == "" {
		return ""
	}
	return source + ":identity-observed"
}

func (s *Server) handle4KDirectory(w http.ResponseWriter, r *http.Request) {
	if s.productPolicies == nil || s.productPolicies.db == nil {
		writeError(w, http.StatusServiceUnavailable, "four_k_directory_unavailable", "4K目录存储不可用")
		return
	}
	source := strings.TrimSpace(r.URL.Query().Get("source"))
	if source == "" {
		var err error
		source, err = s.fourKDirectorySource(r.Context())
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "four_k_source_unavailable", "4K目录来源读取失败")
			return
		}
	}
	catalogPrefix := ""
	groupSource := source
	if source == s.identityBridge.normalized().Source {
		var version int64
		err := s.operations.db.QueryRowContext(r.Context(), `SELECT active_config_version FROM identity_bridge_runtime WHERE bridge_id=$1 AND active_config_version>0`, s.identityBridge.normalized().BridgeID).Scan(&version)
		if err != nil && err != sql.ErrNoRows {
			writeError(w, http.StatusServiceUnavailable, "four_k_source_unavailable", "4K目录来源读取失败")
			return
		}
		if err == nil {
			catalogPrefix = fmt.Sprintf("bridge-catalog-v%d-%%", version)
			groupSource = managedGroupCatalogSource(source, version)
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), fourKDirectoryTimeout)
	defer cancel()
	directory, err := loadFourKDirectoryWithGroupSource(ctx, s.productPolicies.db, source, catalogPrefix, groupSource)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "four_k_directory_failed", err.Error())
		return
	}
	directory.Warnings = directoryWarnings(directory)
	writeJSON(w, http.StatusOK, directory)
}

// fourKDirectoryTimeout bounds the selector read. The directory feeds a form
// dropdown, so it must never hold a request open.
const fourKDirectoryTimeout = 3 * time.Second

// directoryWarnings turns an empty selector into an actionable statement. The
// resolved source is always named, because "empty" is otherwise
// indistinguishable from "we looked somewhere that never had a catalog".
// Accounts and VLANs are free-text inputs, so their empty option lists are
// expected and are not reported.
func directoryWarnings(directory fourKDirectory) []string {
	warnings := []string{}
	if len(directory.Products) == 0 {
		warnings = append(warnings, fmt.Sprintf("来源 %s 没有可用产品目录，请到「认证与处置接入」执行 4K 目录同步", directory.Source))
	}
	if len(directory.Groups) == 0 {
		warnings = append(warnings, fmt.Sprintf("来源 %s 没有可用用户组目录，请在「认证与处置接入」执行 4K 目录同步；也可直接填写用户组标识", directory.Source))
	}
	return warnings
}

// fourKDirectorySource names the source whose product and group directory the
// scope selectors must show.
//
// Selection order matters. A configured identity bridge always wins, including
// while its runtime version is still 0 because no identity snapshot has
// completed yet: the bridge is what the site actually syncs from, and falling
// through to the placeholder source in that state rendered both selectors empty
// with no explanation, because the placeholder has no catalog at all.
func (s *Server) fourKDirectorySource(ctx context.Context) (string, error) {
	defaults := s.identityBridge.normalized()
	var configured bool
	if err := s.operations.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity_bridge_configs WHERE bridge_id=$1) OR EXISTS(SELECT 1 FROM identity_bridge_runtime WHERE bridge_id=$1 AND active_host<>'')`, defaults.BridgeID).Scan(&configured); err != nil {
		return "", err
	}
	if configured {
		return defaults.Source, nil
	}
	var source string
	err := s.operations.db.QueryRowContext(ctx, `SELECT source FROM srun4k_integrations ORDER BY updated_at DESC LIMIT 1`).Scan(&source)
	if err == sql.ErrNoRows {
		return defaultFourKSource, nil
	}
	return source, err
}

// handle4KSync validates the configured 4K execution channel and confirms that
// current product and identity directories are available. Actions remain part
// of an administrator-authored Sentinel policy; this endpoint never creates a
// policy, execution episode or enforcement action.
func (s *Server) handle4KSync(w http.ResponseWriter, r *http.Request, connectorID string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "仅支持同步4K目录")
		return
	}
	if s.productPolicies == nil || s.productPolicies.db == nil {
		writeError(w, http.StatusServiceUnavailable, "four_k_sync_storage_unavailable", "4K同步需要PostgreSQL存储")
		return
	}
	var request struct {
		Source string `json:"source"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "bad_four_k_sync", err.Error())
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeError(w, http.StatusBadRequest, "bad_four_k_sync", "请求体只能包含一个JSON对象")
		return
	}
	request.Source = strings.TrimSpace(request.Source)
	if request.Source == "" {
		request.Source = defaultFourKSource
	}

	doc := emptyOperationsDocument()
	if err := loadConnectorsScoped(r.Context(), s.productPolicies.db, &doc, ` WHERE connector_id=$1`, []any{connectorID}); err != nil {
		writeError(w, http.StatusServiceUnavailable, "four_k_connector_unavailable", err.Error())
		return
	}
	connector, ok := doc.Connectors[connectorID]
	if !ok {
		writeError(w, http.StatusNotFound, "connector_not_found", "4K连接器不存在")
		return
	}
	if connector.ConnectorType != "srun4k" || !connector.Enabled {
		writeError(w, http.StatusConflict, "native_connector_required", "请先启用原生4K连接器")
		return
	}
	onlineTotal, err := s.probeManaged4K(r.Context(), connector, nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "four_k_management_unavailable", err.Error())
		return
	}
	directory, err := loadFourKDirectory(r.Context(), s.productPolicies.db, request.Source)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "four_k_directory_failed", err.Error())
		return
	}
	if directory.ProductObservedAt == nil {
		writeError(w, http.StatusConflict, "four_k_product_sync_waiting", "4K产品采集器尚未提交完整快照")
		return
	}
	if time.Since(*directory.ProductObservedAt) > 3*time.Minute {
		writeError(w, http.StatusConflict, "four_k_product_snapshot_stale", "4K产品快照已中断，请先恢复采集器")
		return
	}
	if directory.IdentityObservedAt == nil {
		writeError(w, http.StatusConflict, "four_k_identity_sync_waiting", "4K用户身份采集器尚未提交完整快照")
		return
	}
	if time.Since(*directory.IdentityObservedAt) > 15*time.Second {
		writeError(w, http.StatusConflict, "four_k_identity_snapshot_stale", "4K用户身份快照已中断，请先恢复采集器")
		return
	}
	// This is capability registration, not an imported policy action. The only
	// native operation currently implemented with session revalidation is drop.
	// Keep the native capabilities registered by the managed integration.  A
	// directory sync must not narrow the connector back to disconnect-only,
	// otherwise the policy editor cannot bind the built-in notification and
	// SafeDisable actions after the next sync.
	if _, err = s.productPolicies.db.ExecContext(r.Context(), `UPDATE enforcement_connectors SET action_mapping=$2,updated_at=clock_timestamp() WHERE connector_id=$1`, connectorID, []byte(`{"account_policy_v1":"supported","session.disconnect":"online-drop","account.notify":"notification-outbox","account.disable_account":"safe-disable"}`)); err != nil {
		writeError(w, http.StatusServiceUnavailable, "four_k_capability_save_failed", err.Error())
		return
	}
	s.appendAudit(r.Context(), "enforcement.4k_directory.sync", connectorID, "source="+request.Source)
	writeJSON(w, http.StatusOK, map[string]any{
		"connector_id": connectorID, "source": request.Source, "online_total": onlineTotal,
		"identity_accounts": len(directory.Accounts), "identity_sessions": directory.IdentitySessions,
		"products": len(directory.Products), "groups": len(directory.Groups), "controls": directory.Controls,
		"capabilities": []string{"disconnect"}, "directory_ready": true,
	})
}
