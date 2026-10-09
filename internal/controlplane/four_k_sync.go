package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
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
	directory := fourKDirectory{Source: source, Products: []fourKDirectoryItem{}, Groups: []fourKDirectoryItem{}, Accounts: []fourKDirectoryItem{}, VLANs: []fourKDirectoryItem{}}
	rows, err := db.QueryContext(ctx, `SELECT product_id,name FROM product_catalog WHERE source=$1 AND active ORDER BY name,product_id`, source)
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
	err = db.QueryRowContext(ctx, `SELECT observed_at,(SELECT count(*) FROM product_control_catalog WHERE source=$1 AND active) FROM product_policy_snapshots WHERE source=$1 ORDER BY observed_at DESC,received_at DESC LIMIT 1`, source).Scan(&productObserved, &directory.Controls)
	if err != nil && err != sql.ErrNoRows {
		return directory, err
	}
	if err == nil {
		directory.ProductObservedAt = &productObserved
	}

	var identityRaw []byte
	var identityObserved time.Time
	err = db.QueryRowContext(ctx, `SELECT document,observed_at,session_count FROM identity_full_snapshots WHERE source=$1 ORDER BY observed_at DESC,received_at DESC LIMIT 1`, source).Scan(&identityRaw, &identityObserved, &directory.IdentitySessions)
	if err == sql.ErrNoRows {
		return directory, nil
	}
	if err != nil {
		return directory, err
	}
	directory.IdentityObservedAt = &identityObserved
	var snapshot store.IdentitySnapshot
	if err = json.Unmarshal(identityRaw, &snapshot); err != nil {
		return directory, err
	}
	directory.Accounts, directory.Groups, directory.VLANs = fourKIdentityDirectory(snapshot)
	groupRows, groupErr := db.QueryContext(ctx, `SELECT group_id,name FROM srun4k_group_catalog WHERE source=$1 AND active`, source)
	if groupErr == nil {
		names := map[string]string{}
		for groupRows.Next() {
			var id, name string
			if groupRows.Scan(&id, &name) == nil {
				names[id] = name
			}
		}
		groupRows.Close()
		for i := range directory.Groups {
			directory.Groups[i].Name = names[directory.Groups[i].ID]
		}
	}
	return directory, nil
}

func (s *Server) handle4KDirectory(w http.ResponseWriter, r *http.Request) {
	if s.productPolicies == nil || s.productPolicies.db == nil {
		writeError(w, http.StatusServiceUnavailable, "four_k_directory_unavailable", "4K目录存储不可用")
		return
	}
	source := strings.TrimSpace(r.URL.Query().Get("source"))
	if source == "" {
		if err := s.productPolicies.db.QueryRowContext(r.Context(), `SELECT source FROM srun4k_integrations ORDER BY updated_at DESC LIMIT 1`).Scan(&source); err != nil {
			source = defaultFourKSource
		}
	}
	directory, err := loadFourKDirectory(r.Context(), s.productPolicies.db, source)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "four_k_directory_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, directory)
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
	if _, err = s.productPolicies.db.ExecContext(r.Context(), `UPDATE enforcement_connectors SET action_mapping=$2,updated_at=clock_timestamp() WHERE connector_id=$1`, connectorID, []byte(`{"account_policy_v1":"supported","session.disconnect":"online-drop"}`)); err != nil {
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
