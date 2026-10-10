package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"proxy-sentinel/internal/productpolicy"
)

var errBridgeCatalogScope = errors.New("catalog does not match the committed identity bridge host and version")

const bridgeCatalogScopeQuery = `SELECT active_host,active_config_version,last_snapshot_at FROM identity_bridge_runtime WHERE bridge_id=$1 FOR SHARE`

func (s *Server) handleIdentityBridgeCatalogSnapshot(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeIdentityBridge(w, r) {
		return
	}
	if s.readOnly && !s.allowIdentityIngest {
		writeError(w, http.StatusForbidden, "read_only", "identity bridge catalog ingestion is disabled")
		return
	}
	snapshotID := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	var value productpolicy.BridgeCatalogSnapshot
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, productpolicy.MaxSnapshotBytes+4096))
	decoder.DisallowUnknownFields()
	var extra any
	if snapshotID == "" || len(snapshotID) > 200 || decoder.Decode(&value) != nil || decoder.Decode(&extra) != io.EOF || !validSRunHost(value.Host) || value.ConfigVersion < 1 || value.Snapshot.Source != s.identityBridge.normalized().Source || len(value.Snapshot.AntiProxyProfiles) > 0 || value.Snapshot.NormalizeAndValidate(time.Now().UTC()) != nil || snapshotID != value.ID() {
		writeError(w, http.StatusBadRequest, "bad_bridge_catalog", "a complete catalog for the managed identity source is required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	created, resolvedID, err := commitBridgeCatalogSnapshot(ctx, s.operations.db, s.identityBridge.normalized(), snapshotID, value)
	if errors.Is(err, errBridgeCatalogScope) || errors.Is(err, errProductPolicySnapshotConflict) {
		writeError(w, http.StatusConflict, "bridge_catalog_conflict", "catalog scope or idempotency conflicts with the current committed source")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "bridge_catalog_commit_failed", "4K产品目录保存失败")
		return
	}
	status := http.StatusAccepted
	if !created {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"snapshot_id": resolvedID, "status": "completed", "replayed": !created, "content_hash": value.Snapshot.ContentHash, "products": len(value.Snapshot.Products), "controls": len(value.Snapshot.Controls)})
}

func commitBridgeCatalogSnapshot(ctx context.Context, db *sql.DB, defaults IdentityBridgeDefaults, snapshotID string, value productpolicy.BridgeCatalogSnapshot) (bool, string, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, "", err
	}
	defer tx.Rollback()
	var host string
	var version int64
	var lastSnapshot sql.NullTime
	// Hold the bridge row through catalog commit: an in-flight old-host read
	// cannot publish after a successful identity-source switch.
	err = tx.QueryRowContext(ctx, bridgeCatalogScopeQuery, defaults.BridgeID).Scan(&host, &version, &lastSnapshot)
	if err == sql.ErrNoRows || err == nil && (host != value.Host || version != value.ConfigVersion || !lastSnapshot.Valid) {
		return false, "", errBridgeCatalogScope
	}
	if err != nil {
		return false, "", err
	}
	created, resolvedID, err := commitProductPolicySnapshotTx(ctx, tx, snapshotID, value.Snapshot)
	if err != nil {
		return false, "", err
	}
	if resolvedID != value.ID() {
		return false, "", errBridgeCatalogScope
	}
	if created {
		_, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(audit_id,actor,action,target,outcome,created_at) VALUES($1,'identity-bridge','integration.identity_bridge.catalog',$2,$3,now())`, "audit-bridge-catalog-"+shortToken(16), defaults.BridgeID, "completed:"+value.Snapshot.ContentHash)
		if err != nil {
			return false, "", err
		}
	}
	return created, resolvedID, tx.Commit()
}
