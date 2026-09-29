package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"sync"
	"time"

	"proxy-sentinel/internal/legacy4k"
	"proxy-sentinel/internal/srunapi"
	"proxy-sentinel/internal/store"
)

type managedIdentityFailure struct {
	Version int64
	Blocker string
}
type managedIdentityFailureCache struct {
	sync.RWMutex
	Values map[string]managedIdentityFailure
}

var fallbackIdentityFailures = &managedIdentityFailureCache{}

func (s *Server) identityFailureCache() *managedIdentityFailureCache {
	if s.managedIdentityFailures != nil {
		return s.managedIdentityFailures
	}
	return fallbackIdentityFailures
}

func (s *Server) rememberIdentityFailure(item managedIdentityRegistration, blocker string) {
	cache := s.identityFailureCache()
	cache.Lock()
	defer cache.Unlock()
	if cache.Values == nil {
		cache.Values = map[string]managedIdentityFailure{}
	}
	previous, ok := cache.Values[item.ID]
	if !ok || previous.Version <= item.Version {
		cache.Values[item.ID] = managedIdentityFailure{item.Version, blocker}
	}
}
func (s *Server) clearIdentityFailure(item managedIdentityRegistration) {
	cache := s.identityFailureCache()
	cache.Lock()
	defer cache.Unlock()
	if previous, ok := cache.Values[item.ID]; ok && previous.Version == item.Version {
		delete(cache.Values, item.ID)
	}
}

type managedIdentityRegistration struct {
	ID                       string
	Version                  int64
	Config                   managedIdentityConfig
	Token                    []byte
	Endpoint, Certificate    string
	State, Blocker           string
	ObservedAt               sql.NullTime
	LastSuccess, LastAttempt sql.NullTime
	RecordCount              int
}

func (s *Server) managedIdentityRegistrations(ctx context.Context) ([]managedIdentityRegistration, error) {
	return s.managedIdentityRegistrationsFiltered(ctx, "", nil)
}

func (s *Server) managedIdentityRegistrationByConnector(ctx context.Context, id string) (managedIdentityRegistration, error) {
	items, err := s.managedIdentityRegistrationsFiltered(ctx, " AND i.connector_id=$1", []any{id})
	if err != nil {
		return managedIdentityRegistration{}, err
	}
	if len(items) == 0 {
		return managedIdentityRegistration{}, fmt.Errorf("identity_source_not_configured")
	}
	return items[0], nil
}

func (s *Server) managedIdentityRegistrationsByScope(ctx context.Context, campus, domain string) ([]managedIdentityRegistration, error) {
	return s.managedIdentityRegistrationsFiltered(ctx, " AND i.public_config->>'campus_id'=$1 AND i.public_config->>'access_domain'=$2", []any{campus, domain})
}

func (s *Server) managedIdentityRegistrationsFiltered(ctx context.Context, filter string, args []any) ([]managedIdentityRegistration, error) {
	if s.operations == nil || s.operations.db == nil {
		return nil, nil
	}
	query := `SELECT i.connector_id,i.config_version,i.public_config,i.encrypted_token,c.endpoint_url,c.certificate_pem,i.state,i.blocker,i.observed_at,i.last_success_at,i.last_attempt_at,i.record_count FROM enforcement_identity_sources i JOIN enforcement_connectors c USING(connector_id) WHERE c.connector_type='srun4k'` + filter + ` ORDER BY i.connector_id LIMIT 17`
	rows, err := s.operations.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []managedIdentityRegistration{}
	for rows.Next() {
		var item managedIdentityRegistration
		var raw []byte
		if rows.Scan(&item.ID, &item.Version, &raw, &item.Token, &item.Endpoint, &item.Certificate, &item.State, &item.Blocker, &item.ObservedAt, &item.LastSuccess, &item.LastAttempt, &item.RecordCount) != nil || json.Unmarshal(raw, &item.Config) != nil {
			return nil, fmt.Errorf("identity configuration unavailable")
		}
		cache := s.identityFailureCache()
		cache.RLock()
		if failure, ok := cache.Values[item.ID]; ok && failure.Version == item.Version {
			item.State = "unavailable"
			item.Blocker = failure.Blocker
		}
		cache.RUnlock()
		out = append(out, item)
	}
	if rows.Err() != nil || len(out) > 16 {
		return nil, fmt.Errorf("identity source bound exceeded or query incomplete")
	}
	return out, nil
}

// Each cycle waits for its two workers before the next tick. A source is never
// reconciled concurrently and the global number of outbound syncs is at most 2.
func (s *Server) startManagedIdentityWorker() {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			s.reconcileManagedIdentityCycle()
			<-ticker.C
		}
	}()
}
func (s *Server) reconcileManagedIdentityCycle() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	registrations, err := s.managedIdentityRegistrations(ctx)
	cancel()
	if err != nil {
		return
	}
	jobs := make(chan managedIdentityRegistration)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				s.reconcileManagedIdentity(item)
			}
		}()
	}
	for _, item := range registrations {
		if item.Config.Enabled {
			jobs <- item
		}
	}
	close(jobs)
	wg.Wait()
}
func (s *Server) readManagedInventory(ctx context.Context, item managedIdentityRegistration) (legacy4k.OnlineInventory, error) {
	if item.Config.Kind != "complete_inventory" {
		return legacy4k.OnlineInventory{}, fmt.Errorf("inventory_completeness_unproven")
	}
	token, err := s.decryptConnectorSecret(string(item.Token))
	if err != nil || token == "" {
		return legacy4k.OnlineInventory{}, fmt.Errorf("inventory_credential_unavailable")
	}
	reader, err := srunapi.NewInventoryHTTP(item.Config.InventoryURL, token, item.Config.CampusID, item.Config.AccessDomain, item.Config.MaxRecords, nil)
	if err != nil {
		return legacy4k.OnlineInventory{}, fmt.Errorf("inventory_configuration_invalid")
	}
	// A pin provisioned for the management server cannot silently establish trust
	// for a different inventory host. Other HTTPS origins use system trust.
	inventoryURL, _ := url.Parse(item.Config.InventoryURL)
	managementURL, _ := url.Parse(item.Endpoint)
	if item.Certificate != "" && inventoryURL.Host == managementURL.Host {
		hc, e := srunapi.NewCertificatePinnedClient([]byte(item.Certificate))
		if e != nil {
			return legacy4k.OnlineInventory{}, fmt.Errorf("inventory_certificate_invalid")
		}
		defer hc.CloseIdleConnections()
		hc.Timeout = 3 * time.Second
		reader.Client = hc
	}
	inventory, err := reader.Read(ctx)
	if err != nil {
		return legacy4k.OnlineInventory{}, fmt.Errorf("inventory_read_failed_or_incomplete")
	}
	return inventory, nil
}
func (s *Server) markManagedIdentityFailure(item managedIdentityRegistration, blocker string) {
	s.rememberIdentityFailure(item, blocker)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// Preserve the last successful observation and facts. Failed current status is
	// independently consulted by every policy read; facts do not grant admission.
	_, _ = s.operations.db.ExecContext(ctx, `UPDATE enforcement_identity_sources SET state='unavailable',blocker=$3,last_attempt_at=now() WHERE connector_id=$1 AND config_version=$2`, item.ID, item.Version, blocker)
}
func (s *Server) reconcileManagedIdentity(item managedIdentityRegistration) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	inventory, err := s.readManagedInventory(ctx, item)
	if err != nil {
		s.markManagedIdentityFailure(item, err.Error())
		return
	}
	inventory.InstanceID = fmt.Sprintf("4k:%s:config-%d:%s", item.ID, item.Version, inventory.InstanceID)
	records, err := inventory.IdentityRecords()
	if err != nil {
		s.markManagedIdentityFailure(item, "inventory_identity_invalid")
		return
	}
	// Every returned address must belong to the configured user-side scope.
	for _, record := range records {
		if !managedAddressInScope(record["ip"], item.Config.UserCIDRs) {
			s.markManagedIdentityFailure(item, "inventory_address_outside_scope")
			return
		}
	}
	count := len(records)
	snapshot, err := prepareIdentitySnapshot(identitySnapshotRequest{IdentityScope: item.Config.IdentityScope, ObservedAt: inventory.ObservedAt, IntervalSeconds: 5, Complete: true, ExpectedCount: &count, Records: records}, legacy4k.StableID(fmt.Sprintf("managed:%s:%d:%s:%s", item.ID, item.Version, inventory.InstanceID, inventory.ObservedAt.Format(time.RFC3339Nano))), time.Now().UTC())
	if err != nil {
		s.markManagedIdentityFailure(item, "inventory_standardization_failed")
		return
	}

	metadata := map[string]map[string]string{}
	for _, row := range inventory.Rows {
		retained := map[string]string{}
		for _, key := range []string{"session_id", "rad_online_id", "user_name", "ip", "user_ip", "ipv6", "ip6", "user_ip6", "user_mac", "nas_ip", "add_time", "group_id", "products_id", "device_id"} {
			if value, ok := row[key]; ok {
				retained[key] = value
			}
		}
		metadata[row["rad_online_id"]] = retained
	}
	for i := range snapshot.Events {
		snapshot.Events[i].RawRef["identity_fields"] = metadata[records[i]["raw_online_id"]]
		snapshot.Events[i].RawRef["session_id_source"] = "derived_connector_source_raw_id_login"
	}

	backend, ok := s.reader.(store.IdentityReconciler)
	if !ok {
		s.markManagedIdentityFailure(item, "identity_storage_unavailable")
		return
	}
	// Acquire only this configuration row after network I/O. Holding the row until
	// commit prevents an old version from committing after a new version is saved.
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		s.markManagedIdentityFailure(item, "identity_storage_unavailable")
		return
	}
	defer tx.Rollback()
	var current int64
	var endpoint, certificate string
	if tx.QueryRowContext(ctx, `SELECT i.config_version,c.endpoint_url,c.certificate_pem FROM enforcement_identity_sources i JOIN enforcement_connectors c USING(connector_id) WHERE i.connector_id=$1 FOR UPDATE OF i FOR SHARE OF c`, item.ID).Scan(&current, &endpoint, &certificate) != nil || current != item.Version || endpoint != item.Endpoint || certificate != item.Certificate {
		return
	}
	if _, err = backend.CommitIdentitySnapshot(ctx, snapshot); err != nil {
		tx.Rollback()
		s.markManagedIdentityFailure(item, "identity_snapshot_commit_failed")
		return
	}
	_, err = tx.ExecContext(ctx, `UPDATE enforcement_identity_sources SET state='healthy',blocker='',last_attempt_at=now(),last_success_at=now(),observed_at=$3,record_count=$4 WHERE connector_id=$1 AND config_version=$2`, item.ID, item.Version, inventory.ObservedAt, count)
	if err != nil || tx.Commit() != nil {
		s.markManagedIdentityFailure(item, "identity_status_commit_failed")
	} else {
		s.clearIdentityFailure(item)
	}
}
