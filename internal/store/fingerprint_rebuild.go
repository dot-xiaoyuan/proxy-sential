package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"proxy-sentinel/internal/fingerprint"
	"sort"
	"time"
)

// Bounded enqueue only: heavy recognition is handled by the reserved queue lane.
func (s *DBStore) runFingerprintRebuild(ctx context.Context) {
	if !fingerprint.HistoryBackfillEnabled() {
		return
	}
	for ctx.Err() == nil {
		c := fingerprint.Default().Catalog()
		raw, _ := json.Marshal(c.Sources)
		sum := sha256.Sum256(raw)
		version := hex.EncodeToString(sum[:])
		grouped := map[string][]fingerprint.SourceRule{}
		mapping := map[string][]string{"hostname": {"hostname", "client_fqdn"}, "user_agent": {"user_agent"}, "dhcp_vendor_class": {"vendor_class"}, "dhcp_requested_options": {"requested_options"}, "http_server": {"server"}, "http_title": {"title"}, "tls_subject": {"certificate_subject"}, "tls_issuer": {"certificate_issuer"}, "tls_san": {"certificate_san"}, "snmp_sysdescr": {"snmp_sysdescr"}, "snmp_sysoid": {"snmp_sysoid"}, "mdns_model": {"mdns_model"}, "ssh_banner": {"ssh_banner"}, "http_body": {"http_body"}, "favicon_md5": {"favicon_md5"}, "sip_server": {"sip_server"}, "sip_user_agent": {"sip_user_agent"}, "http_www_authenticate": {"http_www_authenticate"}}
		for _, r := range c.Rules {
			if r.Status != "converted" {
				continue
			}
			for _, condition := range r.Conditions {
				for _, key := range mapping[condition.Field] {
					grouped[key] = append(grouped[key], r)
				}
			}
		}
		hashes := map[string]string{}
		for field, rules := range grouped {
			raw, _ := json.Marshal(rules)
			sum := sha256.Sum256(raw)
			hashes[field] = hex.EncodeToString(sum[:])
		}
		work, cancel := context.WithTimeout(ctx, 10*time.Second)
		if err := s.enqueueFingerprintRebuild(work, version, hashes); err != nil && ctx.Err() == nil {
			fmt.Printf("fingerprint rebuild enqueue failed: %v\n", err)
		}
		cancel()

		timer := time.NewTimer(5 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func (s *DBStore) enqueueFingerprintRebuild(ctx context.Context, version string, fieldVersions map[string]string) error {
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO read_model_runtime_state(name,state,updated_at) VALUES('fingerprint-rebuild','{}',now()) ON CONFLICT DO NOTHING`)
	if err != nil {
		return err
	}
	var raw []byte
	if err = tx.QueryRowContext(ctx, `SELECT state FROM read_model_runtime_state WHERE name='fingerprint-rebuild' FOR UPDATE`).Scan(&raw); err != nil {
		return err
	}
	var state struct {
		Version       string            `json:"version"`
		Cursor        string            `json:"cursor"`
		Enqueued      int               `json:"enqueued"`
		Complete      bool              `json:"complete"`
		Visited       int               `json:"visited"`
		FieldVersions map[string]string `json:"field_versions"`
		Fields        []string          `json:"fields"`
	}
	if err = json.Unmarshal(raw, &state); err != nil {
		return err
	}
	if state.Version != version {
		changed := map[string]bool{}
		for field, hash := range fieldVersions {
			if state.FieldVersions[field] != hash {
				changed[field] = true
			}
		}
		for field := range state.FieldVersions {
			if _, ok := fieldVersions[field]; !ok {
				changed[field] = true
			}
		}
		state.Fields = []string{}
		for field := range changed {
			state.Fields = append(state.Fields, field)
		}
		sort.Strings(state.Fields)
		state.FieldVersions = fieldVersions
		state.Version = version
		state.Cursor = ""
		state.Enqueued = 0
		state.Visited = 0
		state.Complete = false
	}
	if state.Complete {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT endpoint_id FROM endpoint_entities WHERE entity_role='endpoint' AND endpoint_id>$1 AND last_seen>now()-interval '7 days' AND attributes ?| $2::text[] ORDER BY endpoint_id LIMIT 100`, state.Cursor, state.Fields)
	if err != nil {
		return err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		result, execErr := tx.ExecContext(ctx, `INSERT INTO endpoint_recognition_jobs(endpoint_id,lane) VALUES($1,1) ON CONFLICT(endpoint_id) DO UPDATE SET dirty_generation=endpoint_recognition_jobs.dirty_generation+1,lane=1,not_before=now(),updated_at=now() WHERE endpoint_recognition_jobs.processed_generation>=endpoint_recognition_jobs.dirty_generation`, id)
		if execErr != nil {
			return execErr
		}
		count, _ := result.RowsAffected()
		state.Enqueued += int(count)
		state.Cursor = id
		state.Visited++
	}
	state.Complete = len(ids) < 100
	data, _ := json.Marshal(state)
	if _, err = tx.ExecContext(ctx, `UPDATE read_model_runtime_state SET state=$1,updated_at=now() WHERE name='fingerprint-rebuild'`, data); err != nil {
		return err
	}
	return tx.Commit()
}
