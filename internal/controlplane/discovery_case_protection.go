package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"proxy-sentinel/internal/store"
)

func (s *operationsState) protectDiscoveryEvidence(ctx context.Context, tx *sql.Tx, caseID string, evidence []byte) error {
	var body struct {
		Refs       []store.DiscoveryCaseEvidenceRef `json:"discovery_evidence_refs"`
		StreamRefs []store.StreamBodyRef            `json:"stream_discovery_evidence_refs"`
		SharedRefs []store.StreamBodyRef            `json:"stream_shared_evidence_refs"`
	}
	if err := json.Unmarshal(evidence, &body); err != nil {
		return err
	}
	if len(body.Refs) == 0 && len(body.StreamRefs) == 0 && len(body.SharedRefs) == 0 {
		return nil
	}
	if len(body.Refs)+len(body.StreamRefs)+len(body.SharedRefs) > 100 {
		return fmt.Errorf("too many discovery evidence references")
	}
	if len(body.StreamRefs) > 0 {
		if s.streamEvidenceLoader == nil {
			return fmt.Errorf("stream discovery evidence reader unavailable")
		}
		items, err := s.streamEvidenceLoader(ctx, body.StreamRefs)
		if err != nil {
			return err
		}
		for _, ref := range body.StreamRefs {
			original, ok := items[ref]
			if !ok || original.ContentHash != ref.SHA256 || len(original.Document) == 0 {
				return fmt.Errorf("stream discovery original evidence unavailable")
			}
			encodedRef, err := json.Marshal(ref)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO stream_discovery_case_evidence(case_id,epoch,scope_id,event_key,content_sha256,body_ref,document)
 VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, caseID, ref.Epoch, ref.Scope, ref.Key, ref.SHA256, encodedRef, string(original.Document)); err != nil {
				return err
			}
		}
	}
	if len(body.SharedRefs) > 0 {
		if s.streamSharedEvidenceLoader == nil {
			return fmt.Errorf("stream shared evidence reader unavailable")
		}
		items, err := s.streamSharedEvidenceLoader(ctx, body.SharedRefs)
		if err != nil {
			return err
		}
		for _, ref := range body.SharedRefs {
			original, ok := items[ref]
			if !ok || original.ContentHash != ref.SHA256 || len(original.Document) == 0 {
				return fmt.Errorf("stream shared original evidence unavailable")
			}
			encodedRef, err := json.Marshal(ref)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO stream_shared_case_evidence(case_id,epoch,scope_id,event_key,content_sha256,body_ref,document)
 VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, caseID, ref.Epoch, ref.Scope, ref.Key, ref.SHA256, encodedRef, string(original.Document)); err != nil {
				return err
			}
		}
	}
	if len(body.Refs) == 0 {
		return nil
	}
	for _, ref := range body.Refs {
		if ref.SensorID == "" || ref.SourceID == "" || ref.EventID == "" || ref.Revision < 0 {
			return fmt.Errorf("invalid discovery evidence reference")
		}
	}
	if s.discoveryEvidenceLoader == nil {
		// The database trigger can still protect legacy and unreleased segments.
		return nil
	}
	items, err := s.discoveryEvidenceLoader(ctx, body.Refs)
	if err != nil {
		return err
	}
	for _, ref := range body.Refs {
		original, ok := items[ref]
		if !ok {
			continue // Legacy rows are protected by the trigger.
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO discovery_case_evidence_v2(case_id,event_id,sensor_id,source_id,revision,document,content_hash)
 VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, caseID, ref.EventID, ref.SensorID, ref.SourceID, ref.Revision, original.Document, original.ContentHash); err != nil {
			return err
		}
	}
	return nil
}
