package controlplane

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"proxy-sentinel/internal/evaluation"
	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/risk"
)

type ShadowSampleDetail struct {
	Sample             evaluation.Sample   `json:"sample"`
	Snapshot           *risk.Snapshot      `json:"snapshot,omitempty"`
	Evidence           []evidence.Evidence `json:"evidence"`
	MissingEvidenceIDs []string            `json:"missing_evidence_ids"`
}

func (s *Server) readShadowJSON(parts []string, result any) error {
	root, err := filepath.EvalSymlinks(s.shadowDir)
	if err != nil {
		return err
	}
	path, err := filepath.EvalSymlinks(filepath.Join(append([]string{root}, parts...)...))
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("historical file is outside shadow directory")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	const maxBytes = 32 << 20
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxBytes {
		return fmt.Errorf("historical file exceeds read limit")
	}
	return json.Unmarshal(data, result)
}

func validShadowRunID(id string) bool {
	return id != "" && id != "." && id != ".." && filepath.Base(id) == id && !strings.ContainsAny(id, `/\\`)
}

func (s *Server) shadowRunSamples(runID, date string) ([]evaluation.Sample, *risk.BatchResult, error) {
	if !validShadowRunID(runID) {
		return nil, nil, fmt.Errorf("invalid historical run ID")
	}
	var batch risk.BatchResult
	if err := s.readShadowJSON([]string{"runs", runID, "risk-snapshots.json"}, &batch); err != nil {
		return nil, nil, err
	}
	peers := make([]evaluation.Sample, 0, len(batch.Snapshots))
	for _, snapshot := range batch.Snapshots {
		sample := evaluation.Sample{Date: date, SourceRunID: runID, SubjectType: snapshot.SubjectType, SubjectID: snapshot.SubjectID, IP: snapshot.IP, AccountID: snapshot.AccountID, EndpointID: snapshot.EndpointID, SnapshotTime: snapshot.UpdatedAt, EvidenceIDs: snapshot.EvidenceIDs}
		sample.SampleID = evaluation.SampleID(sample)
		peers = append(peers, sample)
	}
	return peers, &batch, nil
}

func (s *Server) readShadowSample(date, id string) (ShadowSampleDetail, error) {
	result := ShadowSampleDetail{Evidence: []evidence.Evidence{}, MissingEvidenceIDs: []string{}}
	if _, err := time.Parse("2006-01-02", date); err != nil {
		return result, fmt.Errorf("date must use YYYY-MM-DD")
	}
	var export struct {
		Samples []evaluation.Sample `json:"samples"`
	}
	if err := s.readShadowJSON([]string{"review-exports", date + "-review-samples.json"}, &export); err != nil {
		return result, err
	}
	found := false
	for _, sample := range export.Samples {
		sample.Date = date
		sample.SampleID = evaluation.SampleID(sample)
		if sample.SampleID == id {
			result.Sample = sample
			found = true
			break
		}
	}
	if !found {
		return result, os.ErrNotExist
	}
	_, batch, err := s.shadowRunSamples(result.Sample.SourceRunID, date)
	if err != nil {
		return result, err
	}
	for _, snapshot := range batch.Snapshots {
		candidate := evaluation.Sample{Date: date, SourceRunID: result.Sample.SourceRunID, SubjectType: snapshot.SubjectType, SubjectID: snapshot.SubjectID, IP: snapshot.IP, SnapshotTime: snapshot.UpdatedAt}
		if evaluation.SampleID(candidate) == id {
			if result.Snapshot != nil {
				return result, fmt.Errorf("historical snapshot identity is ambiguous")
			}
			copy := snapshot
			result.Snapshot = &copy
		}
	}
	if result.Snapshot == nil {
		return result, fmt.Errorf("sample does not match historical snapshot")
	}
	if !sameEvidenceIDs(result.Sample.EvidenceIDs, result.Snapshot.EvidenceIDs) {
		return result, fmt.Errorf("historical sample evidence references do not match snapshot")
	}
	var data evidence.Result
	if err := s.readShadowJSON([]string{"runs", result.Sample.SourceRunID, "evidence.json"}, &data); err != nil {
		return result, err
	}
	byID := map[string]evidence.Evidence{}
	for _, proof := range data.Evidence {
		byID[proof.EvidenceID] = proof
	}
	for _, evidenceID := range result.Sample.EvidenceIDs {
		if proof, ok := byID[evidenceID]; ok {
			result.Evidence = append(result.Evidence, proof)
		} else {
			result.MissingEvidenceIDs = append(result.MissingEvidenceIDs, evidenceID)
		}
	}
	return result, nil
}

func (s *Server) handleShadowSampleDetail(w http.ResponseWriter, r *http.Request, id string) {
	date := r.URL.Query().Get("date")
	if _, err := time.Parse("2006-01-02", date); err != nil {
		writeError(w, 400, "bad_shadow_review_date", "date must use YYYY-MM-DD")
		return
	}
	result, err := s.readShadowSample(date, id)
	if err != nil {
		if os.IsNotExist(err) {
			writeError(w, 404, "shadow_sample_not_found", "historical sample or evidence has expired")
			return
		}
		writeError(w, 500, "read_shadow_sample_failed", err.Error())
		return
	}
	writeJSON(w, 200, result)
}

func sameEvidenceIDs(left, right []string) bool {
	a, b := append([]string(nil), left...), append([]string(nil), right...)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}
