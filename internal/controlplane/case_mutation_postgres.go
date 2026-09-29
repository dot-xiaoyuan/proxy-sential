package controlplane

import (
	"database/sql"
	"net/http"
)

// State transitions and appended history commit atomically under the target
// case row lock; unrelated cases and organization saves remain independent.
func (s *Server) mutateCasePostgres(w http.ResponseWriter, r *http.Request, id, operation string) {
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		writeError(w, 503, "case_storage_failed", err.Error())
		return
	}
	defer tx.Rollback()
	item, err := readCaseWithinTransaction(ctx, tx, id, true)
	if err == sql.ErrNoRows {
		writeError(w, 404, "case_not_found", "case not found")
		return
	}
	if err != nil {
		writeError(w, 503, "case_storage_failed", err.Error())
		return
	}
	doc := emptyOperationsDocument()
	doc.Cases[id] = item
	state := &operationsState{db: s.operations.db, tx: tx, doc: doc, readView: true, recordBaseline: operationFingerprints(doc), recordVersionBaseline: operationRecordVersions(doc), caseVersionBaseline: map[string]string{id: item.UpdatedAt}, persistedHistory: map[[2]string]bool{}}
	for _, row := range item.Comments {
		state.persistedHistory[[2]string{"comment", row.CommentID}] = true
	}
	for _, row := range item.Timeline {
		state.persistedHistory[[2]string{"timeline", row.EventID}] = true
	}
	for _, row := range item.EvidenceHistory {
		state.persistedHistory[[2]string{"snapshot", row.SnapshotID}] = true
	}
	view := *s
	view.operations = state
	view.mutateCase(w, r.WithContext(ctx), id, operation)
}
