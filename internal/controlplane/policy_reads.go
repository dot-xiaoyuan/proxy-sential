package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"proxy-sentinel/internal/policy"
)

// Read only the requested policy documents. The operations mutation lock also
// reloads all cases, evidence histories and actions and must not gate page reads.
func (s *operationsState) readPolicyDefinitions(ctx context.Context) ([]policy.Definition, error) {
	items := []policy.Definition{}
	if s.db == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, p := range s.doc.Policies {
			items = append(items, p)
		}
		return items, s.lockErr
	}
	rows, err := s.db.QueryContext(ctx, `SELECT document FROM account_policy_definitions ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		var p policy.Definition
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		items = append(items, p)
	}
	return items, rows.Err()
}
func (s *operationsState) readPolicyExecutions(ctx context.Context, account string) ([]policy.Execution, error) {
	items := []policy.Execution{}
	if s.db == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, e := range s.doc.PolicyExecutions {
			if account == "" || account == e.AccountID {
				items = append(items, e)
			}
		}
		return items, s.lockErr
	}
	query := `SELECT document FROM account_policy_executions`
	args := []any{}
	if account != "" {
		query += ` WHERE document->>'account_id'=$1`
		args = append(args, account)
	}
	rows, err := s.db.QueryContext(ctx, query+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		var e policy.Execution
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &e); err != nil {
			return nil, err
		}
		items = append(items, e)
	}
	return items, rows.Err()
}

// Approval previews fetch the requested execution without serializing with writers.
func (s *operationsState) readPolicyExecution(ctx context.Context, id string) (policy.Execution, bool, error) {
	if s.db == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		e, found := s.doc.PolicyExecutions[id]
		return e, found, s.lockErr
	}
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT document FROM account_policy_executions WHERE id=$1`, id).Scan(&raw)
	if err == sql.ErrNoRows {
		return policy.Execution{}, false, nil
	}
	if err != nil {
		return policy.Execution{}, false, err
	}
	var e policy.Execution
	if err = json.Unmarshal(raw, &e); err != nil {
		return e, false, err
	}
	return e, true, nil
}
