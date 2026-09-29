package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"proxy-sentinel/internal/policy"
)

var errPolicyConflict = errors.New("policy already exists or requested policy does not exist")

// Only the target policy is serialized. A target advisory lock also protects
// creation, where no row exists yet to acquire with FOR UPDATE.
func (s *operationsState) writePolicyDefinition(ctx context.Context, p policy.Definition, creating bool) (policy.Definition, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "policy-definition:"+p.ID); err != nil {
		return p, err
	}
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT document FROM account_policy_definitions WHERE id=$1 FOR UPDATE`, p.ID).Scan(&raw)
	exists := err == nil
	if err != nil && err != sql.ErrNoRows {
		return p, err
	}
	if creating == exists {
		return p, errPolicyConflict
	}
	var old policy.Definition
	if exists {
		if err = json.Unmarshal(raw, &old); err != nil {
			return p, err
		}
	}
	p.Revision = old.Revision + 1
	doc := emptyOperationsDocument()
	doc.Policies[p.ID] = p
	if err = savePolicyDocuments(ctx, tx, doc); err != nil {
		return p, err
	}
	return p, tx.Commit()
}
