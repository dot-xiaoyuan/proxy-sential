package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"proxy-sentinel/internal/policy"
	"time"
)

func loadPolicyDocuments(ctx context.Context, q operationsQuerier, doc *operationsDocument) error {
	for _, table := range []string{"account_policy_definitions", "account_policy_executions"} {
		if err := loadPolicyDocumentsScoped(ctx, q, doc, table, "", nil); err != nil {
			return err
		}
	}
	return nil
}
func loadPolicyDocumentsScoped(ctx context.Context, q operationsQuerier, doc *operationsDocument, table, suffix string, args []any) error {
	if table != "account_policy_definitions" && table != "account_policy_executions" {
		return fmt.Errorf("invalid policy table")
	}
	rows, err := q.QueryContext(ctx, "SELECT id,document,updated_at FROM "+table+suffix, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	if doc.policyVersions == nil {
		doc.policyVersions = map[[2]string]time.Time{}
	}
	for rows.Next() {
		var id string
		var raw []byte
		var updated time.Time
		if err = rows.Scan(&id, &raw, &updated); err != nil {
			return err
		}
		if table == "account_policy_definitions" {
			var p policy.Definition
			err = json.Unmarshal(raw, &p)
			doc.Policies[id] = p
		} else {
			var e policy.Execution
			err = json.Unmarshal(raw, &e)
			doc.PolicyExecutions[id] = e
		}
		if err != nil {
			return err
		}
		doc.policyVersions[[2]string{table, id}] = updated
	}
	return rows.Err()
}
func savePolicyDocuments(ctx context.Context, tx *sql.Tx, doc operationsDocument, baselines ...map[[2]string]time.Time) error {
	save := func(table, id string, v any) error {
		raw, err := json.Marshal(v)
		if err != nil {
			return err
		}
		var expected any
		enabled := len(baselines) > 0 && baselines[0] != nil
		if enabled {
			if stamp, found := baselines[0][[2]string{table, id}]; found {
				expected = stamp
			}
		}
		result, err := tx.ExecContext(ctx, "INSERT INTO "+table+"(id,document) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET document=EXCLUDED.document,updated_at=greatest(clock_timestamp(),"+table+".updated_at+interval '1 microsecond') WHERE NOT $3 OR "+table+".updated_at=$4::timestamptz", id, raw, enabled, expected)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err == nil && affected != 1 {
			return fmt.Errorf("policy resource %s changed concurrently; retry", id)
		}
		return err
	}
	for id, p := range doc.Policies {
		if err := save("account_policy_definitions", id, p); err != nil {
			return err
		}
	}
	for id, e := range doc.PolicyExecutions {
		if err := save("account_policy_executions", id, e); err != nil {
			return err
		}
	}
	return nil
}
