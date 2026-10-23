package store

import (
	"context"
	"database/sql"
	"time"
)

// The recognizer consumes the same bounded rows and ordering as the details
// API, but not raw evidence arrays or protocol fields. Existing covering
// indexes supply all these columns without fetching each history heap tuple.
func (s *PostgresStore) recognitionHistory(ctx context.Context, endpoint string, limit int) ([]IdentityIPMACHistory, []IdentityAccessHistory, error) {
	ips := []IdentityIPMACHistory{}
	accesses := []IdentityAccessHistory{}
	rows, err := s.db.QueryContext(ctx, `SELECT event_id,account_id,host(ip),first_seen,last_seen FROM identity_ip_mac_history WHERE endpoint_id=$1 ORDER BY last_seen DESC,first_seen DESC,host(ip),event_id LIMIT $2`, endpoint, limit)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		item := IdentityIPMACHistory{EndpointID: endpoint}
		var account, ip sql.NullString
		var first, last time.Time
		if err = rows.Scan(&item.EventID, &account, &ip, &first, &last); err != nil {
			rows.Close()
			return nil, nil, err
		}
		item.AccountID, item.IP = account.String, ip.String
		item.FirstSeen, item.LastSeen = first.Format(time.RFC3339Nano), last.Format(time.RFC3339Nano)
		ips = append(ips, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, nil, err
	}
	rows, err = s.db.QueryContext(ctx, `SELECT event_id,account_id,access_id,first_seen,last_seen FROM identity_access_history WHERE endpoint_id=$1 ORDER BY last_seen DESC,event_id LIMIT $2`, endpoint, limit)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		item := IdentityAccessHistory{EndpointID: endpoint}
		var account sql.NullString
		var first, last time.Time
		if err = rows.Scan(&item.EventID, &account, &item.AccessID, &first, &last); err != nil {
			return nil, nil, err
		}
		item.AccountID = account.String
		item.FirstSeen, item.LastSeen = first.Format(time.RFC3339Nano), last.Format(time.RFC3339Nano)
		accesses = append(accesses, item)
	}
	return ips, accesses, rows.Err()
}
