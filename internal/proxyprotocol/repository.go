package proxyprotocol

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type ScanState struct {
	From     time.Time `json:"from"`
	To       time.Time `json:"to"`
	After    Cursor    `json:"after"`
	ConfigID string    `json:"config_id"`
}
type Repository struct {
	mu  sync.Mutex
	db  *sql.DB
	dir string
}

func OpenRepository(db *sql.DB, dir string) *Repository { return &Repository{db: db, dir: dir} }
func (c Config) ID() string {
	raw, _ := json.Marshal(c)
	sum := sha256sum(raw)
	return c.Version + ":" + sum[:16]
}
func sha256sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func (r *Repository) State(ctx context.Context) (ScanState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var s ScanState
	var raw []byte
	var err error
	if r.db != nil {
		err = r.db.QueryRowContext(ctx, `SELECT document FROM proxy_protocol_scan WHERE id='main'`).Scan(&raw)
		if err == sql.ErrNoRows {
			return s, nil
		}
	} else {
		raw, err = os.ReadFile(filepath.Join(r.dir, "cursor.json"))
		if os.IsNotExist(err) {
			return s, nil
		}
	}
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(raw, &s)
	return s, err
}
func atomicFile(path string, raw []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".proxy-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func (r *Repository) Commit(ctx context.Context, results []Result, state ScanState) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.db != nil {
		tx, err := r.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('proxy-protocol-results'))`); err != nil {
			return err
		}
		for _, item := range results {
			item = normalizeResult(item)
			var raw []byte
			err = tx.QueryRowContext(ctx, `SELECT document FROM proxy_protocol_results WHERE evidence_id=$1`, item.ID).Scan(&raw)
			if err != nil && err != sql.ErrNoRows {
				return err
			}
			if len(raw) > 0 {
				var old Result
				if err = json.Unmarshal(raw, &old); err != nil {
					return err
				}
				if old.ConfigVersion == item.ConfigVersion {
					item = Merge(old, item)
				}
			}
			raw, err = json.Marshal(item)
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO proxy_protocol_results(evidence_id,ip,observed_at,document) VALUES($1,$2,$3,$4) ON CONFLICT(evidence_id) DO UPDATE SET ip=EXCLUDED.ip,observed_at=EXCLUDED.observed_at,document=EXCLUDED.document`, item.ID, item.IP, item.ObservedAt, raw)
			if err != nil {
				return err
			}
		}
		raw, err := json.Marshal(state)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO proxy_protocol_scan(id,document) VALUES('main',$1) ON CONFLICT(id) DO UPDATE SET document=EXCLUDED.document`, raw)
		if err != nil {
			return err
		}
		return tx.Commit()
	}
	for _, item := range results {
		item = normalizeResult(item)
		path := filepath.Join(r.dir, "results", item.ID+".json")
		raw, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if len(raw) > 0 {
			var old Result
			if err = json.Unmarshal(raw, &old); err != nil {
				return err
			}
			if old.ConfigVersion == item.ConfigVersion {
				item = Merge(old, item)
			}
		}
		raw, err = json.Marshal(item)
		if err != nil {
			return err
		}
		if err = atomicFile(path, raw); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return atomicFile(filepath.Join(r.dir, "cursor.json"), raw)
}
func (r *Repository) Query(ctx context.Context, ip string, since time.Time, limit int) ([]Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if limit < 1 || limit > 10001 {
		limit = 10001
	}
	out := []Result{}
	if r.db != nil {
		rows, err := r.db.QueryContext(ctx, `SELECT document FROM proxy_protocol_results WHERE observed_at >= $1 AND ($2='' OR ip=$2) ORDER BY observed_at DESC,evidence_id LIMIT $3`, since, ip, limit)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			var v Result
			if err = rows.Scan(&raw); err != nil {
				return nil, err
			}
			if err = json.Unmarshal(raw, &v); err != nil {
				return nil, err
			}
			out = append(out, normalizeResult(v))
		}
		return out, rows.Err()
	}
	paths, err := filepath.Glob(filepath.Join(r.dir, "results", "proxy-*.json"))
	if err != nil {
		return nil, err
	}
	for _, path := range paths {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var v Result
		if err = json.Unmarshal(raw, &v); err != nil {
			return nil, fmt.Errorf("read proxy result: %w", err)
		}
		if !v.ObservedAt.Before(since) && (ip == "" || ip == v.IP) {
			out = append(out, normalizeResult(v))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ObservedAt.Equal(out[j].ObservedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].ObservedAt.After(out[j].ObservedAt)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
