package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type MigrationResult struct {
	Applied []string
	Current string
}

func ApplyPostgresMigrations(ctx context.Context, dsn, dir string) (MigrationResult, error) {
	if strings.TrimSpace(dsn) == "" {
		return MigrationResult{}, fmt.Errorf("postgres dsn is required")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return MigrationResult{}, fmt.Errorf("read PostgreSQL migrations: %w", err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			files = append(files, entry.Name())
		}
	}
	sort.Strings(files)
	if len(files) == 0 {
		return MigrationResult{}, fmt.Errorf("no PostgreSQL migrations found in %s", dir)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return MigrationResult{}, err
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return MigrationResult{}, fmt.Errorf("connect PostgreSQL for migrations: %w", err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return MigrationResult{}, fmt.Errorf("create migration ledger: %w", err)
	}
	result := MigrationResult{}
	for _, name := range files {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return result, err
		}
		digest := sha256.Sum256(body)
		checksum := hex.EncodeToString(digest[:])
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return result, err
		}
		if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('proxy-sentinel-migrations'))`); err != nil {
			_ = tx.Rollback()
			return result, err
		}
		var existing string
		err = tx.QueryRowContext(ctx, `SELECT checksum FROM schema_migrations WHERE version=$1`, name).Scan(&existing)
		if err == nil {
			if existing != checksum {
				_ = tx.Rollback()
				return result, fmt.Errorf("migration %s checksum changed after application", name)
			}
			if err := tx.Commit(); err != nil {
				return result, err
			}
			result.Current = name
			continue
		}
		if err != sql.ErrNoRows {
			_ = tx.Rollback()
			return result, err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			_ = tx.Rollback()
			return result, fmt.Errorf("apply migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,checksum) VALUES($1,$2)`, name, checksum); err != nil {
			_ = tx.Rollback()
			return result, err
		}
		if err := tx.Commit(); err != nil {
			return result, err
		}
		result.Applied = append(result.Applied, name)
		result.Current = name
	}
	return result, nil
}

func VerifyPostgresSchema(ctx context.Context, dsn string, requiredTables ...string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return err
	}
	for _, table := range requiredTables {
		var exists bool
		if err := db.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, "public."+table).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("required PostgreSQL table %s is missing", table)
		}
	}
	return nil
}
