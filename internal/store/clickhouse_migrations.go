package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func ApplyClickHouseMigrations(ctx context.Context, dsn, dir string) (MigrationResult, error) {
	clickhouse, err := NewClickHouseStore(ClickHouseOptions{DSN: dsn})
	if err != nil {
		return MigrationResult{}, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return MigrationResult{}, fmt.Errorf("read ClickHouse migrations: %w", err)
	}
	files := []string{}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			files = append(files, entry.Name())
		}
	}
	sort.Strings(files)
	if len(files) == 0 {
		return MigrationResult{}, fmt.Errorf("no ClickHouse migrations found in %s", dir)
	}
	if err := clickhouse.exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version String,checksum String,applied_at DateTime64(6,'UTC') DEFAULT now64(6)) ENGINE=ReplacingMergeTree(applied_at) ORDER BY version`); err != nil {
		return MigrationResult{}, fmt.Errorf("create ClickHouse migration ledger: %w", err)
	}
	result := MigrationResult{}
	for _, name := range files {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return result, err
		}
		digest := sha256.Sum256(body)
		checksum := hex.EncodeToString(digest[:])
		data, err := clickhouse.query(ctx, fmt.Sprintf(`SELECT checksum FROM schema_migrations FINAL WHERE version=%s ORDER BY applied_at DESC LIMIT 1 FORMAT TabSeparatedRaw`, chQuote(name)))
		if err != nil {
			return result, err
		}
		existing := strings.TrimSpace(string(data))
		if existing != "" {
			if existing != checksum {
				return result, fmt.Errorf("migration %s checksum changed after application", name)
			}
			result.Current = name
			continue
		}
		statements, err := splitClickHouseMigration(string(body))
		if err != nil {
			return result, fmt.Errorf("parse ClickHouse migration %s: %w", name, err)
		}
		for index, statement := range statements {
			if err := clickhouse.exec(ctx, statement); err != nil {
				return result, fmt.Errorf("apply ClickHouse migration %s statement %d: %w", name, index+1, err)
			}
		}
		if err := clickhouse.exec(ctx, fmt.Sprintf(`INSERT INTO schema_migrations(version,checksum) VALUES(%s,%s)`, chQuote(name), chQuote(checksum))); err != nil {
			return result, err
		}
		result.Applied = append(result.Applied, name)
		result.Current = name
	}
	return result, nil
}

// splitClickHouseMigration handles the project migration subset while keeping
// semicolons inside quoted strings intact. ClickHouse DDL is not transactional,
// so every migration must remain additive and retry-safe.
func splitClickHouseMigration(body string) ([]string, error) {
	// Migration comments are documentation, not executable statements. Remove
	// full-line comments before splitting so punctuation in prose cannot create
	// an empty ClickHouse request.
	var uncommented strings.Builder
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		uncommented.WriteString(line)
		uncommented.WriteByte('\n')
	}
	body = uncommented.String()
	statements := []string{}
	var current strings.Builder
	var quote rune
	escaped := false
	for _, char := range body {
		if escaped {
			current.WriteRune(char)
			escaped = false
			continue
		}
		if char == '\\' && quote != 0 {
			current.WriteRune(char)
			escaped = true
			continue
		}
		if quote != 0 {
			current.WriteRune(char)
			if char == quote {
				quote = 0
			}
			continue
		}
		if char == '\'' || char == '"' || char == '`' {
			quote = char
			current.WriteRune(char)
			continue
		}
		if char == ';' {
			if statement := strings.TrimSpace(current.String()); statement != "" {
				statements = append(statements, statement)
			}
			current.Reset()
			continue
		}
		current.WriteRune(char)
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quoted string")
	}
	if statement := strings.TrimSpace(current.String()); statement != "" {
		statements = append(statements, statement)
	}
	return statements, nil
}
