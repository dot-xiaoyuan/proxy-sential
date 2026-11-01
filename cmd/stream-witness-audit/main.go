// stream-witness-audit checks a bounded source manifest against PostgreSQL's
// r37 finalization witnesses. It never changes storage or grants cleanup.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"proxy-sentinel/internal/streamaudit"
)

const maxManifestBytes = 1 << 20

func readManifest(reader io.Reader) (streamaudit.Manifest, string, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxManifestBytes+1))
	if err != nil {
		return streamaudit.Manifest{}, "", err
	}
	if len(data) > maxManifestBytes {
		return streamaudit.Manifest{}, "", errors.New("manifest exceeds 1 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest streamaudit.Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return streamaudit.Manifest{}, "", err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return streamaudit.Manifest{}, "", errors.New("manifest contains trailing data")
	}
	sum := sha256.Sum256(data)
	return manifest, hex.EncodeToString(sum[:]), nil
}

type output struct {
	CheckedAtUTC   time.Time          `json:"checked_at_utc"`
	ManifestSHA256 string             `json:"manifest_sha256"`
	Report         streamaudit.Report `json:"report"`
}

func main() {
	path := flag.String("manifest", "", "immutable source manifest JSON (at most 128 segments)")
	flag.Parse()
	if *path == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: stream-witness-audit --manifest /path/to/immutable-interval.json")
		os.Exit(2)
	}
	f, err := os.Open(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open manifest:", err)
		os.Exit(2)
	}
	manifest, digest, err := readManifest(f)
	f.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, "read manifest:", err)
		os.Exit(2)
	}
	var report streamaudit.Report
	if len(streamaudit.ManifestIssues(manifest)) != 0 {
		report = streamaudit.Verify(manifest, nil)
	} else {
		dsn := os.Getenv("PROXY_SENTINEL_POSTGRES_DSN")
		if dsn == "" {
			fmt.Fprintln(os.Stderr, "PROXY_SENTINEL_POSTGRES_DSN is required")
			os.Exit(2)
		}
		db, err := sql.Open("pgx", dsn)
		if err != nil {
			fmt.Fprintln(os.Stderr, "open PostgreSQL:", err)
			os.Exit(2)
		}
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		report, err = streamaudit.AuditPostgres(context.Background(), db, manifest)
		db.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, "read-only PostgreSQL audit:", err)
			os.Exit(1)
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(output{CheckedAtUTC: time.Now().UTC(), ManifestSHA256: digest, Report: report}); err != nil {
		fmt.Fprintln(os.Stderr, "encode audit result:", err)
		os.Exit(1)
	}
	if !report.WitnessConfirmed {
		os.Exit(1)
	}
}
