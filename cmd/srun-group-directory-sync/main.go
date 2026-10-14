// Command srun-group-directory-sync syncs the 4K northbound group directory
// into srun4k_group_catalog.
//
// The group directory changes on the order of days, while online identity churns
// every minute. Coupling the two is what left policy scope selectors showing
// bare group numbers: the identity pipeline only promotes its active config
// version after a complete inventory succeeds, and a churning inventory can
// stall that for hours. This command reads the directory directly and can be run
// once, or re-run whenever the campus group tree changes.
//
// It is read-only against the 4K platform: only the documented token and group
// directory endpoints are called. It never enables, disables or disconnects
// anything.
package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"proxy-sentinel/internal/srunapi"
)

const defaultSource = "ncu-srun4k"

func main() {
	endpoint := flag.String("endpoint", "", "4K northbound origin, for example https://222.204.3.227:8001")
	appID := flag.String("app-id", "", "northbound application id")
	appSecretFile := flag.String("app-secret-file", "", "file holding the northbound application secret")
	source := flag.String("source", defaultSource, "directory source key")
	dsn := flag.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN (defaults to PROXY_SENTINEL_POSTGRES_DSN)")
	insecure := flag.Bool("insecure-skip-verify", false, "skip TLS verification for the northbound endpoint")
	preview := flag.Bool("preview", false, "fetch and print the directory without writing")
	timeout := flag.Duration("timeout", 90*time.Second, "overall timeout")
	flag.Parse()

	if err := run(*endpoint, *appID, *appSecretFile, *source, *dsn, *insecure, *preview, *timeout, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "srun-group-directory-sync:", err)
		os.Exit(1)
	}
}

func run(endpoint, appID, appSecretFile, source, dsn string, insecure, preview bool, timeout time.Duration, out io.Writer) error {
	if strings.TrimSpace(endpoint) == "" || strings.TrimSpace(appID) == "" || strings.TrimSpace(source) == "" {
		return fmt.Errorf("--endpoint, --app-id and --source are required")
	}
	secret, err := readSecret(appSecretFile)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := srunapi.New(endpoint, appID, secret, northboundHTTPClient(insecure))
	if err != nil {
		return err
	}
	groups, err := client.Groups(ctx)
	if err != nil {
		return err
	}
	named, parented := 0, 0
	for _, group := range groups {
		if strings.TrimSpace(group.Name) != "" {
			named++
		}
		if group.ParentID != "" {
			parented++
		}
	}
	fmt.Fprintf(out, "northbound directory: %d groups, %d named, %d with a parent\n", len(groups), named, parented)
	for i, group := range groups {
		if i >= 5 {
			break
		}
		fmt.Fprintf(out, "  %s = %s\n", group.ID, group.Name)
	}
	// The 4K group client refuses an entry without a name; an empty name here
	// means the deployment exposes ids only, and writing them would replace real
	// names with numbers.
	if named == 0 {
		return fmt.Errorf("northbound returned no group names; nothing to sync")
	}
	if preview {
		fmt.Fprintln(out, "preview only: nothing was written")
		return nil
	}
	if strings.TrimSpace(dsn) == "" {
		return fmt.Errorf("--postgres-dsn or PROXY_SENTINEL_POSTGRES_DSN is required to write")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	written, err := replaceGroupCatalog(ctx, db, source, groups, time.Now().UTC())
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %d groups into srun4k_group_catalog source=%s\n", written, source)
	return nil
}

func readSecret(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("--app-secret-file is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read secret: %w", err)
	}
	secret := strings.TrimSpace(string(raw))
	if secret == "" {
		return "", fmt.Errorf("secret file is empty")
	}
	return secret, nil
}

func northboundHTTPClient(insecure bool) *http.Client {
	client := &http.Client{Timeout: 20 * time.Second}
	if insecure {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	return client
}

// replaceGroupCatalog publishes the directory for one source. It mirrors the
// control plane's northbound group writer: deactivate the source's current rows,
// then upsert the observed ones. Nothing outside this source key is touched, so
// an identity-observed directory or another campus's directory is unaffected.
func replaceGroupCatalog(ctx context.Context, db *sql.DB, source string, groups []srunapi.Group, observedAt time.Time) (int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE srun4k_group_catalog SET active=false,updated_at=now() WHERE source=$1`, source); err != nil {
		return 0, err
	}
	written := 0
	for _, group := range groups {
		if strings.TrimSpace(group.ID) == "" || strings.TrimSpace(group.Name) == "" {
			continue
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO srun4k_group_catalog(source,group_id,name,parent_id,path,active,observed_at) VALUES($1,$2,$3,$4,$5,true,$6) ON CONFLICT(source,group_id) DO UPDATE SET name=EXCLUDED.name,parent_id=EXCLUDED.parent_id,path=EXCLUDED.path,active=true,observed_at=EXCLUDED.observed_at,updated_at=now()`,
			source, group.ID, group.Name, group.ParentID, group.Path, observedAt); err != nil {
			return 0, err
		}
		written++
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(audit_id,actor,action,target,outcome,created_at) VALUES($1,'srun-group-directory-sync','integration.srun4k.groups',$2,$3,now())`,
		fmt.Sprintf("audit-srun-groups-%d", observedAt.UnixNano()), source, fmt.Sprintf("synced:%d", written)); err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return written, nil
}
