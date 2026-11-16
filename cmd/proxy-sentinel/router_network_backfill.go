package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"proxy-sentinel/internal/discovery"
)

// Each invocation performs at most one bounded transaction. Deliberately no
// automatic loop runs while the live ingestion queue needs capacity.
func runRouterNetworkBackfill(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: proxy-sentinel router network-backfill status|resume|pause|step --epoch <active-epoch> (requires PROXY_SENTINEL_POSTGRES_DSN in the protected environment)")
	}
	action := args[0]
	if action != "status" && action != "resume" && action != "pause" && action != "step" {
		return fmt.Errorf("unknown router network-backfill action %q", action)
	}
	fs := flag.NewFlagSet("router network-backfill "+action, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	epoch := fs.String("epoch", "", "fixed active source epoch")
	rows := fs.Int("max-rows", 500, "fact rows read in one step; capped at 500")
	devices := fs.Int("max-devices", 1, "typed devices projected in one step; capped at 1")
	bytes := fs.Int("max-bytes", 512*1024, "narrow fact bytes consumed in one step; capped at 512 KiB")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	dsn := os.Getenv("PROXY_SENTINEL_POSTGRES_DSN")
	if fs.NArg() != 0 || *epoch == "" || dsn == "" {
		return errors.New("router network-backfill requires --epoch and PROXY_SENTINEL_POSTGRES_DSN in the protected environment")
	}
	if *rows <= 0 || *rows > 500 || *devices != 1 || *bytes <= 0 || *bytes > 512*1024 {
		return errors.New("network backfill limits must be within 500 rows, exactly 1 device and 512 KiB")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p := discovery.StreamDiscoveryProjector{DB: db}
	var status discovery.StreamNetworkBackfillStatus
	switch action {
	case "status":
		status, err = p.StreamNetworkBackfillStatus(ctx, *epoch)
	case "resume":
		status, err = p.ResumeStreamNetworkBackfill(ctx, *epoch)
	case "pause":
		status, err = p.PauseStreamNetworkBackfill(ctx, *epoch)
	case "step":
		status, err = p.BackfillStreamNetworkStateStep(ctx, *epoch, discovery.StreamNetworkBackfillLimits{MaxRows: *rows, MaxDevices: *devices, MaxBytes: *bytes})
	}
	if err != nil {
		return err
	}
	return writeJSON(os.Stdout, status)
}
