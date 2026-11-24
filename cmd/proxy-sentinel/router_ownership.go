package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"proxy-sentinel/internal/store"
)

func runRouterOwnershipRefresh(args []string) error {
	fs := flag.NewFlagSet("router refresh-ownership", flag.ContinueOnError)
	sensor := fs.String("sensor-id", "", "capture sensor")
	assessment := fs.String("assessment-id", "", "current router assessment")
	apply := fs.Bool("apply", false, "update only active facts verified against the supplied archive reference")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *sensor == "" || *assessment == "" {
		return errors.New("sensor-id and assessment-id are required; supply one archive reference on stdin")
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	if err != nil {
		return err
	}
	if len(raw) > 4096 {
		return errors.New("archive reference exceeds 4096 bytes")
	}
	ref, err := store.ParseStreamBodyRef(string(raw))
	if err != nil {
		return err
	}
	backend, err := store.NewDBStore(store.Options{Mode: store.ModeDB, SensorID: *sensor, PostgresDSN: os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), ClickHouseDSN: os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN"), RequestTimeout: 10 * time.Second})
	if err != nil {
		return err
	}
	defer backend.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	count, err := backend.RefreshPassiveRouterOwnership(ctx, *sensor, *assessment, ref, *apply)
	if err != nil {
		return err
	}
	return writeJSON(os.Stdout, map[string]any{"apply": *apply, "facts": count, "assessment_id": *assessment, "source_sha256": ref.SHA256})
}
