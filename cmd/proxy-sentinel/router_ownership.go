package main

import (
	"bytes"
	"context"
	"encoding/json"
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
		return errors.New("sensor-id and assessment-id are required; supply archive references on stdin")
	}
	const maxBytes = 20 * 4096
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, maxBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > maxBytes {
		return errors.New("archive references exceed size limit")
	}
	var refs []store.StreamBodyRef
	var hashes []string
	decoder := json.NewDecoder(bytes.NewReader(raw))
	for {
		var ref store.StreamBodyRef
		if err := decoder.Decode(&ref); err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		if err := ref.Validate(); err != nil {
			return err
		}
		refs = append(refs, ref)
		hashes = append(hashes, ref.SHA256)
		if len(refs) > 20 {
			return errors.New("at most twenty archived events per outlet")
		}
	}
	if len(refs) == 0 {
		return errors.New("archive references required")
	}
	backend, err := store.NewDBStore(store.Options{Mode: store.ModeDB, SensorID: *sensor, PostgresDSN: os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), ClickHouseDSN: os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN"), RequestTimeout: 10 * time.Second})
	if err != nil {
		return err
	}
	defer backend.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	count, err := backend.RefreshPassiveRouterOwnership(ctx, *sensor, *assessment, refs, *apply)
	if err != nil {
		return err
	}
	result := map[string]any{"apply": *apply, "facts": count, "assessment_id": *assessment, "source_hashes": hashes}
	if len(hashes) == 1 {
		result["source_sha256"] = hashes[0]
	}
	return writeJSON(os.Stdout, result)
}
