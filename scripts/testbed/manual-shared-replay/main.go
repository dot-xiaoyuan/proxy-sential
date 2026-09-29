// Replays explicitly synthetic signals through normal storage and materialization.
// Use only against an isolated test database; never infer field accuracy from it.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"proxy-sentinel/internal/materialize"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/store"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: manual-shared-replay events.json")
	}
	if os.Getenv("SENTINEL_TEST_REPLAY") != "isolated" {
		return fmt.Errorf("explicit isolated test acknowledgement required")
	}
	b, err := store.NewDBStore(store.Options{Mode: store.ModeDB, SensorID: "capture190", PostgresDSN: os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), ClickHouseDSN: os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN")})
	if err != nil {
		return err
	}
	defer b.Close()
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		return err
	}
	var events []normalized.Event
	if err = json.Unmarshal(raw, &events); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err = b.WriteNormalizedEvents(ctx, events); err != nil {
		return err
	}
	result, err := materialize.RunOnce(ctx, b, materialize.Options{SensorID: "capture190", SharedAccess: true, Window: 10 * time.Minute, Limit: 1000})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
