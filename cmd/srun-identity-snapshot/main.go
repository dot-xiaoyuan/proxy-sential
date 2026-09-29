package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/redis/go-redis/v9"
	"os"
	"os/signal"
	"path/filepath"
	"proxy-sentinel/internal/legacy4k"
	"strings"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func writePending(path string, in *legacy4k.OnlineInventory) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".identity-pending-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func secret(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", fmt.Errorf("empty secret file")
	}
	return s, nil
}
func run() error {
	addr := flag.String("redis-addr", "127.0.0.1:16380", "authoritative online Redis")
	passwordFile := flag.String("redis-password-file", "", "Redis credential file")
	endpoint := flag.String("endpoint", "", "Sentinel URL")
	tokenFile := flag.String("token-file", "", "identity integration token file")
	stateFile := flag.String("state-file", "", "durable pending inventory path")
	source := flag.String("source", "", "registered source")
	sensor := flag.String("sensor-id", "", "registered sensor")
	campus := flag.String("campus-id", "", "registered campus")
	domain := flag.String("access-domain", "", "registered access domain")
	interval := flag.Int("interval", 60, "registered reconciliation interval in seconds")
	limit := flag.Int("max-records", 1000, "atomic source read bound")
	once := flag.Bool("once", false, "send one complete inventory")
	preview := flag.Bool("preview", false, "validate the complete source and print counts without sending or storing identities")
	flag.Parse()
	required := []string{*passwordFile}
	if !*preview {
		required = append(required, *endpoint, *tokenFile, *stateFile, *source, *sensor, *campus, *domain)
	}
	for _, v := range required {
		if v == "" {
			return fmt.Errorf("explicit scope, endpoint, secret files and state-file required")
		}
	}
	if *interval < 1 || *interval > 86400 || *limit < 1 || *limit > 10000 {
		return fmt.Errorf("invalid interval or source bound")
	}
	password, err := secret(*passwordFile)
	if err != nil {
		return err
	}
	client := redis.NewClient(&redis.Options{Addr: *addr, Password: password, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second})
	defer client.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *preview {
		batch, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		inventory, err := legacy4k.ReadOnlineInventory(batch, client, "list:rad_online", "rad_online_id", *limit)
		if err != nil {
			return err
		}
		seeded := 0
		withGeneration := 0
		for _, row := range inventory.Rows {
			if row["add_time"] != "" {
				withGeneration++
			}
			if row["seed_tag"] != "" {
				seeded++
			}
		}
		records, err := inventory.IdentityRecords()
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"address_records": len(records), "status": "preview_valid", "observed_at": inventory.ObservedAt, "sessions": len(inventory.Rows), "seeded_records": seeded, "sessions_with_login_generation": withGeneration, "sessions_without_login_generation": len(inventory.Rows) - withGeneration})
	}
	token, err := secret(*tokenFile)
	if err != nil {
		return err
	}
	sender := legacy4k.Sender{Endpoint: *endpoint, Token: token, SensorID: *sensor}
	var pending *legacy4k.OnlineInventory
	if raw, err := os.ReadFile(*stateFile); err == nil {
		if err = json.Unmarshal(raw, &pending); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	for {
		// Each attempt owns its error. A retained inventory must be resent after
		// failure rather than inheriting the prior attempt and skipping SendSnapshot.
		err = nil
		batch, cancel := context.WithTimeout(ctx, 20*time.Second)
		if pending == nil {
			inventory, e := legacy4k.ReadOnlineInventory(batch, client, "list:rad_online", "rad_online_id", *limit)
			err = e
			if err == nil {
				// Never send a snapshot that cannot be recovered after a crash.
				if err = writePending(*stateFile, &inventory); err != nil {
					cancel()
					return fmt.Errorf("persist pending inventory: %w", err)
				}
				pending = &inventory
			}
		}
		if err == nil {
			err = sender.SendSnapshot(batch, *pending, *source, *campus, *domain, *interval)
		}
		cancel()
		if err == nil {
			seeded := 0
			for _, row := range pending.Rows {
				if row["seed_tag"] != "" {
					seeded++
				}
			}
			records, recordErr := pending.IdentityRecords()
			if recordErr != nil {
				return recordErr
			}
			if err = enc.Encode(map[string]any{"address_records": len(records), "status": "committed", "observed_at": pending.ObservedAt, "sessions": len(pending.Rows), "seeded_records": seeded}); err != nil {
				return err
			}
			if err = writePending(*stateFile, nil); err != nil {
				return err
			}
			pending = nil
			if *once {
				return nil
			}
		} else {
			if *once {
				return err
			}
			if e := enc.Encode(map[string]any{"status": "failed", "error": err.Error(), "pending_retained": pending != nil}); e != nil {
				return e
			}
		}
		delay := time.Duration(*interval) * time.Second
		if err != nil {
			delay = 10 * time.Second
		}
		err = nil
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
