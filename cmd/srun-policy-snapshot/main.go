package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"proxy-sentinel/internal/productpolicy"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func readSecret(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", fmt.Errorf("empty secret file")
	}
	return value, nil
}

func writePending(path string, snapshot *productpolicy.Snapshot) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".product-policy-pending-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err = file.Write(raw); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
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

func run() error {
	addr := flag.String("redis-addr", "127.0.0.1:16382", "authoritative product Redis")
	passwordFile := flag.String("redis-password-file", "", "Redis credential file")
	endpoint := flag.String("endpoint", "", "Sentinel URL")
	tokenFile := flag.String("token-file", "", "product-policy integration token file")
	stateFile := flag.String("state-file", "", "durable pending snapshot path")
	source := flag.String("source", "", "source name")
	interval := flag.Int("interval", 60, "snapshot interval in seconds")
	limit := flag.Int("max-records", 1000, "atomic catalog read bound")
	once := flag.Bool("once", false, "send one complete snapshot")
	preview := flag.Bool("preview", false, "validate and print aggregate counts without sending")
	flag.Parse()
	if *passwordFile == "" || *source == "" || (!*preview && (*endpoint == "" || *tokenFile == "" || *stateFile == "")) {
		return fmt.Errorf("source, credential file and delivery configuration required")
	}
	if *interval < 5 || *interval > 86400 || *limit < 1 || *limit > 10000 {
		return fmt.Errorf("invalid interval or source bound")
	}
	password, err := readSecret(*passwordFile)
	if err != nil {
		return err
	}
	client := productpolicy.NewRedisCatalogClient(&redis.Options{Addr: *addr, Password: password, ContextTimeoutEnabled: true, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second})
	defer client.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *preview {
		readCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		snapshot, err := productpolicy.ReadRedisSnapshot(readCtx, client, *source, *limit)
		if err != nil {
			return err
		}
		relations := 0
		for _, product := range snapshot.Products {
			relations += len(product.ControlIDs)
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "preview_valid", "observed_at": snapshot.ObservedAt, "content_hash": snapshot.ContentHash, "products": len(snapshot.Products), "controls": len(snapshot.Controls), "relations": relations})
	}
	token, err := readSecret(*tokenFile)
	if err != nil {
		return err
	}
	sender := productpolicy.Sender{Endpoint: *endpoint, Token: token}
	var pending *productpolicy.Snapshot
	if raw, readErr := os.ReadFile(*stateFile); readErr == nil {
		if err = json.Unmarshal(raw, &pending); err != nil {
			return err
		}
	} else if !os.IsNotExist(readErr) {
		return readErr
	}
	encoder := json.NewEncoder(os.Stdout)
	failures := 0
	for {
		err = nil
		attempt, cancel := context.WithTimeout(ctx, 25*time.Second)
		if pending == nil {
			snapshot, readErr := productpolicy.ReadRedisSnapshot(attempt, client, *source, *limit)
			err = readErr
			if err == nil {
				if err = writePending(*stateFile, &snapshot); err == nil {
					pending = &snapshot
				}
			}
		}
		if err == nil {
			snapshotID := "srun-policy-" + pending.ContentHash[:32]
			err = sender.Send(attempt, *pending, snapshotID)
		}
		cancel()
		if err == nil {
			failures = 0
			relations := 0
			for _, product := range pending.Products {
				relations += len(product.ControlIDs)
			}
			if err = encoder.Encode(map[string]any{"status": "committed", "observed_at": pending.ObservedAt, "content_hash": pending.ContentHash, "products": len(pending.Products), "controls": len(pending.Controls), "relations": relations}); err != nil {
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
			failures++
			if *once {
				return err
			}
			if encodeErr := encoder.Encode(map[string]any{"status": "failed", "error": err.Error(), "pending_retained": pending != nil, "consecutive_failures": failures, "coverage_interrupted": failures >= 3}); encodeErr != nil {
				return encodeErr
			}
		}
		delay := time.Duration(*interval) * time.Second
		if err != nil {
			delay = 10 * time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
