package discovery

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"sync"
	"time"
)

// RunWorker uses the same AES-GCM envelope as control-plane connector credentials.
func RunWorker(ctx context.Context, r Repository, node string, key []byte) error {
	if node == "" || len(key) < 16 {
		return errors.New("node and configured master key required")
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	lastCleanup := time.Time{}
	for {
		if _, err := r.DB.ExecContext(ctx, `INSERT INTO discovery_nodes(node,last_seen) VALUES($1,now()) ON CONFLICT(node) DO UPDATE SET last_seen=now()`, node); err != nil && ctx.Err() == nil {
			log.Print("discovery worker heartbeat failed")
		}
		if time.Since(lastCleanup) > time.Hour {
			if err := r.Cleanup(ctx); err != nil {
				log.Print("discovery retention failed")
			}
			lastCleanup = time.Now()
		}
		if err := r.Associate(ctx); err != nil && ctx.Err() == nil {
			log.Print("discovery identity association failed")
		}
		if err := r.Schedule(ctx); err != nil && ctx.Err() == nil {
			log.Print("discovery schedule failed")
		}
		if err := r.ScheduleScans(ctx); err != nil && ctx.Err() == nil {
			log.Print("discovery scan scheduling failed")
		}
		for i := 0; i < 3; i++ {
			t, err := r.Claim(ctx, node)
			if err != nil {
				break
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				runCtx, cancel := context.WithTimeout(ctx, 90*time.Minute)
				defer cancel()
				done := make(chan struct{})
				defer close(done)
				go func() {
					poll := time.NewTicker(time.Second)
					defer poll.Stop()
					for {
						select {
						case <-done:
							return
						case <-runCtx.Done():
							return
						case <-poll.C:
							var stop bool
							if r.DB.QueryRowContext(runCtx, `SELECT cancel_requested FROM discovery_tasks WHERE id=$1`, t.ID).Scan(&stop) != nil || stop {
								cancel()
								return
							}
						}
					}
				}()
				var s Snapshot
				var err error
				if t.Kind == "scan" {
					s, err = r.runScan(runCtx, t)
				} else {
					pollCtx, end := context.WithTimeout(runCtx, 5*time.Minute)
					s, err = runPoll(pollCtx, t, key)
					end()
				}
				if err == nil {
					err = r.SaveSnapshot(runCtx, s)
				}
				finishCtx, end := context.WithTimeout(context.Background(), 10*time.Second)
				defer end()
				if t.Kind == "scan" && err == nil {
					var p ScanProfile
					if json.Unmarshal(t.Config, &p) == nil {
						_, _ = r.DB.ExecContext(finishCtx, `UPDATE discovery_scan_profiles SET trial_version=$2 WHERE id=$1 AND version=$2 AND EXISTS(SELECT 1 FROM discovery_tasks WHERE id=$3 AND NOT cancel_requested)`, p.ID, t.Version, t.ID)
					}
				}
				if e := r.Finish(finishCtx, t, s, err); e != nil {
					log.Print("discovery task completion failed")
				}
			}()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
func runPoll(ctx context.Context, t Task, key []byte) (Snapshot, error) {
	var s Source
	var secret Secret
	if err := json.Unmarshal(t.Config, &s); err != nil {
		return Snapshot{}, err
	}
	s.ConfigVersion = t.Version
	raw, err := base64.RawStdEncoding.DecodeString(t.EncryptedSecret)
	if err != nil {
		return Snapshot{}, err
	}
	sum := sha256.Sum256(key)
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return Snapshot{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Snapshot{}, err
	}
	if len(raw) < gcm.NonceSize() {
		return Snapshot{}, errors.New("invalid credential envelope")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return Snapshot{}, err
	}
	if err = json.Unmarshal(plain, &secret); err != nil {
		return Snapshot{}, err
	}
	return Poll(ctx, s, secret, t.ID)
}
