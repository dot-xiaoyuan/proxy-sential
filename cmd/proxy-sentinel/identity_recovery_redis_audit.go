package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
)

type identityRedisRawBoundary struct {
	Bytes    int    `json:"bytes"`
	SHA256   string `json:"sha256"`
	SendTime string `json:"send_time,omitempty"`
}

type identityRedisListAudit struct {
	Length int64                     `json:"length"`
	Head   *identityRedisRawBoundary `json:"head,omitempty"`
	Tail   *identityRedisRawBoundary `json:"tail,omitempty"`
}

type identityRedisAudit struct {
	Kind                      string                 `json:"kind"`
	SampleStartedAt           time.Time              `json:"sample_started_at"`
	SampleCompletedAt         time.Time              `json:"sample_completed_at"`
	EventList                 string                 `json:"event_list"`
	ProcessingList            string                 `json:"processing_list"`
	Source                    identityRedisListAudit `json:"source"`
	Processing                identityRedisListAudit `json:"processing"`
	FrozenBatchManifestSHA256 string                 `json:"frozen_batch_manifest_sha256,omitempty"`
	Caveat                    string                 `json:"caveat"`
}

func identityRedisRawSummary(value string) (*identityRedisRawBoundary, error) {
	if value == "" {
		return nil, nil
	}
	if len(value) > 1<<20 {
		return nil, errors.New("identity Redis raw item exceeds one MiB audit bound")
	}
	sum := sha256.Sum256([]byte(value))
	summary := &identityRedisRawBoundary{Bytes: len(value), SHA256: hex.EncodeToString(sum[:])}
	var item map[string]any
	if json.Unmarshal([]byte(value), &item) == nil {
		switch v := item["send_time"].(type) {
		case float64:
			if v > 0 && v < 1<<53 {
				summary.SendTime = time.Unix(int64(v), 0).UTC().Format(time.RFC3339)
			}
		case string:
			if seconds, err := strconv.ParseInt(v, 10, 64); err == nil && seconds > 0 {
				summary.SendTime = time.Unix(seconds, 0).UTC().Format(time.RFC3339)
			}
		}
	}
	return summary, nil
}

func runIdentityRedisAudit(args []string) error {
	fs := flag.NewFlagSet("identity-recovery redis-audit", flag.ContinueOnError)
	addr := fs.String("addr", "", "NCU event Redis host:port")
	passwordFile := fs.String("password-file", "", "0600 NCU event Redis credential file")
	eventList := fs.String("event-list", "", "exact Redis source list key")
	processingList := fs.String("processing-list", "", "exact Redis processing list key")
	output := fs.String("output", "", "new 0600 JSON audit path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *addr == "" || *passwordFile == "" || *eventList == "" || *processingList == "" || !filepath.IsAbs(*output) {
		return errors.New("redis-audit requires addr, password-file, exact source/processing list keys and an absolute output path")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := requireIdentityRecoveryUnitsStopped(ctx); err != nil {
		return err
	}
	secret, err := os.ReadFile(*passwordFile)
	if err != nil {
		return err
	}
	client := redis.NewClient(&redis.Options{Addr: *addr, Password: strings.TrimSpace(string(secret)), ReadTimeout: 8 * time.Second, WriteTimeout: 5 * time.Second})
	defer client.Close()
	started := time.Now().UTC()
	var sourceLen, processingLen *redis.IntCmd
	var sourceHead, sourceTail, processingHead, processingTail *redis.StringSliceCmd
	var frozen *redis.StringCmd
	_, err = client.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		sourceLen = pipe.LLen(ctx, *eventList)
		sourceHead = pipe.LRange(ctx, *eventList, 0, 0)
		sourceTail = pipe.LRange(ctx, *eventList, -1, -1)
		processingLen = pipe.LLen(ctx, *processingList)
		processingHead = pipe.LRange(ctx, *processingList, 0, 0)
		processingTail = pipe.LRange(ctx, *processingList, -1, -1)
		frozen = pipe.Get(ctx, *processingList+":batch")
		return nil
	})
	if err != nil && !errors.Is(err, redis.Nil) {
		return err
	}
	if err := requireIdentityRecoveryUnitsStopped(ctx); err != nil {
		return err
	}
	audit := identityRedisAudit{
		Kind: "identity_redis_boundary_sample_v1", SampleStartedAt: started,
		SampleCompletedAt: time.Now().UTC(), EventList: *eventList, ProcessingList: *processingList,
		Source:     identityRedisListAudit{Length: sourceLen.Val()},
		Processing: identityRedisListAudit{Length: processingLen.Val()},
		Caveat:     "Atomic boundary sample only; it does not prove every earlier source event is retained or identify other Redis consumers.",
	}
	boundary := func(values []string) (*identityRedisRawBoundary, error) {
		if len(values) == 0 {
			return nil, nil
		}
		return identityRedisRawSummary(values[0])
	}
	if audit.Source.Head, err = boundary(sourceHead.Val()); err != nil {
		return err
	}
	if audit.Source.Tail, err = boundary(sourceTail.Val()); err != nil {
		return err
	}
	if audit.Processing.Head, err = boundary(processingHead.Val()); err != nil {
		return err
	}
	if audit.Processing.Tail, err = boundary(processingTail.Val()); err != nil {
		return err
	}
	if audit.Processing.Length > 0 && frozen.Val() == "" {
		return errors.New("processing queue has no frozen durable batch manifest")
	}
	if frozen.Val() != "" {
		sum := sha256.Sum256([]byte(frozen.Val()))
		audit.FrozenBatchManifestSHA256 = hex.EncodeToString(sum[:])
	}
	raw, err := json.MarshalIndent(audit, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	f, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"path": *output, "sha256": hex.EncodeToString(sum[:]), "source_length": audit.Source.Length, "processing_length": audit.Processing.Length})
}

func readIdentityRedisAudit(path, expectedEventList, expectedProcessingList string) (string, identityRedisAudit, error) {
	var audit identityRedisAudit
	info, err := os.Lstat(path)
	if err != nil {
		return "", audit, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() <= 0 || info.Size() > 64<<10 {
		return "", audit, fmt.Errorf("Redis audit must be a nonempty 0600 regular JSON file under 64 KiB")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", audit, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&audit); err != nil {
		return "", audit, err
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return "", audit, errors.New("Redis audit contains trailing data")
	}
	now := time.Now().UTC()
	if audit.Kind != "identity_redis_boundary_sample_v1" || audit.EventList != expectedEventList || audit.ProcessingList != expectedProcessingList ||
		audit.Source.Length < 0 || audit.Processing.Length < 0 ||
		audit.SampleStartedAt.IsZero() || audit.SampleCompletedAt.Before(audit.SampleStartedAt) ||
		audit.SampleCompletedAt.After(now.Add(5*time.Second)) || now.Sub(audit.SampleCompletedAt) > 10*time.Minute ||
		audit.Source.Length > 0 && (audit.Source.Head == nil || audit.Source.Tail == nil) ||
		audit.Processing.Length > 0 && (audit.Processing.Head == nil || audit.Processing.Tail == nil || audit.FrozenBatchManifestSHA256 == "") ||
		!validRedisBoundaryAudit(audit) {
		return "", audit, errors.New("Redis audit is stale, mismatched or incomplete")
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), audit, nil
}

func validRedisBoundaryAudit(audit identityRedisAudit) bool {
	validHash := func(value string) bool {
		if len(value) != 64 {
			return false
		}
		_, err := hex.DecodeString(value)
		return err == nil
	}
	for _, list := range []identityRedisListAudit{audit.Source, audit.Processing} {
		if list.Length > 0 && (list.Head == nil || list.Tail == nil) {
			return false
		}
		if list.Length > 0 && (!validHash(list.Head.SHA256) || !validHash(list.Tail.SHA256)) {
			return false
		}
		if list.Length == 0 && (list.Head != nil || list.Tail != nil) {
			return false
		}
	}
	return audit.FrozenBatchManifestSHA256 == "" || validHash(audit.FrozenBatchManifestSHA256)
}
