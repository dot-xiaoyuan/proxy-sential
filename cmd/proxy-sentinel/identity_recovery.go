package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"proxy-sentinel/internal/store"
	"strings"
	"syscall"
)

func runIdentityRecovery(args []string) error {
	if len(args) > 0 && args[0] == "fresh-cutover" {
		return runIdentityFreshCutover(args[1:])
	}
	if len(args) > 0 && args[0] == "redis-audit" {
		return runIdentityRedisAudit(args[1:])
	}
	fs := flag.NewFlagSet("identity-recovery", flag.ContinueOnError)
	source := fs.String("source", "", "exact identity source")
	sensor := fs.String("sensor-id", "", "exact sensor")
	apply := fs.Bool("apply", false, "import retained failed facts after live inbox catches up")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *source == "" || *sensor == "" {
		return fmt.Errorf("--source and --sensor-id required")
	}
	pg, err := store.NewPostgresStore(store.PostgresOptions{DSN: os.Getenv("PROXY_SENTINEL_POSTGRES_DSN")})
	if err != nil {
		return err
	}
	defer pg.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	report, err := pg.RecoverFailedIdentityBatches(ctx, *source, *sensor, *apply)
	if encodeErr := json.NewEncoder(os.Stdout).Encode(report); encodeErr != nil {
		return encodeErr
	}
	return err
}

func runIdentityFreshCutover(args []string) error {
	fs := flag.NewFlagSet("identity-recovery fresh-cutover", flag.ContinueOnError)
	source := fs.String("source", "", "exact identity source")
	sensor := fs.String("sensor-id", "", "exact sensor")
	campus := fs.String("campus-id", "", "exact campus")
	domain := fs.String("access-domain", "", "exact access domain")
	oldEpoch := fs.String("old-epoch", "", "active immutable source epoch")
	newEpoch := fs.String("new-epoch", "", "new immutable source epoch")
	previousRelease := fs.String("previous-release", "", "verified previous release")
	redisAuditFile := fs.String("redis-audit-file", "", "0600 JSON from identity-recovery redis-audit")
	expectedEventList := fs.String("expected-event-list", "", "exact Redis source list from the active bridge")
	expectedProcessingList := fs.String("expected-processing-list", "", "exact Redis processing list from the active bridge")
	accepted := fs.Int64("expected-accepted-sequence", -1, "observed old accepted sequence")
	processed := fs.Int64("expected-processed-sequence", -1, "observed old processed sequence")
	pending := fs.Int64("expected-pending-records", -1, "observed old pending record count")
	exportPending := fs.Int64("expected-export-pending-records", -1, "observed old export pending count")
	oldStart := fs.Int64("expected-old-start-offset", -1, "observed active cutover start")
	apply := fs.Bool("apply", false, "commit the fenced recovery transaction")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *source == "" || *sensor == "" || *campus == "" || *domain == "" {
		return fmt.Errorf("fresh-cutover requires the exact source, sensor-id, campus-id and access-domain")
	}
	pg, err := store.NewPostgresStore(store.PostgresOptions{DSN: os.Getenv("PROXY_SENTINEL_POSTGRES_DSN")})
	if err != nil {
		return err
	}
	defer pg.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	scope := store.IdentityScope{Source: *source, SensorID: *sensor, CampusID: *campus, AccessDomain: *domain}
	if !*apply {
		inspection, err := pg.InspectIdentityFreshRecovery(ctx, scope)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(inspection)
	}
	if *oldEpoch == "" || *newEpoch == "" || *previousRelease == "" || *redisAuditFile == "" || *expectedEventList == "" || *expectedProcessingList == "" ||
		*accepted < 0 || *processed < 0 || *pending < 0 || *exportPending < 0 || *oldStart < 0 {
		return fmt.Errorf("--apply requires old/new epochs, previous release, exact Redis list keys, audit file and all expected counters")
	}
	if err := requireIdentityRecoveryUnitsStopped(ctx); err != nil {
		return err
	}
	redisAuditSHA256, audit, err := readIdentityRedisAudit(*redisAuditFile, *expectedEventList, *expectedProcessingList)
	if err != nil {
		return err
	}
	boundaryJSON, err := json.Marshal(audit)
	if err != nil {
		return err
	}
	request := store.IdentityFreshRecoveryRequest{Scope: scope, OldEpoch: *oldEpoch, NewEpoch: *newEpoch,
		PreviousRelease: *previousRelease, RedisAuditSHA256: redisAuditSHA256,
		RedisEventList: audit.EventList, RedisProcessingList: audit.ProcessingList,
		RedisSourceLength: audit.Source.Length, RedisProcessingLength: audit.Processing.Length,
		RedisSampleAt: audit.SampleCompletedAt, RedisBoundaryJSON: string(boundaryJSON),
		ExpectedAcceptedSequence: *accepted, ExpectedProcessedSequence: *processed,
		ExpectedPendingRecords: *pending, ExpectedExportPendingRecords: *exportPending,
		ExpectedOldStartOffset: *oldStart}
	plan, err := pg.ApplyIdentityFreshRecovery(ctx, request)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(plan)
}

func requireIdentityRecoveryUnitsStopped(ctx context.Context) error {
	for _, unit := range []string{"proxy-sentinel-ncu-identity-sync.service", "proxy-sentinel-ncu-identity-materializer.service"} {
		output, err := exec.CommandContext(ctx, "systemctl", "is-active", unit).Output()
		state := strings.TrimSpace(string(output))
		if state != "inactive" && state != "failed" {
			return fmt.Errorf("NCU recovery requires %s stopped; state=%q: %v", unit, state, err)
		}
	}
	return nil
}
