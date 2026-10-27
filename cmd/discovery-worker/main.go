package main

import (
	"context"
	"database/sql"
	"flag"
	_ "github.com/jackc/pgx/v5/stdlib"
	"log"
	"os"
	"os/signal"
	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/store"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	mode := flag.String("mode", os.Getenv("PROXY_SENTINEL_DISCOVERY_MODE"), "all, consume-only, passive, stream-prepare, stream-drain, or stream")
	workerDefault := 2
	if v := os.Getenv("PROXY_SENTINEL_DISCOVERY_REALTIME_WORKERS"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil {
			log.Fatal("invalid discovery realtime workers")
		}
		workerDefault = n
	}
	workers := flag.Int("realtime-workers", workerDefault, "realtime workers (1 or 2)")
	collectionFile := flag.String("collection-config", os.Getenv("PROXY_SENTINEL_DISCOVERY_CONFIG"), "unified protocol ownership and capture scope configuration")
	streamJournal := flag.String("stream-journal", "", "fresh-only durable passive stream journal directory")
	streamScope := flag.String("capture-scope-config", "", "controlled fresh passive capture scope")
	streamEpoch := flag.String("stream-epoch", "", "explicit fresh stream generation for stream-prepare")
	streamCancelID := flag.String("stream-cancel-id", "", "audited old discovery cancellation ID")
	streamCutoff := flag.String("stream-cutoff", "", "immutable RFC3339 old-work cancellation cutoff")
	streamPrevious := flag.String("stream-previous-release", "", "currently deployed compatible release")
	iface := flag.String("interface", "", "optional passive capture interface")
	allowCIDRs := flag.String("allow-cidrs", "", "CIDRs allowed for passive discovery observations")
	site := flag.String("site", "", "passive capture site")
	domain := flag.String("domain", "", "passive capture layer-2 scope")
	spool := flag.String("spool", "/var/lib/proxy-sentinel/discovery-spool", "durable passive spool")
	node := flag.String("node", "", "configured discovery node ID")
	describe := flag.Bool("ssdp-describe", true, "read UPnP descriptions of on-link SSDP announcers whose neighbor MAC matches")
	flag.Parse()
	if strings.TrimSpace(*node) == "" {
		log.Fatal("discovery node required")
	}
	collection, err := discovery.LoadCollectionConfig(*collectionFile)
	if err != nil {
		log.Fatal(err)
	}
	if *allowCIDRs == "" {
		*allowCIDRs = collection.AllowedCIDRs
	}
	if *mode == "stream-prepare" {
		if err := runPassiveStreamPrepare(passiveStreamOptions{Interface: *iface, Spool: *spool, JournalDir: *streamJournal, ScopeFile: *streamScope, Node: *node, Site: *site, Domain: *domain}, *streamEpoch, *streamCancelID, *streamPrevious, *streamCutoff); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *mode == "stream" || *mode == "stream-drain" {
		if err := runPassiveStreamWorker(passiveStreamOptions{Interface: *iface, Spool: *spool, JournalDir: *streamJournal, ScopeFile: *streamScope, Node: *node, Site: *site, Domain: *domain, AllowCIDRs: *allowCIDRs, Collection: collection, DrainOnly: *mode == "stream-drain"}); err != nil {
			log.Fatal(err)
		}
		return
	}
	options, err := discovery.NewWorkerOptions(*mode, *workers)
	if err != nil {
		log.Fatal(err)
	}
	db, err := sql.Open("pgx", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"))
	if err != nil {
		log.Fatal("database configuration failed")
	}
	defer db.Close()
	db.SetMaxOpenConns(store.PostgresPoolLimit(4))
	db.SetMaxIdleConns(store.PostgresPoolLimit(4))
	openPool := func(size int) *sql.DB {
		pool, e := sql.Open("pgx", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"))
		if e != nil {
			log.Fatal("database configuration failed")
		}
		pool.SetMaxOpenConns(store.PostgresPoolLimit(size))
		pool.SetMaxIdleConns(store.PostgresPoolLimit(size))
		return pool
	}
	backfillDB, runtimeDB := openPool(2), openPool(2)
	defer backfillDB.Close()
	defer runtimeDB.Close()
	repo := discovery.Repository{BackfillDB: backfillDB, RuntimeDB: runtimeDB, DB: db, Collection: &collection, PipelineV2: os.Getenv("PROXY_SENTINEL_DISCOVERY_V2") == "true"}
	if dsn := os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN"); dsn != "" {
		ch, e := store.NewClickHouseStore(store.ClickHouseOptions{DSN: dsn})
		if e != nil {
			log.Fatal("ClickHouse configuration failed")
		}
		writer := store.NewDiscoveryArchiveWriter(db, ch)
		if repo.PipelineV2 {
			probe, stop := context.WithTimeout(context.Background(), 5*time.Second)
			e = writer.ValidateRecovery(probe)
			stop()
			if e != nil {
				log.Fatal("discovery recovery preflight failed: ", discovery.WorkErrorCode(e))
			}
		}
		if repo.PipelineV2 {
			repo.Archive = writer.Write
			repo.BackfillArchive = store.NewDiscoveryArchiveWriter(backfillDB, ch).Write
		} else {
			repo.Archive = ch.WriteNormalizedEvents
		}
		repo.ArchiveDiscovery = ch.WriteDiscoveryEvidenceArchive
	}

	if repo.PipelineV2 && repo.Archive == nil {
		log.Fatal("ClickHouse configuration required for discovery v2")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	captureFailure := make(chan error, 1)
	if !repo.PipelineV2 && options.Mode != "all" {
		log.Fatal("recovery modes require discovery v2")
	}
	if repo.PipelineV2 {
		go func() {
			if e := repo.RunProjectionWorkersConfigured(ctx, *spool, *node, collection, []byte(os.Getenv("PROXY_SENTINEL_ACTION_MASTER_KEY")), options); e != nil && ctx.Err() == nil {
				log.Print("discovery projection startup failed: ", discovery.WorkErrorCode(e))
				captureFailure <- e
				cancel()
			}
		}()
	}
	if options.Capture() && *iface != "" {
		if *site == "" || *domain == "" {
			log.Fatal("passive site and domain required")
		}
		prefixes, e := discovery.ParseCaptureCIDRs(*allowCIDRs)
		if e != nil {
			log.Fatal(e)
		}
		if *describe && !repo.PipelineV2 {
			describer := discovery.NewDescriber(*spool)
			repo.Describe = describer.Offer
			go describer.Run(ctx)
		}
		go func() {
			if e := discovery.CaptureConfigured(ctx, *iface, *spool, discovery.Source{ID: "passive-" + *node, Address: *iface, Node: *node, Site: *site, Domain: *domain, ConfigVersion: 1}, prefixes, collection); e != nil && ctx.Err() == nil {
				log.Print("passive capture failed: ", e)
				captureFailure <- e
				cancel()
			}
		}()
		go func() {
			tick := time.NewTicker(100 * time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					if e := repo.DrainSpool(ctx, *spool); e != nil {
						log.Print("passive spool processing failed: ", discovery.WorkErrorCode(e))
					}
				}
			}
		}()
	}
	if options.Active() {
		if err = discovery.RunWorker(ctx, repo, *node, []byte(os.Getenv("PROXY_SENTINEL_ACTION_MASTER_KEY"))); err != nil && ctx.Err() == nil {
			log.Fatal(err)
		}
	} else {
		<-ctx.Done()
	}
	select {
	case <-captureFailure:
		// A capture failure must trigger systemd Restart=on-failure. The durable
		// spool remains intact, and the failure is never reported as a clean stop.
		os.Exit(1)
	default:
	}
}
