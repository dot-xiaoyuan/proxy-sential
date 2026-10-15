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
	"syscall"
	"time"
)

func main() {
	collectionFile := flag.String("collection-config", os.Getenv("PROXY_SENTINEL_DISCOVERY_CONFIG"), "unified protocol ownership and capture scope configuration")
	iface := flag.String("interface", "", "optional passive capture interface")
	allowCIDRs := flag.String("allow-cidrs", "", "CIDRs allowed for passive discovery observations")
	site := flag.String("site", "", "passive capture site")
	domain := flag.String("domain", "", "passive capture layer-2 scope")
	spool := flag.String("spool", "/var/lib/proxy-sentinel/discovery-spool", "durable passive spool")
	node := flag.String("node", "", "configured discovery node ID")
	describe := flag.Bool("ssdp-describe", true, "read UPnP descriptions of on-link SSDP announcers whose neighbor MAC matches")
	flag.Parse()
	collection, err := discovery.LoadCollectionConfig(*collectionFile)
	if err != nil {
		log.Fatal(err)
	}
	if *allowCIDRs == "" {
		*allowCIDRs = collection.AllowedCIDRs
	}
	db, err := sql.Open("pgx", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"))
	if err != nil {
		log.Fatal("database configuration failed")
	}
	defer db.Close()
	db.SetMaxOpenConns(12)
	db.SetMaxIdleConns(12)
	repo := discovery.Repository{DB: db, Collection: &collection, PipelineV2: os.Getenv("PROXY_SENTINEL_DISCOVERY_V2") == "true"}
	if dsn := os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN"); dsn != "" {
		ch, e := store.NewClickHouseStore(store.ClickHouseOptions{DSN: dsn})
		if e != nil {
			log.Fatal("ClickHouse configuration failed")
		}
		repo.Archive = ch.WriteNormalizedEvents
		repo.ArchiveDiscovery = ch.WriteDiscoveryEvidenceArchive
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	captureFailure := make(chan error, 1)
	if repo.PipelineV2 {
		go func() {
			if e := repo.RunProjectionWorkers(ctx, *spool, *node, collection, []byte(os.Getenv("PROXY_SENTINEL_ACTION_MASTER_KEY"))); e != nil && ctx.Err() == nil {
				log.Print("discovery projection startup failed: ", discovery.WorkErrorCode(e))
				captureFailure <- e
				cancel()
			}
		}()
	}
	if *iface != "" {
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
	if err = discovery.RunWorker(ctx, repo, *node, []byte(os.Getenv("PROXY_SENTINEL_ACTION_MASTER_KEY"))); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
	select {
	case <-captureFailure:
		// A capture failure must trigger systemd Restart=on-failure. The durable
		// spool remains intact, and the failure is never reported as a clean stop.
		os.Exit(1)
	default:
	}
}
