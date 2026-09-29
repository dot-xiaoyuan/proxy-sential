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
	iface := flag.String("interface", "", "optional passive capture interface")
	site := flag.String("site", "", "passive capture site")
	domain := flag.String("domain", "", "passive capture layer-2 scope")
	spool := flag.String("spool", "/var/lib/proxy-sentinel/discovery-spool", "durable passive spool")
	node := flag.String("node", "", "configured discovery node ID")
	flag.Parse()
	db, err := sql.Open("pgx", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"))
	if err != nil {
		log.Fatal("database configuration failed")
	}
	defer db.Close()
	repo := discovery.Repository{DB: db}
	if dsn := os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN"); dsn != "" {
		ch, e := store.NewClickHouseStore(store.ClickHouseOptions{DSN: dsn})
		if e != nil {
			log.Fatal("ClickHouse configuration failed")
		}
		repo.Archive = ch.WriteNormalizedEvents
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *iface != "" {
		if *site == "" || *domain == "" {
			log.Fatal("passive site and domain required")
		}
		go func() {
			if e := discovery.Capture(ctx, *iface, *spool, discovery.Source{ID: "passive-" + *node, Address: *iface, Node: *node, Site: *site, Domain: *domain, ConfigVersion: 1}); e != nil && ctx.Err() == nil {
				log.Print("passive capture failed: ", e)
				cancel()
			}
		}()
		go func() {
			tick := time.NewTicker(time.Second)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					if e := repo.DrainSpool(ctx, *spool); e != nil {
						log.Print("passive spool processing failed")
					}
				}
			}
		}()
	}
	if err = discovery.RunWorker(ctx, repo, *node, []byte(os.Getenv("PROXY_SENTINEL_ACTION_MASTER_KEY"))); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
}
