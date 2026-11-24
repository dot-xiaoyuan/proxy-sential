package store

import (
	"context"
	"log"
	"time"
)

func (s *DBStore) runDiscoveryListGroups(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	adopted := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			job, cancel := context.WithTimeout(ctx, 5*time.Second)
			var count, ips int
			var err error
			if !adopted {
				err = s.pg.db.QueryRowContext(job, "SELECT discovery_list_adopt(128)").Scan(&adopted)
			}
			if err == nil {
				err = s.pg.db.QueryRowContext(job, "SELECT discovery_list_refresh_groups(64), discovery_list_refresh_ips(250)").Scan(&count, &ips)
			}
			cancel()
			delay := 250 * time.Millisecond
			if err != nil && ctx.Err() == nil {
				log.Printf("discovery list refresh: %v", err)
				delay = 5 * time.Second
			} else if !adopted || count == 64 || ips == 250 {
				delay = 25 * time.Millisecond
			}
			timer.Reset(delay)
		}
	}
}
