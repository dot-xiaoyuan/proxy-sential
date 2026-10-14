package controlplane

import (
	"context"
	"database/sql"
	"os"
	"testing"
)

func TestQianhuOrganizationPreset(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	raw, err := os.ReadFile("../../migrations/postgres/107_ncu_qianhu_organization.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "existing"}[existing], func(t *testing.T) {
			ctx := context.Background()
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			_, err = tx.ExecContext(ctx, `CREATE TEMP TABLE campuses(campus_id text PRIMARY KEY,code text UNIQUE,name text,enabled boolean DEFAULT true,attributes jsonb DEFAULT '{}'); CREATE TEMP TABLE buildings(building_id text PRIMARY KEY,campus_id text REFERENCES campuses,code text,name text,enabled boolean DEFAULT true,attributes jsonb DEFAULT '{}',UNIQUE(campus_id,code)); CREATE TEMP TABLE network_zones(network_zone_id text PRIMARY KEY,campus_id text REFERENCES campuses,name text,cidrs jsonb DEFAULT '[]',ssids jsonb DEFAULT '[]',vlans jsonb DEFAULT '[]',enabled boolean DEFAULT true)`)
			if err != nil {
				t.Fatal(err)
			}
			campusID := "ncu"
			if existing {
				campusID = "site-qianhu"
				_, err = tx.ExecContext(ctx, `INSERT INTO campuses VALUES('site-qianhu','SITE','前湖校区',true,'{}'); INSERT INTO buildings VALUES('existing-library','site-qianhu','LIB','图书馆',true,'{}')`)
				if err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 2; i++ {
				if _, err = tx.ExecContext(ctx, string(raw)); err != nil {
					t.Fatal(err)
				}
			}
			var campuses, buildings, zones, bad int
			if err = tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM campuses),(SELECT count(*) FROM buildings),(SELECT count(*) FROM network_zones),(SELECT count(*) FROM network_zones WHERE campus_id<>$1 OR cidrs<>'[]' OR ssids<>'[]' OR vlans<>'[]')`, campusID).Scan(&campuses, &buildings, &zones, &bad); err != nil {
				t.Fatal(err)
			}
			if campuses != 1 || buildings != 41 || zones != 4 || bad != 0 {
				t.Fatalf("campuses=%d buildings=%d zones=%d incorrect mappings=%d", campuses, buildings, zones, bad)
			}
			// Reapplying the preset must not reset operator-edited names or mappings.
			if _, err = tx.ExecContext(ctx, `UPDATE network_zones SET name='现场区域',cidrs='["10.8.0.0/24"]',enabled=false WHERE network_zone_id='ncu-qh-huiyuan'; UPDATE buildings SET name='现场楼宇' WHERE building_id='ncu-qh-dorm-1'`); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.ExecContext(ctx, string(raw)); err != nil {
				t.Fatal(err)
			}
			var preserved bool
			if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM network_zones WHERE network_zone_id='ncu-qh-huiyuan' AND name='现场区域' AND cidrs='["10.8.0.0/24"]' AND NOT enabled) AND EXISTS(SELECT 1 FROM buildings WHERE building_id='ncu-qh-dorm-1' AND name='现场楼宇')`).Scan(&preserved); err != nil || !preserved {
				t.Fatalf("operator edits not preserved: %v", err)
			}
			if existing {
				var name string
				if err = tx.QueryRowContext(ctx, `SELECT name FROM campuses WHERE campus_id=$1`, campusID).Scan(&name); err != nil || name != "前湖校区" {
					t.Fatalf("existing campus changed: %s %v", name, err)
				}
			}
		})
	}
}
