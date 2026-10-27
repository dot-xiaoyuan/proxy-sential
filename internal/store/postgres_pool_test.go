package store

import "testing"

func TestPostgresPoolLimitOnlyReducesCallerDefault(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_POSTGRES_MAX_OPEN_CONNS", "")
	if got := PostgresPoolLimit(8); got != 8 {
		t.Fatalf("default pool limit=%d want 8", got)
	}
	t.Setenv("PROXY_SENTINEL_POSTGRES_MAX_OPEN_CONNS", "3")
	if got := PostgresPoolLimit(8); got != 3 {
		t.Fatalf("configured pool limit=%d want 3", got)
	}
	if got := PostgresPoolLimit(2); got != 2 {
		t.Fatalf("configured limit must not increase small role pool: %d", got)
	}
	t.Setenv("PROXY_SENTINEL_POSTGRES_MAX_OPEN_CONNS", "bad")
	if got := PostgresPoolLimit(8); got != 8 {
		t.Fatalf("invalid configured limit=%d want 8", got)
	}
}
