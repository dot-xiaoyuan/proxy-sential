package store

import (
	"context"
	"fmt"
	"sync/atomic"
)

type queryTraceKey struct{}
type queryTrace struct {
	id       string
	sequence atomic.Uint64
}

// WithQueryTrace is used by the isolated benchmark fixture, never by public
// request headers on a normal deployment. Each SQL gets a distinct query ID.
func WithQueryTrace(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, queryTraceKey{}, &queryTrace{id: id})
}

func queryTraceID(ctx context.Context) string {
	if trace, ok := ctx.Value(queryTraceKey{}).(*queryTrace); ok {
		return fmt.Sprintf("sentinel-bench-%s-%d", trace.id, trace.sequence.Add(1))
	}
	return ""
}
