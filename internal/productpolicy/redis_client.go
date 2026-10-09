package productpolicy

import (
	"errors"
	"github.com/redis/go-redis/v9"
	"proxy-sentinel/internal/redisguard"
)

const (
	MaxCatalogRelations       = 100000
	MaxCatalogReferenceFields = 200000
	MaxSnapshotBytes          = 16 << 20
	maxRedisBulkBytes         = 1 << 20
)

var ErrCatalogResourceLimit = errors.New("4K产品策略目录超出资源上限")

type RedisCatalogClient struct{ *redisguard.Client }

func NewRedisCatalogClient(options *redis.Options) *RedisCatalogClient {
	return &RedisCatalogClient{Client: redisguard.NewClient(options, redisguard.Limits{ReadBytes: 64 << 20, ReplyBytes: 32 << 20, BulkBytes: maxRedisBulkBytes, ReadElements: 1000000, ReplyElements: 1000000, ArrayLength: 100001, Depth: 8, Error: ErrCatalogResourceLimit})}
}
