package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

var errIdentityLocalWorkInterrupted = errors.New("身份清单本地处理已中断")

// Hash the same JSON bytes as r66, but keep only one record's encoding in
// memory. The header uses the request type itself, preserving its field order,
// time encoding, nulls and string escaping. Cancellation publishes no ID.
func srunIdentitySnapshotIDContext(ctx context.Context, request identitySnapshotRequest) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	headerRequest := request
	headerRequest.Records = nil
	header, err := json.Marshal(headerRequest)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	if request.Records == nil {
		digest.Write(header)
	} else {
		prefix, ok := bytes.CutSuffix(header, []byte(`,"records":null}`))
		if !ok {
			return "", fmt.Errorf("identity snapshot JSON envelope changed")
		}
		digest.Write(prefix)
		digest.Write([]byte(`,"records":[`))
		for i, record := range request.Records {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			raw, err := json.Marshal(record)
			if err != nil {
				return "", err
			}
			if err := ctx.Err(); err != nil {
				return "", err
			}
			if i > 0 {
				digest.Write([]byte(","))
			}
			digest.Write(raw)
		}
		digest.Write([]byte("]}"))
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return "srun4k-identity-" + hex.EncodeToString(digest.Sum(nil))[:32], nil
}

func identityLocalWorkError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", errIdentityLocalWorkInterrupted, err)
	}
	return err
}

func writeIdentityPreparationInterruption(w http.ResponseWriter, err error) bool {
	if errors.Is(err, context.Canceled) {
		writeError(w, http.StatusRequestTimeout, "identity_snapshot_cancelled", "身份快照处理已取消，请重试")
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		writeError(w, http.StatusRequestTimeout, "identity_snapshot_timeout", "身份快照处理超时，请重试")
		return true
	}
	return false
}
