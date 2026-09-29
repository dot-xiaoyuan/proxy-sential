package srunapi

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type DispatchIntent struct {
	Key         string           `json:"key"`
	ConnectorID string           `json:"connector_id"`
	Target      DisconnectTarget `json:"target"`
	DropType    string           `json:"drop_type"`
}

type Reservation struct {
	SendAllowed bool
	ReservedAt  time.Time
}

type Journal struct{ DB *sql.DB }

// Lookup never creates a send reservation. A previously recorded dispatch may
// be observed after authorization is withdrawn, but cannot be rebound or resent.
func (j Journal) Lookup(ctx context.Context, in DispatchIntent) (Reservation, bool, error) {
	if j.DB == nil {
		return Reservation{}, false, fmt.Errorf("native journal database required")
	}
	if err := validateIntent(in); err != nil {
		return Reservation{}, false, err
	}
	body, err := json.Marshal(in)
	if err != nil {
		return Reservation{}, false, err
	}
	var at time.Time
	var identical bool
	err = j.DB.QueryRowContext(ctx, `SELECT intent=$2::jsonb,reserved_at FROM native_action_dispatch WHERE idempotency_key=$1`, in.Key, string(body)).Scan(&identical, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return Reservation{}, false, nil
	}
	if err != nil {
		return Reservation{}, false, err
	}
	if !identical {
		return Reservation{}, false, fmt.Errorf("idempotency key conflicts with immutable native intent")
	}
	return Reservation{ReservedAt: at}, true, nil
}

// Record appends an observation only if it belongs to the exact immutable
// reservation. Concurrent/late observations never overwrite previous evidence.
// Raw controller errors are deliberately not stored here: they may contain
// credentials or user data. Detailed safe reason codes belong to action audit.
func (j Journal) Record(ctx context.Context, in DispatchIntent, result StepResult, failed bool) error {
	if j.DB == nil {
		return fmt.Errorf("native journal database required")
	}
	switch result.Delivery {
	case "reserved", "acknowledged", "uncertain", "rejected":
	default:
		return fmt.Errorf("invalid native delivery observation")
	}
	switch result.Observation {
	case "unknown", "online", "absent", "changed":
	default:
		return fmt.Errorf("invalid native identity observation")
	}
	intent, err := json.Marshal(in)
	if err != nil {
		return err
	}
	body, err := json.Marshal(result)
	if err != nil {
		return err
	}
	res, err := j.DB.ExecContext(ctx, `INSERT INTO native_action_observations(idempotency_key,result,step_failed)
	 SELECT idempotency_key,$3::jsonb,$4 FROM native_action_dispatch WHERE idempotency_key=$1 AND intent=$2::jsonb`, in.Key, string(intent), string(body), failed)
	if err != nil {
		return fmt.Errorf("native observation write failed: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("native observation has no matching immutable reservation")
	}
	return nil
}

// Reserve is an irreversible send gate, not a renewable execution lease. Only
// the caller that observes a successful INSERT acknowledgement may send once.
// Losing that acknowledgement or crashing before the send deliberately requires
// reconciliation/operator review; another worker must never repeat the command.
// Call this after manual confirmation and fresh ownership checks. The surrounding
// executor must persist outcomes and cancellations separately; a reservation is
// neither a successful action nor permission to bypass those checks.
func (j Journal) Reserve(ctx context.Context, in DispatchIntent) (Reservation, error) {
	if j.DB == nil {
		return Reservation{}, fmt.Errorf("native action journal database required")
	}
	if err := validateIntent(in); err != nil {
		return Reservation{}, err
	}
	body, err := json.Marshal(in)
	if err != nil {
		return Reservation{}, err
	}
	var at time.Time
	err = j.DB.QueryRowContext(ctx, `INSERT INTO native_action_dispatch(idempotency_key,intent) VALUES($1,$2::jsonb) ON CONFLICT DO NOTHING RETURNING reserved_at`, in.Key, string(body)).Scan(&at)
	if err == nil {
		return Reservation{SendAllowed: true, ReservedAt: at}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Reservation{}, fmt.Errorf("native reservation not acknowledged: %w", err)
	}
	var identical bool
	err = j.DB.QueryRowContext(ctx, `SELECT intent=$2::jsonb,reserved_at FROM native_action_dispatch WHERE idempotency_key=$1`, in.Key, string(body)).Scan(&identical, &at)
	if err != nil {
		return Reservation{}, fmt.Errorf("native reservation read failed: %w", err)
	}
	if !identical {
		return Reservation{}, fmt.Errorf("idempotency key conflicts with immutable native intent")
	}
	return Reservation{ReservedAt: at}, nil
}

func validateIntent(in DispatchIntent) error {
	for _, s := range []string{in.Key, in.ConnectorID, in.Target.Account, in.Target.InstanceID, in.Target.SessionID, in.Target.RawOnlineID} {
		if s == "" || strings.TrimSpace(s) != s || len(s) > 1024 {
			return fmt.Errorf("invalid immutable dispatch identity")
		}
	}
	hash, err := hex.DecodeString(in.Target.BindingHash)
	if err != nil || len(hash) != 32 {
		return fmt.Errorf("confirmed binding hash required")
	}
	switch in.DropType {
	case "radius", "proxy", "dhcp", "portal":
		return nil
	default:
		return fmt.Errorf("unsupported native drop type")
	}
}

// Cancel creates a tombstone even before a worker reserves this intent. The
// same primary key serializes cancellation with reservation; no TTL may remove
// it while a retry remains possible. Already sent commands require reconciliation.
func (j Journal) Cancel(ctx context.Context, in DispatchIntent) error {
	if j.DB == nil {
		return fmt.Errorf("native journal database required")
	}
	if err := validateIntent(in); err != nil {
		return err
	}
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	res, err := j.DB.ExecContext(ctx, `INSERT INTO native_action_dispatch(idempotency_key,intent,cancelled_at) VALUES($1,$2::jsonb,clock_timestamp())
	ON CONFLICT(idempotency_key) DO UPDATE SET cancelled_at=COALESCE(native_action_dispatch.cancelled_at,EXCLUDED.cancelled_at)
	WHERE native_action_dispatch.intent=EXCLUDED.intent`, in.Key, string(body))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("cancellation conflicts with immutable native intent")
	}
	return nil
}

func (j Journal) Cancelled(ctx context.Context, in DispatchIntent) (bool, error) {
	if j.DB == nil {
		return false, fmt.Errorf("native journal database required")
	}
	body, err := json.Marshal(in)
	if err != nil {
		return false, err
	}
	var cancelled bool
	err = j.DB.QueryRowContext(ctx, `SELECT cancelled_at IS NOT NULL FROM native_action_dispatch WHERE idempotency_key=$1 AND intent=$2::jsonb`, in.Key, string(body)).Scan(&cancelled)
	return cancelled, err
}
