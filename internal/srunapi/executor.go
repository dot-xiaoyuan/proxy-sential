package srunapi

import (
	"context"
	"errors"
	"fmt"
	"proxy-sentinel/internal/legacy4k"
	"time"
)

type DispatchJournal interface {
	Lookup(context.Context, DispatchIntent) (Reservation, bool, error)
	Reserve(context.Context, DispatchIntent) (Reservation, error)
	Record(context.Context, DispatchIntent, StepResult, bool) error
	Cancelled(context.Context, DispatchIntent) (bool, error)
}
type NativeDisconnect interface {
	RequestDisconnectChecked(context.Context, string, string, string, func(context.Context) error) error
}

// Executor is a background-worker component. Authorize must re-read current
// confirmation, evidence, cancellation, shadow admission and controller state;
// it must not rely solely on a previously approved input object.
type Executor struct {
	Journal   DispatchJournal
	Native    NativeDisconnect
	Read      func(context.Context) (legacy4k.OnlineInventory, error)
	Authorize func(context.Context, DispatchIntent) error
	Now       func() time.Time
	MaxAge    time.Duration
}

type StepResult struct {
	Delivery    string    `json:"delivery"`
	Observation string    `json:"observation"`
	ReservedAt  time.Time `json:"reserved_at"`
}

// Step sends at most once and otherwise reconciles. It does not convert an
// absence observation into an action completion receipt: account fan-out and
// durable action/audit records must also be committed by the caller.
func (e Executor) Step(ctx context.Context, intent DispatchIntent) (r StepResult, stepErr error) {
	r = StepResult{Delivery: "not_sent", Observation: "unknown"}
	if e.Journal == nil || e.Native == nil || e.Read == nil || e.Authorize == nil || e.Now == nil || e.MaxAge <= 0 || e.MaxAge > time.Minute {
		return r, fmt.Errorf("complete native executor dependencies required")
	}
	// The installed portal implementation queues an IP-only command. It cannot
	// currently guarantee the confirmed session is still the queue consumer's
	// target. Do not expose it as a session-bound account action.
	if intent.DropType == "portal" {
		return r, fmt.Errorf("portal queue session binding has not been verified")
	}
	reservation, found, err := e.Journal.Lookup(ctx, intent)
	if err != nil {
		return r, err
	}
	if !found {
		if err := e.Authorize(ctx, intent); err != nil {
			return r, fmt.Errorf("native action authorization no longer valid")
		}
	}
	in, err := e.Read(ctx)
	if err != nil {
		return r, fmt.Errorf("authoritative inventory unavailable")
	}
	now := e.Now()
	// Missing/changed targets are not silently rebound. No reservation is created
	// from a broken inventory or a different authentication source instance.
	if checkedRows(in, now, e.MaxAge) != nil || in.InstanceID != intent.Target.InstanceID {
		return r, fmt.Errorf("authoritative inventory invalid")
	}
	if !found {
		reservation, err = e.Journal.Reserve(ctx, intent)
		if err != nil {
			return r, err
		}
	}
	r.ReservedAt = reservation.ReservedAt
	r.Delivery = "reserved"
	defer func() {
		// Cancellation must stop network work, but should not discard knowledge
		// that a request may already have been sent. Bound the final write.
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := e.Journal.Record(writeCtx, intent, r, stepErr != nil); err != nil {
			stepErr = errors.Join(stepErr, err)
		}
	}()
	if !reservation.SendAllowed {
		r.Observation = CheckDisconnect(intent.Target, in, reservation.ReservedAt, now, e.MaxAge)
		return r, nil
	}
	// A cancellation or rebind between preparing and reserving must stop the send.
	if err = e.Authorize(ctx, intent); err != nil {
		return r, fmt.Errorf("native action cancelled or authorization changed")
	}
	in, err = e.Read(ctx)
	if err != nil {
		return r, fmt.Errorf("pre-send authoritative inventory unavailable")
	}
	now = e.Now()
	if CheckDisconnect(intent.Target, in, reservation.ReservedAt, now, e.MaxAge) != "online" {
		return r, fmt.Errorf("pre-send session binding no longer valid")
	}
	sentAt := e.Now()
	stopped, err := e.Journal.Cancelled(ctx, intent)
	if err != nil {
		return r, fmt.Errorf("pre-send cancellation state unavailable")
	}
	if stopped {
		return r, fmt.Errorf("native action cancellation recorded")
	}
	guard := func(checkCtx context.Context) error {
		if err := e.Authorize(checkCtx, intent); err != nil {
			return err
		}
		current, err := e.Read(checkCtx)
		if err != nil {
			return err
		}
		if CheckDisconnect(intent.Target, current, reservation.ReservedAt, e.Now(), e.MaxAge) != "online" {
			return fmt.Errorf("final session binding changed")
		}
		stopped, err := e.Journal.Cancelled(checkCtx, intent)
		if err != nil {
			return err
		}
		if stopped {
			return fmt.Errorf("final cancellation recorded")
		}
		sentAt = e.Now()
		return nil
	}
	if err = e.Native.RequestDisconnectChecked(ctx, intent.Target.Account, intent.Target.RawOnlineID, intent.DropType, guard); err != nil {
		if errors.Is(err, ErrDispatchPrevented) {
			return r, err
		}
		r.Delivery = "uncertain"
		if errors.Is(err, ErrBusinessRejected) {
			r.Delivery = "rejected"
		}
	} else {
		r.Delivery = "acknowledged"
	}
	in, err = e.Read(ctx)
	if err != nil {
		return r, fmt.Errorf("post-send authoritative inventory unavailable; reconcile without resend")
	}
	r.Observation = CheckDisconnect(intent.Target, in, sentAt, e.Now(), e.MaxAge)
	return r, nil
}
