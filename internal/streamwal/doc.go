// Package streamwal provides an opt-in, single-writer durable log foundation.
// It does not interpret capture events, database writes, or source cursors.
// Payloads and IDs are opaque: duplicate detection, source continuity and the
// meaning of accept/attempt/ack/finalized records belong to an adapter, such as
// streamlog.PassiveWALJournal, whose live write path is disabled by default.
//
// # Durability and outcomes
//
// Open owns an exclusive OS file lease until Close. It verifies the existing
// log, synchronizes it, and synchronizes its directory ancestry before exposing
// the writer. This establishes a new barrier for a complete sealed group whose
// previous Sync result was lost. Local filesystems must honor file/directory
// Sync and advisory flock; this is not a replicated log.
//
// Append admits Data; AppendWithClass also admits bounded Control records.
// Both reserve record and byte capacity, copy the payload and return a
// buffered one-result channel. A non-nil admission error means that request was
// not queued. Once admitted, context cancellation cannot retract it: callers
// must await its result, or recover before deciding whether it was committed.
// An admitted request succeeds only after its complete group and seal pass
// File.Sync. The returned Receipt has a consecutive LSN and physical location.
// Concurrent callers are ordered by admission, not by goroutine start time.
//
// A write or Sync failure returns ErrIndeterminate for the active group and
// stops the writer. Unsent queued requests return ErrNotWritten. Capacity is
// reserved before admission; rejection returns no channel and combines
// ErrNotWritten/ErrCapacity with ErrQueueCapacity, ErrDataCapacity, or
// ErrLogCapacity. It does not stop the writer. No error path
// retries or truncates the log. Reopen and Replay are required to reconcile an
// indeterminate result by stable business ID and content; blindly retrying an
// opaque ID can append a duplicate because this package does not deduplicate.
// Close drains all admitted requests and reports terminal errors. It does not
// abandon a blocked Sync to claim a safe cancellation.
//
// # Admission and control reserve
//
// MaxLogBytes is the total write ceiling, default 1 GiB. MaxDataBytes is a
// high-water mark for Data admission, not a separate count of Data payloads:
// all durable bytes and all admitted classes consume the same file position.
// ControlReserveBytes defaults to min(16 MiB, MaxLogBytes/16); MaxDataBytes
// defaults to MaxLogBytes-ControlReserveBytes. An explicit MaxDataBytes may
// reduce that high-water mark, but exceeding it is an invalid configuration.
// A zero reserve selects the default; it does not disable reservation.
//
// Every admitted record reserves its encoded frame plus a separate worst-case
// seal, including queued, held, and currently syncing records. Data cannot use
// the reserved control region; Control can use the remaining total budget.
// A successful group atomically converts those reservations into its actual
// durable bytes, returning unused seal space. Usage exposes a consistent
// logical budget snapshot, not physical free disk. Completion/recovery records
// must be explicitly classified Control by the adapter; event bodies remain Data.
// The fixed reserve supports bounded drain work, not unlimited retries or an
// indefinite sink outage. Queue backpressure can still temporarily reject Control.
//
// Lowering MaxDataBytes preserves remaining Control headroom. Lowering the
// total MaxLogBytes below existing EOF still permits Open, Inspect, Read and
// Replay, but neither class may append beyond that hard ceiling. Reopening
// never increases the ceiling or adds a fresh reserve above EOF. Format reads
// retain a separate 64 GiB file guard and all per-frame/group allocation bounds.
//
// # Format and recovery
//
// records.v1.wal contains bounded data frames followed by a seal for each
// commit group. Every frame hashes its type, LSN, payload length and bytes. A
// seal hashes all encoded data frames and binds the group start offset, first
// LSN and count. Recovery checks consecutive LSNs and exposes records only
// after verifying their entire group. Each frame has a 64-byte header; a seal
// occupies 120 bytes. A data payload contains uint16 kind and ID lengths, their
// bytes, then the opaque payload. Integers use big-endian encoding.
//
// The format hard limits are 4 MiB per opaque payload, 8 MiB per encoded group,
// 1024 records per group, 64 bytes per kind and 256 bytes per ID. Runtime write
// budgets may be smaller and do not invalidate existing frames on recovery.
// Queue admission counts both waiting and currently syncing records. Read and
// recovery allocations are bounded by the format limits, even after queue or
// write budgets have been reduced.
//
// Inspect validates a read-only file snapshot. It does not establish a new
// durability barrier and may see an incomplete tail while a writer is active.
// ErrTail reports an incomplete final group; ErrCorrupt reports invalid bytes,
// sequence or a seal mismatch. Both preserve every original byte, and Open
// refuses to append after either. Complete prefixes are described by Recovery,
// but this package does not repair, truncate or silently skip the suffix.
// Removing an entire valid suffix while the writer is stopped cannot be detected
// from the remaining self-consistent prefix alone. An adapter must cross-check
// independently durable checkpoints/receipts; this format is not redundancy
// against arbitrary storage loss.
//
// Replay verifies one bounded group at a time from a snapshot of the durable
// prefix. Read and Replay can run during a later group's slow Sync and never
// expose that group's bytes before its barrier. Replay is intended for startup
// or controlled inspection, not request-path full-log scans. Its visitor must
// not reenter the Log. Read uses the receipt's private proofs to check just its
// frame and seal, leaving other event bodies unread. Receipt proofs are generated
// by commit/replay, not by
// external callers; persistence across future rotated files needs a separate
// locator/checkpoint contract.
//
// # Integration boundary
//
// This foundation uses one file with an explicit byte ceiling (default 1 GiB).
// It has no rotation, checkpoint, body retirement, source cancellation, lane
// state machine, or corruption repair. Hitting the ceiling stops admission;
// increasing it is not a retention or production-capacity solution. A reliable
// Journal adapter must provide those mechanisms and preserve legacy files,
// unknown sink outcomes, the fixed source start and application rollback before
// enabling this writer for live traffic. No benchmark or unit test here claims
// that mirror capture can survive an unbounded sink outage without a gap.
package streamwal
