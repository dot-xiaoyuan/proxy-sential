-- Reclaim only replaced/failed display generations. Inbox receipts, immutable
-- identity facts and full snapshots are not part of this cleanup queue.
CREATE TABLE identity_projection_cleanup (
 scope_key text NOT NULL,generation text NOT NULL,calibration_epoch bigint NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(scope_key,generation)
);
