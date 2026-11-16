-- Passive network-device type is a clue from current discovery facts, not an
-- IoT classification or a confirmed router role. This sparse read model starts
-- empty and is populated by new observations or normal expiry projection. A
-- separate, manually paced primary-key backfill can cover retained old facts;
-- installation never scans the large fact or device-state tables.
CREATE TABLE stream_discovery_network_state (
 epoch text NOT NULL,
 device_key text NOT NULL,
 scope_id text NOT NULL,
 network_device_type text NOT NULL CHECK(network_device_type IN ('router','gateway','access_point','switch','firewall')),
 status text NOT NULL CHECK(status IN ('clue','expired')),
 type_last_seen timestamptz NOT NULL,
 type_valid_until timestamptz NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(epoch,device_key)
);

-- The page starts from the rare network-type keys, then joins one maintained
-- device-state row. These indexes grow only with network clues, and expiry or
-- withdrawal updates/deletes the same row in the projection transaction.
CREATE INDEX stream_discovery_network_current_page
 ON stream_discovery_network_state(network_device_type,type_last_seen DESC,device_key,epoch)
 WHERE status='clue';
CREATE INDEX stream_discovery_network_history_page
 ON stream_discovery_network_state(network_device_type,type_last_seen DESC,device_key,epoch)
 WHERE status='expired';

-- Backfill checkpoint and one receipt per network-typed device, rather than
-- one receipt per fact. The fact scan uses the existing (epoch,device_key,
-- fact_key) primary key and advances only after derived state commits.
CREATE TABLE stream_discovery_network_backfill_progress (
 epoch text PRIMARY KEY,
 cursor_device_key text NOT NULL DEFAULT '',
 cursor_fact_key text NOT NULL DEFAULT '',
 status text NOT NULL DEFAULT 'paused' CHECK(status IN ('paused','running','failed','complete')),
 scanned_rows bigint NOT NULL DEFAULT 0 CHECK(scanned_rows>=0),
 projected_devices bigint NOT NULL DEFAULT 0 CHECK(projected_devices>=0),
 last_error text NOT NULL DEFAULT '',
 started_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 completed_at timestamptz
);
CREATE TABLE stream_discovery_network_backfill_devices (
 epoch text NOT NULL REFERENCES stream_discovery_network_backfill_progress(epoch),
 device_key text NOT NULL,
 processed_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(epoch,device_key)
);
CREATE TABLE stream_discovery_network_backfill_gaps (
 epoch text NOT NULL REFERENCES stream_discovery_network_backfill_progress(epoch),
 device_key text NOT NULL,
 fact_key text NOT NULL,
 reason text NOT NULL,
 attempts bigint NOT NULL DEFAULT 1 CHECK(attempts>0),
 first_failed_at timestamptz NOT NULL DEFAULT now(),
 last_failed_at timestamptz NOT NULL DEFAULT now(),
 resolved_at timestamptz,
 PRIMARY KEY(epoch,device_key,fact_key)
);
CREATE INDEX stream_discovery_network_backfill_unresolved
 ON stream_discovery_network_backfill_gaps(epoch,last_failed_at)
 WHERE resolved_at IS NULL;
