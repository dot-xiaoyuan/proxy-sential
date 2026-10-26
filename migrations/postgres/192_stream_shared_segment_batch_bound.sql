-- The stream journal permits at most 1,000 events and 4 MiB per segment.
-- Keep the shared receipt's event bound aligned so a durable larger segment
-- can be finalized and replayed without losing its original source position.
ALTER TABLE stream_shared_segment_receipts
  DROP CONSTRAINT stream_shared_segment_receipts_event_count_check,
  ADD CONSTRAINT stream_shared_segment_receipts_event_count_check
    CHECK(event_count >= 0 AND event_count <= 1000);
