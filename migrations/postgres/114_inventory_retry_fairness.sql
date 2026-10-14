-- Keep a failing hotspot from starving untouched devices. Failed work remains
-- pending and visible; the ordering only gives other ready work a chance.
CREATE INDEX inventory_projection_fair_claim ON endpoint_inventory_projection_jobs
 ((last_error<>''), (processed_generation>0) DESC,coalesce(pending_since,updated_at),endpoint_id)
 WHERE processed_generation<dirty_generation;
