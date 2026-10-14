-- Match the claim ordering; avoid sorting every pending endpoint per claim.
CREATE INDEX inventory_projection_work_claim ON endpoint_inventory_projection_jobs
 ((processed_generation>0) DESC,coalesce(pending_since,updated_at),endpoint_id)
 WHERE processed_generation<dirty_generation;
