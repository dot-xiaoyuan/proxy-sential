-- The application API reads the canonical connection summaries directly. The
-- legacy bucket table has no readers, while its materialized view doubles every
-- connection rebuild write and materially slows backlog recovery.
DROP VIEW IF EXISTS application_connection_bucket_facts_mv;
