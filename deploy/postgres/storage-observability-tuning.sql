-- PostgreSQL 写入与可观测性参数（现场部署时由运维以 superuser 执行，随后重启容器生效）。
--
-- 依据 docs/site-184-storage-query-diagnosis-20261015.md：
--   * max_wal_size=8GB 时 13.5 小时内 7 次被迫检查点，单次检查点写 15～76 分钟；
--   * 没有慢日志、pg_stat_statements、track_io_timing，热点 SQL 只能靠采样推断；
--   * 现场 effective_cache_size=32GB，而主机约 62GB 内存中可用于页缓存的约 40GB。
-- 参数沿用 ALTER SYSTEM（写入 PGDATA 下的 postgresql.auto.conf，随卷持久化），与
-- docs/ingest-backlog-recovery.md 已采用的方式一致；shared_buffers 不在此调整。
ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements';
ALTER SYSTEM SET pg_stat_statements.track = 'top';
ALTER SYSTEM SET track_io_timing = on;
ALTER SYSTEM SET log_lock_waits = on;
ALTER SYSTEM SET log_temp_files = 0;
ALTER SYSTEM SET log_min_duration_statement = '500ms';
ALTER SYSTEM SET log_checkpoints = on;
ALTER SYSTEM SET max_wal_size = '32GB';
ALTER SYSTEM SET checkpoint_timeout = '15min';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_compression = 'lz4';
ALTER SYSTEM SET effective_cache_size = '40GB';
-- 重启后执行：CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
