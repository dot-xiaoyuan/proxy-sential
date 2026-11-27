-- 阶段一（P0）高频超时与百万级全表扫描索引补齐：
-- 1. shared_behavior_observations：为 current 视图与 history 强证据视图提供按 (last_seen DESC, observation_id DESC) 的部分索引，消除 377 万行回表排序与 10s 超时。
-- 2. shared_device_profile_jobs：为待处理脏任务队列提供 FIFO 部分索引，配合拆分 claim 查询消除百万级全表扫描。
-- 3. shared_observation_executions：为已过期执行记录按 evidence_version 清理提供部分索引。
-- 4. shared_identity_health_intervals：为健康区间范围查询提供覆盖索引。
-- 5. device_address_leases：为 DHCP 租约存在性检查提供 ack 覆盖部分索引（Index Only Scan）。
--
-- 已有大表线上环境可先在事务外并发预建，再执行本迁移完成校验登记：
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS shared_behavior_current_last_seen_idx
--   ON public.shared_behavior_observations (last_seen DESC, observation_id DESC) WHERE current;
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS shared_behavior_history_strong_idx
--   ON public.shared_behavior_observations (last_seen DESC, observation_id DESC) WHERE NOT current AND status IN ('confirmed', 'candidate');
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS shared_device_profile_jobs_dirty_fifo_idx
--   ON public.shared_device_profile_jobs (dirty_since, subject_key) WHERE processed_generation < dirty_generation;
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS shared_observation_execution_evidence_expired_idx
--   ON public.shared_observation_executions (evidence_version) WHERE state = 'expired';
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS shared_identity_health_healthy_range_idx
--   ON public.shared_identity_health_intervals (bridge_id, valid_from) INCLUDE (valid_to) WHERE healthy;
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS device_address_leases_ack_endpoint_valid_idx
--   ON public.device_address_leases (sensor_id, endpoint_id, observed_at DESC) INCLUDE (valid_until) WHERE action = 'ack';

SET LOCAL lock_timeout = '5s';

CREATE INDEX IF NOT EXISTS shared_behavior_current_last_seen_idx
  ON public.shared_behavior_observations (last_seen DESC, observation_id DESC)
  WHERE current;

CREATE INDEX IF NOT EXISTS shared_behavior_history_strong_idx
  ON public.shared_behavior_observations (last_seen DESC, observation_id DESC)
  WHERE NOT current AND status IN ('confirmed', 'candidate');

CREATE INDEX IF NOT EXISTS shared_device_profile_jobs_dirty_fifo_idx
  ON public.shared_device_profile_jobs (dirty_since, subject_key)
  WHERE processed_generation < dirty_generation;

CREATE INDEX IF NOT EXISTS shared_observation_execution_evidence_expired_idx
  ON public.shared_observation_executions (evidence_version)
  WHERE state = 'expired';

CREATE INDEX IF NOT EXISTS shared_identity_health_healthy_range_idx
  ON public.shared_identity_health_intervals (bridge_id, valid_from)
  INCLUDE (valid_to)
  WHERE healthy;

CREATE INDEX IF NOT EXISTS device_address_leases_ack_endpoint_valid_idx
  ON public.device_address_leases (sensor_id, endpoint_id, observed_at DESC)
  INCLUDE (valid_until)
  WHERE action = 'ack';
