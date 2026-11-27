-- 阶段二（P1）单机 HDD 写放大治理：
-- 新增 5 分钟粒度共享判定趋势聚合桶表，替代将 99.88% 的 insufficient/expired 大 JSONB 逐条写入 policy_decision_records。
-- 每年仅约 105,120 行（< 15 MB），趋势图查询毫秒级完成。
CREATE TABLE IF NOT EXISTS public.shared_decision_trend_buckets (
  bucket_start TIMESTAMPTZ PRIMARY KEY,
  matched_count BIGINT NOT NULL DEFAULT 0,
  insufficient_count BIGINT NOT NULL DEFAULT 0,
  expired_count BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
